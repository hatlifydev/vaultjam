"""El contenedor de la bóveda: header, índice cifrado y operaciones de alto nivel.

Distribución en disco (lo ÚNICO en claro es header.json, y solo contiene lo
imprescindible para derivar la clave: parámetros KDF, salt y la MK envuelta):

    MiBoveda.vault/
    ├── header.json   # magic, versión, params Argon2id, salt, MK envuelta
    ├── index.enc     # TODA la metadata, cifrada (nombres, tamaños, árbol,
    │                 # mapeo archivo->chunks, miniaturas). Con padding a
    │                 # potencia de 2 para no filtrar cuántos archivos hay.
    └── blobs/xx/<128 bits aleatorios>.blob   # todos de tamaño idéntico

La capa de UI solo habla con la clase Vault; nunca toca claves ni AEADs.
"""

from __future__ import annotations

import json
import math
import os
import struct
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path

from . import crypto_core as cc
from .storage import FIXED_TS, BlobStore, _set_creation_time_windows

HEADER_NAME = "header.json"
INDEX_NAME = "index.enc"
INDEX_MIN_PAD = 4096


class VaultError(Exception):
    pass


def is_synced_location(path: Path) -> bool:
    """Detecta si una ruta vive dentro de una carpeta sincronizada a la nube.
    Los blobs cifrados no exponen contenido al sincronizarse, pero SÍ patrones
    de actividad (cuándo y cuánto añades), y un conflicto de sincronización
    sobre index.enc puede corromper la bóveda. La UI avisa activamente."""
    s = str(path).lower()
    return any(m in s for m in ("onedrive", "dropbox", "google drive", "googledrive", "icloud"))


@dataclass
class FileEntry:
    id: str                  # 128 bits hex, aleatorio; clave del AAD de sus chunks
    name: str                # nombre original — SOLO existe dentro del índice cifrado
    folder: str              # ruta lógica de carpeta (cifrada en el índice)
    size: int                # tamaño real en bytes (el padding lo oculta en disco)
    mtime: float             # fecha original del archivo (cifrada en el índice)
    mime: str                # "image" | "video"
    chunks: list[str] = field(default_factory=list)   # ids de blob, en orden
    thumb: str | None = None                          # id de blob de miniatura
    marks: list = field(default_factory=list)         # marcadores: [ms, etiqueta, rot]
    resume_ms: int = 0                                # última posición de video
    rotation: int = 0                                 # rotación del CONTENIDO en el visor
    favorite: bool = False                            # ⭐ favorito
    thumb_rotation: int = 0                           # rotación SOLO de la miniatura
    thumb_scale: float = 1.0                          # tamaño individual en la galería

    @property
    def file_id(self) -> bytes:
        return bytes.fromhex(self.id)

    @property
    def total_chunks(self) -> int:
        return len(self.chunks)


class Vault:
    """Una bóveda abierta. Crear con Vault.create() o Vault.open()."""

    def __init__(self, root: Path | None, store=None, read_only: bool = False):
        # root=None + store => bóveda remota (p.ej. Google Drive). El store
        # solo necesita read(blob_id); en remoto, además read_header/read_index.
        self.root = Path(root) if root is not None else None
        self.store = store if store is not None else BlobStore(self.root)
        self.read_only = bool(read_only)
        self._mk: bytearray | None = None
        self._keys: cc.SubKeys | None = None
        self._entries: dict[str, FileEntry] = {}
        self._folders: list[str] = []
        # Un solo lock serializa las mutaciones de índice/almacén; los
        # descifrados de lectura son seguros en paralelo (AESGCM no tiene
        # estado y cada lector usa su propia caché).
        self._lock = threading.Lock()

    # ------------------------------------------------------------------
    # Creación y apertura
    # ------------------------------------------------------------------

    @classmethod
    def create(cls, root: Path, password: str, params: dict | None = None) -> "Vault":
        params = dict(params or cc.ARGON2_DEFAULTS)
        root = Path(root)
        if root.exists() and any(root.iterdir()):
            raise VaultError("La carpeta destino existe y no está vacía.")
        (root / "blobs").mkdir(parents=True, exist_ok=True)

        salt = cc.random_bytes(cc.SALT_LEN)
        # La MK jamás deriva de la contraseña: es aleatoria pura. La
        # contraseña solo protege su envoltorio.
        mk = bytearray(cc.random_bytes(cc.KEY_LEN))
        kek = cc.derive_kek(password.encode("utf-8"), salt, **params)
        try:
            aad = cc.kdf_aad(params["m_kib"], params["t"], params["p"], salt)
            wrapped = cc.wrap_master_key(kek, mk, aad)
        finally:
            cc.zeroize(kek)  # la KEK no se necesita más: fuera de RAM cuanto antes

        header = {
            "magic": cc.MAGIC,
            "version": cc.VERSION,
            "kdf": {
                "algo": "argon2id",
                "m_kib": params["m_kib"],
                "t": params["t"],
                "p": params["p"],
                "salt": salt.hex(),
            },
            "mk_wrapped": {"nonce": wrapped["nonce"].hex(), "ct": wrapped["ct"].hex()},
        }
        v = cls(root)
        v._write_private(root / HEADER_NAME, json.dumps(header, indent=2).encode())
        v._mk = mk
        v._keys = cc.derive_subkeys(mk)
        v._entries = {}
        v._save_index()
        return v

    @staticmethod
    def _unlock_mk(header: dict, password: str) -> bytearray:
        """Valida el header y desenvuelve la clave maestra. Común a bóvedas
        locales y remotas: la criptografía es idéntica venga de donde venga."""
        if header.get("magic") != cc.MAGIC:
            raise VaultError("No es una bóveda válida.")
        if header.get("version") != cc.VERSION:
            raise VaultError("Versión de bóveda no soportada por esta app.")
        k = header["kdf"]
        salt = bytes.fromhex(k["salt"])
        kek = cc.derive_kek(password.encode("utf-8"), salt, k["m_kib"], k["t"], k["p"])
        try:
            # El AAD ata el envoltorio a los parámetros KDF del header: si
            # alguien los editó (p.ej. para debilitar Argon2), esto falla.
            aad = cc.kdf_aad(k["m_kib"], k["t"], k["p"], salt)
            w = header["mk_wrapped"]
            return cc.unwrap_master_key(
                kek, {"nonce": bytes.fromhex(w["nonce"]), "ct": bytes.fromhex(w["ct"])}, aad
            )
        finally:
            cc.zeroize(kek)

    @classmethod
    def open(cls, root: Path, password: str) -> "Vault":
        root = Path(root)
        try:
            header = json.loads((root / HEADER_NAME).read_text())
        except (OSError, ValueError) as e:
            raise VaultError("No es una bóveda válida (header ilegible).") from e
        mk = cls._unlock_mk(header, password)
        v = cls(root)
        v._mk = mk
        v._keys = cc.derive_subkeys(mk)
        v._load_index()
        return v

    @classmethod
    def open_remote(cls, store, password: str) -> "Vault":
        """Abre una bóveda alojada en un almacén remoto (p.ej. Google Drive)
        en SOLO LECTURA: previsualizar, ver por streaming y exportar. Nada
        se escribe en el remoto, así que no hay riesgo de corromper el
        índice por conflictos de concurrencia."""
        try:
            header = json.loads(store.read_header().decode("utf-8"))
        except (OSError, ValueError) as e:
            raise VaultError("No se pudo leer el header remoto.") from e
        mk = cls._unlock_mk(header, password)
        v = cls(None, store=store, read_only=True)
        v._mk = mk
        v._keys = cc.derive_subkeys(mk)
        v._load_index()
        return v

    @property
    def is_locked(self) -> bool:
        return self._keys is None

    def lock(self) -> None:
        """Borra (best-effort) el material de clave y la metadata de RAM.
        La UI debe cerrar antes visores y cargadores de miniaturas."""
        with self._lock:
            cc.zeroize(self._mk)
            self._mk = None
            self._keys = None       # los AEAD liberan sus claves en OpenSSL
            self._entries = {}

    def change_password(self, old: str, new: str, params: dict | None = None) -> None:
        """Cambiar contraseña = re-envolver 32 bytes. No se recifra contenido."""
        self._require_writable()
        header = json.loads((self.root / HEADER_NAME).read_text())
        k = header["kdf"]
        salt_old = bytes.fromhex(k["salt"])
        kek_old = cc.derive_kek(old.encode(), salt_old, k["m_kib"], k["t"], k["p"])
        try:
            w = header["mk_wrapped"]
            mk = cc.unwrap_master_key(
                kek_old,
                {"nonce": bytes.fromhex(w["nonce"]), "ct": bytes.fromhex(w["ct"])},
                cc.kdf_aad(k["m_kib"], k["t"], k["p"], salt_old),
            )
        finally:
            cc.zeroize(kek_old)

        p = dict(params or cc.ARGON2_DEFAULTS)
        salt_new = cc.random_bytes(cc.SALT_LEN)  # salt SIEMPRE nuevo con contraseña nueva
        kek_new = cc.derive_kek(new.encode(), salt_new, **p)
        try:
            wrapped = cc.wrap_master_key(
                kek_new, mk, cc.kdf_aad(p["m_kib"], p["t"], p["p"], salt_new)
            )
        finally:
            cc.zeroize(kek_new)
            cc.zeroize(mk)

        header["kdf"] = {
            "algo": "argon2id", "m_kib": p["m_kib"], "t": p["t"], "p": p["p"],
            "salt": salt_new.hex(),
        }
        header["mk_wrapped"] = {"nonce": wrapped["nonce"].hex(), "ct": wrapped["ct"].hex()}
        self._write_private(self.root / HEADER_NAME, json.dumps(header, indent=2).encode())

    # ------------------------------------------------------------------
    # Índice cifrado
    # ------------------------------------------------------------------

    def _require_keys(self) -> cc.SubKeys:
        if self._keys is None:
            raise VaultError("La bóveda está bloqueada.")
        return self._keys

    def _require_writable(self) -> None:
        if self.read_only:
            raise VaultError("Bóveda remota: solo lectura (ver y exportar).")

    def _save_index(self) -> None:
        if self.read_only:
            return   # remota: los cambios de metadata se descartan en silencio
        keys = self._require_keys()
        # Las carpetas viven SOLO aquí, dentro del índice cifrado: en disco
        # no existe ninguna estructura de directorios que las refleje.
        js = json.dumps(
            {"files": [e.__dict__ for e in self._entries.values()],
             "folders": self._folders}
        ).encode()
        # Padding a la siguiente potencia de 2 (mínimo 4 KiB): el tamaño de
        # index.enc solo revela un orden de magnitud logarítmico de la
        # cantidad de metadata, no el número de archivos.
        payload = struct.pack(">I", len(js)) + js
        padded_len = max(INDEX_MIN_PAD, 1 << math.ceil(math.log2(len(payload))))
        payload += b"\x00" * (padded_len - len(payload))
        blob = cc.seal(keys.index, payload, cc.index_aad())
        self._write_private(self.root / INDEX_NAME, blob)

    def _load_index(self) -> None:
        keys = self._require_keys()
        if self.root is not None:
            blob = (self.root / INDEX_NAME).read_bytes()
        else:
            blob = self.store.read_index()
        payload = cc.open_sealed(keys.index, blob, cc.index_aad())
        (ln,) = struct.unpack(">I", payload[:4])
        data = json.loads(payload[4 : 4 + ln])
        self._entries = {d["id"]: FileEntry(**d) for d in data["files"]}
        # .get: compatibilidad con bóvedas creadas antes de las carpetas.
        self._folders = list(data.get("folders", []))
        # Migración: los marcadores fueron enteros (ms), luego pares
        # [ms, etiqueta] y ahora tríos [ms, etiqueta, rotación|null].
        # Normalizar cualquier formato antiguo al cargar.
        def _norm_mark(m):
            if isinstance(m, list):
                t = int(m[0])
                lbl = str(m[1]) if len(m) > 1 else ""
                rot = int(m[2]) % 360 if len(m) > 2 and m[2] is not None else None
                return [t, lbl, rot]
            return [int(m), "", None]

        for e in self._entries.values():
            e.marks = [_norm_mark(m) for m in e.marks]

    @staticmethod
    def _write_private(path: Path, data: bytes) -> None:
        """Escritura atómica + marcas de tiempo normalizadas (el mtime del
        índice filtraría la fecha de tu última actividad)."""
        tmp = path.with_suffix(path.suffix + ".tmp")
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        os.utime(path, (FIXED_TS, FIXED_TS))
        _set_creation_time_windows(path, FIXED_TS)

    # ------------------------------------------------------------------
    # Importar / exportar / borrar
    # ------------------------------------------------------------------

    def entries(self, folder: str | None = None, favorites: bool = False) -> list[FileEntry]:
        """Todos los elementos (folder=None), los de una carpeta ("" = sin
        carpeta) o solo los favoritos (favorites=True ignora la carpeta)."""
        es = self._entries.values()
        if favorites:
            es = [e for e in es if e.favorite]
        elif folder is not None:
            es = [e for e in es if e.folder == folder]
        return sorted(es, key=lambda e: (e.folder, e.name.lower()))

    def get(self, entry_id: str) -> FileEntry:
        return self._entries[entry_id]

    # ---- carpetas (metadata pura: viven solo en el índice cifrado) ----

    def folders(self) -> list[str]:
        return sorted(self._folders, key=str.lower)

    def create_folder(self, name: str) -> None:
        self._require_writable()
        name = name.strip()
        if not name or "/" in name or "\\" in name:
            raise VaultError("Nombre de carpeta no válido.")
        if name in self._folders:
            raise VaultError("Ya existe una carpeta con ese nombre.")
        with self._lock:
            self._folders.append(name)
            self._save_index()

    def delete_folder(self, name: str) -> None:
        """Quita la carpeta; su contenido pasa a 'sin carpeta'. Nunca borra
        archivos: borrar contenido es una acción separada y explícita."""
        self._require_writable()
        with self._lock:
            if name in self._folders:
                self._folders.remove(name)
            for e in self._entries.values():
                if e.folder == name:
                    e.folder = ""
            self._save_index()

    def move_files(self, entry_ids: list[str], folder: str) -> None:
        self._require_writable()
        if folder and folder not in self._folders:
            raise VaultError("La carpeta destino no existe.")
        with self._lock:
            for eid in entry_ids:
                self._entries[eid].folder = folder
            self._save_index()

    def set_marks(self, entry_id: str, marks: list) -> None:
        """Marcadores de video: acepta [ms], [(ms, etiqueta)] o
        [(ms, etiqueta, rotación|None)]. Ordena y deduplica por tiempo.
        La rotación opcional permite que un marcador aplique su propia
        orientación al saltar (videos con tramos grabados de lado).
        Persisten dentro del índice cifrado: en disco jamás se ve ni
        cuántos hay, ni dónde, ni sus nombres."""
        if self.read_only:
            return   # remota: la metadata de sesión no persiste ni se simula
        norm: dict[int, tuple[str, int | None]] = {}
        for m in marks:
            if isinstance(m, (list, tuple)):
                t = int(m[0])
                lbl = str(m[1]) if len(m) > 1 else ""
                rot = (int(m[2]) % 360) if len(m) > 2 and m[2] is not None else None
                norm[t] = (lbl, rot)
            else:
                norm[int(m)] = ("", None)
        with self._lock:
            self._entries[entry_id].marks = [
                [t, norm[t][0], norm[t][1]] for t in sorted(norm)
            ]
            self._save_index()

    def set_resume(self, entry_id: str, ms: int) -> None:
        """Última posición de reproducción, para «continuar donde ibas»."""
        if self.read_only:
            return
        with self._lock:
            self._entries[entry_id].resume_ms = max(0, int(ms))
            self._save_index()

    def set_rotation(self, entry_id: str, rotation: int) -> None:
        """Rotación persistida: un video vertical girado se queda girado."""
        if self.read_only:
            return
        with self._lock:
            self._entries[entry_id].rotation = int(rotation) % 360
            self._save_index()

    def set_favorite(self, entry_id: str, fav: bool) -> None:
        if self.read_only:
            return
        with self._lock:
            self._entries[entry_id].favorite = bool(fav)
            self._save_index()

    def rotate_thumbs(self, entry_ids: list[str]) -> None:
        """Gira 90° SOLO las miniaturas. Independiente por completo de la
        rotación del contenido (`rotation`): girar la miniatura no gira el
        video/foto en el visor, ni al revés."""
        if self.read_only:
            return
        with self._lock:
            for eid in entry_ids:
                e = self._entries[eid]
                e.thumb_rotation = (e.thumb_rotation + 90) % 360
            self._save_index()

    def set_thumb_scale(self, entry_ids: list[str], scale: float) -> None:
        """Tamaño individual de la miniatura en la galería (1.0 = normal)."""
        if self.read_only:
            return
        scale = max(0.5, min(3.0, float(scale)))
        with self._lock:
            for eid in entry_ids:
                self._entries[eid].thumb_scale = scale
            self._save_index()

    def import_file(
        self, src: Path, mime: str, thumb_jpeg: bytes | None, folder: str = ""
    ) -> FileEntry:
        """Cifra e ingiere un archivo. El original NO se toca ni se borra:
        eliminarlo es decisión explícita del usuario (y ver SEGURIDAD.md
        sobre los límites del borrado en SSD)."""
        self._require_writable()
        keys = self._require_keys()
        src = Path(src)
        size = src.stat().st_size
        st_mtime = src.stat().st_mtime
        file_id = cc.random_bytes(16)
        total = max(1, math.ceil(size / cc.CHUNK_SIZE))

        chunk_ids: list[str] = []
        with self._lock:
            try:
                with open(src, "rb") as f:
                    for idx in range(total):
                        chunk = f.read(cc.CHUNK_SIZE)
                        if len(chunk) < cc.CHUNK_SIZE:
                            # Relleno con ceros hasta el tamaño fijo. La
                            # longitud real vive solo en el índice cifrado:
                            # en disco todos los blobs son idénticos.
                            chunk = chunk + b"\x00" * (cc.CHUNK_SIZE - len(chunk))
                        sealed = cc.seal(
                            keys.content, chunk, cc.chunk_aad(file_id, idx, total)
                        )
                        chunk_ids.append(self.store.write(sealed))

                thumb_id = None
                if thumb_jpeg is not None:
                    # La miniatura también se rellena al tamaño de chunk:
                    # si fuera más pequeña, contar "blobs chicos" revelaría
                    # cuántos archivos hay en la bóveda.
                    if len(thumb_jpeg) > cc.CHUNK_SIZE - 4:
                        raise VaultError("Miniatura inesperadamente grande.")
                    padded = struct.pack(">I", len(thumb_jpeg)) + thumb_jpeg
                    padded += b"\x00" * (cc.CHUNK_SIZE - len(padded))
                    sealed = cc.seal(keys.thumbs, padded, cc.thumb_aad(file_id))
                    thumb_id = self.store.write(sealed)

                entry = FileEntry(
                    id=file_id.hex(),
                    name=src.name,
                    folder=folder,
                    size=size,
                    mtime=st_mtime,
                    mime=mime,
                    chunks=chunk_ids,
                    thumb=thumb_id,
                )
                self._entries[entry.id] = entry
                self._save_index()
                return entry
            except BaseException:
                # Importación fallida o cancelada: no dejar blobs huérfanos.
                for cid in chunk_ids:
                    self.store.delete(cid)
                raise

    def read_thumb(self, entry_id: str) -> bytes | None:
        keys = self._require_keys()
        e = self._entries[entry_id]
        if e.thumb is None:
            return None
        payload = cc.open_sealed(
            keys.thumbs, self.store.read(e.thumb), cc.thumb_aad(e.file_id)
        )
        (ln,) = struct.unpack(">I", payload[:4])
        return payload[4 : 4 + ln]

    def open_reader(self, entry_id: str) -> "ChunkReader":
        return ChunkReader(self, self._entries[entry_id])

    def availability(self, refresh: bool = False) -> dict[str, bool] | None:
        """Solo almacenes remotos: qué elementos tienen TODOS sus chunks ya
        disponibles (p.ej. con una subida a Drive aún en curso). None si el
        almacén no lo soporta (local: siempre completo)."""
        if not hasattr(self.store, "available_blobs"):
            return None
        if refresh and hasattr(self.store, "refresh"):
            self.store.refresh()
        avail = self.store.available_blobs()
        return {
            e.id: all(c in avail for c in e.chunks)
            for e in self._entries.values()
        }

    def export_file(self, entry_id: str, dst_dir: Path) -> Path:
        """Descifra a disco. SOLO se llama por acción explícita del usuario;
        la UI advierte de que el resultado queda en claro."""
        e = self._entries[entry_id]
        dst = Path(dst_dir) / e.name
        n = 1
        while dst.exists():  # no sobreescribir silenciosamente
            dst = Path(dst_dir) / f"{Path(e.name).stem} ({n}){Path(e.name).suffix}"
            n += 1
        reader = self.open_reader(entry_id)
        with open(dst, "wb") as f:
            while True:
                data = reader.read(cc.CHUNK_SIZE)
                if not data:
                    break
                f.write(data)
        os.utime(dst, (e.mtime, e.mtime))  # restaurar la fecha original
        return dst

    def delete_file(self, entry_id: str) -> None:
        self._require_writable()
        with self._lock:
            e = self._entries.pop(entry_id)
            self._save_index()  # primero el índice: si falla, no perdemos blobs referenciados
            for cid in e.chunks:
                self.store.delete(cid)
            if e.thumb:
                self.store.delete(e.thumb)


class ChunkReader:
    """Lector con seek que descifra chunks BAJO DEMANDA, solo en RAM.

    Es la pieza que permite reproducir un video de gigas sin materializarlo
    entero en memoria y sin temporales en disco: mantiene una caché LRU de
    unos pocos chunks descifrados (~8 MiB) y verifica el tag GCM de cada
    chunk ANTES de entregar un solo byte.

    Thread-safe: el backend multimedia de Qt puede leer desde sus propios
    hilos internos.
    """

    def __init__(self, vault: Vault, entry: FileEntry, cache_chunks: int = 8):
        self._keys = vault._require_keys()
        self._store = vault.store
        self._entry = entry
        self._pos = 0
        self._cache: OrderedDict[int, bytes] = OrderedDict()
        self._cache_max = cache_chunks
        self._mutex = threading.Lock()

    @property
    def size(self) -> int:
        return self._entry.size

    def _chunk(self, idx: int) -> bytes:
        cached = self._cache.get(idx)
        if cached is not None:
            self._cache.move_to_end(idx)
            return cached
        e = self._entry
        sealed = self._store.read(e.chunks[idx])
        # AAD = (archivo, posición, total): un blob movido de sitio o de
        # archivo NO descifra. La integridad se comprueba chunk a chunk,
        # antes de usar los datos, no al final del archivo.
        plain = cc.open_sealed(
            self._keys.content, sealed, cc.chunk_aad(e.file_id, idx, e.total_chunks)
        )
        # Recortar el padding del último chunk a la longitud real.
        if idx == e.total_chunks - 1:
            real = e.size - idx * cc.CHUNK_SIZE
            plain = plain[:real]
        self._cache[idx] = plain
        if len(self._cache) > self._cache_max:
            self._cache.popitem(last=False)
        return plain

    # API estilo archivo (usable por PyAV y por el QIODevice del visor)

    def read(self, n: int = -1) -> bytes:
        with self._mutex:
            if n < 0:
                n = self._entry.size - self._pos
            n = max(0, min(n, self._entry.size - self._pos))
            out = bytearray()
            while n > 0:
                idx, off = divmod(self._pos, cc.CHUNK_SIZE)
                piece = self._chunk(idx)[off : off + n]
                if not piece:
                    break
                out += piece
                self._pos += len(piece)
                n -= len(piece)
            return bytes(out)

    def seek(self, pos: int, whence: int = 0) -> int:
        with self._mutex:
            if whence == 1:
                pos += self._pos
            elif whence == 2:
                pos += self._entry.size
            self._pos = max(0, min(pos, self._entry.size))
            return self._pos

    def tell(self) -> int:
        return self._pos

    def close(self) -> None:
        with self._mutex:
            self._cache.clear()  # soltar los chunks descifrados cuanto antes
