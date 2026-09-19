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

import copy
import hashlib
import hmac
import io
import json
import math
import os
import struct
import threading
import time
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
    adjust: dict = field(default_factory=dict)        # ajustes de imagen persistidos
    flip_h: bool = False                              # espejo horizontal persistido
    flip_v: bool = False                              # espejo vertical persistido

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
        self._pin: str | None = None   # "salt_hex:sha256_hex" del PIN de cortina
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
            self._pin = None

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
             "folders": self._folders,
             "pin": self._pin}
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
        self._pin = data.get("pin")
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
        src = Path(src)
        st = src.stat()
        with open(src, "rb") as f:
            return self._import_stream(f, st.st_size, src.name, st.st_mtime,
                                       mime, thumb_jpeg, folder)

    def import_bytes(self, name: str, data: bytes, mime: str,
                     thumb_jpeg: bytes | None, folder: str = "") -> FileEntry:
        """Importa contenido que SOLO existe en RAM (p.ej. un fotograma
        capturado en el visor): jamás pasa por el disco en claro."""
        return self._import_stream(io.BytesIO(data), len(data), name,
                                   time.time(), mime, thumb_jpeg, folder)

    # ------------------------------------------------------------------
    # Traer desde la nube (orquestado por gpull.CloudImport)
    # ------------------------------------------------------------------

    def same_master_key(self, other: "Vault") -> bool:
        """True si ESTA bóveda y `other` comparten clave maestra ⇒ son la
        MISMA bóveda (aunque una esté en Drive). Comparación en tiempo
        constante para no filtrar por temporización. Ambas deben estar
        desbloqueadas."""
        if self._mk is None or getattr(other, "_mk", None) is None:
            return False
        return hmac.compare_digest(bytes(self._mk), bytes(other._mk))

    def ensure_folder(self, name: str) -> None:
        """Añade una carpeta (plana) al índice si falta; idempotente y
        seguro entre hilos (traída en paralelo). No valida como
        create_folder porque el nombre proviene de otra bóveda ya existente,
        no de una entrada del usuario. El caller persiste el índice."""
        if not name:
            return
        with self._lock:
            if name not in self._folders:
                self._folders.append(name)

    def find_duplicate(self, name: str, size: int, mtime: float,
                       folder: str) -> bool:
        """¿Ya existe una entrada equivalente? Dedup del modo importar para
        que reintentar no cree copias. Igualdad por (nombre, tamaño, fecha,
        carpeta): barato y sin descargar/descifrar nada. Itera sobre una
        instantánea bajo lock (otras traídas en paralelo mutan el índice)."""
        with self._lock:
            entries = list(self._entries.values())
        for e in entries:
            if (e.name == name and e.size == size and e.folder == folder
                    and int(e.mtime) == int(mtime)):
                return True
        return False

    def graft_ciphertext_entry(self, entry: FileEntry, src_store,
                               cancelled=lambda: False) -> str:
        """MODO ESPEJO (misma clave maestra): copia el CIPHERTEXT de los
        blobs de esta entrada que falten en local —conservando su id— y
        añade/repara la entrada en el índice. No descifra: solo mueve bytes
        ya cifrados, así que ni siquiera usa la clave. Dedup por id de
        entrada. Devuelve 'added' | 'repaired' | 'skipped'."""
        self._require_writable()
        ids = list(entry.chunks) + ([entry.thumb] if entry.thumb else [])
        copied = 0
        for bid in ids:
            if cancelled():
                raise VaultError("Cancelado.")
            if not self.store.exists(bid):
                self.store.put(bid, src_store.read(bid))   # ciphertext tal cual
                copied += 1
        with self._lock:
            existed = entry.id in self._entries
            if not existed:
                # Añadir la carpeta AQUÍ mismo (ya tenemos el lock): llamar a
                # ensure_folder lo re-tomaría y self._lock NO es reentrante
                # (threading.Lock) → se auto-bloquearía.
                if entry.folder and entry.folder not in self._folders:
                    self._folders.append(entry.folder)
                self._entries[entry.id] = copy.deepcopy(entry)
            self._save_index()
        return "added" if not existed else ("repaired" if copied else "skipped")

    def import_decrypted_entry(self, src_vault: "Vault", entry: FileEntry,
                               folder: str | None = None,
                               cancelled=lambda: False) -> FileEntry | None:
        """MODO IMPORTAR (bóveda distinta): descifra el contenido de la
        bóveda de ORIGEN en RAM (jamás a disco, igual que el visor) y lo
        reingiere re-cifrado bajo la clave de ESTA bóveda (blobs e id
        nuevos). Conserva ajustes cosméticos (marcadores, rotación, favorito,
        ajustes de imagen). Dedup por (nombre, tamaño, fecha, carpeta).
        Devuelve la entrada nueva, o None si era duplicado."""
        self._require_writable()
        dst_folder = entry.folder if folder is None else folder
        if self.find_duplicate(entry.name, entry.size, entry.mtime, dst_folder):
            return None
        # El lector descifra por streaming: el texto plano transita RAM
        # chunk a chunk, nunca hay una copia entera ni un temporal en claro.
        reader = src_vault.open_reader(entry.id)
        try:
            thumb = src_vault.read_thumb(entry.id)
        except Exception:
            thumb = None
        self.ensure_folder(dst_folder)
        new = self._import_stream(reader, entry.size, entry.name, entry.mtime,
                                  entry.mime, thumb, dst_folder)
        with self._lock:
            new.marks = copy.deepcopy(entry.marks)
            new.rotation = entry.rotation
            new.favorite = entry.favorite
            new.thumb_rotation = entry.thumb_rotation
            new.thumb_scale = entry.thumb_scale
            new.adjust = dict(entry.adjust)
            new.flip_h, new.flip_v = entry.flip_h, entry.flip_v
            self._save_index()
        return new

    def _write_thumb_blob(self, keys: cc.SubKeys, file_id: bytes,
                          thumb_jpeg: bytes) -> str:
        """Sella una miniatura con el padding estándar (blob uniforme)."""
        if len(thumb_jpeg) > cc.CHUNK_SIZE - 4:
            raise VaultError("Miniatura inesperadamente grande.")
        padded = struct.pack(">I", len(thumb_jpeg)) + thumb_jpeg
        padded += b"\x00" * (cc.CHUNK_SIZE - len(padded))
        return self.store.write(cc.seal(keys.thumbs, padded, cc.thumb_aad(file_id)))

    def _import_stream(self, f, size: int, name: str, mtime: float, mime: str,
                       thumb_jpeg: bytes | None, folder: str) -> FileEntry:
        self._require_writable()
        keys = self._require_keys()
        file_id = cc.random_bytes(16)
        total = max(1, math.ceil(size / cc.CHUNK_SIZE))

        # El cifrado y la escritura de blobs NO necesitan el lock: cada blob
        # tiene id aleatorio propio y su archivo es independiente. Dejarlos
        # FUERA del lock permite que varias importaciones avancen a la vez
        # (traer desde la nube en paralelo); el lock solo protege el alta
        # atómica en el índice compartido.
        chunk_ids: list[str] = []
        try:
            for idx in range(total):
                chunk = f.read(cc.CHUNK_SIZE)
                if len(chunk) < cc.CHUNK_SIZE:
                    # Relleno con ceros hasta el tamaño fijo. La longitud
                    # real vive solo en el índice cifrado: en disco todos los
                    # blobs son idénticos.
                    chunk = chunk + b"\x00" * (cc.CHUNK_SIZE - len(chunk))
                sealed = cc.seal(
                    keys.content, chunk, cc.chunk_aad(file_id, idx, total)
                )
                chunk_ids.append(self.store.write(sealed))

            thumb_id = None
            if thumb_jpeg is not None:
                # La miniatura también se rellena al tamaño de chunk: si
                # fuera más pequeña, contar "blobs chicos" revelaría cuántos
                # archivos hay en la bóveda.
                thumb_id = self._write_thumb_blob(keys, file_id, thumb_jpeg)

            entry = FileEntry(
                id=file_id.hex(),
                name=name,
                folder=folder,
                size=size,
                mtime=mtime,
                mime=mime,
                chunks=chunk_ids,
                thumb=thumb_id,
            )
            with self._lock:                 # solo el índice: alta + guardado
                self._entries[entry.id] = entry
                self._save_index()
            return entry
        except BaseException:
            # Importación fallida o cancelada: no dejar blobs huérfanos.
            for cid in chunk_ids:
                self.store.delete(cid)
            raise

    def set_thumb(self, entry_id: str, thumb_jpeg: bytes) -> None:
        """Reemplaza la miniatura (p.ej. «usar este fotograma»): sella el
        blob nuevo, actualiza el índice y borra el antiguo."""
        self._require_writable()
        keys = self._require_keys()
        e = self._entries[entry_id]
        new_id = self._write_thumb_blob(keys, e.file_id, thumb_jpeg)
        with self._lock:
            old = e.thumb
            e.thumb = new_id
            self._save_index()
        if old:
            self.store.delete(old)

    def set_adjust(self, entry_id: str, adjust: dict) -> None:
        """Ajustes de imagen persistidos por elemento (brillo, gamma…).
        Un dict vacío = sin ajustes. En remotas: solo sesión."""
        if self.read_only:
            return
        with self._lock:
            self._entries[entry_id].adjust = dict(adjust)
            self._save_index()

    def set_flip(self, entry_id: str, flip_h: bool, flip_v: bool) -> None:
        """Espejo horizontal/vertical persistido (como la rotación)."""
        if self.read_only:
            return
        with self._lock:
            e = self._entries[entry_id]
            e.flip_h = bool(flip_h)
            e.flip_v = bool(flip_v)
            self._save_index()

    def read_thumb(self, entry_id: str, background: bool = False) -> bytes | None:
        """background=True marca la lectura como de FONDO: en almacenes
        remotos cede el paso a los chunks de video (el video manda)."""
        keys = self._require_keys()
        e = self._entries[entry_id]
        if e.thumb is None:
            return None
        read_bg = getattr(self.store, "read_bg", None) if background else None
        raw = read_bg(e.thumb) if read_bg else self.store.read(e.thumb)
        payload = cc.open_sealed(keys.thumbs, raw, cc.thumb_aad(e.file_id))
        (ln,) = struct.unpack(">I", payload[:4])
        return payload[4 : 4 + ln]

    def open_reader(self, entry_id: str) -> "ChunkReader":
        return ChunkReader(self, self._entries[entry_id])

    # ---- PIN de cortina (ocultar/mostrar contenido en pantalla) ----
    #
    # NO es criptografía: es una cortina de cortesía contra miradas ajenas
    # con la bóveda ABIERTA (p.ej. durante una sincronización larga). Quien
    # tenga la contraseña de la bóveda lo esquiva por definición. Se guarda
    # como hash con salt dentro del índice cifrado; en bóvedas remotas
    # (solo lectura) el cambio vive solo durante la sesión.

    @property
    def has_pin(self) -> bool:
        return self._pin is not None

    def check_pin(self, pin: str) -> bool:
        if self._pin is None:
            return False
        salt_hex, h = self._pin.split(":", 1)
        return hashlib.sha256(bytes.fromhex(salt_hex) + pin.encode()).hexdigest() == h

    def verify_password(self, password: str) -> bool:
        """Comprueba la contraseña maestra sin abrir nada (deriva la KEK y
        desenvuelve la MK; tarda ~1 s por Argon2id, a propósito). Es la
        llave de escape del PIN: quien la tiene ya es el dueño."""
        try:
            if self.root is not None:
                header = json.loads((self.root / HEADER_NAME).read_text())
            else:
                header = json.loads(self.store.read_header().decode("utf-8"))
            mk = self._unlock_mk(header, password)
            cc.zeroize(mk)
            return True
        except (VaultError, cc.VaultCryptoError, OSError, ValueError):
            return False

    def _pin_gate(self, old: str | None, password: str | None) -> None:
        """Autoriza tocar un PIN existente: PIN antiguo correcto O
        contraseña maestra correcta (PIN olvidado)."""
        if self._pin is None:
            return
        if old is not None and self.check_pin(old):
            return
        if password is not None and self.verify_password(password):
            return
        raise VaultError("El PIN actual (o la contraseña de la bóveda) no es correcto.")

    def set_pin(self, old: str | None, new: str,
                password: str | None = None) -> None:
        """Crea o cambia el PIN. Cambiar exige el PIN anterior, o la
        contraseña maestra si se olvidó."""
        self._pin_gate(old, password)
        if not (new.isdigit() and len(new) == 4):
            raise VaultError("El PIN debe ser exactamente 4 dígitos.")
        salt = cc.random_bytes(16)
        digest = hashlib.sha256(salt + new.encode()).hexdigest()
        with self._lock:
            self._pin = f"{salt.hex()}:{digest}"
            self._save_index()   # remota: no-op -> PIN solo de esta sesión

    def remove_pin(self, old: str | None = None,
                   password: str | None = None) -> None:
        """Elimina el PIN, autorizado por el PIN actual o la contraseña."""
        self._pin_gate(old, password)
        with self._lock:
            self._pin = None
            self._save_index()

    def all_blob_ids(self) -> list[str]:
        """Todos los blobs que referencia el índice (chunks + miniaturas),
        sin duplicados. Es el inventario que debe existir en un espejo."""
        out: dict[str, None] = {}
        for e in self._entries.values():
            for c in e.chunks:
                out[c] = None
            if e.thumb:
                out[e.thumb] = None
        return list(out)

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
        self._last_idx: int | None = None   # detectar saltos de reproducción

    @property
    def size(self) -> int:
        return self._entry.size

    def _chunk(self, idx: int) -> bytes:
        cached = self._cache.get(idx)
        if cached is not None:
            self._cache.move_to_end(idx)
            return cached
        e = self._entry
        # Salto de reproducción: cancelar las pre-cargas del punto antiguo
        # para que TODO el ancho de banda vaya al nuevo punto.
        if self._last_idx is not None and abs(idx - self._last_idx) > 1:
            cancel = getattr(self._store, "cancel_prefetch", None)
            if cancel is not None:
                cancel()
        self._last_idx = idx
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
        # Lectura adelantada en almacenes remotos: pedir YA los próximos
        # chunks en segundo plano. Reproducir fluye, y tras un salto la
        # ventana de pre-carga sigue al nuevo punto automáticamente.
        pf = getattr(self._store, "prefetch", None)
        if pf is not None:
            nxt = e.chunks[idx + 1: idx + 4]
            if nxt:
                pf(nxt)
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

    def prefetch_ahead(self, n: int = 8, start_idx: int | None = None,
                       horizon: int = 64) -> None:
        """Relleno PROGRESIVO del buffer desde la FRONTERA DE LECTURA REAL
        del reproductor (`self._pos`, que el demuxer avanza a través del
        DecryptingIODevice), no desde una estimación tiempo→byte, que en
        video de bitrate variable apunta a chunks equivocados. Anclando en
        la lectura real, la pre-carga siempre va justo por delante de donde
        el reproductor consume: contiguo al reproducir y correcto en pausa
        (los próximos bytes que pedirá al reanudar). Cada tick pide el
        siguiente lote (n) aún no descargado dentro del horizonte."""
        pf = getattr(self._store, "prefetch", None)
        if pf is None or not self._entry.chunks:
            return
        idx = start_idx if start_idx is not None else self._pos // cc.CHUNK_SIZE
        idx = max(0, min(idx, self._entry.total_chunks - 1))
        down = getattr(self._store, "downloaded", None) or set()
        window = self._entry.chunks[idx: idx + horizon]
        pending = [c for c in window if c not in down][:n]
        if pending:
            pf(pending)

    def buffered_ranges(self) -> list[tuple[float, float]]:
        """Tramos [0..1] del video ya descargados en esta sesión, para
        pintar el mapa de buffer en la barra de avance. En almacenes
        locales todo está 'cargado'."""
        total = self._entry.total_chunks
        if not total:
            return []
        down = getattr(self._store, "downloaded", None)
        if down is None:
            return [(0.0, 1.0)]
        have = sorted(set(self._cache) |
                      {i for i, c in enumerate(self._entry.chunks) if c in down})
        ranges: list[tuple[float, float]] = []
        start = prev = None
        for i in have:
            if prev is None or i != prev + 1:
                if start is not None:
                    ranges.append((start / total, (prev + 1) / total))
                start = i
            prev = i
        if start is not None:
            ranges.append((start / total, (prev + 1) / total))
        return ranges

    def close(self) -> None:
        with self._mutex:
            self._cache.clear()  # soltar los chunks descifrados cuanto antes
