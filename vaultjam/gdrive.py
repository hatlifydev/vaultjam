"""Acceso de SOLO LECTURA a bóvedas alojadas en Google Drive.

Decisiones de seguridad:

  - Scope mínimo: `drive.readonly`. El token OAuth que la app guarda no
    puede escribir ni borrar nada en tu Drive, solo leer.
  - El token se guarda en %APPDATA%\\VaultJam\\token.json. Es sensible en el
    sentido de que da LECTURA de tu Drive a quien lo robe (no de la bóveda:
    esa sigue cifrada). `forget_token()` lo borra; también puedes revocar el
    acceso en https://myaccount.google.com/permissions.
  - Lo que viaja y se cachea de Drive es SIEMPRE ciphertext: los blobs se
    descifran en RAM al llegar, exactamente igual que desde disco local.
  - Solo lectura también hacia la bóveda: abrir una bóveda remota jamás la
    modifica, así que no hay riesgo de corromper el índice por conflictos.

El streaming funciona porque el formato ya es remoto-amigable: cada chunk
de 1 MiB es un archivo independiente; el reproductor pide un chunk, se
descarga, se verifica su tag GCM y se descifra en RAM.
"""

from __future__ import annotations

import io
import os
import threading
from collections import OrderedDict
from pathlib import Path

SCOPES_RO = ["https://www.googleapis.com/auth/drive.readonly"]
SCOPES_RW = ["https://www.googleapis.com/auth/drive"]   # solo para sincronizar
SCOPES = SCOPES_RO   # alias de compatibilidad
APPDIR = Path(os.environ.get("APPDATA", str(Path.home()))) / "VaultJam"
TOKEN_PATH = APPDIR / "token.json"        # token de SOLO LECTURA (abrir remotas)
TOKEN_RW_PATH = APPDIR / "token_rw.json"  # token de escritura (solo sincronizar)


def get_credentials(client_secret_path: str, readonly: bool = True):
    """Autentica (abre el navegador la primera vez) y devuelve las
    credenciales. Tokens SEPARADOS por nivel de permiso: abrir bóvedas
    remotas usa solo-lectura; sincronizar pide escritura aparte, así el
    token de uso diario nunca puede modificar tu Drive.

    Se separa del servicio porque el cliente HTTP de Google NO es
    thread-safe: la subida en paralelo construye un servicio por hilo a
    partir de estas mismas credenciales."""
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow

    scopes = SCOPES_RO if readonly else SCOPES_RW
    token_path = TOKEN_PATH if readonly else TOKEN_RW_PATH
    creds = None
    if token_path.exists():
        try:
            creds = Credentials.from_authorized_user_file(str(token_path), scopes)
        except Exception:
            creds = None
    if creds is not None and not creds.has_scopes(scopes):
        creds = None   # el token guardado no cubre el permiso pedido
    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
        except Exception:
            creds = None
    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file(client_secret_path, scopes)
        # Abre el navegador del usuario; el "servidor" es un puerto efímero
        # en localhost solo para recibir el código OAuth.
        #  - prompt="select_account": SIEMPRE muestra el selector de cuentas
        #    (sin esto, Google reutiliza la sesión activa del navegador y
        #    puede autorizar con la cuenta equivocada).
        #  - timeout_seconds: si el usuario cancela o cierra la pestaña,
        #    Google nunca redirige al puerto local; sin timeout el flujo se
        #    quedaría colgado para siempre y no se podría reintentar.
        creds = flow.run_local_server(port=0, prompt="select_account",
                                      timeout_seconds=180)
        if creds is None:
            raise RuntimeError(
                "La autorización no se completó (cancelada o caducada). "
                "Vuelve a intentarlo y elige la cuenta correcta.")
        APPDIR.mkdir(parents=True, exist_ok=True)
        token_path.write_text(creds.to_json(), encoding="utf-8")
    return creds


def build_service(creds):
    """Un cliente de la API por hilo (httplib2 no es thread-safe).

    static_discovery=True usa el documento de descubrimiento EMPAQUETADO:
    sin él, cada cliente nuevo (cada hilo de descarga) haría una petición
    de red para descargarlo, ralentizando el primer acceso de cada hilo."""
    from googleapiclient.discovery import build
    return build("drive", "v3", credentials=creds,
                 cache_discovery=False, static_discovery=True)


def get_service(client_secret_path: str, readonly: bool = True):
    return build_service(get_credentials(client_secret_path, readonly))


def forget_token() -> None:
    TOKEN_PATH.unlink(missing_ok=True)
    TOKEN_RW_PATH.unlink(missing_ok=True)


def find_vaults(service) -> list[tuple[str, str]]:
    """Carpetas *.vault en el Drive del usuario: [(nombre, folder_id)]."""
    q = ("mimeType='application/vnd.google-apps.folder' "
         "and name contains '.vault' and trashed=false")
    res = service.files().list(q=q, fields="files(id,name)",
                               pageSize=100).execute()
    return sorted((f["name"], f["id"]) for f in res.get("files", []))


class _PriorityGate:
    """EL VIDEO MANDA: las descargas de primer plano (chunks del
    reproductor y su pre-carga) tienen prioridad absoluta; las de fondo
    (miniaturas) esperan a que no haya ninguna activa. Sin esto, abrir un
    video con la galería aún cargando lo dejaba a la cola."""

    def __init__(self):
        self._cv = threading.Condition()
        self._fg = 0

    def enter_fg(self):
        with self._cv:
            self._fg += 1

    def exit_fg(self):
        with self._cv:
            self._fg -= 1
            if self._fg <= 0:
                self._cv.notify_all()

    def wait_for_fg_idle(self, max_wait: float = 2.5):
        """Cede el paso al primer plano, pero NUNCA se bloquea para siempre:
        pasado max_wait, la lectura de fondo avanza igual (evita que una
        miniatura quede colgada si algo de primer plano no cierra bien)."""
        import time as _t
        deadline = _t.monotonic() + max_wait
        with self._cv:
            while self._fg > 0:
                remaining = deadline - _t.monotonic()
                if remaining <= 0:
                    return
                self._cv.wait(min(0.25, remaining))


class DriveStore:
    """Almacén de blobs sobre Drive con la misma interfaz de lectura que el
    BlobStore local (`read(blob_id)`), más header/índice.

    - Los listados de subcarpetas (blobs/xx/) se cachean: un solo listado
      por subcarpeta para mapear nombre→fileId, luego descargas directas.
    - Caché LRU de blobs cifrados para que retroceder en un video no
      re-descargue.
    - El cliente de Google no es thread-safe: cada hilo usa el SUYO
      (_thread_svc). El lock protege solo las estructuras en memoria, nunca
      una llamada de red, para que ninguna lectura bloquee a otra.
    """

    writable = False

    def __init__(self, service, folder_id: str, name: str = "",
                 cache_blobs: int = 96, service_factory=None):
        # cache 96 MiB: retiene el horizonte de pre-carga del video (64)
        # más miniaturas recientes sin re-descargar.
        self._svc = service
        self._svc_factory = service_factory   # un cliente HTTP por hilo
        self._tls = threading.local()
        self.folder_id = folder_id
        self.name = name or folder_id
        self._lock = threading.RLock()
        self._children: dict[str, dict[str, str]] = {}   # folderId -> {nombre: id}
        self._cache: OrderedDict[str, bytes] = OrderedDict()
        self._cache_max = cache_blobs
        self._inflight: set[str] = set()      # pre-cargas en vuelo (dedup)
        self._prefetch_pool = None
        self._pf_gen = 0                      # generación: saltar => cancelar
        self._gate = _PriorityGate()          # video antes que miniaturas
        self.downloaded: set[str] = set()     # bajados en la sesión (mapa
                                              # de buffer de la barra)
        # Con fábrica de servicios, las descargas pueden ir EN PARALELO
        # (miniaturas, video y previews a la vez, sin cola única).
        self.parallel_reads = 6 if service_factory else 1

        root = self._list(folder_id)
        if "header.json" not in root or "blobs" not in root:
            raise RuntimeError(
                "Esa carpeta de Drive no parece una bóveda (faltan header.json o blobs/).")
        self._root = root
        self._blobs_id = root["blobs"]

    # ------------------------------------------------------------------

    def _thread_svc(self):
        """Cliente de Drive PROPIO de este hilo (httplib2 no es thread-safe).
        Sin fábrica (apertura inicial) cae al único servicio compartido."""
        if self._svc_factory is None:
            return self._svc
        svc = getattr(self._tls, "svc", None)
        if svc is None:
            svc = self._svc_factory()
            self._tls.svc = svc
        return svc

    def _list(self, folder_id: str) -> dict[str, str]:
        # El lock protege SOLO la caché, JAMÁS la llamada de red: antes se
        # sostenía durante el listado HTTP, así que abrir un video mientras
        # una miniatura listaba su subcarpeta dejaba al video BLOQUEADO
        # esperando ese lock -> "se queda pegado". Ahora la red va fuera del
        # lock y con el cliente propio del hilo.
        with self._lock:
            cached = self._children.get(folder_id)
        if cached is not None:
            return cached
        svc = self._thread_svc()
        out: dict[str, str] = {}
        token = None
        while True:
            res = svc.files().list(
                q=f"'{folder_id}' in parents and trashed=false",
                fields="nextPageToken,files(id,name)",
                pageSize=1000, pageToken=token).execute()
            for f in res.get("files", []):
                out[f["name"]] = f["id"]
            token = res.get("nextPageToken")
            if not token:
                break
        with self._lock:
            self._children[folder_id] = out
        return out

    @staticmethod
    def _download_with(svc, file_id: str) -> bytes:
        from googleapiclient.http import MediaIoBaseDownload
        buf = io.BytesIO()
        dl = MediaIoBaseDownload(buf, svc.files().get_media(fileId=file_id))
        done = False
        while not done:
            _, done = dl.next_chunk()
        return buf.getvalue()

    def _download(self, file_id: str) -> bytes:
        # Descarga con el cliente del hilo, SIN lock: paralelismo real.
        return self._download_with(self._thread_svc(), file_id)

    def prefetch(self, blob_ids: list[str]) -> None:
        """Pre-descarga en segundo plano: el lector de video la invoca con
        los PRÓXIMOS chunks mientras el reproductor consume el actual, y
        tras un salto, con los que siguen al nuevo punto. Reproducir deja
        de atascarse esperando cada descarga."""
        if self._svc_factory is None:
            return
        if self._prefetch_pool is None:
            import concurrent.futures as cf
            self._prefetch_pool = cf.ThreadPoolExecutor(
                max_workers=4, thread_name_prefix="vj-prefetch")
        for b in blob_ids:
            with self._lock:
                if b in self._cache or b in self._inflight:
                    continue
                self._inflight.add(b)
                gen = self._pf_gen
            self._prefetch_pool.submit(self._prefetch_one, b, gen)

    def cancel_prefetch(self) -> None:
        """Invalida las pre-cargas pendientes (el usuario saltó a otro
        punto): las encoladas se descartan al arrancar; las ya en vuelo
        terminan su blob (~1 MiB) y quedan en caché por si acaso."""
        with self._lock:
            self._pf_gen += 1

    def _prefetch_one(self, blob_id: str, gen: int) -> None:
        try:
            with self._lock:
                if gen != self._pf_gen:
                    return          # obsoleta: el video ya está en otro punto
            self.read(blob_id)      # read() cachea el resultado
        except Exception:
            pass                    # la lectura real reintentará y avisará
        finally:
            with self._lock:
                self._inflight.discard(blob_id)

    def refresh(self) -> None:
        """Descarta los listados cacheados: la próxima consulta verá el
        estado actual de Drive (útil mientras una subida sigue en curso)."""
        with self._lock:
            self._children.clear()

    def available_blobs(self) -> set[str]:
        """Ids de los blobs YA presentes en Drive. Solo lee metadata, y en
        LOTES: una consulta puede abarcar ~40 subcarpetas a la vez
        («'a' in parents or 'b' in parents …»), así que una bóveda de 40k
        blobs necesita ~45 peticiones en vez de ~300."""
        subs = [fid for name, fid in self._list(self._blobs_id).items()
                if len(name) == 2]
        out: set[str] = set()
        svc = self._thread_svc()          # cliente del hilo, sin lock de red
        GROUP = 40
        for i in range(0, len(subs), GROUP):
            clause = " or ".join(f"'{sid}' in parents"
                                 for sid in subs[i:i + GROUP])
            q = f"({clause}) and trashed=false"
            token = None
            while True:
                res = svc.files().list(
                    q=q, fields="nextPageToken,files(name)",
                    pageSize=1000, pageToken=token).execute()
                for f in res.get("files", []):
                    n = f["name"]
                    if n.endswith(".blob"):
                        out.add(n[:-5])
                token = res.get("nextPageToken")
                if not token:
                    break
        return out

    # ---- interfaz que consume Vault ----

    def read_header(self) -> bytes:
        return self._download(self._root["header.json"])

    def read_index(self) -> bytes:
        return self._download(self._root["index.enc"])

    def _read_impl(self, blob_id: str) -> bytes:
        with self._lock:
            hit = self._cache.get(blob_id)
            if hit is not None:
                self._cache.move_to_end(blob_id)
                return hit
        sub_id = self._list(self._blobs_id).get(blob_id[:2])
        if not sub_id:
            raise FileNotFoundError(blob_id)
        file_id = self._list(sub_id).get(f"{blob_id}.blob")
        if not file_id:
            raise FileNotFoundError(blob_id)
        data = self._download(file_id)
        with self._lock:
            self._cache[blob_id] = data
            self.downloaded.add(blob_id)
            while len(self._cache) > self._cache_max:
                self._cache.popitem(last=False)
        return data

    def read(self, blob_id: str) -> bytes:
        """Lectura de PRIMER PLANO (video, export): pasa por delante de
        cualquier descarga de fondo."""
        self._gate.enter_fg()
        try:
            return self._read_impl(blob_id)
        finally:
            self._gate.exit_fg()

    def read_bg(self, blob_id: str) -> bytes:
        """Lectura de FONDO (miniaturas): cede el paso mientras el video
        esté descargando. Con el video en pausa o al día, avanza normal."""
        self._gate.wait_for_fg_idle()
        return self._read_impl(blob_id)
