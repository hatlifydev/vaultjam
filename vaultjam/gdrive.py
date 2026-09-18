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

SCOPES = ["https://www.googleapis.com/auth/drive.readonly"]
APPDIR = Path(os.environ.get("APPDATA", str(Path.home()))) / "VaultJam"
TOKEN_PATH = APPDIR / "token.json"


def get_service(client_secret_path: str):
    """Autentica (abre el navegador la primera vez) y devuelve el cliente
    de la API de Drive. El refresh token queda en %APPDATA%\\VaultJam."""
    from google.auth.transport.requests import Request
    from google.oauth2.credentials import Credentials
    from google_auth_oauthlib.flow import InstalledAppFlow
    from googleapiclient.discovery import build

    creds = None
    if TOKEN_PATH.exists():
        try:
            creds = Credentials.from_authorized_user_file(str(TOKEN_PATH), SCOPES)
        except Exception:
            creds = None
    if creds and creds.expired and creds.refresh_token:
        try:
            creds.refresh(Request())
        except Exception:
            creds = None
    if not creds or not creds.valid:
        flow = InstalledAppFlow.from_client_secrets_file(client_secret_path, SCOPES)
        # Abre el navegador del usuario; el "servidor" es un puerto efímero
        # en localhost solo para recibir el código OAuth.
        creds = flow.run_local_server(port=0)
        APPDIR.mkdir(parents=True, exist_ok=True)
        TOKEN_PATH.write_text(creds.to_json(), encoding="utf-8")
    return build("drive", "v3", credentials=creds, cache_discovery=False)


def forget_token() -> None:
    TOKEN_PATH.unlink(missing_ok=True)


def find_vaults(service) -> list[tuple[str, str]]:
    """Carpetas *.vault en el Drive del usuario: [(nombre, folder_id)]."""
    q = ("mimeType='application/vnd.google-apps.folder' "
         "and name contains '.vault' and trashed=false")
    res = service.files().list(q=q, fields="files(id,name)",
                               pageSize=100).execute()
    return sorted((f["name"], f["id"]) for f in res.get("files", []))


class DriveStore:
    """Almacén de blobs sobre Drive con la misma interfaz de lectura que el
    BlobStore local (`read(blob_id)`), más header/índice.

    - Los listados de subcarpetas (blobs/xx/) se cachean: un solo listado
      por subcarpeta para mapear nombre→fileId, luego descargas directas.
    - Caché LRU de blobs cifrados (~48 MiB) para que retroceder en un video
      no re-descargue.
    - Un lock serializa las llamadas HTTP: el cliente de Google no es
      thread-safe, y aquí leen varios hilos (miniaturas, video, previews).
    """

    writable = False

    def __init__(self, service, folder_id: str, name: str = "",
                 cache_blobs: int = 48):
        self._svc = service
        self.folder_id = folder_id
        self.name = name or folder_id
        self._lock = threading.RLock()
        self._children: dict[str, dict[str, str]] = {}   # folderId -> {nombre: id}
        self._cache: OrderedDict[str, bytes] = OrderedDict()
        self._cache_max = cache_blobs

        root = self._list(folder_id)
        if "header.json" not in root or "blobs" not in root:
            raise RuntimeError(
                "Esa carpeta de Drive no parece una bóveda (faltan header.json o blobs/).")
        self._root = root
        self._blobs_id = root["blobs"]

    # ------------------------------------------------------------------

    def _list(self, folder_id: str) -> dict[str, str]:
        with self._lock:
            if folder_id in self._children:
                return self._children[folder_id]
            out: dict[str, str] = {}
            token = None
            while True:
                res = self._svc.files().list(
                    q=f"'{folder_id}' in parents and trashed=false",
                    fields="nextPageToken,files(id,name)",
                    pageSize=1000, pageToken=token).execute()
                for f in res.get("files", []):
                    out[f["name"]] = f["id"]
                token = res.get("nextPageToken")
                if not token:
                    break
            self._children[folder_id] = out
            return out

    def _download(self, file_id: str) -> bytes:
        from googleapiclient.http import MediaIoBaseDownload
        with self._lock:
            buf = io.BytesIO()
            dl = MediaIoBaseDownload(buf, self._svc.files().get_media(fileId=file_id))
            done = False
            while not done:
                _, done = dl.next_chunk()
            return buf.getvalue()

    def refresh(self) -> None:
        """Descarta los listados cacheados: la próxima consulta verá el
        estado actual de Drive (útil mientras una subida sigue en curso)."""
        with self._lock:
            self._children.clear()

    def available_blobs(self) -> set[str]:
        """Ids de los blobs YA presentes en Drive. Solo lee metadata
        (listados de carpetas), no descarga contenido: sirve para marcar
        qué elementos están completos mientras una subida va a medias."""
        out: set[str] = set()
        for name, fid in self._list(self._blobs_id).items():
            if len(name) == 2:   # subcarpetas de prefijo xx/
                for child in self._list(fid):
                    if child.endswith(".blob"):
                        out.add(child[:-5])
        return out

    # ---- interfaz que consume Vault ----

    def read_header(self) -> bytes:
        return self._download(self._root["header.json"])

    def read_index(self) -> bytes:
        return self._download(self._root["index.enc"])

    def read(self, blob_id: str) -> bytes:
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
            while len(self._cache) > self._cache_max:
                self._cache.popitem(last=False)
        return data
