"""Almacén de blobs cifrados en disco.

Propiedades de seguridad de esta capa:

  - Los nombres de archivo son 128 bits aleatorios en hex: no codifican nada
    (ni nombre original, ni orden, ni pertenencia). El mapeo blob->archivo
    vive exclusivamente en el índice cifrado.
  - TODOS los blobs tienen exactamente el mismo tamaño en disco
    (CHUNK_SIZE + nonce + tag), así que ni los tamaños de los archivos ni
    cuántos archivos hay se pueden deducir mirando el almacén.
  - Las marcas de tiempo (creación y modificación) se normalizan a una fecha
    fija para no filtrar CUÁNDO se importó cada cosa. (El journal de NTFS
    queda fuera de nuestro alcance; ver SEGURIDAD.md.)
  - Escritura atómica: temporal cifrado + os.replace, para que un corte de
    luz nunca deje un blob a medias. El temporal ya está cifrado, así que
    jamás toca el disco nada en claro.
"""

from __future__ import annotations

import os
from pathlib import Path

from .crypto_core import random_bytes

# 2000-01-01 00:00:00 UTC — fecha fija para todas las marcas de tiempo.
FIXED_TS = 946684800


def _set_creation_time_windows(path: Path, ts: int) -> None:
    """En Windows, os.utime cambia mtime/atime pero NO la fecha de creación
    (birth time), que también filtraría la fecha de importación. La fijamos
    vía la API Win32 SetFileTime con ctypes. Best-effort: si falla, la
    fecha de creación queda como metadato residual (documentado)."""
    if os.name != "nt":
        return
    try:
        import ctypes
        from ctypes import wintypes

        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateFileW.restype = wintypes.HANDLE
        k32.CreateFileW.argtypes = [
            wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, wintypes.LPVOID,
            wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
        ]
        k32.SetFileTime.restype = wintypes.BOOL
        k32.SetFileTime.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 3
        k32.CloseHandle.argtypes = [wintypes.HANDLE]

        # FILETIME: intervalos de 100 ns desde 1601-01-01.
        ft = wintypes.FILETIME()
        val = int((ts + 11644473600) * 10_000_000)
        ft.dwLowDateTime = val & 0xFFFFFFFF
        ft.dwHighDateTime = val >> 32
        FILE_WRITE_ATTRIBUTES = 0x0100
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL = 3, 0x80
        INVALID_HANDLE = ctypes.c_void_p(-1).value
        handle = k32.CreateFileW(
            str(path), FILE_WRITE_ATTRIBUTES, 0, None, OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL, None,
        )
        if handle not in (None, INVALID_HANDLE):
            k32.SetFileTime(handle, ctypes.byref(ft), ctypes.byref(ft), ctypes.byref(ft))
            k32.CloseHandle(handle)
    except Exception:
        pass


class BlobStore:
    def __init__(self, root: Path):
        self.blob_dir = Path(root) / "blobs"

    def new_blob_id(self) -> str:
        # 128 bits aleatorios: probabilidad de colisión despreciable y cero
        # información codificada en el nombre.
        return random_bytes(16).hex()

    def path_for(self, blob_id: str) -> Path:
        # Subcarpetas por prefijo para que NTFS no degrade con decenas de
        # miles de entradas en un solo directorio.
        return self.blob_dir / blob_id[:2] / f"{blob_id}.blob"

    def write(self, data: bytes) -> str:
        """Escribe un blob (YA cifrado por la capa superior) de forma atómica
        y con marcas de tiempo normalizadas. Devuelve su id."""
        blob_id = self.new_blob_id()
        dest = self.path_for(blob_id)
        dest.parent.mkdir(parents=True, exist_ok=True)
        tmp = dest.with_suffix(".tmp")
        with open(tmp, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())  # que llegue al disco antes del rename
        os.replace(tmp, dest)
        os.utime(dest, (FIXED_TS, FIXED_TS))
        _set_creation_time_windows(dest, FIXED_TS)
        return blob_id

    def read(self, blob_id: str) -> bytes:
        return self.path_for(blob_id).read_bytes()

    def delete(self, blob_id: str) -> None:
        # Borrado normal del sistema de archivos. NO es un borrado seguro:
        # en SSDs el wear-leveling hace imposible garantizar la destrucción
        # física desde una app (ver SEGURIDAD.md). El contenido borrado
        # sigue siendo ciphertext, así que solo sería recuperable por quien
        # además tuviera la clave.
        self.path_for(blob_id).unlink(missing_ok=True)
