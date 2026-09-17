"""Generación de miniaturas al importar.

Las miniaturas se generan desde el ARCHIVO ORIGEN (que aún está en claro,
porque es el archivo del usuario que se está importando) y el JPEG resultante
se entrega a Vault.import_file, que lo cifra como un blob más bajo la
subclave de miniaturas. La miniatura en claro solo existe en RAM durante la
importación; jamás se escribe a disco.
"""

from __future__ import annotations

import io
from pathlib import Path

from PIL import Image, ImageOps

THUMB_MAX = 512   # lado mayor de la miniatura, px
THUMB_QUALITY = 85

PHOTO_EXTS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".webp", ".tif", ".tiff"}
VIDEO_EXTS = {".mp4", ".m4v", ".mov", ".mkv", ".avi", ".webm", ".wmv", ".mpg", ".mpeg", ".3gp"}


def classify(path: Path) -> str | None:
    """'image' | 'video' | None (no soportado)."""
    ext = Path(path).suffix.lower()
    if ext in PHOTO_EXTS:
        return "image"
    if ext in VIDEO_EXTS:
        return "video"
    return None


def _pil_to_jpeg(img: Image.Image) -> bytes:
    img = ImageOps.exif_transpose(img)  # respetar la orientación EXIF
    if img.mode not in ("RGB", "L"):
        img = img.convert("RGB")
    img.thumbnail((THUMB_MAX, THUMB_MAX))
    buf = io.BytesIO()  # solo RAM: nunca un archivo temporal
    img.save(buf, "JPEG", quality=THUMB_QUALITY)
    return buf.getvalue()


def _photo_thumb(path: Path) -> bytes:
    with Image.open(path) as img:
        return _pil_to_jpeg(img)


def _video_thumb(path: Path) -> bytes:
    # PyAV (bindings de ffmpeg): decodifica el primer fotograma útil ~1 s
    # dentro del video para evitar fundidos de negro iniciales.
    import av  # import perezoso: si PyAV no está, degradamos a icono genérico

    with av.open(str(path)) as container:
        stream = container.streams.video[0]
        stream.thread_type = "AUTO"
        # Intentar saltar al segundo 1; si el video es más corto, primer frame.
        try:
            container.seek(int(1 / stream.time_base) if stream.time_base else 0,
                           stream=stream, any_frame=False)
        except Exception:
            pass
        for frame in container.decode(stream):
            return _pil_to_jpeg(frame.to_image())
    raise ValueError("El video no contiene fotogramas decodificables.")


def make_thumbnail(path: Path, mime: str) -> bytes | None:
    """JPEG de miniatura, o None si no se pudo (la UI mostrará un icono
    genérico; la importación NUNCA falla por culpa de la miniatura)."""
    try:
        if mime == "image":
            return _photo_thumb(Path(path))
        if mime == "video":
            return _video_thumb(Path(path))
    except Exception:
        return None
    return None
