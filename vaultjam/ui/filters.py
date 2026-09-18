"""Filtros de imagen del visor: brillo, contraste, gamma, saturación,
temperatura de color y nitidez/suavizado.

Todo el procesado ocurre EN RAM sobre una copia del frame, con numpy
(operaciones vectorizadas en C): las correcciones puntuales (brillo,
contraste, gamma, temperatura) se colapsan en 3 tablas LUT de 256 entradas
—una pasada por canal—, y la saturación/nitidez usan aritmética en float32.
Con todos los controles en neutro el coste es CERO (se devuelve la imagen
original sin tocar).

Nunca se escribe nada a disco: entra un QImage descifrado y sale otro
QImage, ambos efímeros en RAM.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np
from PySide6.QtGui import QImage


@dataclass
class FilterParams:
    brightness: int = 0    # -100..100  (aclarar / oscurecer)
    contrast: int = 0      # -100..100
    gamma: int = 0         # -100..100  -> factor 2^(v/60): ~0.31x .. ~3.2x
    saturation: int = 0    # -100 (blanco y negro) .. +100 (color x2)
    temperature: int = 0   # -100 (frío/azul) .. +100 (cálido/rojo)
    sharpness: int = 0     # -100 (suavizado máximo) .. +100 (nitidez)
    smooth: bool = False   # interpolación al escalar; APAGADO por defecto
                           # (petición del usuario: píxeles reales salvo
                           # que se active el interruptor «Suavizar»)

    def neutral(self) -> bool:
        """True si ningún filtro altera píxeles (smooth solo afecta al escalado)."""
        return not (self.brightness or self.contrast or self.gamma
                    or self.saturation or self.temperature or self.sharpness)


def _build_luts(p: FilterParams) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    """Colapsa contraste -> brillo -> gamma -> temperatura en 3 LUTs uint8."""
    x = np.linspace(0.0, 1.0, 256, dtype=np.float32)
    y = (x - 0.5) * (1.0 + p.contrast / 100.0) + 0.5   # contraste alrededor del gris medio
    y = y + p.brightness / 100.0 * 0.5                 # brillo: desplazamiento ±50 %
    g = 2.0 ** (p.gamma / 60.0)                        # gamma en escala logarítmica
    y = np.clip(y, 0.0, 1.0) ** (1.0 / g)
    t = p.temperature / 100.0 * 0.25                   # cálido sube R y baja B
    lut_r = np.clip(y * (1.0 + t) * 255.0, 0, 255).astype(np.uint8)
    lut_g = np.clip(y * 255.0, 0, 255).astype(np.uint8)
    lut_b = np.clip(y * (1.0 - t) * 255.0, 0, 255).astype(np.uint8)
    return lut_r, lut_g, lut_b


def apply_filters(img: QImage, p: FilterParams) -> QImage:
    if p.neutral() or img.isNull():
        return img

    src = img.convertToFormat(QImage.Format.Format_RGBA8888)
    w, h, bpl = src.width(), src.height(), src.bytesPerLine()
    # Vista numpy sobre los bytes del QImage (respetando el stride) y copia
    # propia: jamás mutamos la imagen original (podría ser la foto cacheada).
    flat = np.frombuffer(src.constBits(), np.uint8, h * bpl).reshape(h, bpl)
    arr = flat[:, : w * 4].reshape(h, w, 4).copy()
    rgb = arr[..., :3]

    lut_r, lut_g, lut_b = _build_luts(p)
    rgb[..., 0] = lut_r[rgb[..., 0]]
    rgb[..., 1] = lut_g[rgb[..., 1]]
    rgb[..., 2] = lut_b[rgb[..., 2]]

    if p.saturation:
        # Interpolar cada canal respecto a su luma (Rec. 601): s=0 -> B/N.
        s = 1.0 + p.saturation / 100.0
        f = rgb.astype(np.float32)
        luma = f[..., 0] * 0.299 + f[..., 1] * 0.587 + f[..., 2] * 0.114
        f -= luma[..., None]
        f *= s
        f += luma[..., None]
        rgb[...] = np.clip(f, 0, 255).astype(np.uint8)

    if p.sharpness:
        # Vecindario en cruz (5 taps): base del suavizado y de la máscara de
        # enfoque. Barato y sin dependencias (no hay scipy).
        f = rgb.astype(np.float32)
        blur = (np.roll(f, 1, 0) + np.roll(f, -1, 0)
                + np.roll(f, 1, 1) + np.roll(f, -1, 1) + f) / 5.0
        k = p.sharpness / 100.0
        if k > 0:
            f = f + (f - blur) * (1.5 * k)     # unsharp mask
        else:
            f = f + (blur - f) * (-k)          # fundido hacia el desenfoque
        rgb[...] = np.clip(f, 0, 255).astype(np.uint8)

    out = QImage(arr.data, w, h, w * 4, QImage.Format.Format_RGBA8888)
    return out.copy()  # copia dueña de sus datos, independiente del buffer numpy
