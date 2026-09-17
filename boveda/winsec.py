"""Endurecimiento específico de Windows (best-effort).

SetWindowDisplayAffinity con WDA_EXCLUDEFROMCAPTURE (Windows 10 2004+)
excluye una ventana de las APIs estándar de captura: Impr Pant, Recortes,
grabadoras, compartir pantalla y Windows Recall ven un rectángulo negro.

Límites honestos: NO protege contra malware con drivers en kernel, contra
una cámara apuntando a la pantalla, ni contra el propio usuario exportando.
Es una capa más, no un escudo absoluto.
"""

from __future__ import annotations

import os

WDA_NONE = 0x00
WDA_MONITOR = 0x01            # fallback para Windows < 10 2004: captura en negro
WDA_EXCLUDEFROMCAPTURE = 0x11  # la ventana se omite por completo de la captura


def set_capture_protection(widget, enable: bool) -> bool:
    """Aplica/retira la protección a una ventana top-level de Qt.
    Devuelve False si el SO no lo soporta (la app sigue funcionando)."""
    if os.name != "nt":
        return False
    try:
        import ctypes

        u32 = ctypes.windll.user32
        hwnd = int(widget.winId())  # fuerza la creación de la ventana nativa
        if enable:
            if u32.SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE):
                return True
            return bool(u32.SetWindowDisplayAffinity(hwnd, WDA_MONITOR))
        return bool(u32.SetWindowDisplayAffinity(hwnd, WDA_NONE))
    except Exception:
        return False
