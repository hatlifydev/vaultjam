"""Lienzo común para fotos y video, con rotación, zoom, paneo y filtros.

Los filtros de píxel (brillo, contraste, gamma, saturación, temperatura,
nitidez) viven en `filters.py` y se aplican EN RAM con caché: para una foto
solo se reprocesa al mover un slider; para video, frame a frame (y con los
controles en neutro el coste es cero). El interruptor «Suavizar» decide la
interpolación al escalar: desactivado, el zoom muestra los píxeles reales.

Nada de esto genera archivos ni copias persistentes: solo se transforma lo
que ya está en RAM camino de la pantalla.
"""

from __future__ import annotations

from PySide6.QtCore import QPointF, Qt, Signal
from PySide6.QtGui import QColor, QImage, QPainter
from PySide6.QtWidgets import (
    QCheckBox, QHBoxLayout, QLabel, QPushButton, QSlider, QVBoxLayout, QWidget,
)

from .filters import FilterParams, apply_filters

ZOOM_MIN, ZOOM_MAX = 1.0, 8.0


class MediaCanvas(QWidget):
    zoomChanged = Signal(float)
    doubleClicked = Signal()
    rotationChanged = Signal(int)   # emitida solo por acciones del usuario

    def __init__(self, parent=None):
        super().__init__(parent)
        self._src: QImage | None = None    # frame/foto descifrado original
        self._fx: QImage | None = None     # resultado filtrado (caché)
        self._params = FilterParams()
        self._rotation = 0                 # 0/90/180/270
        self._zoom = 1.0                   # 1.0 = ajustar a ventana
        self._pan = QPointF(0, 0)
        self._drag_start: QPointF | None = None
        self.setMinimumSize(1, 1)

    # ------------------------- estado -------------------------

    def set_image(self, img: QImage):
        self._src = img
        self._fx = None                    # el frame nuevo invalida la caché
        self.update()

    def rotate_cw(self):
        self._rotation = (self._rotation + 90) % 360
        self._pan = QPointF(0, 0)
        self.update()
        self.rotationChanged.emit(self._rotation)

    def set_rotation(self, rotation: int):
        """Aplica una rotación SIN emitir señal (para restaurar la rotación
        persistida al cargar, sin que el visor la re-guarde)."""
        self._rotation = int(rotation) % 360
        self._pan = QPointF(0, 0)
        self.update()

    @property
    def view_rotation(self) -> int:
        return self._rotation

    def set_zoom(self, z: float, anchor: QPointF | None = None):
        """Cambia el zoom. Con `anchor` (posición del cursor), el punto de
        la imagen bajo el cursor se queda quieto — zoom hacia donde miras."""
        old = self._zoom
        z = max(ZOOM_MIN, min(ZOOM_MAX, z))
        if z <= ZOOM_MIN + 1e-6:
            self._pan = QPointF(0, 0)      # al volver a "ajustar", centrar
        elif old > 0:
            ratio = z / old
            c = QPointF(self.width() / 2, self.height() / 2)
            a = anchor if anchor is not None else c
            # Mantener fijo el punto bajo el ancla: pan' = a−c − (a−c−pan)·r
            self._pan = a - c - (a - c - self._pan) * ratio
        self._zoom = z
        self.update()
        self.zoomChanged.emit(z)

    def _set_param(self, name: str, value):
        setattr(self._params, name, value)
        self._fx = None                    # cambiar un filtro invalida la caché
        self.update()

    def set_brightness(self, v: int):  self._set_param("brightness", int(v))
    def set_contrast(self, v: int):    self._set_param("contrast", int(v))
    def set_gamma(self, v: int):       self._set_param("gamma", int(v))
    def set_saturation(self, v: int):  self._set_param("saturation", int(v))
    def set_temperature(self, v: int): self._set_param("temperature", int(v))
    def set_sharpness(self, v: int):   self._set_param("sharpness", int(v))
    def set_smooth(self, on: bool):    self._set_param("smooth", bool(on))

    def reset_view(self):
        rot_changed = self._rotation != 0
        self._rotation = 0
        self._zoom = 1.0
        self._pan = QPointF(0, 0)
        self._params = FilterParams()
        self._fx = None
        self.update()
        self.zoomChanged.emit(self._zoom)
        if rot_changed:
            self.rotationChanged.emit(0)   # «Restablecer» también persiste 0°

    # ------------------------- interacción -------------------------

    def wheelEvent(self, ev):
        steps = ev.angleDelta().y() / 120
        # Zoom anclado al cursor: amplía hacia donde apunta el ratón.
        self.set_zoom(self._zoom * (1.15 ** steps), anchor=ev.position())

    def mousePressEvent(self, ev):
        if ev.button() == Qt.MouseButton.LeftButton and self._zoom > 1.001:
            self._drag_start = ev.position() - self._pan
            self.setCursor(Qt.CursorShape.ClosedHandCursor)

    def mouseMoveEvent(self, ev):
        if self._drag_start is not None:
            self._pan = ev.position() - self._drag_start
            self.update()

    def mouseReleaseEvent(self, ev):
        self._drag_start = None
        self.unsetCursor()

    def mouseDoubleClickEvent(self, ev):
        # Doble clic: alternar pantalla completa (lo escucha el visor). El
        # zoom queda en la rueda del ratón y el slider.
        self.doubleClicked.emit()

    # ------------------------- pintado -------------------------

    def paintEvent(self, ev):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(0, 0, 0))
        if self._src is None or self._src.isNull():
            p.end()
            return
        if self._fx is None:
            self._fx = apply_filters(self._src, self._params)
        img = self._fx
        # Suavizar: interpolación bilineal; desactivado: vecino más próximo
        # (con zoom se ven los píxeles reales, útil para inspección).
        p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, self._params.smooth)

        iw, ih = img.width(), img.height()
        bw, bh = (ih, iw) if self._rotation in (90, 270) else (iw, ih)
        base = min(self.width() / bw, self.height() / bh)
        s = base * self._zoom

        p.translate(self.width() / 2 + self._pan.x(), self.height() / 2 + self._pan.y())
        p.rotate(self._rotation)
        p.scale(s, s)
        p.translate(-iw / 2, -ih / 2)
        p.drawImage(0, 0, img)
        p.end()


class AdjustBar(QWidget):
    """Barra de ajustes en dos filas.

    Fila 1: girar, zoom, brillo, contraste, restablecer (+ botones extra
    del visor vía addWidget). Fila 2: gamma, color (saturación),
    temperatura, nitidez/suavizado y el interruptor de píxeles.
    """

    def __init__(self, canvas: MediaCanvas, parent=None):
        super().__init__(parent)
        self._canvas = canvas
        self._sliders: list[QSlider] = []

        def slider(lo, hi, val, tip, cb, width=100):
            s = QSlider(Qt.Orientation.Horizontal)
            s.setRange(lo, hi)
            s.setValue(val)
            s.setFixedWidth(width)
            s.setToolTip(tip)
            s.valueChanged.connect(cb)
            self._sliders.append(s)
            return s

        btn_rot = QPushButton("↻")
        btn_rot.setToolTip("Girar 90°")
        btn_rot.setFixedWidth(36)
        btn_rot.clicked.connect(canvas.rotate_cw)

        self._zoom = slider(100, int(ZOOM_MAX * 100), 100,
                            "Zoom (también con la rueda del ratón)",
                            lambda v: canvas.set_zoom(v / 100))
        canvas.zoomChanged.connect(self._sync_zoom)

        self._bri = slider(-100, 100, 0, "Brillo: aclarar / oscurecer", canvas.set_brightness)
        self._con = slider(-100, 100, 0, "Contraste", canvas.set_contrast)
        self._gam = slider(-100, 100, 0, "Gamma (medios tonos)", canvas.set_gamma)
        self._sat = slider(-100, 100, 0, "Color: −100 = blanco y negro, +100 = saturado",
                           canvas.set_saturation)
        self._tmp = slider(-100, 100, 0, "Temperatura: frío (azul) / cálido (rojo)",
                           canvas.set_temperature)
        self._shp = slider(-100, 100, 0, "Nitidez (+) / Suavizado (−)", canvas.set_sharpness)

        self._smooth = QCheckBox("Suavizar")
        self._smooth.setChecked(False)   # apagado por defecto
        self._smooth.setToolTip(
            "Interpolar al escalar. Desactívalo para ver los píxeles reales al hacer zoom."
        )
        self._smooth.toggled.connect(canvas.set_smooth)

        btn_reset = QPushButton("Restablecer")
        btn_reset.clicked.connect(self.reset_all)

        row1 = QHBoxLayout()
        row1.setContentsMargins(6, 2, 6, 0)
        for w in (btn_rot, QLabel("🔍"), self._zoom, QLabel("☀"), self._bri,
                  QLabel("◐"), self._con):
            row1.addWidget(w)
        row1.addStretch(1)
        row1.addWidget(btn_reset)
        self._row1 = row1

        row2 = QHBoxLayout()
        row2.setContentsMargins(6, 0, 6, 2)
        for w in (QLabel("γ"), self._gam, QLabel("🎨"), self._sat,
                  QLabel("🌡"), self._tmp, QLabel("✦"), self._shp):
            row2.addWidget(w)
        row2.addStretch(1)
        row2.addWidget(self._smooth)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.setSpacing(2)
        lay.addLayout(row1)
        lay.addLayout(row2)

    def addWidget(self, w):
        """El visor añade controles extra (p.ej. pantalla completa) a la fila 1."""
        self._row1.addWidget(w)

    def _sync_zoom(self, z: float):
        self._zoom.blockSignals(True)
        self._zoom.setValue(int(z * 100))
        self._zoom.blockSignals(False)

    def reset_sliders(self):
        """Pone los controles a neutro SIN tocar el lienzo (para cuando el
        visor ya llamó a canvas.reset_view, p.ej. al cambiar de elemento)."""
        for s in self._sliders:
            s.blockSignals(True)
            s.setValue(100 if s is self._zoom else 0)
            s.blockSignals(False)
        self._smooth.blockSignals(True)
        self._smooth.setChecked(False)   # neutro = sin suavizar
        self._smooth.blockSignals(False)

    def reset_all(self):
        self._canvas.reset_view()
        self.reset_sliders()
