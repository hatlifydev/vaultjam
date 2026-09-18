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

import time

from PySide6.QtCore import QPointF, QRect, Qt, QTimer, Signal
from PySide6.QtGui import (QColor, QImage, QPainter, QPainterPath, QPen,
                           QPixmap, QTransform)
from PySide6.QtWidgets import (
    QCheckBox, QHBoxLayout, QLabel, QPushButton, QSlider, QVBoxLayout, QWidget,
)

from .filters import FilterParams, apply_filters

ZOOM_MIN, ZOOM_MAX = 1.0, 8.0
LOUPE_RADIUS, LOUPE_MAG = 90, 3.0   # lupa: radio en px y aumento


class MediaCanvas(QWidget):
    zoomChanged = Signal(float)
    doubleClicked = Signal()
    rotationChanged = Signal(int)        # emitida solo por acciones del usuario
    flipChanged = Signal(bool, bool)     # espejo H/V, solo acciones del usuario

    def __init__(self, parent=None):
        super().__init__(parent)
        self._src: QImage | None = None    # frame/foto descifrado original
        self._fx: QImage | None = None     # resultado filtrado (caché)
        self._params = FilterParams()
        self._rotation = 0                 # 0/90/180/270
        self._flip_h = False               # espejo horizontal
        self._flip_v = False               # espejo vertical
        self._zoom = 1.0                   # 1.0 = ajustar a ventana
        self._pan = QPointF(0, 0)
        self._drag_start: QPointF | None = None
        self._show_original = False        # "antes/después": ver sin filtros
        self._loupe: QPointF | None = None # posición de la lupa (o None)
        self._loupe_follow = False         # lupa siguiendo al cursor (tecla)
        self._kb_scale = 1.0               # zoom lento del modo cine (Ken Burns)
        self._fade_pix: QPixmap | None = None   # fundido entre elementos
        self._fade_t0 = 0.0
        self._fade_ms = 0
        self._fade_timer = QTimer(self)
        self._fade_timer.setInterval(16)
        self._fade_timer.timeout.connect(self.update)
        self.setMinimumSize(1, 1)

    # ------------------------- estado -------------------------

    def set_image(self, img: QImage, fade_ms: int = 0):
        if fade_ms > 0 and self._src is not None and self.isVisible():
            # Fundido del modo cine: instantánea de lo que se ve ahora,
            # desvanecida sobre la imagen nueva. Vive solo en RAM.
            self._fade_pix = self.grab()
            self._fade_t0 = time.time()
            self._fade_ms = fade_ms
            self._fade_timer.start()
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

    # ---- espejo, antes/después, lupa, cine, 100 % ----

    def toggle_flip_h(self):
        self._flip_h = not self._flip_h
        self.update()
        self.flipChanged.emit(self._flip_h, self._flip_v)

    def toggle_flip_v(self):
        self._flip_v = not self._flip_v
        self.update()
        self.flipChanged.emit(self._flip_h, self._flip_v)

    def set_flip(self, flip_h: bool, flip_v: bool):
        """Restaura el espejo persistido SIN emitir señal."""
        self._flip_h, self._flip_v = bool(flip_h), bool(flip_v)
        self.update()

    @property
    def flips(self) -> tuple[bool, bool]:
        return self._flip_h, self._flip_v

    def set_show_original(self, on: bool):
        """Mantener «antes/después»: pinta el original sin filtros de color
        (la geometría —rotación, espejo, zoom— se conserva)."""
        self._show_original = bool(on)
        self.update()

    def set_loupe(self, pos: QPointF | None):
        self._loupe = pos
        self.update()

    def set_loupe_follow(self, on: bool):
        self._loupe_follow = bool(on)
        if not on:
            self._loupe = None
        self.update()

    def set_kenburns(self, scale: float):
        """Zoom lento del modo cine (1.0 = sin efecto)."""
        self._kb_scale = max(1.0, min(1.25, float(scale)))
        self.update()

    def toggle_actual_size(self):
        """Alterna entre ajustar a ventana y 100 % (1 píxel = 1 píxel)."""
        if self._src is None or self._src.isNull():
            return
        iw, ih = self._src.width(), self._src.height()
        bw, bh = (ih, iw) if self._rotation in (90, 270) else (iw, ih)
        base = min(self.width() / bw, self.height() / bh)
        if base <= 0:
            return
        if abs(self._zoom * base - 1.0) < 0.02:
            self.set_zoom(1.0)     # ya estaba al 100 %: volver a ajustar
        else:
            self.set_zoom(1.0 / base)   # (si la imagen es pequeña, clampa)

    def params_dict(self) -> dict:
        return self._params.to_dict()

    def apply_params(self, d: dict | None):
        """Restaura ajustes persistidos SIN pasar por los sliders."""
        self._params = FilterParams.from_dict(d)
        self._fx = None
        self.update()

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
        flip_changed = self._flip_h or self._flip_v
        self._rotation = 0
        self._flip_h = self._flip_v = False
        self._zoom = 1.0
        self._pan = QPointF(0, 0)
        self._params = FilterParams()
        self._fx = None
        self._kb_scale = 1.0
        self._show_original = False
        self._loupe = None
        self.update()
        self.zoomChanged.emit(self._zoom)
        if rot_changed:
            self.rotationChanged.emit(0)   # «Restablecer» también persiste 0°
        if flip_changed:
            self.flipChanged.emit(False, False)

    # ------------------------- interacción -------------------------

    def wheelEvent(self, ev):
        steps = ev.angleDelta().y() / 120
        # Zoom anclado al cursor: amplía hacia donde apunta el ratón.
        self.set_zoom(self._zoom * (1.15 ** steps), anchor=ev.position())

    def mousePressEvent(self, ev):
        if ev.button() == Qt.MouseButton.LeftButton and self._zoom > 1.001:
            self._drag_start = ev.position() - self._pan
            self.setCursor(Qt.CursorShape.ClosedHandCursor)
        elif ev.button() == Qt.MouseButton.MiddleButton:
            # Lupa: mantener pulsado el botón central del ratón.
            self.set_loupe(ev.position())

    def mouseMoveEvent(self, ev):
        if self._drag_start is not None:
            self._pan = ev.position() - self._drag_start
            self.update()
        if self._loupe is not None or self._loupe_follow:
            self._loupe = ev.position()
            self.update()

    def mouseReleaseEvent(self, ev):
        self._drag_start = None
        if ev.button() == Qt.MouseButton.MiddleButton and not self._loupe_follow:
            self.set_loupe(None)
        self.unsetCursor()

    def mouseDoubleClickEvent(self, ev):
        # Doble clic: alternar pantalla completa (lo escucha el visor). El
        # zoom queda en la rueda del ratón y el slider.
        self.doubleClicked.emit()

    # ------------------------- pintado -------------------------

    def _view_scale(self, iw: int, ih: int) -> float:
        bw, bh = (ih, iw) if self._rotation in (90, 270) else (iw, ih)
        base = min(self.width() / bw, self.height() / bh)
        return base * self._zoom * self._kb_scale

    def _apply_view_ops(self, p: QPainter, iw: int, ih: int):
        """Secuencia única de transformaciones de la vista (la comparten el
        dibujo principal y la lupa, garantizando coherencia exacta)."""
        s = self._view_scale(iw, ih)
        p.translate(self.width() / 2 + self._pan.x(),
                    self.height() / 2 + self._pan.y())
        p.rotate(self._rotation)
        p.scale(s * (-1 if self._flip_h else 1),
                s * (-1 if self._flip_v else 1))
        p.translate(-iw / 2, -ih / 2)

    def _view_transform(self, iw: int, ih: int) -> QTransform:
        s = self._view_scale(iw, ih)
        t = QTransform()
        t.translate(self.width() / 2 + self._pan.x(),
                    self.height() / 2 + self._pan.y())
        t.rotate(self._rotation)
        t.scale(s * (-1 if self._flip_h else 1),
                s * (-1 if self._flip_v else 1))
        t.translate(-iw / 2, -ih / 2)
        return t

    def paintEvent(self, ev):
        p = QPainter(self)
        p.fillRect(self.rect(), QColor(0, 0, 0))
        if self._src is None or self._src.isNull():
            p.end()
            return
        if self._fx is None:
            self._fx = apply_filters(self._src, self._params)
        # «Antes/después»: el original salta los filtros de color, pero
        # conserva rotación/espejo/zoom para comparar en contexto.
        img = self._src if self._show_original else self._fx
        # Suavizar: interpolación bilineal; desactivado: vecino más próximo
        # (con zoom se ven los píxeles reales, útil para inspección).
        p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, self._params.smooth)

        iw, ih = img.width(), img.height()
        p.save()
        self._apply_view_ops(p, iw, ih)
        p.drawImage(0, 0, img)
        p.restore()

        # ---- lupa (misma secuencia de ops, ampliada alrededor del cursor)
        if self._loupe is not None:
            cur = self._loupe
            path = QPainterPath()
            path.addEllipse(cur, LOUPE_RADIUS, LOUPE_RADIUS)
            p.save()
            p.setClipPath(path)
            p.fillRect(self.rect(), QColor(0, 0, 0))
            p.translate(cur)
            p.scale(LOUPE_MAG, LOUPE_MAG)
            p.translate(-cur)
            self._apply_view_ops(p, iw, ih)
            p.drawImage(0, 0, img)
            p.restore()
            p.setRenderHint(QPainter.RenderHint.Antialiasing, True)
            p.setPen(QPen(QColor(255, 255, 255, 210), 2))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawEllipse(cur, LOUPE_RADIUS, LOUPE_RADIUS)

        # ---- mini-mapa cuando hay zoom: dónde estás dentro de la imagen
        if self._zoom > 1.01:
            mw = max(80, min(160, self.width() // 5))
            mh = max(24, int(mw * ih / max(1, iw)))
            mx, my = self.width() - mw - 10, 10
            p.setOpacity(0.85)
            p.drawImage(QRect(mx, my, mw, mh), img)
            p.setOpacity(1.0)
            p.setPen(QPen(QColor(255, 255, 255, 160), 1))
            p.drawRect(mx, my, mw, mh)
            inv, ok = self._view_transform(iw, ih).inverted()
            if ok:
                vis = inv.mapRect(QRect(0, 0, self.width(), self.height()))
                vis = vis.intersected(QRect(0, 0, iw, ih))
                if not vis.isEmpty():
                    p.setPen(QPen(QColor(255, 80, 80), 2))
                    p.drawRect(mx + vis.x() * mw // iw, my + vis.y() * mh // ih,
                               max(4, vis.width() * mw // iw),
                               max(4, vis.height() * mh // ih))

        # ---- fundido del modo cine (instantánea previa desvaneciéndose)
        if self._fade_pix is not None:
            a = (time.time() - self._fade_t0) / max(0.001, self._fade_ms / 1000)
            if a >= 1.0:
                self._fade_pix = None
                self._fade_timer.stop()
            else:
                p.setOpacity(1.0 - a)
                p.drawPixmap(0, 0, self._fade_pix)
                p.setOpacity(1.0)
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

        btn_fh = QPushButton("⇋")
        btn_fh.setToolTip("Espejo horizontal (se recuerda por elemento)")
        btn_fh.setFixedWidth(36)
        btn_fh.clicked.connect(canvas.toggle_flip_h)
        btn_fv = QPushButton("⇵")
        btn_fv.setToolTip("Espejo vertical (se recuerda por elemento)")
        btn_fv.setFixedWidth(36)
        btn_fv.clicked.connect(canvas.toggle_flip_v)

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
        for w in (btn_rot, btn_fh, btn_fv, QLabel("🔍"), self._zoom,
                  QLabel("☀"), self._bri, QLabel("◐"), self._con):
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

    def sync_from_canvas(self):
        """Alinea los sliders con los parámetros del lienzo (p.ej. tras
        restaurar los ajustes persistidos de un elemento)."""
        p = self._canvas._params
        for s, val in ((self._bri, p.brightness), (self._con, p.contrast),
                       (self._gam, p.gamma), (self._sat, p.saturation),
                       (self._tmp, p.temperature), (self._shp, p.sharpness)):
            s.blockSignals(True)
            s.setValue(val)
            s.blockSignals(False)
        self._smooth.blockSignals(True)
        self._smooth.setChecked(p.smooth)
        self._smooth.blockSignals(False)
