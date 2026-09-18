"""Visor unificado de fotos y videos, descifrando SOLO en RAM.

Un único ViewerWindow recorre una lista de reproducción (el orden de la
galería) mezclando fotos y videos:

  - Fotos: bytes descifrados -> QImage -> MediaCanvas (GIF animados vía
    QMovie sobre un buffer en RAM). Cero disco.
  - Videos: QMediaPlayer leyendo de un DecryptingIODevice que descifra
    chunks bajo demanda (~8 MiB en RAM); cada frame llega por QVideoSink al
    MediaCanvas. Plan B si el códec no admite streaming: QBuffer (RAM).
    NUNCA temporales en claro.

Atajos (H o ? muestra esta lista en pantalla):
  - Comunes: F/doble clic = pantalla completa, Esc = salir, AvPág/RePág =
    siguiente/anterior, S = ⭐ favorito, P = presentación, H = ayuda.
  - Fotos: ←/→ = anterior/siguiente.
  - Video: ←/→ = ±10 s, Espacio = play/pausa, +/− = velocidad, E/R = frame
    a frame, M = marcador, L = bucle, B = repetición A–B.

Persistencia (todo dentro del ÍNDICE CIFRADO, nada en claro): marcadores
con nombre, última posición de reproducción (reanudar), rotación por
elemento y favoritos.

La vista previa al pasar el ratón por la barra de avance decodifica el
fotograma más próximo (keyframe) con PyAV leyendo del propio lector
cifrado, en un hilo aparte, con caché LRU en RAM.
"""

from __future__ import annotations

import random
import time
from collections import OrderedDict
from datetime import datetime

from PySide6.QtCore import (
    QBuffer, QByteArray, QEvent, QIODevice, QPoint, Qt, QThread, QTimer, QUrl,
    Signal,
)
from PySide6.QtGui import QColor, QImage, QMovie, QPainter, QPen, QPixmap
from PySide6.QtMultimedia import QAudioOutput, QMediaMetaData, QMediaPlayer, QVideoSink
from PySide6.QtWidgets import (
    QAbstractButton, QAbstractSlider, QDialog, QFileDialog, QHBoxLayout,
    QInputDialog, QLabel, QMenu, QMessageBox, QPushButton, QSlider, QStyle,
    QToolTip, QVBoxLayout, QWidget,
)

from ..memio import DecryptingIODevice
from ..vault import Vault
from ..winsec import set_capture_protection
from .canvas import AdjustBar, MediaCanvas

SEEK_STEP_MS = 10_000      # ←/→ en video: 10 segundos
HOVER_ZONE_PX = 130        # franja inferior que revela los controles en FS
SLIDESHOW_MS = 5_000       # presentación: segundos por foto
CURSOR_HIDE_MS = 2_000     # ocultar el cursor en FS tras esta inactividad
PREVIEW_BUCKET_MS = 2_000  # granularidad de la vista previa de la barra
PREVIEW_CACHE_MAX = 60     # fotogramas de preview en RAM como máximo

# Botones superpuestos: invisibles hasta que el ratón pasa por encima.
_OVERLAY_QSS = """
QPushButton { border: none; border-radius: 10px;
              background: rgba(0,0,0,0); color: rgba(255,255,255,0);
              font-size: 30px; font-weight: bold; }
QPushButton:hover { background: rgba(0,0,0,110); color: rgba(255,255,255,225); }
"""

_OSD_QSS = ("QLabel { background: rgba(0,0,0,170); color: white;"
            " padding: 8px 18px; border-radius: 10px; font-size: 17px; }")

_HELP_HTML = """
<div style='font-size:13px'>
<b>Atajos del visor</b><br/>
<table cellspacing='6'>
<tr><td><b>F</b> / doble clic</td><td>pantalla completa (Esc sale)</td></tr>
<tr><td><b>‹ ›</b> bordes / AvPág·RePág</td><td>siguiente / anterior</td></tr>
<tr><td><b>← →</b></td><td>video: −10 s / +10 s &nbsp;·&nbsp; foto: anterior / siguiente</td></tr>
<tr><td><b>Espacio</b></td><td>reproducir / pausar</td></tr>
<tr><td><b>+ −</b></td><td>velocidad ±0.25×</td></tr>
<tr><td><b>E / R</b></td><td>un frame adelante / atrás</td></tr>
<tr><td><b>M</b> / 🔖</td><td>marcador aquí (clic dcho en el chip: renombrar/eliminar)</td></tr>
<tr><td><b>L</b> / 🔁</td><td>repetición: este video → todos los videos → apagada</td></tr>
<tr><td><b>B</b></td><td>repetición A–B (1.º fija A, 2.º fija B, 3.º la quita)</td></tr>
<tr><td><b>S</b></td><td>⭐ favorito</td></tr>
<tr><td><b>P</b></td><td>presentación: normal → aleatoria → parar (cine: fundido + zoom lento)</td></tr>
<tr><td><b>⌫</b></td><td>volver al punto anterior al último salto</td></tr>
<tr><td><b>I</b></td><td>información del elemento</td></tr>
<tr><td><b>C</b></td><td>alternar ajustar ↔ 100 % (1:1)</td></tr>
<tr><td><b>U</b> / botón central</td><td>lupa 3× siguiendo el cursor</td></tr>
<tr><td><b>O</b> (mantener)</td><td>ver el original sin ajustes (antes/después)</td></tr>
<tr><td>⇋ ⇵</td><td>espejo horizontal/vertical (se recuerda)</td></tr>
<tr><td>📸 / 🖼 / ✂</td><td>fotograma → foto cifrada · miniatura · exportar tramo A–B</td></tr>
<tr><td><b>H</b> / <b>?</b></td><td>esta ayuda</td></tr>
</table></div>
"""


def _fmt_ms(ms: int) -> str:
    s = max(0, ms // 1000)
    return f"{s // 60}:{s % 60:02d}"


class _SeekSlider(QSlider):
    """Barra de avance: clic directo para saltar, muescas ámbar para los
    marcadores, banda para el tramo A–B y hover con vista previa."""

    hoverMoved = Signal(int, int)   # (ms bajo el cursor, x local)
    hoverLeft = Signal()

    def __init__(self):
        super().__init__(Qt.Orientation.Horizontal)
        self._marks: list[tuple[int, bool, str]] = []  # (ms, ¿rotación?, nombre)
        self._ab: tuple[int, int] | None = None
        self.setMouseTracking(True)

    def set_marks(self, marks: list[tuple[int, bool, str]]):
        self._marks = [(int(t), bool(r), str(lbl)) for t, r, lbl in marks]
        self.update()

    def set_ab(self, a: int | None, b: int | None):
        self._ab = (a, b) if a is not None and b is not None else None
        self.update()

    def _val_at(self, x: float) -> int:
        return QStyle.sliderValueFromPosition(
            self.minimum(), self.maximum(), round(x), self.width()
        )

    def mousePressEvent(self, ev):
        if ev.button() == Qt.MouseButton.LeftButton and self.maximum() > self.minimum():
            val = self._val_at(ev.position().x())
            self.setValue(val)
            self.sliderMoved.emit(val)   # reutiliza el cableado -> setPosition
        super().mousePressEvent(ev)

    def mouseMoveEvent(self, ev):
        if self.maximum() > self.minimum():
            x = ev.position().x()
            self.hoverMoved.emit(self._val_at(x), round(x))
            # Tooltip al rozar una muesca: nombre del marcador (o su tiempo).
            span = self.width() - 8
            for t, _r, lbl in self._marks:
                if abs(4 + t / self.maximum() * span - x) <= 6:
                    QToolTip.showText(ev.globalPosition().toPoint(),
                                      lbl or f"🔖 {_fmt_ms(t)}", self)
                    break
        super().mouseMoveEvent(ev)

    def leaveEvent(self, ev):
        self.hoverLeft.emit()
        super().leaveEvent(ev)

    def paintEvent(self, ev):
        super().paintEvent(ev)
        if self.maximum() <= 0:
            return
        p = QPainter(self)
        span = self.width() - 8
        if self._ab is not None:
            xa = 4 + round(self._ab[0] / self.maximum() * span)
            xb = 4 + round(self._ab[1] / self.maximum() * span)
            p.fillRect(xa, 3, max(2, xb - xa), self.height() - 6,
                       QColor(255, 190, 0, 70))
        if self._marks:
            # Ámbar: marcador normal. Turquesa: marcador con rotación (desde
            # ahí el video se ve girado, hasta el siguiente turquesa).
            pen_plain = QPen(QColor(255, 190, 0), 2)
            pen_rot = QPen(QColor(0, 200, 230), 3)
            for t, has_rot, _lbl in self._marks:
                x = 4 + round(t / self.maximum() * span)
                p.setPen(pen_rot if has_rot else pen_plain)
                p.drawLine(x, 2, x, self.height() - 3)
        p.end()


class _PreviewPopup(QWidget):
    """Tarjetita sobre la barra de avance con el fotograma y el tiempo."""

    W, H = 224, 152

    def __init__(self, parent):
        super().__init__(parent)
        self.setFixedSize(self.W, self.H)
        self.setStyleSheet("background: rgba(15,15,15,235); border-radius: 8px;")
        self._img = QLabel(self)
        self._img.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._img.setGeometry(2, 2, self.W - 4, self.H - 26)
        self._time = QLabel(self)
        self._time.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._time.setStyleSheet("color: white; font-weight: bold; background: transparent;")
        self._time.setGeometry(0, self.H - 24, self.W, 22)
        self.hide()

    def show_frame(self, time_text: str, img: QImage | None):
        self._time.setText(time_text)
        if img is not None and not img.isNull():
            self._img.setPixmap(QPixmap.fromImage(img).scaled(
                self._img.size(), Qt.AspectRatioMode.KeepAspectRatio,
                Qt.TransformationMode.SmoothTransformation))
        else:
            self._img.setPixmap(QPixmap())
            self._img.setText("…")
            self._img.setStyleSheet("color: #888; background: transparent;")
        self.show()
        self.raise_()


class _PreviewWorker(QThread):
    """Decodifica fotogramas para la vista previa con PyAV, leyendo del
    lector cifrado (RAM). Vive en su propio hilo; atiende siempre la última
    petición (las intermedias se descartan)."""

    ready = Signal(int, QImage)

    def __init__(self, vault: Vault, entry_id: str, parent=None):
        super().__init__(parent)
        self._reader = vault.open_reader(entry_id)
        self._pending = -1
        self._stopping = False

    def request(self, ms: int):
        self._pending = ms

    def stop(self):
        self._stopping = True

    def run(self):
        try:
            import av
            container = av.open(self._reader)   # file-like sobre chunks cifrados
            stream = container.streams.video[0]
        except Exception:
            self._reader.close()
            return
        done = -2
        try:
            while not self._stopping:
                t = self._pending
                if t == done or t < 0:
                    self.msleep(25)
                    continue
                done = t
                try:
                    ts = int((t / 1000) / stream.time_base)
                    container.seek(ts, stream=stream)
                    for frame in container.decode(stream):
                        pil = frame.to_image()
                        pil.thumbnail((220, 220))
                        pil = pil.convert("RGB")
                        qimg = QImage(pil.tobytes(), pil.width, pil.height,
                                      pil.width * 3, QImage.Format.Format_RGB888).copy()
                        self.ready.emit(t, qimg)
                        break
                except Exception:
                    pass   # códec/seek quisquilloso: sin preview para ese punto
        finally:
            try:
                container.close()
            except Exception:
                pass
            self._reader.close()


def _export_clip_av(vault: Vault, entry_id: str, a_ms: int, b_ms: int,
                    dst: str) -> str:
    """Recorte A–B por REMUX (sin recodificar): copia los paquetes
    comprimidos tal cual desde el lector cifrado al archivo destino, con
    corte alineado al keyframe anterior a A. Rápido y sin pérdida."""
    import av
    reader = vault.open_reader(entry_id)
    try:
        inp = av.open(reader)
        vstream = inp.streams.video[0]
        streams = [s for s in inp.streams if s.type in ("video", "audio")]
        out = av.open(dst, "w")
        omap = {}
        for s in streams:
            try:
                omap[s.index] = out.add_stream_from_template(s)
            except AttributeError:   # PyAV antiguos
                omap[s.index] = out.add_stream(template=s)
        start, end = a_ms / 1000, b_ms / 1000
        inp.seek(int(start / vstream.time_base), stream=vstream, backward=True)
        offsets: dict[int, int] = {}
        for pkt in inp.demux(streams):
            if pkt.dts is None or pkt.stream.index not in omap:
                continue
            ref = pkt.pts if pkt.pts is not None else pkt.dts
            t = float(ref * pkt.time_base)
            if pkt.stream.type == "video":
                if t > end:
                    break                      # el video manda el final
            elif t < start - 0.2 or t > end:
                continue                       # audio fuera del tramo
            si = pkt.stream.index
            if si not in offsets:
                offsets[si] = pkt.dts          # re-basar tiempos a ~0
            pkt.pts = None if pkt.pts is None else pkt.pts - offsets[si]
            pkt.dts = pkt.dts - offsets[si]
            pkt.stream = omap[si]
            out.mux(pkt)
        out.close()
        inp.close()
    finally:
        reader.close()
    return dst


class _ClipWorker(QThread):
    done = Signal(object)   # ruta str | Exception

    def __init__(self, vault: Vault, entry_id: str, a_ms: int, b_ms: int,
                 dst: str, parent=None):
        super().__init__(parent)
        self._args = (vault, entry_id, a_ms, b_ms, dst)

    def run(self):
        try:
            self.done.emit(_export_clip_av(*self._args))
        except Exception as e:  # noqa: BLE001
            self.done.emit(e)


class ViewerWindow(QDialog):
    def __init__(self, vault: Vault, entry_id: str,
                 playlist: list[str] | None = None, parent=None):
        super().__init__(parent)
        self._vault = vault
        self._playlist = list(playlist) if playlist else [entry_id]
        if entry_id not in self._playlist:
            self._playlist.insert(0, entry_id)
        self._idx = self._playlist.index(entry_id)
        self._entry = vault.get(entry_id)
        self._was_maximized = False
        self._loading = False
        self.resize(1020, 800)

        # --- infraestructura multimedia (se crea una sola vez) ---
        self._player = QMediaPlayer(self)
        self._audio = QAudioOutput(self)
        self._audio.setVolume(0.0)   # el volumen SIEMPRE arranca en silencio
        self._player.setAudioOutput(self._audio)
        self._canvas = MediaCanvas()
        self._canvas.doubleClicked.connect(self.toggle_fullscreen)
        self._canvas.rotationChanged.connect(self._on_rotation)
        self._canvas.flipChanged.connect(self._on_flip)
        self._sink = QVideoSink(self)
        self._sink.videoFrameChanged.connect(self._on_frame)
        self._player.setVideoSink(self._sink)
        self._device: QIODevice | None = None
        self._buffer_data: QByteArray | None = None
        self._tried_buffer_fallback = False
        self._movie: QMovie | None = None       # GIF animados (RAM)
        self._movie_buf: QBuffer | None = None
        self._pending_resume = 0

        # Estado de reproducción avanzada
        self._slideshow = False
        self._slide_timer = QTimer(self)
        self._slide_timer.setSingleShot(True)
        self._slide_timer.timeout.connect(self._slideshow_tick)
        # Repetición: "off" | "one" (este video) | "all" (todos los videos).
        # Sobrevive a la navegación a propósito: en modo "all" el visor
        # encadena videos, y resetearlo en cada cambio lo rompería.
        self._repeat = "off"
        self._ab: list[int] = []                # [] | [a] | [a, b]
        self._jump_stack: list[int] = []        # posiciones para «volver» (⌫)
        self._clip_worker: _ClipWorker | None = None
        self.content_added = False              # la ventana principal recarga
        self.thumbs_changed: set[str] = set()   # miniaturas a invalidar en caché
        self._advance_fade = False              # el próximo cambio viene del
        self._slide_t0 = 0.0                    # avance de la presentación
        self._kb_timer = QTimer(self)           # zoom lento del modo cine
        self._kb_timer.setInterval(80)
        self._kb_timer.timeout.connect(self._kb_tick)
        # Última rotación aplicada por los SEGMENTOS de marcadores (un
        # marcador con rotación define "de aquí en adelante" hasta el
        # siguiente marcador con rotación).
        self._auto_rot: int | None = None

        # --- barra de ajustes (2 filas) ---
        self._adjust = AdjustBar(self._canvas)

        # --- barra de reproducción (solo videos) ---
        self._btn_play = QPushButton("⏸")
        self._btn_play.setFixedWidth(44)
        self._btn_play.clicked.connect(self._toggle)
        self._pos = _SeekSlider()
        self._pos.sliderMoved.connect(self._on_slider_jump)
        self._pos.hoverMoved.connect(self._on_seek_hover)
        self._pos.hoverLeft.connect(lambda: self._preview.hide())
        self._time = QLabel("0:00 / 0:00")
        self._vol = QSlider(Qt.Orientation.Horizontal)
        self._vol.setFixedWidth(100)
        self._vol.setRange(0, 100)
        self._vol.setValue(0)        # por defecto: silencio
        self._vol.valueChanged.connect(self._on_volume)
        self._last_vol = 80          # nivel a restaurar al quitar el silencio
        self._btn_mute = QPushButton("🔇")
        self._btn_mute.setFixedWidth(34)
        self._btn_mute.setFlat(True)
        self._btn_mute.setToolTip("Silenciar / restaurar el volumen anterior")
        self._btn_mute.clicked.connect(self._toggle_mute)

        btn_fback = QPushButton("◀|")
        btn_fback.setFixedWidth(34)
        btn_fback.setToolTip("Un frame atrás (tecla R)")
        btn_fback.clicked.connect(lambda: self._step_frame(-1))
        btn_ffwd = QPushButton("|▶")
        btn_ffwd.setFixedWidth(34)
        btn_ffwd.setToolTip("Un frame adelante (tecla E)")
        btn_ffwd.clicked.connect(lambda: self._step_frame(1))

        self._rate = 1.0
        btn_slower = QPushButton("−")
        btn_slower.setFixedWidth(28)
        btn_slower.setToolTip("Velocidad −0.25× (tecla −)")
        btn_slower.clicked.connect(lambda: self._change_rate(-0.25))
        self._rate_lbl = QLabel("1.00×")
        self._rate_lbl.setToolTip("Velocidad (teclas + / −)")
        btn_faster = QPushButton("+")
        btn_faster.setFixedWidth(28)
        btn_faster.setToolTip("Velocidad +0.25× (tecla +)")
        btn_faster.clicked.connect(lambda: self._change_rate(+0.25))

        self._btn_repeat = QPushButton("🔁")
        self._btn_repeat.setFixedWidth(34)
        self._btn_repeat.setFlat(True)
        self._btn_repeat.setToolTip(
            "Repetición (tecla L): desactivada → 🔂 este video → "
            "🔁 todos los videos de la lista")
        self._btn_repeat.clicked.connect(self._cycle_repeat)
        self._update_repeat_button()

        btn_mark = QPushButton("🔖")
        btn_mark.setFixedWidth(34)
        btn_mark.setToolTip("Añadir marcador en la posición actual (tecla M)")
        btn_mark.clicked.connect(self._add_mark)

        btn_shot = QPushButton("📸")
        btn_shot.setFixedWidth(34)
        btn_shot.setToolTip("Guardar este fotograma como FOTO CIFRADA dentro "
                            "de la bóveda (nunca toca el disco en claro)")
        btn_shot.clicked.connect(self._capture_frame)

        btn_sthumb = QPushButton("🖼")
        btn_sthumb.setFixedWidth(34)
        btn_sthumb.setToolTip("Usar este fotograma como miniatura del video")
        btn_sthumb.clicked.connect(self._frame_as_thumb)

        self._btn_clip = QPushButton("✂")
        self._btn_clip.setFixedWidth(34)
        self._btn_clip.setToolTip("Exportar el tramo A–B como video "
                                  "(descifrado, sin recodificar)")
        self._btn_clip.clicked.connect(self._export_clip)

        btn_fs = QPushButton("⛶")
        btn_fs.setFixedWidth(34)
        btn_fs.setToolTip("Pantalla completa (tecla F; Esc para salir)")
        btn_fs.clicked.connect(self.toggle_fullscreen)

        vbar = QHBoxLayout()
        vbar.setContentsMargins(6, 0, 6, 2)
        for w in (self._btn_play, btn_fback, btn_ffwd):
            vbar.addWidget(w)
        vbar.addWidget(self._pos, 1)
        vbar.addWidget(self._time)
        for w in (btn_slower, self._rate_lbl, btn_faster, self._btn_repeat,
                  btn_mark, btn_shot, btn_sthumb, self._btn_clip,
                  self._btn_mute, self._vol, btn_fs):
            vbar.addWidget(w)
        self._video_bar = QWidget()
        self._video_bar.setLayout(vbar)

        # botón de pantalla completa también para fotos (fila 1 de ajustes)
        btn_fs2 = QPushButton("⛶")
        btn_fs2.setFixedWidth(34)
        btn_fs2.setToolTip("Pantalla completa (tecla F; Esc para salir)")
        btn_fs2.clicked.connect(self.toggle_fullscreen)
        self._adjust.addWidget(btn_fs2)

        # --- fila de chips de marcadores (solo videos con marcadores) ---
        self._marks_row = QWidget()
        self._marks_lay = QHBoxLayout(self._marks_row)
        self._marks_lay.setContentsMargins(6, 0, 6, 0)
        self._marks_lay.addStretch(1)  # el stretch final se conserva siempre

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 4)
        lay.setSpacing(2)
        lay.addWidget(self._canvas, 1)
        lay.addWidget(self._marks_row)
        lay.addWidget(self._adjust)
        lay.addWidget(self._video_bar)

        # --- superpuestos sobre el lienzo ---
        self._nav_prev = QPushButton("‹", self._canvas)
        self._nav_prev.setToolTip("Anterior (RePág; en fotos también ←)")
        self._nav_prev.clicked.connect(lambda: self._go(-1))
        self._nav_next = QPushButton("›", self._canvas)
        self._nav_next.setToolTip("Siguiente (AvPág; en fotos también →)")
        self._nav_next.clicked.connect(lambda: self._go(+1))
        for b in (self._nav_prev, self._nav_next):
            b.setStyleSheet(_OVERLAY_QSS)
            b.setCursor(Qt.CursorShape.PointingHandCursor)
            b.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        self._osd_lbl = QLabel("", self._canvas)
        self._osd_lbl.setStyleSheet(_OSD_QSS)
        self._osd_lbl.hide()
        self._osd_timer = QTimer(self)
        self._osd_timer.setSingleShot(True)
        self._osd_timer.timeout.connect(self._osd_lbl.hide)

        self._help_lbl = QLabel(_HELP_HTML, self._canvas)
        self._help_lbl.setStyleSheet(
            "QLabel { background: rgba(10,10,10,225); color: #ddd;"
            " padding: 18px 26px; border-radius: 12px; }")
        self._help_lbl.hide()

        self._info_lbl = QLabel("", self._canvas)
        self._info_lbl.setStyleSheet(
            "QLabel { background: rgba(10,10,10,215); color: #ddd;"
            " padding: 10px 14px; border-radius: 10px; font-size: 13px; }")
        self._info_lbl.hide()

        self._preview = _PreviewPopup(self)
        self._preview_worker: _PreviewWorker | None = None
        self._preview_cache: OrderedDict[int, QImage] = OrderedDict()
        self._preview_bucket = -1

        # Cursor invisible en pantalla completa tras inactividad.
        self._cursor_timer = QTimer(self)
        self._cursor_timer.setSingleShot(True)
        self._cursor_timer.timeout.connect(self._hide_cursor)

        # Rastrear el ratón sin botones: hover de controles en FS + cursor.
        self._bars_on = True
        self._canvas.setMouseTracking(True)
        self._canvas.installEventFilter(self)

        self._player.positionChanged.connect(self._on_pos)
        self._player.durationChanged.connect(self._on_duration)
        self._player.errorOccurred.connect(self._on_error)
        self._player.mediaStatusChanged.connect(self._on_media_status)

        # CLAVE para los atajos: ningún control acepta foco de teclado. Si
        # un slider lo tuviera, Qt le entregaría ←/→ (movería el slider) y
        # el visor jamás vería la tecla. El ratón no se ve afectado.
        for w in self.findChildren(QAbstractButton) + self.findChildren(QAbstractSlider):
            w.setFocusPolicy(Qt.FocusPolicy.NoFocus)

        self._load_current()

    # ------------------------------------------------------------------
    # OSD y ayuda
    # ------------------------------------------------------------------

    def _osd(self, text: str):
        """Aviso efímero sobre la imagen: feedback inmediato de cada atajo."""
        self._osd_lbl.setText(text)
        self._osd_lbl.adjustSize()
        self._osd_lbl.move((self._canvas.width() - self._osd_lbl.width()) // 2, 26)
        self._osd_lbl.show()
        self._osd_lbl.raise_()
        self._osd_timer.start(1100)

    def _toggle_help(self):
        if self._help_lbl.isVisible():
            self._help_lbl.hide()
            return
        self._help_lbl.adjustSize()
        self._help_lbl.move((self._canvas.width() - self._help_lbl.width()) // 2,
                            max(10, (self._canvas.height() - self._help_lbl.height()) // 2))
        self._help_lbl.show()
        self._help_lbl.raise_()

    # ------------------------------------------------------------------
    # Carga y navegación por la lista de reproducción
    # ------------------------------------------------------------------

    def _update_title(self):
        star = "⭐ " if self._entry.favorite else ""
        self.setWindowTitle(
            f"{star}{self._entry.name}   ({self._idx + 1}/{len(self._playlist)})")

    def _load_current(self):
        self._loading = True
        fade_on = self._advance_fade      # ¿venimos de un avance de cine?
        self._advance_fade = False
        self._save_resume()          # posición del elemento saliente
        self._save_adjust()          # y sus ajustes de imagen, si cambiaron
        self._teardown_source()
        self._teardown_movie()
        self._stop_preview()
        self._ab = []                    # A-B es por posición: no sobrevive
        self._pos.set_ab(None, None)     # (la repetición 🔁 sí se mantiene)
        self._auto_rot = None            # los segmentos se recalculan
        self._jump_stack.clear()
        self._slide_timer.stop()
        self._kb_timer.stop()
        self._info_lbl.hide()

        self._entry = e = self._vault.get(self._playlist[self._idx])
        self._update_title()
        # Vista y filtros neutros por elemento; rotación, espejo y ajustes
        # persistidos se restauran sin re-guardarse (flag _loading).
        self._canvas.reset_view()
        self._adjust.reset_sliders()
        if e.rotation:
            self._canvas.set_rotation(e.rotation)
        if e.flip_h or e.flip_v:
            self._canvas.set_flip(e.flip_h, e.flip_v)
        if e.adjust:
            self._canvas.apply_params(e.adjust)
            self._adjust.sync_from_canvas()
        if not fade_on:
            self._canvas.set_image(QImage())

        multiple = len(self._playlist) > 1
        self._nav_prev.setVisible(multiple)
        self._nav_next.setVisible(multiple)

        if e.mime == "video":
            self._rate = 1.0
            self._rate_lbl.setText("1.00×")
            self._player.setPlaybackRate(1.0)
            self._btn_play.setText("⏸")
            self._tried_buffer_fallback = False
            self._pending_resume = int(e.resume_ms or 0)
            self._rebuild_marks()
            self._start_streaming()
        else:
            reader = self._vault.open_reader(e.id)
            data = reader.read(-1)      # foto completa en RAM (solo RAM)
            reader.close()
            if e.name.lower().endswith(".gif"):
                # GIF animado: QMovie sobre un buffer en RAM (cero disco).
                self._movie_buf = QBuffer(self)
                self._movie_buf.setData(QByteArray(data))
                self._movie_buf.open(QIODevice.OpenModeFlag.ReadOnly)
                self._movie = QMovie(self)
                self._movie.setDevice(self._movie_buf)
                self._movie.setFormat(b"gif")
                self._movie.frameChanged.connect(self._on_movie_frame)
                self._movie.start()
            else:
                img = QImage.fromData(data)
                if img.isNull():
                    QMessageBox.warning(self, "Visor", "No se pudo decodificar la imagen.")
                else:
                    # Modo cine: fundido suave al llegar por avance automático.
                    self._canvas.set_image(img, fade_ms=400 if fade_on else 0)
            del data
            if self._slideshow:
                self._start_slide_timers()

        # En ventana: controles siempre visibles. En pantalla completa:
        # ocultos hasta que el ratón baje a la franja inferior.
        self._set_bars_visible(not self.isFullScreen())
        self._loading = False

    def _go(self, delta: int):
        self._idx = (self._idx + delta) % len(self._playlist)  # circular
        self._load_current()

    def _on_movie_frame(self, _n: int):
        if self._movie is not None:
            img = self._movie.currentImage()
            if not img.isNull():
                self._canvas.set_image(img)

    def _teardown_movie(self):
        if self._movie is not None:
            self._movie.stop()
            self._movie.deleteLater()
            self._movie = None
        if self._movie_buf is not None:
            self._movie_buf.close()
            self._movie_buf = None

    # ------------------------------------------------------------------
    # Persistencia por elemento (todo dentro del índice cifrado)
    # ------------------------------------------------------------------

    def _save_resume(self):
        """Guarda la posición del video para «continuar donde ibas». Solo si
        el punto es significativo (ni el arranque ni el final)."""
        try:
            if (not self._vault.is_locked and self._entry.mime == "video"
                    and self._player.duration() > 0):
                pos = int(self._player.position())
                dur = self._player.duration()
                # Umbrales proporcionales con tope: no guardar si estás al
                # principio (no aporta) ni al final (ya lo viste).
                start_skip = min(5000, max(500, dur // 10))
                end_skip = min(3000, max(400, dur // 10))
                keep = pos if start_skip < pos < dur - end_skip else 0
                if keep != int(self._entry.resume_ms or 0):
                    self._vault.set_resume(self._entry.id, keep)
        except Exception:
            pass

    def _on_rotation(self, rot: int):
        if self._loading:
            return
        self._vault.set_rotation(self._entry.id, rot)
        self._osd(f"↻ {rot}°")

    def _on_flip(self, fh: bool, fv: bool):
        if self._loading:
            return
        self._vault.set_flip(self._entry.id, fh, fv)
        estado = ("horizontal" if fh else "") + (" vertical" if fv else "")
        self._osd(f"⇋ Espejo {estado.strip()}" if (fh or fv) else "Espejo desactivado")

    def _save_adjust(self):
        """Persiste los ajustes de imagen del elemento saliente si cambiaron
        (en el índice cifrado; el archivo original queda intacto)."""
        try:
            if not self._vault.is_locked:
                cur = self._canvas.params_dict()
                if cur != (self._entry.adjust or {}):
                    self._vault.set_adjust(self._entry.id, cur)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Captura de fotograma, miniatura, recorte A–B, saltos e info
    # ------------------------------------------------------------------

    @staticmethod
    def _qimage_jpeg(img: QImage, max_side: int | None = None,
                     quality: int = 92) -> bytes:
        """QImage -> JPEG en RAM (QBuffer): jamás pasa por el disco."""
        if max_side:
            img = img.scaled(max_side, max_side,
                             Qt.AspectRatioMode.KeepAspectRatio,
                             Qt.TransformationMode.SmoothTransformation)
        buf = QBuffer()
        buf.open(QIODevice.OpenModeFlag.WriteOnly)
        img.save(buf, "JPG", quality)
        data = bytes(buf.data())
        buf.close()
        return data

    def _current_frame_image(self) -> QImage | None:
        img = self._canvas._src
        return None if img is None or img.isNull() else img.copy()

    def _capture_frame(self):
        if self._entry.mime != "video" or self._read_only_notice():
            return
        img = self._current_frame_image()
        if img is None:
            return
        pos = int(self._player.position())
        stem = self._entry.name.rsplit(".", 1)[0]
        name = f"{stem}_frame_{_fmt_ms(pos).replace(':', 'm')}s.jpg"
        self._vault.import_bytes(
            name, self._qimage_jpeg(img), "image",
            self._qimage_jpeg(img, max_side=512, quality=85),
            folder=self._entry.folder)
        self.content_added = True   # la galería se recarga al cerrar el visor
        self._osd(f"📸 Guardada como foto cifrada: {name}")

    def _frame_as_thumb(self):
        if self._entry.mime != "video" or self._read_only_notice():
            return
        img = self._current_frame_image()
        if img is None:
            return
        self._vault.set_thumb(self._entry.id,
                              self._qimage_jpeg(img, max_side=512, quality=85))
        self.content_added = True
        self.thumbs_changed.add(self._entry.id)   # que la galería la re-lea
        self._osd("🖼 Este fotograma es ahora la miniatura del video")

    def _export_clip(self):
        if self._entry.mime != "video" or len(self._ab) != 2:
            self._osd("Marca primero un tramo con A–B (tecla B)")
            return
        if self._clip_worker is not None:
            return
        stem = self._entry.name.rsplit(".", 1)[0]
        dst, _ = QFileDialog.getSaveFileName(
            self, "Exportar recorte A–B (quedará DESCIFRADO en disco)",
            f"{stem}_recorte.mp4", "Video (*.mp4 *.mkv)")
        if not dst:
            return
        a, b = self._ab
        self._osd("✂ Exportando recorte…")
        self._clip_worker = w = _ClipWorker(self._vault, self._entry.id, a, b,
                                            dst, self)

        def done(res):
            self._clip_worker = None
            if isinstance(res, str):
                QMessageBox.information(
                    self, "Recorte A–B",
                    f"Recorte exportado (descifrado) en:\n{res}\n\n"
                    "Nota honesta: el corte se alinea al keyframe anterior a "
                    "Ⓐ (sin recodificar no se puede cortar más fino), así que "
                    "puede empezar hasta unos segundos antes.")
            else:
                QMessageBox.warning(self, "Recorte A–B",
                                    f"No se pudo exportar:\n{res}")

        w.done.connect(done)
        w.start()

    def _push_jump(self):
        pos = int(self._player.position())
        if not self._jump_stack or abs(self._jump_stack[-1] - pos) > 1000:
            self._jump_stack.append(pos)
            del self._jump_stack[:-50]

    def _on_slider_jump(self, val: int):
        # Un salto grande por la barra deja miga de pan para ⌫.
        if abs(val - self._player.position()) > 5000:
            self._push_jump()
        self._player.setPosition(val)

    def _jump_back(self):
        if not self._jump_stack:
            self._osd("No hay salto que deshacer")
            return
        pos = self._jump_stack.pop()
        self._player.setPosition(pos)
        self._osd(f"↩ De vuelta en {_fmt_ms(pos)}")

    def _toggle_info(self):
        if self._info_lbl.isVisible():
            self._info_lbl.hide()
            return
        e = self._entry
        img = self._canvas._src
        res = (f"{img.width()}×{img.height()}"
               if img is not None and not img.isNull() else "—")
        lines = [f"<b>{e.name}</b>",
                 f"Resolución: {res}",
                 f"Tamaño: {e.size / (1024 * 1024):.1f} MB",
                 f"Fecha original: "
                 f"{datetime.fromtimestamp(e.mtime).strftime('%d/%m/%Y %H:%M')}"]
        if e.mime == "video":
            lines.insert(2, f"Duración: {_fmt_ms(self._player.duration())}")
            if e.marks:
                lines.append(f"Marcadores: {len(e.marks)}")
        if e.folder:
            lines.append(f"Carpeta: {e.folder}")
        self._info_lbl.setText("<br/>".join(lines))
        self._info_lbl.adjustSize()
        self._info_lbl.move(16, 16)
        self._info_lbl.show()
        self._info_lbl.raise_()

    def _toggle_favorite(self):
        if self._read_only_notice():
            return
        fav = not self._entry.favorite
        self._vault.set_favorite(self._entry.id, fav)
        self._update_title()
        self._osd("⭐ Añadido a favoritos" if fav else "☆ Quitado de favoritos")

    # ------------------------------------------------------------------
    # Marcadores con nombre
    # ------------------------------------------------------------------

    def _read_only_notice(self) -> bool:
        """True (y avisa) si la bóveda es remota: la metadata no persiste."""
        if self._vault.read_only:
            self._osd("Bóveda remota: solo lectura")
            return True
        return False

    def _add_mark(self):
        if self._entry.mime != "video" or self._read_only_notice():
            return
        pos = int(self._player.position())
        self._vault.set_marks(self._entry.id, list(self._entry.marks) + [[pos, "", None]])
        self._rebuild_marks()
        self._osd(f"🔖 Marcador en {_fmt_ms(pos)}")

    def _remove_mark(self, t: int):
        self._vault.set_marks(
            self._entry.id, [m for m in self._entry.marks if m[0] != t])
        self._rebuild_marks()

    def _rename_mark(self, t: int, current: str):
        txt, ok = QInputDialog.getText(self, "Marcador", "Nombre:", text=current)
        if ok:
            self._vault.set_marks(
                self._entry.id,
                [[m[0], (txt.strip() if m[0] == t else m[1]), m[2]]
                 for m in self._entry.marks])
            self._rebuild_marks()

    def _set_mark_rotation(self, t: int, rot: int | None):
        """Guarda (o quita, con None) la rotación de segmento del marcador:
        desde ese punto en adelante el video se ve con esa orientación,
        hasta el siguiente marcador que tenga la suya."""
        self._vault.set_marks(
            self._entry.id,
            [[m[0], m[1], (rot if m[0] == t else m[2])] for m in self._entry.marks])
        self._rebuild_marks()
        if rot is not None:
            self._osd(f"🔖 Desde {_fmt_ms(t)} el video se ve a ↻ {rot}°")
        else:
            self._osd(f"🔖 Marcador {_fmt_ms(t)} sin rotación propia")

    def _goto_mark(self, t: int, rot: int | None):
        # Solo salta: la rotación la resuelve el sistema de segmentos en
        # cuanto llega el primer positionChanged.
        self._push_jump()   # ⌫ vuelve a donde estabas antes del salto
        self._player.setPosition(t)

    def _segment_rotation(self, p: int) -> int | None:
        """Rotación del segmento activo en la posición p: la del último
        marcador con rotación cuyo tiempo sea <= p (los marcadores están
        ordenados). None si aún no se cruzó ninguno."""
        rot = None
        for t, _lbl, r in self._entry.marks:
            if t <= p:
                if r is not None:
                    rot = r
            else:
                break
        return rot

    def _apply_segment_rotation(self, p: int):
        seg = self._segment_rotation(p)
        desired = seg if seg is not None else (self._entry.rotation or 0)
        if desired != self._auto_rot:
            self._auto_rot = desired
            # set_rotation es silencioso: NO persiste ni toca la rotación
            # base del video; es solo la vista del segmento actual.
            self._canvas.set_rotation(desired)

    def _rebuild_marks(self):
        while self._marks_lay.count() > 1:   # conservar el stretch final
            item = self._marks_lay.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        marks = list(self._entry.marks)
        visible_now = getattr(self, "_bars_on", True)
        self._auto_rot = None   # los segmentos cambiaron: recalcular
        for t, label, rot in marks:
            # Chip doble: [nombre -> saltar] [↻ -> rotación del segmento].
            row = QWidget()
            h = QHBoxLayout(row)
            h.setContentsMargins(0, 0, 0, 0)
            h.setSpacing(0)

            btn_label = QPushButton(label if label else f"▸ {_fmt_ms(t)}")
            btn_label.setToolTip(
                f"{_fmt_ms(t)} — clic: saltar · clic derecho: renombrar/eliminar")
            btn_label.clicked.connect(
                lambda _=False, tt=t, rr=rot: self._goto_mark(tt, rr))
            btn_label.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            btn_label.customContextMenuRequested.connect(
                lambda pos, tt=t, ll=label, rr=rot, c=btn_label:
                    self._mark_menu(c, pos, tt, ll, rr))

            # El icono ↻ es el control de rotación PROPIO de este marcador:
            # cada clic suma 90° a su segmento (90→180→270→0→sin rotación).
            btn_rot = QPushButton("↻" if rot is None else f"↻{rot}°")
            btn_rot.setFixedWidth(34 if rot is None else 54)
            btn_rot.setStyleSheet(
                "QPushButton { color: %s; }" % ("#9a9a9a" if rot is None else "#00c8e6"))
            btn_rot.setToolTip(
                "Rotación de este segmento (desde este marcador hasta el "
                "siguiente o el final; hacia atrás rige otra). Cada clic "
                "suma 90°; después de 0° se quita y hereda la rotación base.")
            btn_rot.clicked.connect(
                lambda _=False, tt=t, rr=rot: self._cycle_mark_rotation(tt, rr))

            for b in (btn_label, btn_rot):
                b.setFocusPolicy(Qt.FocusPolicy.NoFocus)  # no robar los atajos
                h.addWidget(b)
            row.label_btn = btn_label   # accesibles para pruebas
            row.rot_btn = btn_rot
            self._marks_lay.insertWidget(self._marks_lay.count() - 1, row)
        self._marks_row.setVisible(bool(marks) and visible_now)
        self._pos.set_marks([(m[0], m[2] is not None, m[1]) for m in marks])

    def _cycle_mark_rotation(self, t: int, rot: int | None):
        """Icono ↻ del chip: cicla la rotación del segmento en pasos de 90°
        (sin rotación → 90 → 180 → 270 → 0 → sin rotación)."""
        if self._read_only_notice():
            return
        order = [None, 90, 180, 270, 0]
        nxt = order[(order.index(rot) + 1) % len(order)]
        self._set_mark_rotation(t, nxt)

    def _mark_menu(self, chip: QPushButton, pos, t: int, label: str, rot: int | None):
        if self._read_only_notice():
            return
        menu = QMenu(self)
        act_ren = menu.addAction("Renombrar…")
        act_unrot = menu.addAction("Quitar la rotación del segmento") if rot is not None else None
        act_del = menu.addAction(f"Eliminar marcador {_fmt_ms(t)}")
        chosen = menu.exec(chip.mapToGlobal(pos))
        if chosen is act_del:
            self._remove_mark(t)
        elif chosen is act_ren:
            self._rename_mark(t, label)
        elif act_unrot is not None and chosen is act_unrot:
            self._set_mark_rotation(t, None)

    # ------------------------------------------------------------------
    # Pantalla completa, controles por hover y cursor
    # ------------------------------------------------------------------

    def _set_bars_visible(self, on: bool):
        self._bars_on = on
        video = self._entry.mime == "video"
        self._adjust.setVisible(on)
        self._video_bar.setVisible(on and video)
        self._marks_row.setVisible(on and video and bool(self._entry.marks))

    def toggle_fullscreen(self):
        if self.isFullScreen():
            self._exit_fullscreen()
        else:
            self._enter_fullscreen()

    def _enter_fullscreen(self):
        if self.isFullScreen():
            return
        self._was_maximized = self.isMaximized()
        self._set_bars_visible(False)
        self.showFullScreen()
        self._cursor_timer.start(CURSOR_HIDE_MS)

    def _exit_fullscreen(self):
        if not self.isFullScreen():
            return
        self._cursor_timer.stop()
        self._canvas.unsetCursor()
        self._set_bars_visible(True)
        if self._was_maximized:
            self.showMaximized()
        else:
            self.showNormal()

    def _hide_cursor(self):
        if self.isFullScreen():
            self._canvas.setCursor(Qt.CursorShape.BlankCursor)

    def eventFilter(self, obj, ev):
        if obj is self._canvas:
            if ev.type() == QEvent.Type.Resize:
                w, h = self._canvas.width(), self._canvas.height()
                self._nav_prev.setGeometry(10, h // 2 - 70, 54, 140)
                self._nav_next.setGeometry(w - 64, h // 2 - 70, 54, 140)
            elif ev.type() == QEvent.Type.MouseMove:
                if self.isFullScreen():
                    # revivir el cursor y rearmar su temporizador
                    self._canvas.unsetCursor()
                    self._cursor_timer.start(CURSOR_HIDE_MS)
                    in_zone = ev.position().y() >= self._canvas.height() - HOVER_ZONE_PX
                    if in_zone != self._bars_on:
                        self._set_bars_visible(in_zone)
        return False

    # ------------------------------------------------------------------
    # Presentación, bucle y A–B
    # ------------------------------------------------------------------

    def _toggle_slideshow(self):
        # P cicla: apagada -> normal -> aleatoria -> apagada.
        order = [False, "normal", "random"]
        self._slideshow = order[(order.index(self._slideshow) + 1) % 3]
        if self._slideshow:
            modo = "aleatoria " if self._slideshow == "random" else ""
            self._osd(f"▶ Presentación {modo}— P cambia el modo o la detiene")
            if not self.isFullScreen():
                self._enter_fullscreen()
            if self._entry.mime == "image":
                self._start_slide_timers()
            elif self._player.playbackState() != QMediaPlayer.PlaybackState.PlayingState:
                self._toggle()
        else:
            self._slide_timer.stop()
            self._kb_timer.stop()
            self._canvas.set_kenburns(1.0)
            self._osd("⏹ Presentación detenida")

    def _start_slide_timers(self):
        self._slide_timer.start(SLIDESHOW_MS)
        self._slide_t0 = time.time()
        self._kb_timer.start()   # Ken Burns: zoom lento durante la foto

    def _kb_tick(self):
        if self._slideshow and self._entry.mime == "image":
            prog = (time.time() - self._slide_t0) / (SLIDESHOW_MS / 1000)
            self._canvas.set_kenburns(1.0 + 0.06 * min(1.0, prog))
        else:
            self._kb_timer.stop()
            self._canvas.set_kenburns(1.0)

    def _advance_slideshow(self):
        """Avance automático de la presentación (con fundido; en modo
        aleatorio salta a cualquier otro elemento)."""
        self._advance_fade = True
        n = len(self._playlist)
        if self._slideshow == "random" and n > 1:
            j = self._idx
            while j == self._idx:
                j = random.randrange(n)
            self._idx = j
            self._load_current()
        else:
            self._go(+1)

    def _slideshow_tick(self):
        if self._slideshow and self._entry.mime == "image":
            self._advance_slideshow()

    def _cycle_repeat(self):
        if self._entry.mime != "video":
            return
        order = ["off", "one", "all"]
        self._repeat = order[(order.index(self._repeat) + 1) % 3]
        self._update_repeat_button()
        self._osd({"off": "Repetición desactivada",
                   "one": "🔂 Repetir este video",
                   "all": "🔁 Repetir todos los videos"}[self._repeat])

    def _update_repeat_button(self):
        self._btn_repeat.setText("🔂" if self._repeat == "one" else "🔁")
        # Ámbar cuando está activo; gris cuando no.
        color = "#e6b400" if self._repeat != "off" else "#9a9a9a"
        self._btn_repeat.setStyleSheet(f"QPushButton {{ color: {color}; }}")

    def _next_video_idx(self) -> int:
        """Siguiente VIDEO de la lista (las fotos se saltan), circular.
        Si este es el único video, devuelve el índice actual."""
        n = len(self._playlist)
        for step in range(1, n + 1):
            j = (self._idx + step) % n
            if self._vault.get(self._playlist[j]).mime == "video":
                return j
        return self._idx

    def _ab_press(self):
        if self._entry.mime != "video":
            return
        pos = int(self._player.position())
        if not self._ab:
            self._ab = [pos]
            self._osd(f"Ⓐ fijado en {_fmt_ms(pos)} — pulsa B para el final")
        elif len(self._ab) == 1:
            a = self._ab[0]
            if pos <= a + 300:
                self._osd("Ⓑ debe ser posterior a Ⓐ")
                return
            self._ab = [a, pos]
            self._pos.set_ab(a, pos)
            self._osd(f"🔁 A–B {_fmt_ms(a)} – {_fmt_ms(pos)}")
            self._player.setPosition(a)
        else:
            self._ab = []
            self._pos.set_ab(None, None)
            self._osd("A–B desactivado")

    def _on_media_status(self, status):
        if status != QMediaPlayer.MediaStatus.EndOfMedia:
            return
        if len(self._ab) == 2:
            self._player.setPosition(self._ab[0])
            self._player.play()
        elif self._repeat == "one":
            self._player.setPosition(0)
            self._player.play()
        elif self._repeat == "all":
            nxt = self._next_video_idx()
            if nxt == self._idx:
                self._player.setPosition(0)   # único video: repetirse
                self._player.play()
            else:
                self._idx = nxt
                self._load_current()          # encadena el siguiente video
        elif self._slideshow:
            self._advance_slideshow()
        else:
            self._btn_play.setText("▶")

    # ------------------------------------------------------------------
    # Vista previa sobre la barra de avance
    # ------------------------------------------------------------------

    def _stop_preview(self):
        self._preview.hide()
        self._preview_cache.clear()
        if self._preview_worker is not None:
            self._preview_worker.stop()
            self._preview_worker.wait(2000)
            self._preview_worker = None

    def _on_seek_hover(self, ms: int, x_local: int):
        if self._entry.mime != "video" or self._player.duration() <= 0:
            return
        bucket = ms - ms % PREVIEW_BUCKET_MS
        self._preview_bucket = bucket
        img = self._preview_cache.get(bucket)
        if img is not None:
            self._preview_cache.move_to_end(bucket)
        self._preview.show_frame(_fmt_ms(ms), img)
        top_left = self._pos.mapTo(self, QPoint(0, 0))
        x = top_left.x() + x_local - self._preview.width() // 2
        x = max(4, min(x, self.width() - self._preview.width() - 4))
        self._preview.move(x, max(4, top_left.y() - self._preview.height() - 8))
        if img is None:
            if self._preview_worker is None:
                self._preview_worker = _PreviewWorker(self._vault, self._entry.id, self)
                self._preview_worker.ready.connect(self._on_preview_ready)
                self._preview_worker.start()
            self._preview_worker.request(bucket)

    def _on_preview_ready(self, bucket: int, img: QImage):
        self._preview_cache[bucket] = img
        while len(self._preview_cache) > PREVIEW_CACHE_MAX:
            self._preview_cache.popitem(last=False)
        if self._preview.isVisible() and bucket == self._preview_bucket:
            self._preview.show_frame(_fmt_ms(bucket), img)

    # ------------------------------------------------------------------
    # Video: streaming, velocidad, frames, seek, volumen
    # ------------------------------------------------------------------

    def _on_frame(self, frame):
        if frame.isValid():
            img = frame.toImage()
            if not img.isNull():
                self._canvas.set_image(img)

    def _source_hint(self) -> QUrl:
        n = self._entry.name
        ext = "." + n.rsplit(".", 1)[-1].lower() if "." in n else ".mp4"
        return QUrl(f"boveda:///video{ext}")

    def _start_streaming(self):
        """Intento 1: streaming con descifrado bajo demanda (ventana ~8 MiB)."""
        self._device = DecryptingIODevice(self._vault.open_reader(self._entry.id))
        self._player.setSourceDevice(self._device, self._source_hint())
        self._player.play()

    def _fallback_buffer(self):
        """Intento 2: video completo descifrado a RAM (QBuffer)."""
        self._tried_buffer_fallback = True
        self._teardown_source()
        reader = self._vault.open_reader(self._entry.id)
        self._buffer_data = QByteArray(reader.read(-1))
        reader.close()
        buf = QBuffer(self._buffer_data, self)
        buf.open(QIODevice.OpenModeFlag.ReadOnly)
        self._device = buf
        self._player.setSourceDevice(buf, self._source_hint())
        self._player.play()

    def _on_error(self, _err, msg: str):
        if self._entry.mime != "video":
            return
        if not self._tried_buffer_fallback:
            self._fallback_buffer()
        else:
            QMessageBox.warning(
                self, "Reproducción",
                "El backend multimedia no pudo reproducir este formato desde "
                f"memoria.\n({msg})\n\n"
                "Este visor NUNCA escribe temporales en claro; si necesitas "
                "ver este archivo, usa Exportar.",
            )

    def _toggle(self):
        if self._player.playbackState() == QMediaPlayer.PlaybackState.PlayingState:
            self._player.pause()
            self._btn_play.setText("▶")
        else:
            self._player.play()
            self._btn_play.setText("⏸")

    def _on_volume(self, v: int):
        self._audio.setVolume(v / 100)
        if v > 0:
            self._last_vol = v       # recordar el último nivel audible
        self._btn_mute.setText("🔊" if v > 0 else "🔇")

    def _toggle_mute(self):
        """Clic en el icono: silenciar, o volver al nivel que había."""
        if self._vol.value() > 0:
            self._vol.setValue(0)
            self._osd("🔇 Silencio")
        else:
            self._vol.setValue(self._last_vol or 80)
            self._osd(f"🔊 {self._vol.value()} %")

    def _change_rate(self, delta: float):
        # Redondear a múltiplos de 0.25 evita deriva de coma flotante.
        self._rate = max(0.25, min(4.0, round((self._rate + delta) * 4) / 4))
        self._player.setPlaybackRate(self._rate)
        self._rate_lbl.setText(f"{self._rate:.2f}×")
        self._osd(f"⏱ {self._rate:.2f}×")

    def _frame_ms(self) -> int:
        fps = 0.0
        try:
            v = self._player.metaData().value(QMediaMetaData.Key.VideoFrameRate)
            fps = float(v) if v else 0.0
        except Exception:
            pass
        return max(1, round(1000 / fps)) if fps > 0 else 33

    def _step_frame(self, direction: int):
        """Un frame exacto adelante/atrás; pausa primero."""
        if self._player.playbackState() == QMediaPlayer.PlaybackState.PlayingState:
            self._player.pause()
            self._btn_play.setText("▶")
        pos = self._player.position() + direction * self._frame_ms()
        self._player.setPosition(max(0, min(pos, self._player.duration())))

    def _seek_rel(self, delta_ms: int):
        pos = self._player.position() + delta_ms
        self._player.setPosition(max(0, min(pos, self._player.duration())))
        self._osd(f"{'⏩ +10 s' if delta_ms > 0 else '⏪ −10 s'}")

    def _on_pos(self, p: int):
        if not self._pos.isSliderDown():
            self._pos.setValue(p)
        self._time.setText(f"{_fmt_ms(p)} / {_fmt_ms(self._player.duration())}")
        if len(self._ab) == 2 and p >= self._ab[1]:
            self._player.setPosition(self._ab[0])   # repetición A–B
        if self._entry.mime == "video":
            self._apply_segment_rotation(p)         # segmentos de rotación

    def _on_duration(self, d: int):
        self._pos.setRange(0, d)
        self._pos.set_marks(
            [(m[0], m[2] is not None, m[1]) for m in self._entry.marks])
        if self._pending_resume and 0 < self._pending_resume < d - 2000:
            self._player.setPosition(self._pending_resume)
            self._osd(f"⏵ Continuando en {_fmt_ms(self._pending_resume)}")
        self._pending_resume = 0

    # ------------------------------------------------------------------

    def keyPressEvent(self, ev):
        k = ev.key()
        video = self._entry.mime == "video"
        if k == Qt.Key.Key_F:
            self.toggle_fullscreen()
        elif k == Qt.Key.Key_Escape and self._help_lbl.isVisible():
            self._help_lbl.hide()
        elif k == Qt.Key.Key_Escape and self.isFullScreen():
            self._exit_fullscreen()      # Esc sale de pantalla completa
        elif k in (Qt.Key.Key_H, Qt.Key.Key_Question):
            self._toggle_help()
        elif k == Qt.Key.Key_S:
            self._toggle_favorite()
        elif k == Qt.Key.Key_P:
            self._toggle_slideshow()
        elif k == Qt.Key.Key_I:
            self._toggle_info()
        elif k == Qt.Key.Key_C:
            self._canvas.toggle_actual_size()
        elif k == Qt.Key.Key_U:
            follow = not self._canvas._loupe_follow
            self._canvas.set_loupe_follow(follow)
            self._osd("🔍 Lupa: mueve el ratón (U para quitarla)"
                      if follow else "Lupa desactivada")
        elif k == Qt.Key.Key_O and not ev.isAutoRepeat():
            self._canvas.set_show_original(True)   # mantener pulsada = original
        elif video and k == Qt.Key.Key_Backspace:
            self._jump_back()
        elif k == Qt.Key.Key_PageDown:
            self._go(+1)
        elif k == Qt.Key.Key_PageUp:
            self._go(-1)
        elif video and k == Qt.Key.Key_Right:
            self._seek_rel(+SEEK_STEP_MS)    # +10 s
        elif video and k == Qt.Key.Key_Left:
            self._seek_rel(-SEEK_STEP_MS)    # −10 s
        elif not video and k == Qt.Key.Key_Right:
            self._go(+1)
        elif not video and k == Qt.Key.Key_Left:
            self._go(-1)
        elif video and k in (Qt.Key.Key_Plus, Qt.Key.Key_Equal):
            self._change_rate(+0.25)
        elif video and k == Qt.Key.Key_Minus:
            self._change_rate(-0.25)
        elif video and k == Qt.Key.Key_E:
            self._step_frame(1)
        elif video and k == Qt.Key.Key_R:
            self._step_frame(-1)
        elif video and k == Qt.Key.Key_Space:
            self._toggle()
        elif video and k == Qt.Key.Key_M:
            self._add_mark()
        elif video and k == Qt.Key.Key_L:
            self._cycle_repeat()
        elif video and k == Qt.Key.Key_B:
            self._ab_press()
        else:
            super().keyPressEvent(ev)
            return
        ev.accept()

    def keyReleaseEvent(self, ev):
        if ev.key() == Qt.Key.Key_O and not ev.isAutoRepeat():
            self._canvas.set_show_original(False)
            ev.accept()
            return
        super().keyReleaseEvent(ev)

    # ------------------------------------------------------------------

    def _teardown_source(self):
        self._player.stop()
        self._player.setSource(QUrl())  # desengancha el QIODevice del backend
        if self._device is not None:
            self._device.close()
            self._device = None
        if self._buffer_data is not None:
            # Best-effort: truncar el QByteArray con el video en claro.
            self._buffer_data.clear()
            self._buffer_data = None

    def closeEvent(self, ev):
        self._slide_timer.stop()
        self._kb_timer.stop()
        self._save_resume()
        self._save_adjust()
        self._stop_preview()
        if self._clip_worker is not None:
            self._clip_worker.wait(30000)   # dejar terminar el recorte
        self._teardown_movie()
        self._teardown_source()
        super().closeEvent(ev)


def open_viewer(vault: Vault, entry_id: str, parent=None, protect: bool = True,
                playlist: list[str] | None = None) -> QDialog:
    dlg = ViewerWindow(vault, entry_id, playlist=playlist, parent=parent)
    dlg.setAttribute(Qt.WidgetAttribute.WA_DeleteOnClose)
    if protect:
        # El contenido descifrado en pantalla queda excluido de capturas,
        # grabación, compartir pantalla y Recall (best-effort del SO).
        set_capture_protection(dlg, True)
    dlg.show()
    return dlg
