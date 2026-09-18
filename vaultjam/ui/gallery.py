"""Galería con miniaturas y control de zoom.

Las miniaturas se descifran BAJO DEMANDA en un hilo de fondo y viven solo
como QPixmap en RAM. Al bloquear la bóveda, el modelo se vacía por completo
(iconos incluidos) antes de tirar las claves.
"""

from __future__ import annotations

from PySide6.QtCore import QPointF, QSize, Qt, QThread, Signal
from PySide6.QtGui import (QColor, QImage, QPainter, QPen, QPixmap,
                           QPolygonF, QStandardItem, QStandardItemModel,
                           QTransform)
from PySide6.QtWidgets import QListView, QMenu, QVBoxLayout, QWidget

from ..vault import Vault


def _placeholder(mime: str, px: int = 256) -> QPixmap:
    pm = QPixmap(px, px)
    pm.fill(QColor("#2b2b2b"))
    p = QPainter(pm)
    p.setPen(QColor("#777"))
    f = p.font(); f.setPointSize(px // 6); p.setFont(f)
    p.drawText(pm.rect(), Qt.AlignmentFlag.AlignCenter, "🎞" if mime == "video" else "🖼")
    p.end()
    return pm


def _overlay_play(pm: QPixmap) -> QPixmap:
    """Triángulo de 'play' sobre las miniaturas de video, para distinguirlas."""
    out = QPixmap(pm)
    p = QPainter(out)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    w, h = out.width(), out.height()
    r = min(w, h) // 5
    cx, cy = w / 2, h / 2
    p.setBrush(QColor(0, 0, 0, 140))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawEllipse(QPointF(cx, cy), r, r)
    p.setBrush(QColor(255, 255, 255, 230))
    tri = QPolygonF([QPointF(cx - r * 0.32, cy - r * 0.55),
                     QPointF(cx - r * 0.32, cy + r * 0.55),
                     QPointF(cx + r * 0.62, cy)])
    p.drawPolygon(tri)
    p.end()
    return out


class _ThumbLoader(QThread):
    """Descifra miniaturas en segundo plano. Emite QImage (thread-safe en Qt;
    el QPixmap se crea en el hilo de la UI). Parable en cualquier momento
    para poder bloquear la bóveda sin carreras."""

    thumbReady = Signal(str, QImage)

    def __init__(self, vault: Vault, entry_ids: list[str], parent=None):
        super().__init__(parent)
        self._vault = vault
        self._ids = entry_ids
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        for eid in self._ids:
            if self._stop or self._vault.is_locked:
                return
            try:
                data = self._vault.read_thumb(eid)
            except Exception:
                continue  # miniatura corrupta: se queda el placeholder
            if data:
                img = QImage.fromData(data)
                if not img.isNull():
                    self.thumbReady.emit(eid, img)


class GalleryWidget(QWidget):
    openRequested = Signal(str)          # doble clic -> abrir en el visor
    selectionChangedSig = Signal()
    favoritesChanged = Signal()          # para refrescar contadores laterales

    def __init__(self, parent=None):
        super().__init__(parent)
        self._vault: Vault | None = None
        self._loader: _ThumbLoader | None = None

        self._model = QStandardItemModel(self)
        self._view = QListView()
        self._view.setModel(self._model)
        self._view.setViewMode(QListView.ViewMode.IconMode)
        self._view.setResizeMode(QListView.ResizeMode.Adjust)
        self._view.setMovement(QListView.Movement.Static)
        self._view.setSelectionMode(QListView.SelectionMode.ExtendedSelection)
        self._view.setEditTriggers(QListView.EditTrigger.NoEditTriggers)
        self._view.setWordWrap(True)
        self._view.setSpacing(8)
        self._view.doubleClicked.connect(
            lambda ix: self.openRequested.emit(ix.data(Qt.ItemDataRole.UserRole))
        )
        self._view.selectionModel().selectionChanged.connect(
            lambda *_: self.selectionChangedSig.emit()
        )
        self._view.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._view.customContextMenuRequested.connect(self._context_menu)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        lay.addWidget(self._view)
        self._masters: dict[str, QPixmap] = {}   # miniaturas a resolución completa
        self._base = 160                         # tamaño base del slider
        # Disponibilidad remota por elemento (subidas a Drive en curso):
        # True = todos sus chunks presentes (marco verde), False = aún
        # incompleto (marco rojo), ausente = sin información (sin marco).
        self._avail: dict[str, bool] = {}
        self._privacy = False    # cortina 🙈: iconos y nombres ocultos
        self.set_zoom(160)

    # ------------------------------------------------------------------

    def set_zoom(self, px: int):
        """Slider de la barra: fija el tamaño BASE. Cada elemento lo
        multiplica por su escala individual (menú contextual), así una
        miniatura puede ser más grande que el resto — por eso no hay
        rejilla uniforme: el layout fluye con el tamaño de cada una."""
        self._base = px
        # iconSize es el techo de dibujo: base × escala máxima (2×).
        self._view.setIconSize(QSize(px * 2, px * 2))
        for row in range(self._model.rowCount()):
            self._apply_pixmap(self._model.item(row))

    def _apply_pixmap(self, item: QStandardItem):
        """Pinta el icono a su tamaño propio (base × escala individual).
        La rotación de miniatura y el distintivo ▶ se aplican aquí, al
        vuelo: girar o redimensionar una miniatura NUNCA re-descifra nada
        (el master decodificado se reutiliza tal cual)."""
        scale0 = item.data(Qt.ItemDataRole.UserRole + 3) or 1.0
        if self._privacy:
            # Cortina activa: losa neutra idéntica para todos, sin pista
            # alguna del contenido (ni imagen, ni proporciones).
            target = max(48, int(self._base * scale0))
            pm = QPixmap(target, target)
            pm.fill(QColor("#3c3c3c"))
            p = QPainter(pm)
            p.setPen(QColor("#777"))
            f = p.font()
            f.setPointSize(max(10, target // 5))
            p.setFont(f)
            p.drawText(pm.rect(), Qt.AlignmentFlag.AlignCenter, "🙈")
            p.end()
            item.setIcon(pm)
            item.setSizeHint(QSize(target + 24, target + 46))
            return
        master = self._masters.get(item.data(Qt.ItemDataRole.UserRole))
        if master is None:
            return
        pm = master
        rot = item.data(Qt.ItemDataRole.UserRole + 2) or 0
        if rot:
            pm = pm.transformed(QTransform().rotate(rot),
                                Qt.TransformationMode.SmoothTransformation)
        scale = item.data(Qt.ItemDataRole.UserRole + 3) or 1.0
        target = max(48, int(self._base * scale))
        pm = pm.scaled(target, target,
                       Qt.AspectRatioMode.KeepAspectRatio,
                       Qt.TransformationMode.SmoothTransformation)
        if item.data(Qt.ItemDataRole.UserRole + 1) == "video":
            pm = _overlay_play(pm)
        state = self._avail.get(item.data(Qt.ItemDataRole.UserRole))
        if state is not None:
            # Marco de disponibilidad remota: verde = completo en Drive,
            # rojo = a este elemento aún le faltan chunks por subir.
            pm = QPixmap(pm)   # copia propia antes de pintar encima
            p = QPainter(pm)
            p.setPen(QPen(QColor("#27ae60") if state else QColor("#e74c3c"), 6))
            p.drawRect(pm.rect().adjusted(3, 3, -3, -3))
            p.end()
        item.setIcon(pm)
        item.setSizeHint(QSize(target + 24, target + 46))

    def set_privacy(self, on: bool):
        """Cortina 🙈: oculta miniaturas y nombres sin descartar nada (los
        masters siguen en RAM; al mostrar, refresh_meta restaura textos)."""
        self._privacy = on
        for row in range(self._model.rowCount()):
            item = self._model.item(row)
            if on:
                item.setText("•••")
                item.setToolTip("")
            self._apply_pixmap(item)

    def set_availability(self, status: dict[str, bool]):
        """Aplica (y recuerda para futuras recargas) la disponibilidad
        remota de cada elemento, repintando los marcos en sitio."""
        self._avail = dict(status)
        for row in range(self._model.rowCount()):
            self._apply_pixmap(self._model.item(row))

    def refresh_meta(self, vault: Vault):
        """Sincroniza EN SITIO lo que pudo cambiar (⭐, rotación y tamaño de
        miniatura) sin re-descifrar: reutiliza los masters ya decodificados.
        Es lo que corre al cerrar un visor, en vez de recargar todo."""
        if self._privacy:
            return   # con la cortina activa no se restauran nombres
        for row in range(self._model.rowCount()):
            item = self._model.item(row)
            try:
                e = vault.get(item.data(Qt.ItemDataRole.UserRole))
            except KeyError:
                continue
            item.setText(("⭐ " + e.name) if e.favorite else e.name)
            item.setToolTip(e.name)
            item.setData(e.thumb_rotation, Qt.ItemDataRole.UserRole + 2)
            item.setData(e.thumb_scale, Qt.ItemDataRole.UserRole + 3)
            self._apply_pixmap(item)

    def load(self, vault: Vault, folder: str | None = None, favorites: bool = False):
        """folder=None muestra todo; "" solo lo sin carpeta; favorites=True
        solo los marcados con ⭐ (ignora la carpeta)."""
        avail = self._avail          # la disponibilidad remota sobrevive a
        self.clear_secure()          # las recargas (solo se borra al bloquear)
        self._avail = avail
        self._vault = vault
        entries = vault.entries(None if favorites else folder, favorites=favorites)
        for e in entries:
            item = QStandardItem()
            # Con la cortina activa, ni siquiera una recarga (cambio de
            # carpeta) revela los nombres.
            if self._privacy:
                item.setText("•••")
            else:
                item.setText(("⭐ " + e.name) if e.favorite else e.name)
            item.setData(e.id, Qt.ItemDataRole.UserRole)
            item.setData(e.mime, Qt.ItemDataRole.UserRole + 1)
            # Rotación y escala PROPIAS de la miniatura (independientes de
            # la rotación del contenido en el visor).
            item.setData(e.thumb_rotation, Qt.ItemDataRole.UserRole + 2)
            item.setData(e.thumb_scale, Qt.ItemDataRole.UserRole + 3)
            item.setToolTip("" if self._privacy else e.name)
            self._masters[e.id] = _placeholder(e.mime)
            self._model.appendRow(item)
            self._apply_pixmap(item)
        self._loader = _ThumbLoader(vault, [e.id for e in entries], self)
        self._loader.thumbReady.connect(self._on_thumb)
        self._loader.start()

    def _on_thumb(self, entry_id: str, img: QImage):
        for row in range(self._model.rowCount()):
            item = self._model.item(row)
            if item.data(Qt.ItemDataRole.UserRole) == entry_id:
                # El master se guarda SIN rotar ni decorar: rotación, escala
                # y ▶ se aplican en _apply_pixmap. Así los cambios de
                # metadata jamás requieren volver a descifrar la miniatura.
                self._masters[entry_id] = QPixmap.fromImage(img)
                self._apply_pixmap(item)
                break

    def selected_ids(self) -> list[str]:
        return [ix.data(Qt.ItemDataRole.UserRole) for ix in self._view.selectedIndexes()]

    def _context_menu(self, pos):
        ids = self.selected_ids()
        if not ids or self._vault is None or self._privacy:
            return
        if getattr(self._vault, "read_only", False):
            return   # bóveda remota: sin favoritos/rotación/tamaño
        menu = QMenu(self)
        act_fav = menu.addAction("⭐ Alternar favorito")
        act_rot = menu.addAction("↻ Girar miniatura 90°")
        size_menu = menu.addMenu("🔍 Tamaño de miniatura")
        act_s1 = size_menu.addAction("Normal (1×)")
        act_s15 = size_menu.addAction("Grande (1.5×)")
        act_s2 = size_menu.addAction("Muy grande (2×)")
        chosen = menu.exec(self._view.mapToGlobal(pos))
        if chosen is act_fav:
            for eid in ids:
                self._vault.set_favorite(eid, not self._vault.get(eid).favorite)
            self.favoritesChanged.emit()   # la ventana principal recarga todo
        elif chosen is act_rot:
            # SOLO gira la miniatura: la rotación del contenido en el visor
            # es un estado aparte y no se toca.
            self._vault.rotate_thumbs(ids)
            self.favoritesChanged.emit()
        elif chosen in (act_s1, act_s15, act_s2):
            scale = {act_s1: 1.0, act_s15: 1.5, act_s2: 2.0}[chosen]
            self._vault.set_thumb_scale(ids, scale)
            self.favoritesChanged.emit()

    def ordered_ids(self) -> list[str]:
        """Ids en el orden mostrado: es la lista de reproducción del visor."""
        return [self._model.item(r).data(Qt.ItemDataRole.UserRole)
                for r in range(self._model.rowCount())]

    def count(self) -> int:
        return self._model.rowCount()

    def clear_secure(self):
        """Orden importa: parar el hilo que usa las claves ANTES de que la
        bóveda las destruya, y soltar todos los pixmaps descifrados."""
        if self._loader is not None:
            self._loader.stop()
            self._loader.wait(3000)
            self._loader = None
        self._model.clear()
        self._masters.clear()   # soltar los pixmaps descifrados
        self._avail = {}
        self._vault = None
