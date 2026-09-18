"""Ventana principal: galería, importar/exportar/eliminar, zoom y bloqueo.

El bloqueo (manual o por inactividad) sigue un orden estricto:
  1. cerrar visores (sueltan QIODevice/buffers descifrados),
  2. parar el hilo de miniaturas y vaciar la galería (pixmaps fuera),
  3. Vault.lock() — zeroize de la MK y descarte de subclaves e índice.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QEvent, QObject, Qt, QThread, QTimer, Signal
from PySide6.QtWidgets import (
    QComboBox, QFileDialog, QInputDialog, QLabel, QListWidget,
    QListWidgetItem, QMainWindow, QMenu, QMessageBox, QProgressDialog,
    QSlider, QSplitter, QToolBar, QWidget,
)

from ..thumbs import PHOTO_EXTS, VIDEO_EXTS, classify, make_thumbnail
from ..vault import Vault
from ..winsec import set_capture_protection
from .gallery import GalleryWidget
from .viewer import open_viewer

AUTOLOCK_CHOICES = [("1 min", 60), ("5 min", 300), ("15 min", 900), ("30 min", 1800)]
FAV_KEY = "::favoritos::"   # centinela de la fila ⭐ en la barra lateral


class _ImportWorker(QThread):
    progress = Signal(int, int, str)     # hecho, total, nombre
    finished_ok = Signal(int, list)      # importados, errores [(nombre, motivo)]

    def __init__(self, vault: Vault, paths: list[str], folder: str = "", parent=None):
        super().__init__(parent)
        self._vault = vault
        self._paths = paths
        self._folder = folder      # importar directo a la carpeta activa
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self):
        ok, errors = 0, []
        total = len(self._paths)
        for i, p in enumerate(self._paths):
            if self._cancel or self._vault.is_locked:
                break
            path = Path(p)
            self.progress.emit(i, total, path.name)
            mime = classify(path)
            if mime is None:
                errors.append((path.name, "formato no soportado"))
                continue
            try:
                # La miniatura se genera desde el original (aún en claro por
                # ser el archivo del usuario) y solo existe en RAM hasta que
                # import_file la cifra.
                thumb = make_thumbnail(path, mime)
                self._vault.import_file(path, mime, thumb, folder=self._folder)
                ok += 1
            except Exception as e:  # noqa: BLE001
                errors.append((path.name, str(e)))
        self.finished_ok.emit(ok, errors)


class _InactivityFilter(QObject):
    """Cualquier actividad de teclado/ratón en la app rearma el temporizador
    de auto-bloqueo."""

    activity = Signal()
    _TYPES = {
        QEvent.Type.MouseMove, QEvent.Type.MouseButtonPress,
        QEvent.Type.KeyPress, QEvent.Type.Wheel, QEvent.Type.TouchBegin,
    }

    def eventFilter(self, obj, ev):
        if ev.type() in self._TYPES:
            self.activity.emit()
        return False


class MainWindow(QMainWindow):
    locked = Signal()          # volver a la pantalla de desbloqueo
    quitRequested = Signal()   # cerrar la app

    def __init__(self, vault: Vault, parent=None):
        super().__init__(parent)
        self._vault = vault
        self._viewers: list[QWidget] = []
        self._import_worker: _ImportWorker | None = None
        self._closing_to_lock = False

        self.setWindowTitle("VaultJam")
        self.resize(1100, 750)

        # Barra lateral de carpetas. Las carpetas son metadata del índice
        # cifrado: solo existen en RAM mientras la bóveda está abierta.
        self._sidebar = QListWidget()
        self._sidebar.setMinimumWidth(150)
        self._sidebar.setMaximumWidth(260)
        self._sidebar.currentItemChanged.connect(self._on_folder_selected)
        self._sidebar.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self._sidebar.customContextMenuRequested.connect(self._folder_menu)

        self._gallery = GalleryWidget()
        self._gallery.openRequested.connect(self._open_entry)
        self._gallery.favoritesChanged.connect(self._light_refresh)

        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(self._sidebar)
        split.addWidget(self._gallery)
        split.setStretchFactor(1, 1)
        split.setSizes([190, 900])
        self.setCentralWidget(split)

        tb = QToolBar("Principal")
        tb.setMovable(False)
        self.addToolBar(tb)
        tb.addAction("📥 Importar", self._import)
        self._act_export = tb.addAction("📤 Exportar", self._export)
        self._act_delete = tb.addAction("🗑 Eliminar", self._delete)
        tb.addSeparator()
        tb.addAction("📁 Nueva carpeta", self._new_folder)
        tb.addAction("📂 Mover a…", self._move_selected)
        tb.addSeparator()

        tb.addWidget(QLabel(" Zoom: "))
        self._zoom = QSlider(Qt.Orientation.Horizontal)
        self._zoom.setRange(64, 512)
        self._zoom.setValue(160)
        self._zoom.setFixedWidth(160)
        self._zoom.valueChanged.connect(self._gallery.set_zoom)
        tb.addWidget(self._zoom)
        tb.addSeparator()

        tb.addWidget(QLabel(" Auto-bloqueo: "))
        self._autolock_combo = QComboBox()
        for label, _secs in AUTOLOCK_CHOICES:
            self._autolock_combo.addItem(label)
        self._autolock_combo.setCurrentIndex(1)  # 5 min por defecto
        self._autolock_combo.currentIndexChanged.connect(self._reset_autolock)
        tb.addWidget(self._autolock_combo)
        tb.addSeparator()

        # Anti-captura (SetWindowDisplayAffinity): la galería y los visores
        # aparecen en negro en capturas, grabaciones, pantalla compartida y
        # Windows Recall. Activado por defecto; interruptor visible por si
        # necesitas compartir pantalla a propósito. No se persiste en disco
        # (la app no escribe preferencias fuera de la bóveda).
        self._act_protect = tb.addAction("🕶 Anti-captura")
        self._act_protect.setCheckable(True)
        self._act_protect.setChecked(True)
        self._act_protect.setToolTip(
            "Excluir la galería y los visores de capturas de pantalla, "
            "grabación y Recall (Windows 10 2004+)."
        )
        self._act_protect.toggled.connect(self._apply_capture_protection)
        tb.addSeparator()
        tb.addAction("🔒 Bloquear ahora", self.lock_now)
        set_capture_protection(self, True)

        # Temporizador de inactividad sobre TODA la aplicación.
        self._autolock = QTimer(self)
        self._autolock.setSingleShot(True)
        self._autolock.timeout.connect(self.lock_now)
        self._filter = _InactivityFilter(self)
        self._filter.activity.connect(self._reset_autolock)
        from PySide6.QtWidgets import QApplication
        QApplication.instance().installEventFilter(self._filter)
        self._reset_autolock()

        self._reload_sidebar(select=None)
        self._update_status()

    # ---------------- carpetas ----------------

    def _current_folder(self) -> str | None:
        """None = 'Todo'; "" = sin carpeta; otro valor = nombre de carpeta."""
        item = self._sidebar.currentItem()
        return item.data(Qt.ItemDataRole.UserRole) if item else None

    def _reload_sidebar(self, select: str | None | object = "KEEP",
                        reload_gallery: bool = True):
        current = self._current_folder() if select == "KEEP" else select
        self._sidebar.blockSignals(True)
        self._sidebar.clear()
        total = len(self._vault.entries())
        root = len(self._vault.entries(""))
        favs = len(self._vault.entries(favorites=True))
        rows: list[tuple[str, str | None]] = [
            (f"🗂 Todo ({total})", None),
            (f"⭐ Favoritos ({favs})", FAV_KEY),
            (f"📄 Sin carpeta ({root})", ""),
        ]
        for f in self._vault.folders():
            rows.append((f"📁 {f} ({len(self._vault.entries(f))})", f))
        target_row = 0
        for i, (label, data) in enumerate(rows):
            item = QListWidgetItem(label)
            item.setData(Qt.ItemDataRole.UserRole, data)
            self._sidebar.addItem(item)
            if data == current:
                target_row = i
        self._sidebar.setCurrentRow(target_row)
        self._sidebar.blockSignals(False)
        if reload_gallery:
            self._load_gallery_view()
        self._update_status()

    def _light_refresh(self):
        """Sincronización ligera tras cerrar un visor o tocar metadata:
        contadores y textos al día SIN recargar la galería (las miniaturas
        ya descifradas se reutilizan; nada se vuelve a leer del disco)."""
        if self._vault.is_locked:
            return
        if self._current_folder() == FAV_KEY:
            # La pertenencia a ⭐ pudo cambiar: aquí sí hay que recargar.
            self._reload_sidebar()
            return
        self._gallery.refresh_meta(self._vault)
        self._reload_sidebar(reload_gallery=False)

    def _load_gallery_view(self):
        cur = self._current_folder()
        if cur == FAV_KEY:
            self._gallery.load(self._vault, favorites=True)
        else:
            self._gallery.load(self._vault, cur)

    def _on_folder_selected(self, *_):
        self._load_gallery_view()
        self._update_status()

    def _new_folder(self):
        name, ok = QInputDialog.getText(self, "Nueva carpeta", "Nombre:")
        if not ok or not name.strip():
            return
        try:
            self._vault.create_folder(name)
        except Exception as e:  # noqa: BLE001
            QMessageBox.warning(self, "Carpetas", str(e))
            return
        self._reload_sidebar(select=name.strip())

    def _move_selected(self):
        ids = self._gallery.selected_ids()
        if not ids:
            QMessageBox.information(self, "Mover", "Selecciona uno o más elementos.")
            return
        options = ["(Sin carpeta)"] + self._vault.folders()
        choice, ok = QInputDialog.getItem(
            self, "Mover a carpeta", f"Mover {len(ids)} elemento(s) a:",
            options, 0, False,
        )
        if not ok:
            return
        self._vault.move_files(ids, "" if choice == "(Sin carpeta)" else choice)
        self._reload_sidebar()

    def _folder_menu(self, pos):
        item = self._sidebar.itemAt(pos)
        folder = item.data(Qt.ItemDataRole.UserRole) if item else None
        if not folder or folder == FAV_KEY:  # Todo/Sin carpeta/⭐ no se eliminan
            return
        menu = QMenu(self)
        act = menu.addAction(f"Eliminar carpeta «{folder}»")
        if menu.exec(self._sidebar.mapToGlobal(pos)) is act:
            n = len(self._vault.entries(folder))
            msg = (f"La carpeta «{folder}» se eliminará y sus {n} elemento(s) "
                   "pasarán a «Sin carpeta». No se borra ningún archivo. ¿Continuar?")
            if QMessageBox.question(self, "Eliminar carpeta", msg) == QMessageBox.StandardButton.Yes:
                self._vault.delete_folder(folder)
                self._reload_sidebar(select=None)

    # ------------------------------------------------------------------

    def _reset_autolock(self):
        secs = AUTOLOCK_CHOICES[self._autolock_combo.currentIndex()][1]
        self._autolock.start(secs * 1000)

    def _update_status(self):
        self.statusBar().showMessage(f"{self._gallery.count()} elementos cifrados en la bóveda")

    def _apply_capture_protection(self, on: bool):
        set_capture_protection(self, on)
        for v in self._viewers:
            set_capture_protection(v, on)

    def _open_entry(self, entry_id: str):
        # La lista de reproducción es lo que se ve en la galería (respeta la
        # carpeta activa y su orden), mezclando fotos y videos.
        dlg = open_viewer(self._vault, entry_id, self,
                          protect=self._act_protect.isChecked(),
                          playlist=self._gallery.ordered_ids())
        self._viewers.append(dlg)
        dlg.destroyed.connect(lambda *_, d=dlg: self._on_viewer_closed(d))

    def _on_viewer_closed(self, dlg):
        if dlg in self._viewers:
            self._viewers.remove(dlg)
        # El visor solo puede cambiar ⭐ (y metadata que no afecta a las
        # miniaturas), así que basta el refresco ligero: nada se re-descifra
        # y las miniaturas no parpadean.
        self._light_refresh()

    # ------------------------------------------------------------------

    def _import(self):
        exts = " ".join(f"*{e}" for e in sorted(PHOTO_EXTS | VIDEO_EXTS))
        paths, _ = QFileDialog.getOpenFileNames(
            self, "Importar fotos y videos", "", f"Fotos y videos ({exts})"
        )
        if not paths:
            return
        prog = QProgressDialog("Cifrando…", "Cancelar", 0, len(paths), self)
        prog.setWindowModality(Qt.WindowModality.WindowModal)
        prog.setMinimumDuration(300)

        # Importar a la carpeta activa (⭐ y Todo importan a «Sin carpeta»).
        cur = self._current_folder()
        folder = cur if cur and cur != FAV_KEY else ""
        self._import_worker = w = _ImportWorker(self._vault, paths, folder, self)
        w.progress.connect(lambda i, n, name: (prog.setValue(i), prog.setLabelText(f"Cifrando {name}…")))
        prog.canceled.connect(w.cancel)

        def done(ok: int, errors: list):
            prog.setValue(prog.maximum())
            self._reload_sidebar()   # recarga contadores, galería y miniaturas
            if errors:
                detail = "\n".join(f"• {n}: {m}" for n, m in errors[:10])
                QMessageBox.warning(
                    self, "Importación",
                    f"Importados {ok} archivos. {len(errors)} fallaron:\n{detail}",
                )
            self._import_worker = None

        w.finished_ok.connect(done)
        w.start()

    def _export(self):
        ids = self._gallery.selected_ids()
        if not ids:
            QMessageBox.information(self, "Exportar", "Selecciona uno o más elementos.")
            return
        if QMessageBox.warning(
            self, "Exportar",
            f"Se escribirán {len(ids)} archivo(s) DESCIFRADOS en la carpeta "
            "que elijas. Quedarán en claro fuera de la bóveda. ¿Continuar?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        dst = QFileDialog.getExistingDirectory(self, "Carpeta de destino")
        if not dst:
            return
        errors = []
        for eid in ids:
            try:
                self._vault.export_file(eid, Path(dst))
            except Exception as e:  # noqa: BLE001
                errors.append(str(e))
        if errors:
            QMessageBox.warning(self, "Exportar", "Algunos archivos fallaron:\n" + "\n".join(errors[:10]))
        else:
            QMessageBox.information(self, "Exportar", "Exportación completada.")

    def _delete(self):
        ids = self._gallery.selected_ids()
        if not ids:
            return
        if QMessageBox.warning(
            self, "Eliminar",
            f"¿Eliminar {len(ids)} elemento(s) de la bóveda? Esta acción no se puede deshacer.",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return
        for eid in ids:
            self._vault.delete_file(eid)
        self._reload_sidebar()

    # ------------------------------------------------------------------

    def lock_now(self):
        """Bloqueo manual o por inactividad. Orden: visores -> galería -> claves."""
        if self._vault.is_locked:
            return
        self._autolock.stop()
        if self._import_worker is not None:
            self._import_worker.cancel()
            self._import_worker.wait(10000)
        for v in list(self._viewers):
            v.close()
        self._viewers.clear()
        self._gallery.clear_secure()
        self._sidebar.clear()   # los nombres de carpeta también son metadata
        self._vault.lock()
        self._closing_to_lock = True
        self.close()
        self.locked.emit()

    def closeEvent(self, ev):
        from PySide6.QtWidgets import QApplication
        QApplication.instance().removeEventFilter(self._filter)
        if not self._closing_to_lock:
            # Cerrar la ventana = salir de la app: nunca dejamos la bóveda
            # abierta sin UI. Mismo orden de limpieza que el bloqueo.
            self._autolock.stop()
            if self._import_worker is not None:
                self._import_worker.cancel()
                self._import_worker.wait(10000)
            for v in list(self._viewers):
                v.close()
            self._gallery.clear_secure()
            self._sidebar.clear()
            self._vault.lock()
            self.quitRequested.emit()
        super().closeEvent(ev)
