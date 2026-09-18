"""Ventana principal: galería, importar/exportar/eliminar, zoom y bloqueo.

El bloqueo (manual o por inactividad) sigue un orden estricto:
  1. cerrar visores (sueltan QIODevice/buffers descifrados),
  2. parar el hilo de miniaturas y vaciar la galería (pixmaps fuera),
  3. Vault.lock() — zeroize de la MK y descarte de subclaves e índice.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QEvent, QObject, QSettings, Qt, QThread, QTimer, Signal
from PySide6.QtWidgets import (
    QComboBox, QFileDialog, QFrame, QInputDialog, QLabel, QLineEdit,
    QListWidget, QListWidgetItem, QMainWindow, QMenu, QMessageBox,
    QProgressBar, QProgressDialog, QPushButton, QSlider, QSplitter,
    QToolBar, QVBoxLayout, QWidget,
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


class _SyncWorker(QThread):
    """Espejo local → Drive en segundo plano. Solo mueve ciphertext: toma
    la lista de blobs y las rutas ANTES de arrancar, así ni siquiera
    necesita la bóveda desbloqueada mientras sube."""

    progress = Signal(int, int)
    status = Signal(str)
    finished_ok = Signal(object)   # dict resumen | Exception

    def __init__(self, secret: str, root, blob_ids: list[str],
                 folder_name: str, folder_hint: str | None, parent=None):
        super().__init__(parent)
        self._secret = secret
        self._root = root
        self._blob_ids = blob_ids
        self._folder_name = folder_name
        self._hint = folder_hint
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self):
        try:
            from ..gdrive import get_service
            from ..gsync import DriveOps, DriveSyncer
            self.status.emit("Autorizando con Google (permiso de escritura)…")
            svc = get_service(self._secret, readonly=False)
            syncer = DriveSyncer(DriveOps(svc), self._root, self._blob_ids,
                                 folder_name=self._folder_name,
                                 folder_hint=self._hint)
            self.finished_ok.emit(syncer.sync(
                progress=lambda d, t: self.progress.emit(d, t),
                status=lambda m: self.status.emit(m),
                cancelled=lambda: self._cancel))
        except Exception as e:  # noqa: BLE001
            self.finished_ok.emit(e)


class _MirrorCheckWorker(QThread):
    """Solo verifica el espejo de Drive de una bóveda LOCAL (listados, sin
    subir ni crear nada) para pintar los marcos verde/rojo."""

    done = Signal(object)   # (folder_id, set[str]) | Exception

    def __init__(self, secret: str, folder_name: str, hint: str | None,
                 parent=None):
        super().__init__(parent)
        self._secret = secret
        self._folder_name = folder_name
        self._hint = hint

    def run(self):
        try:
            from pathlib import Path as _P

            from ..gdrive import get_service
            from ..gsync import DriveOps, DriveSyncer
            svc = get_service(self._secret, readonly=True)
            syncer = DriveSyncer(DriveOps(svc), _P("."), [],
                                 folder_name=self._folder_name,
                                 folder_hint=self._hint)
            self.done.emit(syncer.mirrored_blobs())
        except Exception as e:  # noqa: BLE001
            self.done.emit(e)


class _AvailWorker(QThread):
    """Consulta en segundo plano qué elementos están completos en Drive
    (solo listados de carpetas, sin descargar contenido)."""

    done = Signal(object)   # dict[id, bool] | Exception

    def __init__(self, vault: Vault, refresh: bool, parent=None):
        super().__init__(parent)
        self._vault = vault
        self._refresh = refresh

    def run(self):
        try:
            self.done.emit(self._vault.availability(refresh=self._refresh))
        except Exception as e:  # noqa: BLE001
            self.done.emit(e)


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

        # Panel de sincronización: vive ENCIMA de las carpetas, en la
        # columna lateral. Nada de diálogos modales: la bóveda sigue
        # plenamente usable (navegar, ver, cortina 🙈) durante horas de
        # subida; solo Importar/Eliminar se pausan mientras tanto.
        self._sync_panel = QFrame()
        self._sync_panel.setFrameShape(QFrame.Shape.StyledPanel)
        sp = QVBoxLayout(self._sync_panel)
        sp.setContentsMargins(8, 6, 8, 6)
        sp.setSpacing(4)
        sync_title = QLabel("☁ Sincronizando a Drive")
        sync_title.setStyleSheet("font-weight: bold;")
        self._sync_label = QLabel("Preparando…")
        self._sync_label.setWordWrap(True)
        self._sync_bar = QProgressBar()
        self._sync_bar.setRange(0, 0)
        self._sync_cancel_btn = QPushButton("Cancelar subida")
        self._sync_cancel_btn.clicked.connect(self._cancel_sync)
        for wdg in (sync_title, self._sync_label, self._sync_bar,
                    self._sync_cancel_btn):
            sp.addWidget(wdg)
        self._sync_panel.hide()

        side = QWidget()
        sv = QVBoxLayout(side)
        sv.setContentsMargins(0, 0, 0, 0)
        sv.setSpacing(4)
        sv.addWidget(self._sync_panel)
        sv.addWidget(self._sidebar, 1)

        split = QSplitter(Qt.Orientation.Horizontal)
        split.addWidget(side)
        split.addWidget(self._gallery)
        split.setStretchFactor(1, 1)
        split.setSizes([190, 900])
        self.setCentralWidget(split)

        tb = QToolBar("Principal")
        tb.setMovable(False)
        self.addToolBar(tb)
        self._act_import = tb.addAction("📥 Importar", self._import)
        self._act_export = tb.addAction("📤 Exportar", self._export)
        self._act_delete = tb.addAction("🗑 Eliminar", self._delete)
        tb.addSeparator()
        self._act_newfolder = tb.addAction("📁 Nueva carpeta", self._new_folder)
        self._act_move = tb.addAction("📂 Mover a…", self._move_selected)
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
        # Cortina 🙈 con PIN: oculta miniaturas y nombres e impide abrir,
        # sin bloquear la bóveda (una sincronización sigue corriendo).
        self._privacy = False
        self._act_privacy = tb.addAction("🙈 Ocultar", self._toggle_privacy)
        self._act_privacy.setToolTip(
            "Ocultar el contenido en pantalla (miniaturas, nombres y visor) "
            "sin bloquear la bóveda. Para mostrar de nuevo pide el PIN.")
        self._act_pin = tb.addAction("PIN…", self._change_pin)
        self._act_pin.setToolTip("Crear o cambiar el PIN de la cortina "
                                 "(cambiarlo pide el PIN actual)")
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

        self._avail_worker: _AvailWorker | None = None
        if vault.read_only:
            # Bóveda remota (Google Drive): ver, reproducir por streaming y
            # exportar. Todo lo que escribe queda deshabilitado.
            for a in (self._act_import, self._act_delete,
                      self._act_newfolder, self._act_move):
                a.setEnabled(False)
            self.setWindowTitle("VaultJam — remota (solo lectura)")
            self._act_check = tb.addAction("🔄 Verificar Drive",
                                           lambda: self._check_availability(refresh=True))
            self._act_check.setToolTip(
                "Comprobar qué elementos ya tienen todos sus chunks en Drive "
                "(marco verde = completo, rojo = subida incompleta)")
        else:
            self._act_sync = tb.addAction("☁ Sincronizar a Drive", self._sync_drive)
            self._act_sync.setToolTip(
                "Sube a tu Google Drive los blobs cifrados que falten y "
                "actualiza el índice (espejo de respaldo/visualización). "
                "Reanudable y verificado; requiere autorizar escritura.")
            self._act_mirror = tb.addAction("🔄 Verificar espejo",
                                            self._check_mirror)
            self._act_mirror.setToolTip(
                "Comprobar qué elementos están ya completos en el espejo de "
                "Drive: marco verde = subido entero, rojo = aún incompleto. "
                "Solo lee listados; no sube nada.")
        self._sync_worker: _SyncWorker | None = None
        self._mirror_worker: _MirrorCheckWorker | None = None

        self._update_action_states()
        self._reload_sidebar(select=None)
        self._update_status()
        if vault.read_only:
            self._check_availability(refresh=False)   # chequeo inicial

    # ---------------- sincronizar a Drive (bóveda local) ----------------

    def _update_action_states(self):
        """Único punto que decide qué acciones están activas, combinando
        los tres estados: bóveda remota, cortina 🙈 y sincronización."""
        ro = self._vault.read_only
        syncing = getattr(self, "_sync_worker", None) is not None
        priv = getattr(self, "_privacy", False)
        self._act_import.setEnabled(not ro and not syncing)
        self._act_delete.setEnabled(not ro and not syncing and not priv)
        self._act_export.setEnabled(not priv)
        self._act_newfolder.setEnabled(not ro)
        self._act_move.setEnabled(not ro and not priv)
        if hasattr(self, "_act_sync"):
            self._act_sync.setEnabled(not syncing)

    def _cancel_sync(self):
        if self._sync_worker is not None:
            self._sync_worker.cancel()
            self._sync_cancel_btn.setEnabled(False)
            self._sync_label.setText("Cancelando… (termina el blob en curso)")

    def _apply_mirror_availability(self, ok_blobs: set):
        """Pinta los marcos verde/rojo de la bóveda LOCAL según qué blobs
        están ya completos en el espejo de Drive."""
        status = {e.id: all(c in ok_blobs for c in e.chunks)
                  for e in self._vault.entries()}
        self._gallery.set_availability(status)
        done = sum(1 for v in status.values() if v)
        self.statusBar().showMessage(
            f"Espejo Drive: {done} de {len(status)} elementos completos "
            "(marco verde = subido, rojo = pendiente)")

    def _check_mirror(self):
        if self._mirror_worker is not None or self._vault.read_only:
            return
        settings = QSettings("VaultJam", "VaultJam")
        secret = str(settings.value("gdrive_secret", ""))
        if not secret or not Path(secret).exists():
            QMessageBox.information(
                self, "Verificar espejo",
                "Primero configura tu client_secret.json en la pestaña "
                "«Google Drive» de la pantalla de desbloqueo (ver README).")
            return
        key = f"syncfolder/{self._vault.root}"
        hint = str(settings.value(key, "")) or None
        self.statusBar().showMessage("Comprobando el espejo en Drive…")
        self._act_mirror.setEnabled(False)
        self._mirror_worker = w = _MirrorCheckWorker(
            secret, self._vault.root.name, hint, self)

        def done(result):
            self._mirror_worker = None
            self._act_mirror.setEnabled(True)
            if self._vault.is_locked:
                return
            if isinstance(result, tuple):
                fid, ok = result
                settings.setValue(key, fid)
                self._apply_mirror_availability(ok)
            else:
                self.statusBar().showMessage(
                    f"No se pudo verificar el espejo: {result}")

        w.done.connect(done)
        w.start()

    def _sync_drive(self):
        if self._sync_worker is not None:
            return
        settings = QSettings("VaultJam", "VaultJam")
        secret = str(settings.value("gdrive_secret", ""))
        if not secret or not Path(secret).exists():
            QMessageBox.information(
                self, "Sincronizar a Drive",
                "Primero configura tu client_secret.json en la pestaña "
                "«Google Drive» de la pantalla de desbloqueo (ver README).")
            return
        if QMessageBox.question(
            self, "Sincronizar a Drive",
            "Se subirán a tu Google Drive los blobs cifrados que falten y se "
            "actualizará el índice del espejo.\n\n"
            "• Google solo recibe ciphertext, como siempre.\n"
            "• Requiere autorizar permiso de ESCRITURA en Drive (token "
            "aparte del de solo lectura; la primera vez se abre el navegador).\n"
            "• Si tienes una subida por la web en curso sobre esa carpeta, "
            "cancélala para evitar duplicados.\n"
            "• Es reanudable: puedes cancelar y continuar más tarde.\n\n"
            "¿Continuar?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
        ) != QMessageBox.StandardButton.Yes:
            return

        key = f"syncfolder/{self._vault.root}"
        hint = str(settings.value(key, "")) or None

        self._sync_worker = w = _SyncWorker(
            secret, self._vault.root, self._vault.all_blob_ids(),
            self._vault.root.name, hint, self)
        self._autolock.stop()   # sin auto-bloqueo mientras se sincroniza
        self._update_action_states()
        # Panel lateral en marcha (no modal: la bóveda sigue usable)
        self._sync_bar.setRange(0, 0)
        self._sync_label.setText("Autorizando con Google…")
        self._sync_cancel_btn.setEnabled(True)
        self._sync_panel.show()
        w.status.connect(self._sync_label.setText)

        def on_progress(done: int, total: int):
            self._sync_bar.setRange(0, max(total, 1))
            self._sync_bar.setValue(done)

        w.progress.connect(on_progress)

        def done(result):
            self._sync_worker = None
            self._sync_panel.hide()
            self._reset_autolock()   # rearmar la cuenta atrás al terminar
            self._update_action_states()
            if isinstance(result, dict):
                settings.setValue(key, result["folder_id"])
                if "ok_blobs" in result:
                    # Marcos verde/rojo al día con lo recién verificado.
                    self._apply_mirror_availability(result["ok_blobs"])
                if result.get("cancelado"):
                    self.statusBar().showMessage(
                        f"Sincronización cancelada sin peligro: {result['subidos']} "
                        f"blobs subidos quedan aprovechados; faltan "
                        f"{result['pendientes']}. Pulsa ☁ para continuar.")
                else:
                    extra = (f"\nBlobs huérfanos en el espejo: {result['huerfanos']} "
                             "(de elementos borrados localmente; son ciphertext "
                             "inofensivo)") if result.get("huerfanos") else ""
                    QMessageBox.information(
                        self, "Sincronizar a Drive",
                        "Espejo completo y verificado ✔\n\n"
                        f"Subidos ahora: {result['subidos']} "
                        f"(corregidos: {result['corregidos']})\n"
                        f"Ya estaban: {result['ya_presentes']}\n"
                        f"Total en el espejo: {result['total']} blobs{extra}")
            else:
                QMessageBox.critical(self, "Sincronizar a Drive",
                                     f"La sincronización falló:\n{result}\n\n"
                                     "Reintenta: continuará donde quedó.")

        w.finished_ok.connect(done)
        w.start()

    # ---------------- disponibilidad remota ----------------

    def _check_availability(self, refresh: bool = False):
        if not self._vault.read_only or self._avail_worker is not None:
            return
        self.statusBar().showMessage("Comprobando disponibilidad en Drive…")
        if hasattr(self, "_act_check"):
            self._act_check.setEnabled(False)
        self._avail_worker = w = _AvailWorker(self._vault, refresh, self)
        w.done.connect(self._on_availability)
        w.start()

    def _on_availability(self, result):
        self._avail_worker = None
        if hasattr(self, "_act_check"):
            self._act_check.setEnabled(True)
        if self._vault.is_locked:
            return
        if isinstance(result, dict):
            self._gallery.set_availability(result)
            ok = sum(1 for v in result.values() if v)
            self.statusBar().showMessage(
                f"Drive: {ok} de {len(result)} elementos completos "
                "(verde = listo, rojo = aún subiéndose) · 🔄 para re-comprobar")
        elif result is not None:
            self.statusBar().showMessage(f"No se pudo comprobar Drive: {result}")

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
        if not folder or folder == FAV_KEY or self._vault.read_only:
            return   # Todo/Sin carpeta/⭐ no se eliminan; remota es solo lectura
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
        # Con una sincronización a Drive o una importación en curso, la
        # cuenta atrás de auto-bloqueo se SUSPENDE: bloquear a mitad
        # cancelaría horas de subida. Se rearma sola al terminar el trabajo;
        # el botón de bloqueo manual sigue disponible en todo momento.
        if (getattr(self, "_sync_worker", None) is not None
                or self._import_worker is not None):
            self._autolock.stop()
            return
        secs = AUTOLOCK_CHOICES[self._autolock_combo.currentIndex()][1]
        self._autolock.start(secs * 1000)

    def _update_status(self):
        suffix = "  ·  remota Google Drive (solo lectura)" if self._vault.read_only else ""
        self.statusBar().showMessage(
            f"{self._gallery.count()} elementos cifrados en la bóveda{suffix}")

    def _apply_capture_protection(self, on: bool):
        set_capture_protection(self, on)
        for v in self._viewers:
            set_capture_protection(v, on)

    # ---------------- cortina con PIN ----------------

    def _ask_pin(self, title: str, label: str) -> str | None:
        while True:
            txt, ok = QInputDialog.getText(
                self, title, label, QLineEdit.EchoMode.Password)
            if not ok:
                return None
            if txt.isdigit() and len(txt) == 4:
                return txt
            QMessageBox.warning(self, title, "El PIN debe ser de 4 dígitos.")

    def _toggle_privacy(self):
        if not self._privacy:
            if not self._vault.has_pin:
                p1 = self._ask_pin("Crear PIN", "Nuevo PIN (4 dígitos):")
                if p1 is None:
                    return
                p2 = self._ask_pin("Crear PIN", "Repite el PIN:")
                if p2 != p1:
                    QMessageBox.warning(self, "Crear PIN", "Los PIN no coinciden.")
                    return
                self._vault.set_pin(None, p1)
                if self._vault.read_only:
                    QMessageBox.information(
                        self, "PIN", "Bóveda remota: el PIN vale solo para "
                        "esta sesión (no se escribe nada en Drive).")
            # activar la cortina: cerrar visores y ocultar todo
            self._privacy = True
            for v in list(self._viewers):
                v.close()
            self._viewers.clear()
            self._gallery.set_privacy(True)
            self._update_action_states()
            self._act_privacy.setText("👁 Mostrar")
            self.statusBar().showMessage("Contenido oculto 🙈 — 👁 Mostrar pide el PIN")
        else:
            pin = self._ask_pin("Mostrar contenido", "PIN:")
            if pin is None:
                return
            if not self._vault.check_pin(pin):
                # Llave de escape: la contraseña maestra también muestra.
                if QMessageBox.question(
                    self, "Mostrar contenido",
                    "PIN incorrecto. ¿Mostrar usando la contraseña de la bóveda?",
                    QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                ) != QMessageBox.StandardButton.Yes:
                    return
                if self._ask_vault_password() is None:
                    return
            self._privacy = False
            self._gallery.set_privacy(False)
            self._gallery.refresh_meta(self._vault)   # restaura nombres/estrellas
            self._update_action_states()
            self._act_privacy.setText("🙈 Ocultar")
            self._update_status()

    def _ask_vault_password(self) -> str | None:
        """Pide y verifica la contraseña maestra (llave de escape del PIN).
        La verificación tarda ~1 s (Argon2id) con cursor de espera."""
        from PySide6.QtWidgets import QApplication
        txt, ok = QInputDialog.getText(
            self, "Contraseña de la bóveda",
            "Contraseña maestra (para restablecer el PIN):",
            QLineEdit.EchoMode.Password)
        if not ok or not txt:
            return None
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            valid = self._vault.verify_password(txt)
        finally:
            QApplication.restoreOverrideCursor()
        if not valid:
            QMessageBox.warning(self, "Contraseña", "Contraseña incorrecta.")
            return None
        return txt

    def _ask_new_pin(self, title: str) -> str | None:
        p1 = self._ask_pin(title, "Nuevo PIN (4 dígitos):")
        if p1 is None:
            return None
        p2 = self._ask_pin(title, "Repite el nuevo PIN:")
        if p2 != p1:
            QMessageBox.warning(self, title, "Los PIN no coinciden.")
            return None
        return p1

    def _pin_note(self) -> str:
        return " (solo esta sesión: bóveda remota)" if self._vault.read_only else ""

    def _change_pin(self):
        if not self._vault.has_pin:
            p = self._ask_new_pin("Crear PIN")
            if p is not None:
                self._vault.set_pin(None, p)
                QMessageBox.information(self, "PIN", f"PIN creado{self._pin_note()}.")
            return

        box = QMessageBox(self)
        box.setWindowTitle("PIN")
        box.setText("¿Qué quieres hacer con el PIN de la cortina?")
        b_change = box.addButton("Cambiar PIN", QMessageBox.ButtonRole.AcceptRole)
        b_remove = box.addButton("Quitar PIN", QMessageBox.ButtonRole.DestructiveRole)
        b_forgot = box.addButton("Olvidé el PIN…", QMessageBox.ButtonRole.HelpRole)
        box.addButton(QMessageBox.StandardButton.Cancel)
        box.exec()
        clicked = box.clickedButton()

        if clicked is b_change:
            old = self._ask_pin("Cambiar PIN", "PIN actual:")
            if old is None:
                return
            if not self._vault.check_pin(old):
                QMessageBox.warning(self, "Cambiar PIN", "El PIN actual no es correcto.")
                return
            p = self._ask_new_pin("Cambiar PIN")
            if p is not None:
                self._vault.set_pin(old, p)
                QMessageBox.information(self, "PIN", f"PIN actualizado{self._pin_note()}.")
        elif clicked is b_remove:
            old = self._ask_pin("Quitar PIN", "PIN actual:")
            if old is None:
                return
            if not self._vault.check_pin(old):
                QMessageBox.warning(self, "Quitar PIN", "El PIN actual no es correcto.")
                return
            self._vault.remove_pin(old=old)
            QMessageBox.information(self, "PIN", f"PIN eliminado{self._pin_note()}.")
        elif clicked is b_forgot:
            # La contraseña maestra autoriza: quien la tiene ya es el dueño.
            pw = self._ask_vault_password()
            if pw is None:
                return
            ret = QMessageBox.question(
                self, "Restablecer PIN",
                "Contraseña correcta. ¿Definir un PIN nuevo?\n"
                "(«No» elimina el PIN.)",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                | QMessageBox.StandardButton.Cancel)
            if ret == QMessageBox.StandardButton.Yes:
                p = self._ask_new_pin("Restablecer PIN")
                if p is not None:
                    self._vault.set_pin(None, p, password=pw)
                    QMessageBox.information(self, "PIN", f"PIN restablecido{self._pin_note()}.")
            elif ret == QMessageBox.StandardButton.No:
                self._vault.remove_pin(password=pw)
                QMessageBox.information(self, "PIN", f"PIN eliminado{self._pin_note()}.")

    def _open_entry(self, entry_id: str):
        if self._privacy:
            return   # con la cortina activa no se abre nada
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
        if self._vault.is_locked:
            return
        if getattr(dlg, "content_added", False):
            # El visor añadió contenido (📸 fotograma) o cambió una
            # miniatura (🖼): recarga completa para verlo.
            self._reload_sidebar()
        else:
            # Solo metadata (⭐, ajustes…): refresco ligero sin re-descifrar.
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
            self._import_worker = None
            self._reset_autolock()   # rearmar tras la importación
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
        if self._sync_worker is not None:
            self._sync_worker.cancel()      # corta en el próximo blob; seguro
            self._sync_worker.wait(30000)
            self._sync_worker = None
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
            if self._sync_worker is not None:
                self._sync_worker.cancel()
                self._sync_worker.wait(30000)
                self._sync_worker = None
            for v in list(self._viewers):
                v.close()
            self._gallery.clear_secure()
            self._sidebar.clear()
            self._vault.lock()
            self.quitRequested.emit()
        super().closeEvent(ev)
