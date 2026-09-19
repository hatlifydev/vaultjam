"""Diálogo «⬇️ Traer desde la nube».

Conecta a Google Drive (SOLO LECTURA), deja elegir una bóveda de origen y su
contraseña, autodetecta el modo (espejo si comparte clave maestra, importar
si es otra bóveda), muestra su contenido para seleccionar y trae lo elegido a
la bóveda LOCAL abierta. Toda la lógica de traída vive en gpull.CloudImport;
aquí solo va la UI y los hilos que no deben congelar la ventana.

Nota de seguridad: en modo importar, el contenido de la bóveda de origen se
descifra en RAM y se re-cifra bajo la clave local; nunca hay texto plano en
disco. Drive se abre en solo lectura: traer jamás escribe en la nube.
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt, QThread, Signal
from PySide6.QtWidgets import (
    QComboBox, QDialog, QFileDialog, QHBoxLayout, QLabel, QLineEdit,
    QMessageBox, QProgressBar, QPushButton, QTreeWidget, QTreeWidgetItem,
    QVBoxLayout, QWidget,
)
from PySide6.QtCore import QSettings

from ..gpull import CloudImport
from ..vault import Vault

NO_FOLDER = "(sin carpeta)"
KEEP_FOLDERS = "(conservar carpetas de origen)"


def _human_size(n: int) -> str:
    f = float(n)
    for unit in ("B", "KB", "MB", "GB"):
        if f < 1024 or unit == "GB":
            return f"{f:.0f} {unit}" if unit == "B" else f"{f:.1f} {unit}"
        f /= 1024
    return f"{f:.1f} GB"


class _ConnectWorker(QThread):
    done = Signal(object)   # (creds, svc, [(name, fid)]) | Exception

    def __init__(self, secret: str, parent=None):
        super().__init__(parent)
        self._secret = secret

    def run(self):
        try:
            from ..gdrive import build_service, find_vaults, get_credentials
            creds = get_credentials(self._secret, readonly=True)
            svc = build_service(creds)
            self.done.emit((creds, svc, find_vaults(svc)))
        except Exception as e:  # noqa: BLE001
            self.done.emit(e)


class _OpenWorker(QThread):
    done = Signal(object)   # Vault (remota) | Exception

    def __init__(self, svc, creds, fid: str, name: str, pw: str, parent=None):
        super().__init__(parent)
        self._svc, self._creds = svc, creds
        self._fid, self._name, self._pw = fid, name, pw

    def run(self):
        try:
            from ..gdrive import DriveStore, build_service
            creds = self._creds
            store = DriveStore(self._svc, self._fid, self._name,
                               service_factory=lambda: build_service(creds))
            self.done.emit(Vault.open_remote(store, self._pw))
        except Exception as e:  # noqa: BLE001
            self.done.emit(e)


class _PullWorker(QThread):
    progress = Signal(int, int)
    status = Signal(str)
    done = Signal(object)   # dict resumen | Exception

    def __init__(self, imp: CloudImport, ids: list[str],
                 folder_override, parent=None):
        super().__init__(parent)
        self._imp = imp
        self._ids = ids
        self._folder = folder_override
        self._cancel = False

    def cancel(self):
        self._cancel = True

    def run(self):
        try:
            self.done.emit(self._imp.run(
                self._ids, folder_override=self._folder,
                progress=lambda d, t: self.progress.emit(d, t),
                status=lambda m: self.status.emit(m),
                cancelled=lambda: self._cancel))
        except Exception as e:  # noqa: BLE001
            self.done.emit(e)


class PullFromCloudDialog(QDialog):
    """Devuelve True (accepted) si trajo algo, para que la ventana recargue."""

    def __init__(self, dst_vault: Vault, parent=None):
        super().__init__(parent)
        self._dst = dst_vault
        self._creds = self._svc = None
        self._src: Vault | None = None
        self._imp: CloudImport | None = None
        self._worker: QThread | None = None
        self.changed = False        # ¿se trajo algo? (para recargar galería)

        self.setWindowTitle("⬇️ Traer desde la nube")
        self.setMinimumSize(560, 560)
        root = QVBoxLayout(self)

        # --- Paso 1: conexión a Drive ---
        self._secret = str(QSettings("VaultJam", "VaultJam").value("gdrive_secret", ""))
        row1 = QHBoxLayout()
        self._btn_connect = QPushButton("Conectar a Google Drive")
        self._btn_connect.clicked.connect(self._connect)
        self._btn_secret = QPushButton("client_secret.json…")
        self._btn_secret.setToolTip("Elegir/actualizar tu archivo de credenciales OAuth")
        self._btn_secret.clicked.connect(self._pick_secret)
        row1.addWidget(self._btn_connect, 1)
        row1.addWidget(self._btn_secret)
        root.addLayout(row1)

        # --- Paso 2: elegir bóveda de origen y contraseña ---
        self._combo = QComboBox()
        self._combo.setEnabled(False)
        self._pw = QLineEdit()
        self._pw.setEchoMode(QLineEdit.EchoMode.Password)
        self._pw.setPlaceholderText("Contraseña de la bóveda de origen")
        self._pw.setEnabled(False)
        self._pw.returnPressed.connect(self._open_source)
        self._btn_open = QPushButton("Abrir bóveda de origen")
        self._btn_open.setEnabled(False)
        self._btn_open.clicked.connect(self._open_source)
        root.addWidget(QLabel("Bóveda de origen en tu Drive:"))
        root.addWidget(self._combo)
        row2 = QHBoxLayout()
        row2.addWidget(self._pw, 1)
        row2.addWidget(self._btn_open)
        root.addLayout(row2)

        self._mode_lbl = QLabel("")
        self._mode_lbl.setWordWrap(True)
        root.addWidget(self._mode_lbl)

        # --- Paso 3: selección de contenido ---
        selrow = QHBoxLayout()
        self._btn_all = QPushButton("Marcar todo")
        self._btn_all.clicked.connect(lambda: self._check_all(True))
        self._btn_none = QPushButton("Desmarcar todo")
        self._btn_none.clicked.connect(lambda: self._check_all(False))
        self._btn_all.setEnabled(False)
        self._btn_none.setEnabled(False)
        selrow.addWidget(self._btn_all)
        selrow.addWidget(self._btn_none)
        selrow.addStretch(1)
        selrow.addWidget(QLabel("Carpeta destino:"))
        self._dst_folder = QComboBox()
        self._dst_folder.setEnabled(False)
        selrow.addWidget(self._dst_folder)
        root.addLayout(selrow)

        self._tree = QTreeWidget()
        self._tree.setHeaderLabels(["Elemento", "Tipo", "Tamaño"])
        self._tree.setColumnWidth(0, 320)
        root.addWidget(self._tree, 1)

        # --- Progreso + acciones ---
        self._bar = QProgressBar()
        self._bar.hide()
        self._status = QLabel("")
        self._status.setWordWrap(True)
        root.addWidget(self._bar)
        root.addWidget(self._status)

        actrow = QHBoxLayout()
        actrow.addStretch(1)
        self._btn_pull = QPushButton("⬇️ Traer seleccionados")
        self._btn_pull.setEnabled(False)
        self._btn_pull.clicked.connect(self._pull)
        self._btn_close = QPushButton("Cerrar")
        self._btn_close.clicked.connect(self.reject)
        actrow.addWidget(self._btn_pull)
        actrow.addWidget(self._btn_close)
        root.addLayout(actrow)

        if not self._secret:
            self._status.setText("Primero elige tu client_secret.json (botón de la derecha).")

    # ---------------- conexión ----------------

    def _pick_secret(self):
        path, _ = QFileDialog.getOpenFileName(
            self, "Selecciona client_secret.json", "", "JSON (*.json)")
        if path:
            self._secret = path
            QSettings("VaultJam", "VaultJam").setValue("gdrive_secret", path)
            self._status.setText("Credenciales listas. Pulsa «Conectar».")

    def _busy(self, on: bool, msg: str = ""):
        for w in (self._btn_connect, self._btn_open, self._btn_pull,
                  self._btn_secret, self._combo, self._pw):
            w.setEnabled(not on and w is not self._btn_pull)
        self._status.setText(msg)
        self.setCursor(Qt.CursorShape.WaitCursor if on else Qt.CursorShape.ArrowCursor)

    def _connect(self):
        if not self._secret or not Path(self._secret).exists():
            QMessageBox.warning(self, "Google Drive",
                                "Selecciona primero tu client_secret.json.")
            return
        self._busy(True, "Conectando con Google (la primera vez abre el navegador)…")
        self._worker = _ConnectWorker(self._secret)
        self._worker.done.connect(self._on_connected)
        self._worker.start()

    def _on_connected(self, result):
        self._busy(False)
        if isinstance(result, Exception):
            QMessageBox.critical(self, "Google Drive", f"No se pudo conectar:\n{result}")
            return
        self._creds, self._svc, vaults = result
        self._combo.clear()
        for name, fid in vaults:
            self._combo.addItem(name, fid)
        if vaults:
            self._combo.setEnabled(True)
            self._pw.setEnabled(True)
            self._btn_open.setEnabled(True)
            self._pw.setFocus()
            self._status.setText("Elige la bóveda de origen y escribe su contraseña.")
        else:
            self._status.setText("No se encontraron carpetas *.vault en tu Drive.")

    # ---------------- abrir origen ----------------

    def _open_source(self):
        if self._svc is None or self._combo.count() == 0:
            return
        pw = self._pw.text()
        if not pw:
            return
        self._busy(True, "Leyendo la bóveda remota y derivando su clave (Argon2id)…")
        self._worker = _OpenWorker(self._svc, self._creds,
                                   self._combo.currentData(),
                                   self._combo.currentText(), pw)
        self._worker.done.connect(self._on_opened)
        self._worker.start()

    def _on_opened(self, result):
        self._busy(False)
        if isinstance(result, Exception):
            QMessageBox.critical(
                self, "Bóveda de origen",
                f"No se pudo abrir (¿contraseña incorrecta?):\n{result}")
            return
        self._src = result
        self._imp = CloudImport(self._src, self._dst)
        if self._imp.same_vault:
            self._mode_lbl.setText(
                "🔗 <b>Modo espejo</b>: es la MISMA bóveda. Se copiarán tal cual "
                "los blobs que falten en tu copia local (sin re-cifrar).")
            self._dst_folder.setEnabled(False)
        else:
            self._mode_lbl.setText(
                "📥 <b>Modo importar</b>: es OTRA bóveda. Su contenido se "
                "descifrará en memoria y se re-cifrará bajo la clave de tu "
                "bóveda local (copias nuevas).")
            self._dst_folder.clear()
            self._dst_folder.addItem(KEEP_FOLDERS, None)
            self._dst_folder.addItem("(raíz, sin carpeta)", "")
            for f in self._dst.folders():
                self._dst_folder.addItem(f, f)
            self._dst_folder.setEnabled(True)
        self._populate_tree()
        self._btn_all.setEnabled(True)
        self._btn_none.setEnabled(True)
        self._btn_pull.setEnabled(True)
        self._combo.setEnabled(False)
        self._pw.setEnabled(False)
        self._btn_open.setEnabled(False)

    def _populate_tree(self):
        self._tree.clear()
        for folder, entries in sorted(self._imp.source_by_folder().items()):
            parent = QTreeWidgetItem(self._tree, [folder or NO_FOLDER, "", ""])
            parent.setFlags(parent.flags() | Qt.ItemFlag.ItemIsUserCheckable
                            | Qt.ItemFlag.ItemIsAutoTristate)
            parent.setCheckState(0, Qt.CheckState.Checked)
            for e in sorted(entries, key=lambda x: x.name.lower()):
                icon = "🎬" if e.mime == "video" else "📷"
                child = QTreeWidgetItem(
                    parent, [f"{icon} {e.name}", e.mime, _human_size(e.size)])
                child.setFlags(child.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                child.setCheckState(0, Qt.CheckState.Checked)
                child.setData(0, Qt.ItemDataRole.UserRole, e.id)
        self._tree.expandAll()

    def _check_all(self, on: bool):
        state = Qt.CheckState.Checked if on else Qt.CheckState.Unchecked
        for i in range(self._tree.topLevelItemCount()):
            self._tree.topLevelItem(i).setCheckState(0, state)

    def _selected_ids(self) -> list[str]:
        ids = []
        for i in range(self._tree.topLevelItemCount()):
            top = self._tree.topLevelItem(i)
            for j in range(top.childCount()):
                c = top.child(j)
                if c.checkState(0) == Qt.CheckState.Checked:
                    ids.append(c.data(0, Qt.ItemDataRole.UserRole))
        return ids

    # ---------------- traer ----------------

    def _pull(self):
        ids = self._selected_ids()
        if not ids:
            QMessageBox.information(self, "Traer", "No hay elementos marcados.")
            return
        folder_override = (self._dst_folder.currentData()
                           if self._imp and not self._imp.same_vault else None)
        self._bar.setRange(0, len(ids))
        self._bar.setValue(0)
        self._bar.show()
        self._btn_pull.setEnabled(False)
        self._btn_close.setEnabled(False)
        self._tree.setEnabled(False)
        self._worker = _PullWorker(self._imp, ids, folder_override)
        self._worker.progress.connect(lambda d, t: self._bar.setValue(d))
        self._worker.status.connect(self._status.setText)
        self._worker.done.connect(self._on_pulled)
        self._worker.start()

    def _on_pulled(self, result):
        self._btn_close.setEnabled(True)
        self._tree.setEnabled(True)
        self._bar.hide()
        if isinstance(result, Exception):
            QMessageBox.critical(self, "Traer", f"Error:\n{result}")
            self._btn_pull.setEnabled(True)
            return
        r = result
        trajo = r["añadidos"] + r["reparados"] + r["importados"]
        self.changed = self.changed or trajo > 0
        partes = []
        if r["importados"]:
            partes.append(f"{r['importados']} importados")
        if r["añadidos"]:
            partes.append(f"{r['añadidos']} añadidos")
        if r["reparados"]:
            partes.append(f"{r['reparados']} reparados")
        if r["omitidos"]:
            partes.append(f"{r['omitidos']} ya presentes")
        resumen = ", ".join(partes) or "nada que traer"
        if r["errores"]:
            resumen += f"\n⚠️ {len(r['errores'])} con error: {r['errores'][0]}"
        QMessageBox.information(
            self, "Traer desde la nube",
            f"Modo {r['modo']}. {resumen}."
            + ("\n(Cancelado antes de terminar.)" if r["cancelado"] else ""))
        self._status.setText(resumen)
        self._btn_pull.setEnabled(True)

    def reject(self):
        # Cerrar mientras trae: cancelar y esperar a que termine el elemento.
        w = self._worker
        if isinstance(w, _PullWorker) and w.isRunning():
            w.cancel()
            w.wait(5000)
        super().reject()
