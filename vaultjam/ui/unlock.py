"""Diálogo de crear/abrir bóveda.

Decisiones de seguridad de esta pantalla:
  - La contraseña se lee del QLineEdit (modo Password), se pasa al KDF y no
    se guarda en ningún atributo, log ni setting. (Límite honesto: los str
    de Python son inmutables; no podemos sobreescribir la copia interna del
    widget. Ver SEGURIDAD.md.)
  - Argon2id corre en un hilo (libera el GIL) para no congelar la UI ~1 s.
  - Si la ruta elegida está dentro de OneDrive/Dropbox/etc., se avisa
    activamente del riesgo (patrones de actividad + conflictos de sync).
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import QSettings, Qt, QThread, QTimer, Signal
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QFileDialog, QFormLayout, QHBoxLayout,
    QLabel, QLineEdit, QMessageBox, QPushButton, QTabWidget, QVBoxLayout,
    QWidget,
)

from ..vault import Vault, VaultError, is_synced_location
from ..crypto_core import VaultCryptoError
from ..winsec import set_capture_protection

MIN_PASSWORD_LEN = 8

MAX_RECENTS = 8

SYNC_WARNING = (
    "⚠️ Esta ruta parece estar en una carpeta sincronizada a la nube "
    "(OneDrive/Dropbox/…). El contenido cifrado no se expone, pero sí tus "
    "patrones de actividad, y un conflicto de sincronización puede corromper "
    "la bóveda. Se recomienda una carpeta local no sincronizada."
)


def _load_recents() -> list[str]:
    """Rutas de bóvedas abiertas recientemente.

    ADVERTENCIA DE PRIVACIDAD (documentada en SEGURIDAD.md): las RUTAS se
    guardan en claro en el registro de Windows (HKCU\\Software\\VaultJam).
    No exponen contenido alguno, pero sí que existen bóvedas y dónde. El
    botón «Olvidar» las borra. Se filtran las que ya no existen.
    """
    s = QSettings("VaultJam", "VaultJam")
    paths = s.value("recientes", []) or []
    if isinstance(paths, str):
        paths = [paths]
    return [p for p in paths if (Path(p) / "header.json").exists()][:MAX_RECENTS]


def _remember_enabled() -> bool:
    """Preferencia (persistente) de recordar o no las rutas recientes.
    Activada por defecto; el usuario puede apagarla desde la casilla."""
    v = QSettings("VaultJam", "VaultJam").value("recordar_recientes", True)
    return v in (True, "true", "True", 1, "1")


def _set_remember(on: bool) -> None:
    QSettings("VaultJam", "VaultJam").setValue("recordar_recientes", bool(on))
    if not on:
        # Apagar el recuerdo también borra lo ya guardado: una preferencia
        # de privacidad que deja rastros previos no sirve de nada.
        _clear_recents()


def _push_recent(path: str) -> None:
    if not _remember_enabled():
        return
    paths = [p for p in _load_recents() if p != path]
    paths.insert(0, path)
    QSettings("VaultJam", "VaultJam").setValue("recientes", paths[:MAX_RECENTS])


def _clear_recents() -> None:
    QSettings("VaultJam", "VaultJam").remove("recientes")


class _KdfWorker(QThread):
    """Ejecuta crear/abrir (incluye Argon2id, ~256 MiB de RAM) fuera del
    hilo de la UI. Emite la Vault abierta o la excepción."""

    done = Signal(object)

    def __init__(self, fn, parent=None):
        super().__init__(parent)
        self._fn = fn

    def run(self):
        try:
            self.done.emit(self._fn())
        except Exception as e:  # noqa: BLE001 — se re-presenta en la UI
            self.done.emit(e)


class UnlockDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("VaultJam — desbloquear")
        self.setMinimumWidth(520)
        self.vault: Vault | None = None
        self._worker: _KdfWorker | None = None

        tabs = QTabWidget()
        tabs.addTab(self._build_open_tab(), "Abrir bóveda")
        tabs.addTab(self._build_create_tab(), "Crear bóveda nueva")

        self._status = QLabel("")
        self._status.setWordWrap(True)

        lay = QVBoxLayout(self)
        lay.addWidget(tabs)
        lay.addWidget(self._status)
        self._tabs = tabs
        self._last_tab = "open"
        # Al cambiar de pestaña, el foco va directo al campo de contraseña.
        tabs.currentChanged.connect(self._focus_password)
        # La pantalla de contraseña queda siempre excluida de capturas.
        set_capture_protection(self, True)

    def showEvent(self, ev):
        super().showEvent(ev)
        # Foco directo en la contraseña al abrir: teclear y Enter, sin clics.
        QTimer.singleShot(0, self._focus_password)

    def _focus_password(self, *_):
        target = self._open_pw if self._tabs.currentIndex() == 0 else self._create_pw
        target.setFocus()
        target.selectAll()

    # ---------------- pestaña Abrir ----------------

    def _build_open_tab(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)

        # Bóvedas recientes: seleccionar una rellena la ruta. «Olvidar»
        # borra la lista del registro (ver nota de privacidad en SEGURIDAD.md).
        recents = _load_recents()
        self._recent_combo = QComboBox()
        self._recent_combo.setToolTip(
            "Últimas bóvedas abiertas. Solo se guardan las RUTAS (en el "
            "registro de Windows), nunca contraseñas ni contenido."
        )
        for p in recents:
            self._recent_combo.addItem(p)
        self._recent_combo.activated.connect(
            lambda i: self._open_path.setText(self._recent_combo.itemText(i))
        )
        btn_forget = QPushButton("Olvidar")
        btn_forget.setToolTip("Borrar la lista de bóvedas recientes")
        btn_forget.clicked.connect(self._forget_recents)
        row_rec = QHBoxLayout()
        row_rec.addWidget(self._recent_combo, 1)
        row_rec.addWidget(btn_forget)
        form.addRow("Recientes:", row_rec)

        self._chk_remember = QCheckBox("Recordar las últimas bóvedas abiertas")
        self._chk_remember.setChecked(_remember_enabled())
        self._chk_remember.setToolTip(
            "Guarda las rutas (solo las rutas) en el registro de Windows para "
            "rellenarlas la próxima vez. Al desactivarlo se borra la lista y "
            "no se guardará nada más."
        )
        self._chk_remember.toggled.connect(self._on_remember_toggled)
        self._recent_combo.setEnabled(_remember_enabled())
        form.addRow("", self._chk_remember)

        self._open_path = QLineEdit()
        if recents:
            self._open_path.setText(recents[0])   # la última usada, lista
        btn_browse = QPushButton("Examinar…")
        btn_browse.clicked.connect(self._pick_open_dir)
        row = QHBoxLayout()
        row.addWidget(self._open_path)
        row.addWidget(btn_browse)
        form.addRow("Carpeta de la bóveda:", row)

        self._open_pw = QLineEdit()
        self._open_pw.setEchoMode(QLineEdit.EchoMode.Password)
        self._open_pw.returnPressed.connect(self._do_open)
        form.addRow("Contraseña:", self._open_pw)

        self._open_warn = QLabel("")
        self._open_warn.setWordWrap(True)
        self._open_warn.setStyleSheet("color: #b8860b;")
        form.addRow(self._open_warn)
        self._open_path.textChanged.connect(
            lambda t: self._open_warn.setText(SYNC_WARNING if t and is_synced_location(Path(t)) else "")
        )

        self._btn_open = QPushButton("Abrir")
        self._btn_open.clicked.connect(self._do_open)
        form.addRow(self._btn_open)
        return w

    # ---------------- pestaña Crear ----------------

    def _build_create_tab(self) -> QWidget:
        w = QWidget()
        form = QFormLayout(w)

        self._create_parent = QLineEdit()
        btn_browse = QPushButton("Examinar…")
        btn_browse.clicked.connect(self._pick_create_dir)
        row = QHBoxLayout()
        row.addWidget(self._create_parent)
        row.addWidget(btn_browse)
        form.addRow("Crear en la carpeta:", row)

        self._create_name = QLineEdit("MiBoveda")
        form.addRow("Nombre de la bóveda:", self._create_name)

        self._create_pw = QLineEdit()
        self._create_pw.setEchoMode(QLineEdit.EchoMode.Password)
        form.addRow("Contraseña:", self._create_pw)

        self._create_pw2 = QLineEdit()
        self._create_pw2.setEchoMode(QLineEdit.EchoMode.Password)
        self._create_pw2.returnPressed.connect(self._do_create)
        form.addRow("Repetir contraseña:", self._create_pw2)

        hint = QLabel(
            "La contraseña es lo ÚNICO que protege tus datos: no hay "
            "recuperación posible si la olvidas. Usa una frase larga y única."
        )
        hint.setWordWrap(True)
        hint.setStyleSheet("color: gray;")
        form.addRow(hint)

        self._create_warn = QLabel("")
        self._create_warn.setWordWrap(True)
        self._create_warn.setStyleSheet("color: #b8860b;")
        form.addRow(self._create_warn)
        self._create_parent.textChanged.connect(
            lambda t: self._create_warn.setText(SYNC_WARNING if t and is_synced_location(Path(t)) else "")
        )

        self._btn_create = QPushButton("Crear bóveda")
        self._btn_create.clicked.connect(self._do_create)
        form.addRow(self._btn_create)
        return w

    # ---------------- acciones ----------------

    def _forget_recents(self):
        _clear_recents()
        self._recent_combo.clear()

    def _on_remember_toggled(self, on: bool):
        _set_remember(on)
        if not on:
            self._recent_combo.clear()
        self._recent_combo.setEnabled(on)

    def _pick_open_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Selecciona la carpeta .vault")
        if d:
            self._open_path.setText(d)

    def _pick_create_dir(self):
        d = QFileDialog.getExistingDirectory(self, "Carpeta donde crear la bóveda")
        if d:
            self._create_parent.setText(d)

    def _busy(self, on: bool, msg: str = ""):
        self._tabs.setEnabled(not on)
        self._status.setText(msg)
        self.setCursor(Qt.CursorShape.WaitCursor if on else Qt.CursorShape.ArrowCursor)

    def _do_open(self):
        path = Path(self._open_path.text().strip())
        pw = self._open_pw.text()
        if not path.is_dir() or not (path / "header.json").exists():
            QMessageBox.warning(self, "VaultJam", "Esa carpeta no contiene una bóveda válida.")
            return
        if not pw:
            return
        self._last_tab = "open"
        self._busy(True, "Derivando clave (Argon2id, 256 MiB)… esto tarda ~1 s a propósito.")
        self._worker = _KdfWorker(lambda: Vault.open(path, pw))
        self._worker.done.connect(self._on_done)
        self._worker.start()

    def _do_create(self):
        parent = Path(self._create_parent.text().strip() or ".")
        name = self._create_name.text().strip()
        pw, pw2 = self._create_pw.text(), self._create_pw2.text()
        if not name:
            QMessageBox.warning(self, "VaultJam", "Ponle un nombre a la bóveda.")
            return
        if len(pw) < MIN_PASSWORD_LEN:
            QMessageBox.warning(
                self, "VaultJam",
                f"La contraseña debe tener al menos {MIN_PASSWORD_LEN} caracteres "
                "(y cuanto más larga, mejor: es tu única defensa real).",
            )
            return
        if pw != pw2:
            QMessageBox.warning(self, "VaultJam", "Las contraseñas no coinciden.")
            return
        target = parent / f"{name}.vault"
        if target.exists():
            QMessageBox.warning(self, "VaultJam", "Ya existe una carpeta con ese nombre.")
            return
        self._last_tab = "create"
        self._busy(True, "Creando bóveda y derivando clave (Argon2id, 256 MiB)…")
        self._worker = _KdfWorker(lambda: Vault.create(target, pw))
        self._worker.done.connect(self._on_done)
        self._worker.start()

    def _on_done(self, result):
        self._busy(False)
        # Descartar las contraseñas de los widgets en cuanto dejan de hacer falta.
        self._open_pw.clear()
        self._create_pw.clear()
        self._create_pw2.clear()
        if isinstance(result, Vault):
            _push_recent(str(result.root))   # recordar la ruta (solo la ruta)
            self.vault = result
            self.accept()
            return
        if isinstance(result, VaultCryptoError):
            QMessageBox.critical(self, "VaultJam", str(result))
        elif isinstance(result, (VaultError, Exception)):
            QMessageBox.critical(self, "VaultJam", f"No se pudo abrir/crear la bóveda:\n{result}")
        # Tras el error, el campo de contraseña vuelve a quedar enfocado y
        # listo para reintentar sin tocar el ratón.
        target = self._open_pw if self._last_tab == "open" else self._create_pw
        target.setFocus()
        target.selectAll()
