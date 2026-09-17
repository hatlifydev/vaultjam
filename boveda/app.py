"""Punto de entrada de la aplicación.

Ciclo: desbloquear -> ventana principal -> (bloqueo) -> desbloquear -> …
Al salir por cualquier vía, la bóveda queda bloqueada (claves zeroizadas).

Nota: la app no escribe NINGÚN log. Cualquier error se muestra en la UI;
jamás se registran rutas internas de la bóveda, nombres de archivos ni,
por supuesto, contraseñas o claves.
"""

from __future__ import annotations

import sys

from PySide6.QtCore import QEventLoop
from PySide6.QtWidgets import QApplication, QDialog

from .ui.main_window import MainWindow
from .ui.unlock import UnlockDialog


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("Boveda")
    app.setOrganizationName("Boveda")

    while True:
        dlg = UnlockDialog()
        if dlg.exec() != QDialog.DialogCode.Accepted:
            return 0  # el usuario canceló el desbloqueo: salir
        vault = dlg.vault

        win = MainWindow(vault)
        session = QEventLoop()
        relock = {"flag": False}

        def on_locked():
            relock["flag"] = True
            session.quit()

        win.locked.connect(on_locked)
        win.quitRequested.connect(session.quit)
        win.show()
        session.exec()
        win.deleteLater()

        if not relock["flag"]:
            return 0  # cierre de ventana = salir (la bóveda ya quedó bloqueada)


if __name__ == "__main__":
    sys.exit(main())
