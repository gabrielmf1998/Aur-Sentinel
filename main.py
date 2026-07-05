from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from aur_sentinel.i18n import apply_language, initial_language
from aur_sentinel.ui.main_window import MainWindow


def main() -> int:
    app = QApplication(sys.argv)
    app.setOrganizationName("AURAudit")
    app.setApplicationName("Aur Sentinel")
    app.setStyle("Fusion")
    apply_language(initial_language(), app)
    window = MainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
