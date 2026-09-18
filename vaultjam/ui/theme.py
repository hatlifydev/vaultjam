"""Tema visual de VaultJam: oscuro, moderno y consistente.

Se aplica una sola vez sobre el estilo Fusion (la base neutra de Qt) con
una hoja QSS global: superficies grafito, acento índigo suave, esquinas
redondeadas y controles compactos. Ningún estilo toca la seguridad: es
pura presentación.
"""

from __future__ import annotations

ACCENT = "#6c7bff"
ACCENT_DIM = "#4a56b8"
BG = "#141519"          # fondo base
SURFACE = "#1d1f26"     # barras y paneles
SURFACE_2 = "#262933"   # hover / bordes
TEXT = "#e8e8ee"
TEXT_DIM = "#9aa0ae"

QSS = f"""
* {{
    font-family: 'Segoe UI', sans-serif;
    font-size: 10pt;
    color: {TEXT};
}}
QMainWindow, QDialog {{ background: {BG}; }}
QWidget {{ background: transparent; }}

QToolBar {{
    background: {SURFACE};
    border: none;
    border-bottom: 1px solid {SURFACE_2};
    padding: 6px 8px;
    spacing: 4px;
}}
QToolBar QToolButton {{
    background: transparent;
    border: none;
    border-radius: 8px;
    padding: 6px 12px;
}}
QToolBar QToolButton:hover {{ background: {SURFACE_2}; }}
QToolBar QToolButton:pressed {{ background: {ACCENT_DIM}; }}
QToolBar QToolButton:checked {{ background: {ACCENT_DIM}; color: white; }}
QToolBar QToolButton:disabled {{ color: {TEXT_DIM}; }}
QToolBar::separator {{ background: {SURFACE_2}; width: 1px; margin: 6px 6px; }}

QPushButton {{
    background: {SURFACE_2};
    border: none;
    border-radius: 8px;
    padding: 6px 14px;
}}
QPushButton:hover {{ background: #303442; }}
QPushButton:pressed {{ background: {ACCENT_DIM}; }}
QPushButton:disabled {{ color: {TEXT_DIM}; background: {SURFACE}; }}
QPushButton:flat {{ background: transparent; }}

QLineEdit, QComboBox {{
    background: {SURFACE};
    border: 1px solid {SURFACE_2};
    border-radius: 8px;
    padding: 6px 10px;
    selection-background-color: {ACCENT_DIM};
}}
QLineEdit:focus, QComboBox:focus {{ border-color: {ACCENT}; }}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{
    background: {SURFACE};
    border: 1px solid {SURFACE_2};
    selection-background-color: {ACCENT_DIM};
}}

QListWidget {{
    background: {SURFACE};
    border: none;
    border-radius: 10px;
    padding: 6px;
    outline: none;
}}
QListWidget::item {{ padding: 7px 10px; border-radius: 8px; margin: 1px 0; }}
QListWidget::item:hover {{ background: {SURFACE_2}; }}
QListWidget::item:selected {{ background: {ACCENT_DIM}; color: white; }}

QListView {{
    background: {BG};
    border: none;
    outline: none;
}}
QListView::item {{ border-radius: 8px; padding: 4px; }}
QListView::item:hover {{ background: {SURFACE}; }}
QListView::item:selected {{ background: {SURFACE_2}; border: 1px solid {ACCENT}; }}

QSlider::groove:horizontal {{
    height: 4px; border-radius: 2px; background: {SURFACE_2};
}}
QSlider::sub-page:horizontal {{ background: {ACCENT}; border-radius: 2px; }}
QSlider::handle:horizontal {{
    width: 14px; height: 14px; margin: -5px 0;
    border-radius: 7px; background: {TEXT};
}}
QSlider::handle:horizontal:hover {{ background: {ACCENT}; }}

QProgressBar {{
    background: {SURFACE_2};
    border: none; border-radius: 6px;
    height: 10px; text-align: center;
    font-size: 8pt; color: {TEXT};
}}
QProgressBar::chunk {{ background: {ACCENT}; border-radius: 6px; }}

QMenu {{
    background: {SURFACE};
    border: 1px solid {SURFACE_2};
    border-radius: 10px;
    padding: 6px;
}}
QMenu::item {{ padding: 7px 26px 7px 14px; border-radius: 6px; }}
QMenu::item:selected {{ background: {ACCENT_DIM}; color: white; }}
QMenu::separator {{ height: 1px; background: {SURFACE_2}; margin: 5px 8px; }}

QStatusBar {{
    background: {SURFACE};
    border-top: 1px solid {SURFACE_2};
    color: {TEXT_DIM};
}}
QStatusBar QLabel {{ color: {TEXT_DIM}; }}

QScrollBar:vertical {{ background: transparent; width: 10px; margin: 2px; }}
QScrollBar::handle:vertical {{
    background: {SURFACE_2}; border-radius: 5px; min-height: 30px;
}}
QScrollBar::handle:vertical:hover {{ background: {ACCENT_DIM}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; width: 0; }}
QScrollBar:horizontal {{ background: transparent; height: 10px; margin: 2px; }}
QScrollBar::handle:horizontal {{
    background: {SURFACE_2}; border-radius: 5px; min-width: 30px;
}}

QToolTip {{
    background: {SURFACE};
    color: {TEXT};
    border: 1px solid {SURFACE_2};
    border-radius: 6px;
    padding: 5px 8px;
}}

QTabWidget::pane {{ border: none; }}
QTabBar::tab {{
    background: transparent; color: {TEXT_DIM};
    padding: 8px 16px; border-radius: 8px; margin-right: 4px;
}}
QTabBar::tab:hover {{ background: {SURFACE_2}; }}
QTabBar::tab:selected {{ background: {ACCENT_DIM}; color: white; }}

QCheckBox {{ spacing: 8px; }}
QCheckBox::indicator {{
    width: 16px; height: 16px; border-radius: 5px;
    border: 1px solid {SURFACE_2}; background: {SURFACE};
}}
QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}

QSplitter::handle {{ background: transparent; width: 6px; }}

QFrame#syncPanel {{
    background: {SURFACE};
    border: 1px solid {ACCENT_DIM};
    border-radius: 10px;
}}
QFrame#syncPanel QLabel {{ background: transparent; }}
"""


def apply_theme(app) -> None:
    app.setStyle("Fusion")
    app.setStyleSheet(QSS)
