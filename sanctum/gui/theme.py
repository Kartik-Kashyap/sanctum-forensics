"""
Visual theme.

A dark, high-contrast palette suited to a forensic workstation: long sessions,
dense tabular data, and a need to make status legible at a glance. Colours are
chosen for contrast rather than decoration, and status colours are reserved
strictly for status - a red element always means a failure or a hazard, never
just emphasis.
"""

from __future__ import annotations

# Palette
BG = "#12161c"
BG_ALT = "#171c24"
PANEL = "#1c2330"
PANEL_HI = "#232b3a"
LINE = "#2c3547"
INK = "#e6ebf2"
MUTED = "#8a97a8"
ACCENT = "#4b9fd6"
ACCENT_DIM = "#2f6d94"
OK = "#4ec27e"
WARN = "#e0a54a"
BAD = "#e0605e"
CRIT = "#c93c3c"

STYLESHEET = f"""
QWidget {{
    background: {BG};
    color: {INK};
    font-family: "Segoe UI", -apple-system, Roboto, Helvetica, sans-serif;
    font-size: 13px;
}}
QMainWindow, QDialog {{ background: {BG}; }}

/* ---- Sidebar ---- */
QListWidget#nav {{
    background: {BG_ALT};
    border: none;
    outline: none;
    padding: 8px 0;
}}
QListWidget#nav::item {{
    padding: 11px 18px;
    border-left: 3px solid transparent;
    color: {MUTED};
}}
QListWidget#nav::item:hover {{ background: {PANEL}; color: {INK}; }}
QListWidget#nav::item:selected {{
    background: {PANEL};
    color: {INK};
    border-left: 3px solid {ACCENT};
    font-weight: 600;
}}

/* ---- Panels & cards ---- */
QFrame#card, QGroupBox {{
    background: {PANEL};
    border: 1px solid {LINE};
    border-radius: 8px;
}}
QGroupBox {{
    margin-top: 16px;
    padding: 16px 14px 12px;
    font-weight: 600;
}}
QGroupBox::title {{
    subcontrol-origin: margin;
    left: 12px; top: 2px;
    padding: 0 6px;
    color: {ACCENT};
    text-transform: uppercase;
    font-size: 11px;
    letter-spacing: 0.08em;
}}
QFrame#statCard {{
    background: {PANEL};
    border: 1px solid {LINE};
    border-radius: 8px;
}}
QLabel#statValue {{ font-size: 21px; font-weight: 700; }}
QLabel#statLabel {{
    color: {MUTED}; font-size: 11px;
    text-transform: uppercase; letter-spacing: 0.07em;
}}
QLabel#pageTitle {{ font-size: 20px; font-weight: 700; }}
QLabel#pageSub {{ color: {MUTED}; font-size: 12px; }}
QLabel#muted {{ color: {MUTED}; }}
QLabel#hint {{ color: {MUTED}; font-size: 12px; }}

/* ---- Buttons ---- */
QPushButton {{
    background: {PANEL_HI};
    border: 1px solid {LINE};
    border-radius: 6px;
    padding: 8px 16px;
    color: {INK};
}}
QPushButton:hover {{ background: {LINE}; }}
QPushButton:disabled {{ color: {MUTED}; background: {PANEL}; }}
QPushButton#primary {{
    background: {ACCENT_DIM};
    border-color: {ACCENT};
    font-weight: 600;
}}
QPushButton#primary:hover {{ background: {ACCENT}; }}
QPushButton#danger {{
    background: {CRIT};
    border-color: {BAD};
    font-weight: 600;
}}
QPushButton#danger:hover {{ background: {BAD}; }}

/* ---- Inputs ---- */
QLineEdit, QComboBox, QSpinBox, QDoubleSpinBox, QPlainTextEdit, QTextEdit {{
    background: {BG_ALT};
    border: 1px solid {LINE};
    border-radius: 6px;
    padding: 7px 9px;
    selection-background-color: {ACCENT_DIM};
}}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QPlainTextEdit:focus {{
    border-color: {ACCENT};
}}
QComboBox::drop-down {{ border: none; width: 22px; }}
QComboBox QAbstractItemView {{
    background: {PANEL};
    border: 1px solid {LINE};
    selection-background-color: {ACCENT_DIM};
}}

/* ---- Tables & lists ---- */
QTableWidget, QTableView {{
    background: {BG_ALT};
    alternate-background-color: {PANEL};
    border: 1px solid {LINE};
    border-radius: 8px;
    gridline-color: {LINE};
    selection-background-color: {ACCENT_DIM};
}}
QHeaderView::section {{
    background: {PANEL};
    color: {MUTED};
    border: none;
    border-bottom: 1px solid {LINE};
    padding: 8px;
    font-size: 11px;
    text-transform: uppercase;
    letter-spacing: 0.06em;
}}
QTableCornerButton::section {{ background: {PANEL}; border: none; }}

/* ---- Progress ---- */
QProgressBar {{
    background: {BG_ALT};
    border: 1px solid {LINE};
    border-radius: 6px;
    height: 20px;
    text-align: center;
    color: {INK};
}}
QProgressBar::chunk {{ background: {ACCENT_DIM}; border-radius: 5px; }}

/* ---- Misc ---- */
QScrollBar:vertical {{ background: {BG}; width: 11px; margin: 0; }}
QScrollBar::handle:vertical {{ background: {LINE}; border-radius: 5px; min-height: 28px; }}
QScrollBar::handle:vertical:hover {{ background: {MUTED}; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}
QScrollBar:horizontal {{ background: {BG}; height: 11px; }}
QScrollBar::handle:horizontal {{ background: {LINE}; border-radius: 5px; min-width: 28px; }}
QCheckBox::indicator, QRadioButton::indicator {{
    width: 15px; height: 15px;
    border: 1px solid {LINE}; border-radius: 3px; background: {BG_ALT};
}}
QCheckBox::indicator:checked {{ background: {ACCENT}; border-color: {ACCENT}; }}
QTabWidget::pane {{ border: 1px solid {LINE}; border-radius: 8px; top: -1px; }}
QTabBar::tab {{
    background: transparent; color: {MUTED};
    padding: 8px 16px; border-bottom: 2px solid transparent;
}}
QTabBar::tab:selected {{ color: {INK}; border-bottom: 2px solid {ACCENT}; }}
QStatusBar {{ background: {BG_ALT}; color: {MUTED}; border-top: 1px solid {LINE}; }}
QToolTip {{
    background: {PANEL_HI}; color: {INK};
    border: 1px solid {LINE}; padding: 6px;
}}
QSplitter::handle {{ background: {LINE}; }}
"""

#: Status tones, used consistently across every view.
TONE = {
    "ok": OK,
    "warn": WARN,
    "bad": BAD,
    "info": ACCENT,
    "muted": MUTED,
    "critical": CRIT,
}

#: Colour per confidence label, matching the report's semantics.
CONFIDENCE_TONE = {
    "High": OK,
    "Medium": WARN,
    "Low": BAD,
}
