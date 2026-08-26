"""
VoltGuard — Theme Service
===========================
Singleton service that builds and applies the application's dark QSS
stylesheet to the Qt application.

Responsibilities:
  - Define the complete dark-theme colour palette.
  - Generate a QSS (Qt Style Sheet) string from the palette.
  - Apply the stylesheet to a ``QApplication`` instance.
  - Support switching between themes in a later milestone.

Usage:
    from src.services.theme_service import theme_service

    theme_service.apply_dark_theme(app)
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from PyQt6.QtWidgets import QApplication


# ---------------------------------------------------------------------------
# Colour Palette
# ---------------------------------------------------------------------------

class _DarkPalette:
    """
    VoltGuard dark theme colour tokens.

    All colours are defined here so that the QSS generator has a single
    source of truth.  Changing a colour here automatically propagates to
    every widget that uses it.
    """
    # Backgrounds
    BG_PRIMARY    = "#0D1117"   # Main window background
    BG_SECONDARY  = "#161B22"   # Sidebar, panels
    BG_TERTIARY   = "#1C2128"   # Cards, inputs
    BG_HOVER      = "#21262D"   # Button / item hover
    BG_SELECTED   = "#1F6FEB"   # Selected navigation item

    # Borders
    BORDER_DEFAULT = "#30363D"
    BORDER_FOCUS   = "#388BFD"

    # Text
    TEXT_PRIMARY   = "#E6EDF3"  # Main readable text
    TEXT_SECONDARY = "#8B949E"  # Captions, labels
    TEXT_MUTED     = "#484F58"  # Placeholder, disabled
    TEXT_ACCENT    = "#58A6FF"  # Hyperlinks, highlights

    # Accent / Status
    ACCENT_BLUE    = "#1F6FEB"
    ACCENT_GREEN   = "#3FB950"
    ACCENT_YELLOW  = "#D29922"
    ACCENT_RED     = "#F85149"
    ACCENT_ORANGE  = "#F0883E"
    ACCENT_PURPLE  = "#BC8CFF"

    # Sidebar
    SIDEBAR_WIDTH  = "220px"
    SIDEBAR_BG     = "#0D1117"

    # Status bar
    STATUSBAR_BG   = "#161B22"

    # Scrollbar
    SCROLL_BG      = "#161B22"
    SCROLL_HANDLE  = "#30363D"
    SCROLL_HANDLE_HOVER = "#484F58"

    # Font
    FONT_FAMILY    = "'Segoe UI', Roboto, Helvetica, Arial, sans-serif"
    FONT_SIZE_BASE = "13px"


class _ThemeService:
    """
    Qt Style Sheet (QSS) theme manager for VoltGuard.

    Generates a comprehensive dark stylesheet and applies it to the
    running QApplication instance.  The stylesheet covers all standard
    Qt widgets used in the application.
    """

    def __init__(self) -> None:
        self._current_theme: str = "dark"

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def apply_dark_theme(self, app: "QApplication") -> None:
        """
        Apply the VoltGuard dark stylesheet to the given QApplication.

        Args:
            app: The running ``QApplication`` instance.
        """
        qss = self._build_dark_qss()
        app.setStyleSheet(qss)
        self._current_theme = "dark"

    @property
    def current_theme(self) -> str:
        """Name of the currently active theme ('dark' or 'light')."""
        return self._current_theme

    def get_status_colour(self, status: str) -> str:
        """
        Return a hex colour string appropriate for a given status label.

        Args:
            status: Status string such as 'Running', 'Error', 'Idle'.

        Returns:
            A hex colour code string.
        """
        p = _DarkPalette
        lower = status.lower()
        if "running" in lower or "connected" in lower or "ok" in lower:
            return p.ACCENT_GREEN
        if "error" in lower or "fail" in lower or "block" in lower:
            return p.ACCENT_RED
        if "warn" in lower:
            return p.ACCENT_YELLOW
        if "idle" in lower or "ready" in lower:
            return p.ACCENT_BLUE
        return p.TEXT_SECONDARY

    # ------------------------------------------------------------------ #
    #  QSS Generation                                                      #
    # ------------------------------------------------------------------ #

    def _build_dark_qss(self) -> str:
        """
        Build and return the complete dark QSS stylesheet string.

        Returns:
            A multi-line QSS string ready to pass to ``setStyleSheet()``.
        """
        p = _DarkPalette
        return f"""
/* ===================================================== */
/*  VoltGuard Dark Theme — Qt Style Sheet                */
/* ===================================================== */

/* --- Global / QWidget --------------------------------- */
* {{
    font-family: {p.FONT_FAMILY};
    font-size: {p.FONT_SIZE_BASE};
    color: {p.TEXT_PRIMARY};
    outline: none;
}}

QWidget {{
    background-color: {p.BG_PRIMARY};
    color: {p.TEXT_PRIMARY};
}}

/* --- Main Window --------------------------------------- */
QMainWindow {{
    background-color: {p.BG_PRIMARY};
}}

QMainWindow::separator {{
    background-color: {p.BORDER_DEFAULT};
    width: 1px;
    height: 1px;
}}

/* --- Menu Bar ------------------------------------------ */
QMenuBar {{
    background-color: {p.BG_SECONDARY};
    color: {p.TEXT_PRIMARY};
    border-bottom: 1px solid {p.BORDER_DEFAULT};
    padding: 2px 4px;
}}

QMenuBar::item {{
    background-color: transparent;
    padding: 6px 12px;
    border-radius: 4px;
}}

QMenuBar::item:selected {{
    background-color: {p.BG_HOVER};
}}

QMenu {{
    background-color: {p.BG_SECONDARY};
    border: 1px solid {p.BORDER_DEFAULT};
    border-radius: 6px;
    padding: 4px;
}}

QMenu::item {{
    padding: 6px 20px;
    border-radius: 4px;
}}

QMenu::item:selected {{
    background-color: {p.BG_SELECTED};
    color: {p.TEXT_PRIMARY};
}}

/* --- Tool Bar ------------------------------------------ */
QToolBar {{
    background-color: {p.BG_SECONDARY};
    border-bottom: 1px solid {p.BORDER_DEFAULT};
    padding: 4px 8px;
    spacing: 8px;
}}

QToolBar QLabel {{
    color: {p.TEXT_PRIMARY};
    font-size: 14px;
    font-weight: bold;
}}

QToolButton {{
    background-color: transparent;
    color: {p.TEXT_PRIMARY};
    border: 1px solid transparent;
    border-radius: 6px;
    padding: 5px 10px;
}}

QToolButton:hover {{
    background-color: {p.BG_HOVER};
    border-color: {p.BORDER_DEFAULT};
}}

QToolButton:pressed {{
    background-color: {p.BG_SELECTED};
}}

/* --- Status Bar ---------------------------------------- */
QStatusBar {{
    background-color: {p.STATUSBAR_BG};
    color: {p.TEXT_SECONDARY};
    border-top: 1px solid {p.BORDER_DEFAULT};
    font-size: 12px;
    padding: 2px 8px;
}}

QStatusBar::item {{
    border: none;
}}

/* --- Push Button --------------------------------------- */
QPushButton {{
    background-color: {p.BG_TERTIARY};
    color: {p.TEXT_PRIMARY};
    border: 1px solid {p.BORDER_DEFAULT};
    border-radius: 6px;
    padding: 7px 16px;
    font-weight: 500;
}}

QPushButton:hover {{
    background-color: {p.BG_HOVER};
    border-color: {p.BORDER_FOCUS};
}}

QPushButton:pressed {{
    background-color: {p.ACCENT_BLUE};
    border-color: {p.ACCENT_BLUE};
    color: #ffffff;
}}

QPushButton:disabled {{
    background-color: {p.BG_TERTIARY};
    color: {p.TEXT_MUTED};
    border-color: {p.BORDER_DEFAULT};
}}

/* --- Line Edit / Text Input ---------------------------- */
QLineEdit {{
    background-color: {p.BG_TERTIARY};
    color: {p.TEXT_PRIMARY};
    border: 1px solid {p.BORDER_DEFAULT};
    border-radius: 6px;
    padding: 6px 10px;
    selection-background-color: {p.ACCENT_BLUE};
}}

QLineEdit:focus {{
    border-color: {p.BORDER_FOCUS};
}}

QLineEdit:disabled {{
    background-color: {p.BG_SECONDARY};
    color: {p.TEXT_MUTED};
}}

/* --- Combo Box ----------------------------------------- */
QComboBox {{
    background-color: {p.BG_TERTIARY};
    color: {p.TEXT_PRIMARY};
    border: 1px solid {p.BORDER_DEFAULT};
    border-radius: 6px;
    padding: 6px 10px;
    min-width: 120px;
}}

QComboBox:hover {{
    border-color: {p.BORDER_FOCUS};
}}

QComboBox::drop-down {{
    border: none;
    width: 24px;
}}

QComboBox::down-arrow {{
    width: 10px;
    height: 10px;
}}

QComboBox QAbstractItemView {{
    background-color: {p.BG_SECONDARY};
    color: {p.TEXT_PRIMARY};
    border: 1px solid {p.BORDER_DEFAULT};
    selection-background-color: {p.ACCENT_BLUE};
    outline: none;
}}

/* --- Table View --------------------------------------- */
QTableView, QTableWidget {{
    background-color: {p.BG_SECONDARY};
    color: {p.TEXT_PRIMARY};
    border: 1px solid {p.BORDER_DEFAULT};
    border-radius: 6px;
    gridline-color: {p.BORDER_DEFAULT};
    selection-background-color: {p.BG_SELECTED};
    alternate-background-color: {p.BG_PRIMARY};
}}

QTableView::item {{
    padding: 6px 10px;
    border: none;
}}

QTableView::item:selected {{
    background-color: {p.BG_SELECTED};
    color: {p.TEXT_PRIMARY};
}}

QHeaderView::section {{
    background-color: {p.BG_TERTIARY};
    color: {p.TEXT_SECONDARY};
    border: none;
    border-right: 1px solid {p.BORDER_DEFAULT};
    border-bottom: 1px solid {p.BORDER_DEFAULT};
    padding: 8px 10px;
    font-weight: 600;
    font-size: 12px;
}}

/* --- List View --------------------------------------- */
QListView {{
    background-color: {p.BG_SECONDARY};
    border: 1px solid {p.BORDER_DEFAULT};
    border-radius: 6px;
    color: {p.TEXT_PRIMARY};
}}

QListView::item {{
    padding: 6px 10px;
    border-radius: 4px;
}}

QListView::item:hover {{
    background-color: {p.BG_HOVER};
}}

QListView::item:selected {{
    background-color: {p.BG_SELECTED};
}}

/* --- Scroll Bar ---------------------------------------- */
QScrollBar:vertical {{
    background-color: {p.SCROLL_BG};
    width: 8px;
    border-radius: 4px;
    margin: 0;
}}

QScrollBar::handle:vertical {{
    background-color: {p.SCROLL_HANDLE};
    border-radius: 4px;
    min-height: 30px;
}}

QScrollBar::handle:vertical:hover {{
    background-color: {p.SCROLL_HANDLE_HOVER};
}}

QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical {{
    height: 0;
    background: none;
}}

QScrollBar:horizontal {{
    background-color: {p.SCROLL_BG};
    height: 8px;
    border-radius: 4px;
    margin: 0;
}}

QScrollBar::handle:horizontal {{
    background-color: {p.SCROLL_HANDLE};
    border-radius: 4px;
    min-width: 30px;
}}

QScrollBar::handle:horizontal:hover {{
    background-color: {p.SCROLL_HANDLE_HOVER};
}}

QScrollBar::add-line:horizontal,
QScrollBar::sub-line:horizontal {{
    width: 0;
    background: none;
}}

/* --- Tab Widget --------------------------------------- */
QTabWidget::pane {{
    border: 1px solid {p.BORDER_DEFAULT};
    border-radius: 6px;
    background-color: {p.BG_SECONDARY};
}}

QTabBar::tab {{
    background-color: {p.BG_TERTIARY};
    color: {p.TEXT_SECONDARY};
    border: 1px solid {p.BORDER_DEFAULT};
    border-bottom: none;
    border-radius: 4px 4px 0 0;
    padding: 8px 16px;
    margin-right: 2px;
}}

QTabBar::tab:selected {{
    background-color: {p.BG_SECONDARY};
    color: {p.TEXT_PRIMARY};
    border-bottom: 2px solid {p.ACCENT_BLUE};
}}

QTabBar::tab:hover:!selected {{
    background-color: {p.BG_HOVER};
}}

/* --- Group Box ----------------------------------------- */
QGroupBox {{
    border: 1px solid {p.BORDER_DEFAULT};
    border-radius: 8px;
    margin-top: 12px;
    padding: 12px 10px 10px 10px;
    font-weight: 600;
    color: {p.TEXT_SECONDARY};
}}

QGroupBox::title {{
    subcontrol-origin: margin;
    subcontrol-position: top left;
    left: 10px;
    top: -6px;
    padding: 0 6px;
    background-color: {p.BG_PRIMARY};
    color: {p.TEXT_SECONDARY};
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.5px;
    text-transform: uppercase;
}}

/* --- Check Box ----------------------------------------- */
QCheckBox {{
    color: {p.TEXT_PRIMARY};
    spacing: 8px;
}}

QCheckBox::indicator {{
    width: 16px;
    height: 16px;
    border: 1px solid {p.BORDER_DEFAULT};
    border-radius: 4px;
    background-color: {p.BG_TERTIARY};
}}

QCheckBox::indicator:checked {{
    background-color: {p.ACCENT_BLUE};
    border-color: {p.ACCENT_BLUE};
}}

/* --- Spin Box ------------------------------------------ */
QSpinBox, QDoubleSpinBox {{
    background-color: {p.BG_TERTIARY};
    color: {p.TEXT_PRIMARY};
    border: 1px solid {p.BORDER_DEFAULT};
    border-radius: 6px;
    padding: 5px 8px;
}}

QSpinBox:focus, QDoubleSpinBox:focus {{
    border-color: {p.BORDER_FOCUS};
}}

/* --- Text Edit ----------------------------------------- */
QTextEdit, QPlainTextEdit {{
    background-color: {p.BG_TERTIARY};
    color: {p.TEXT_PRIMARY};
    border: 1px solid {p.BORDER_DEFAULT};
    border-radius: 6px;
    padding: 6px;
    selection-background-color: {p.ACCENT_BLUE};
}}

QTextEdit:focus, QPlainTextEdit:focus {{
    border-color: {p.BORDER_FOCUS};
}}

/* --- Label --------------------------------------------- */
QLabel {{
    background-color: transparent;
    color: {p.TEXT_PRIMARY};
}}

/* --- Splitter ------------------------------------------ */
QSplitter::handle {{
    background-color: {p.BORDER_DEFAULT};
}}

QSplitter::handle:horizontal {{
    width: 1px;
}}

QSplitter::handle:vertical {{
    height: 1px;
}}

/* --- Tool Tip ------------------------------------------ */
QToolTip {{
    background-color: {p.BG_SECONDARY};
    color: {p.TEXT_PRIMARY};
    border: 1px solid {p.BORDER_DEFAULT};
    border-radius: 4px;
    padding: 4px 8px;
    font-size: 12px;
}}

/* --- Message Box --------------------------------------- */
QMessageBox {{
    background-color: {p.BG_SECONDARY};
    color: {p.TEXT_PRIMARY};
}}

QMessageBox QPushButton {{
    min-width: 80px;
}}

/* --- Progress Bar -------------------------------------- */
QProgressBar {{
    background-color: {p.BG_TERTIARY};
    border: 1px solid {p.BORDER_DEFAULT};
    border-radius: 4px;
    text-align: center;
    color: {p.TEXT_PRIMARY};
    height: 8px;
}}

QProgressBar::chunk {{
    background-color: {p.ACCENT_BLUE};
    border-radius: 4px;
}}
"""


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
ThemeService = _ThemeService
theme_service: ThemeService = ThemeService()
