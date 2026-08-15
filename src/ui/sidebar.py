"""
VoltGuard — Sidebar Navigation Widget
========================================
Implements the left-side navigation panel of the main window.

The sidebar contains a navigation item for each page of the application.
Clicking an item emits the ``page_changed`` signal with the zero-based
page index so the ``MainWindow`` can switch the central stacked widget.

Navigation items:
  0 — Dashboard
  1 — Packet Monitor
  2 — Physics Monitor
  3 — Analytics
  4 — Reports
  5 — Settings

Architecture:
  The sidebar is a pure UI component.  It emits signals and receives
  commands but never directly manipulates other widgets.  The MainWindow
  is responsible for connecting the sidebar to the content area.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, pyqtSignal
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import (
    QFrame,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)


class _NavButton(QPushButton):
    """
    A single navigation button in the sidebar.

    Extends ``QPushButton`` to carry a page index and provide
    consistent active/inactive visual states.
    """

    # Colour tokens (kept local — sidebar-specific colours)
    _BG_IDLE     = "transparent"
    _BG_HOVER    = "#21262D"
    _BG_ACTIVE   = "#1C2B3A"
    _TEXT_IDLE   = "#8B949E"
    _TEXT_ACTIVE = "#E6EDF3"
    _ACCENT_BAR  = "#1F6FEB"

    def __init__(
        self,
        label: str,
        icon: str,
        page_index: int,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._page_index: int = page_index
        self._active: bool = False
        self._build_button(label, icon)

    def _build_button(self, label: str, icon: str) -> None:
        """Configure the button text, size, and alignment."""
        # Combine icon + label in a single text string for simplicity.
        self.setText(f"  {icon}   {label}")
        self.setCheckable(False)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setMinimumHeight(44)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        font = QFont()
        font.setPointSize(11)
        self.setFont(font)
        self._apply_style(active=False)

    def set_active(self, active: bool) -> None:
        """
        Toggle the active/selected visual state.

        Args:
            active: True if this is the currently selected navigation item.
        """
        self._active = active
        self._apply_style(active)

    def _apply_style(self, active: bool) -> None:
        """Apply QSS for the given active state."""
        border = f"border-left: 3px solid {self._ACCENT_BAR};" if active else \
                 "border-left: 3px solid transparent;"
        bg     = self._BG_ACTIVE if active else self._BG_IDLE
        color  = self._TEXT_ACTIVE if active else self._TEXT_IDLE
        weight = "700" if active else "400"

        self.setStyleSheet(
            f"""
            QPushButton {{
                background-color: {bg};
                color: {color};
                {border}
                border-right: none;
                border-top: none;
                border-bottom: none;
                border-radius: 0;
                padding: 0 0 0 12px;
                text-align: left;
                font-weight: {weight};
                font-size: 13px;
            }}
            QPushButton:hover {{
                background-color: {self._BG_HOVER};
                color: {self._TEXT_ACTIVE};
            }}
            """
        )

    @property
    def page_index(self) -> int:
        """Zero-based index of the page this button activates."""
        return self._page_index


class Sidebar(QWidget):
    """
    Left-side navigation panel for VoltGuard.

    Emits:
        page_changed (int): The index of the newly selected page.
    """

    page_changed = pyqtSignal(int)

    # Navigation item definitions: (label, icon, page_index)
    _NAV_ITEMS = [
        ("Dashboard",        "🏠", 0),
        ("Packet Monitor",   "📡", 1),
        ("Physics Monitor",  "⚙",  2),
        ("Analytics",        "📊", 3),
        ("Reports",          "📋", 4),
        ("Settings",         "⚙",  5),
    ]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._buttons: list[_NavButton] = []
        self._current_index: int = 0
        self._build_ui()
        self._select(0)

    # ------------------------------------------------------------------ #
    #  UI Construction                                                     #
    # ------------------------------------------------------------------ #

    def _build_ui(self) -> None:
        """Build the sidebar layout with logo, nav items, and footer."""
        self.setObjectName("Sidebar")
        self.setStyleSheet(
            """
            QWidget#Sidebar {
                background-color: #0D1117;
                border-right: 1px solid #30363D;
            }
            """
        )
        self.setFixedWidth(220)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # ---- Logo / brand area ---------------------------------------- #
        layout.addWidget(self._build_brand())

        # ---- Separator ------------------------------------------------ #
        layout.addWidget(self._build_separator())

        # ---- Navigation items ----------------------------------------- #
        layout.addSpacing(8)
        for label, icon, idx in self._NAV_ITEMS:
            btn = _NavButton(label, icon, idx, self)
            btn.clicked.connect(lambda checked, b=btn: self._on_nav_clicked(b))
            self._buttons.append(btn)
            layout.addWidget(btn)

        layout.addStretch()

        # ---- Footer separator ----------------------------------------- #
        layout.addWidget(self._build_separator())

        # ---- Version footer ------------------------------------------- #
        layout.addWidget(self._build_footer())

    def _build_brand(self) -> QWidget:
        """Build the application logo and name area at the top of the sidebar."""
        brand = QWidget()
        brand.setFixedHeight(72)
        brand.setStyleSheet("background-color: #0D1117;")

        v = QVBoxLayout(brand)
        v.setContentsMargins(16, 14, 16, 10)
        v.setSpacing(2)

        name_label = QLabel("VoltGuard")
        name_label.setStyleSheet(
            "font-size: 16px; font-weight: 800; color: #E6EDF3; "
            "letter-spacing: -0.3px; background: transparent;"
        )
        v.addWidget(name_label)

        tagline = QLabel("ICS/SCADA IPS")
        tagline.setStyleSheet(
            "font-size: 10px; color: #1F6FEB; font-weight: 600; "
            "letter-spacing: 0.5px; text-transform: uppercase; background: transparent;"
        )
        v.addWidget(tagline)

        return brand

    def _build_separator(self) -> QFrame:
        """Build a horizontal separator line."""
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setFixedHeight(1)
        sep.setStyleSheet("background-color: #30363D; border: none;")
        return sep

    def _build_footer(self) -> QWidget:
        """Build the version info footer at the bottom of the sidebar."""
        footer = QWidget()
        footer.setFixedHeight(40)
        footer.setStyleSheet("background-color: #0D1117;")

        layout = QVBoxLayout(footer)
        layout.setContentsMargins(16, 8, 16, 8)
        layout.setSpacing(0)

        ver_label = QLabel("v1.0.0  ·  Day 1")
        ver_label.setStyleSheet(
            "font-size: 10px; color: #484F58; background: transparent;"
        )
        layout.addWidget(ver_label)

        return footer

    # ------------------------------------------------------------------ #
    #  Navigation Logic                                                    #
    # ------------------------------------------------------------------ #

    def _on_nav_clicked(self, button: _NavButton) -> None:
        """Handle a navigation button click."""
        self._select(button.page_index)
        self.page_changed.emit(button.page_index)

    def _select(self, index: int) -> None:
        """
        Activate the navigation button at ``index`` and deactivate all others.

        Args:
            index: Zero-based page index to select.
        """
        self._current_index = index
        for btn in self._buttons:
            btn.set_active(btn.page_index == index)

    def navigate_to(self, index: int) -> None:
        """
        Programmatically select a navigation item without emitting a signal.
        Used by MainWindow to synchronise the sidebar when the page changes
        via other means (e.g. keyboard shortcuts).

        Args:
            index: Zero-based page index to select.
        """
        self._select(index)

    @property
    def current_index(self) -> int:
        """Index of the currently selected navigation item."""
        return self._current_index
