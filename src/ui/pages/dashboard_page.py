"""
VoltGuard — Dashboard Page
============================
Implements the main dashboard view with eight live status cards.

Cards display:
  1. Application Status
  2. Database Status
  3. Current Network Interface
  4. Packets Captured
  5. Allowed Packets
  6. Blocked Packets
  7. System Time
  8. Application Version

All values are read from the service layer (AppState, ConfigService).
The dashboard auto-refreshes every second via a QTimer so counters
and the system clock stay current without any manual interaction.

Architecture:
  This module contains only UI construction and layout code.
  No business logic or data computation happens here.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from src.core.app_state import app_state
from src.services.config_service import config_service
from src.services.theme_service import theme_service


class _StatCard(QFrame):
    """
    A single dashboard statistics card widget.

    Displays an icon label, a title, and a large value label.
    The value can be updated via ``set_value()``.
    """

    def __init__(
        self,
        title: str,
        icon: str,
        initial_value: str = "—",
        accent_colour: str = "#58A6FF",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._accent = accent_colour
        self._build_ui(title, icon, initial_value)
        self._apply_card_style()

    def _build_ui(self, title: str, icon: str, initial_value: str) -> None:
        """Construct the card layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 18, 20, 18)
        layout.setSpacing(8)

        # Header row: icon + title
        header = QHBoxLayout()
        header.setSpacing(10)

        icon_label = QLabel(icon)
        icon_label.setFont(QFont("Segoe UI Emoji, Arial", 20))
        icon_label.setFixedSize(32, 32)
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setStyleSheet("background: transparent;")
        header.addWidget(icon_label)

        title_label = QLabel(title)
        title_label.setStyleSheet(
            "color: #8B949E; font-size: 11px; font-weight: 600; "
            "letter-spacing: 0.5px; text-transform: uppercase; background: transparent;"
        )
        title_label.setWordWrap(False)
        header.addWidget(title_label, 1)
        header.addStretch()

        layout.addLayout(header)

        # Value label — large and prominent
        self._value_label = QLabel(initial_value)
        self._value_label.setStyleSheet(
            f"color: {self._accent}; font-size: 26px; font-weight: 700; "
            f"background: transparent; letter-spacing: -0.5px;"
        )
        self._value_label.setAlignment(Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self._value_label)

    def _apply_card_style(self) -> None:
        """Apply the card's background and border stylesheet."""
        self.setStyleSheet(
            """
            _StatCard, QFrame#statcard {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 10px;
            }
            _StatCard:hover, QFrame#statcard:hover {
                border-color: #388BFD;
            }
            """
        )
        self.setObjectName("statcard")
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setMinimumHeight(110)
        self.setSizePolicy(
            QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed
        )

    def set_value(self, text: str) -> None:
        """
        Update the displayed value text.

        Args:
            text: New value to display.
        """
        self._value_label.setText(text)

    def set_value_colour(self, hex_colour: str) -> None:
        """
        Change the accent colour of the value label.

        Args:
            hex_colour: CSS hex colour string (e.g. '#3FB950').
        """
        self._accent = hex_colour
        self._value_label.setStyleSheet(
            f"color: {hex_colour}; font-size: 26px; font-weight: 700; "
            f"background: transparent; letter-spacing: -0.5px;"
        )


class DashboardPage(QWidget):
    """
    Dashboard page widget for VoltGuard.

    Displays a 4×2 grid of live status cards and a section header.
    A one-second QTimer drives the refresh cycle.
    """

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._cards: dict[str, _StatCard] = {}
        self._timer = QTimer(self)
        self._build_ui()
        self._connect_signals()
        self._refresh()

    # ------------------------------------------------------------------ #
    #  UI Construction                                                     #
    # ------------------------------------------------------------------ #

    def _build_ui(self) -> None:
        """Build the page layout."""
        root_layout = QVBoxLayout(self)
        root_layout.setContentsMargins(0, 0, 0, 0)
        root_layout.setSpacing(0)

        # ---- Scrollable container --------------------------------------- #
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        root_layout.addWidget(scroll)

        container = QWidget()
        container.setObjectName("dashContainer")
        container.setStyleSheet("#dashContainer { background: transparent; }")
        scroll.setWidget(container)

        layout = QVBoxLayout(container)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.setSpacing(24)

        # ---- Page header ----------------------------------------------- #
        layout.addWidget(self._build_header())

        # ---- Status cards grid ----------------------------------------- #
        layout.addWidget(self._build_cards_grid())
        layout.addStretch()

    def _build_header(self) -> QWidget:
        """Build the page title and subtitle header."""
        header = QWidget()
        header.setStyleSheet("background: transparent;")
        h_layout = QVBoxLayout(header)
        h_layout.setContentsMargins(0, 0, 0, 0)
        h_layout.setSpacing(4)

        title = QLabel("Dashboard")
        title.setStyleSheet(
            "font-size: 22px; font-weight: 700; color: #E6EDF3; background: transparent;"
        )
        h_layout.addWidget(title)

        subtitle = QLabel("Live system overview — all values refresh every second.")
        subtitle.setStyleSheet(
            "font-size: 13px; color: #8B949E; background: transparent;"
        )
        h_layout.addWidget(subtitle)

        return header

    def _build_cards_grid(self) -> QWidget:
        """Build the 4×2 grid of status cards."""
        grid_widget = QWidget()
        grid_widget.setStyleSheet("background: transparent;")
        grid = QGridLayout(grid_widget)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(14)

        # Card definitions: (key, title, icon, initial_value, accent)
        card_defs = [
            ("app_status",  "Application Status",      "🛡",  "Idle",    "#58A6FF"),
            ("db_status",   "Database Status",          "🗄",  "—",       "#3FB950"),
            ("interface",   "Network Interface",        "🌐",  "—",       "#D29922"),
            ("captured",    "Packets Captured",         "📡",  "0",       "#BC8CFF"),
            ("allowed",     "Allowed Packets",          "✅",  "0",       "#3FB950"),
            ("blocked",     "Blocked Packets",          "🚫",  "0",       "#F85149"),
            ("time",        "System Time",              "🕐",  "—",       "#58A6FF"),
            ("version",     "Application Version",     "📦",  "—",       "#8B949E"),
        ]

        for idx, (key, title, icon, value, colour) in enumerate(card_defs):
            row, col = divmod(idx, 4)
            card = _StatCard(title, icon, value, colour)
            self._cards[key] = card
            grid.addWidget(card, row, col)

        # Equal column stretch
        for col in range(4):
            grid.setColumnStretch(col, 1)

        return grid_widget

    # ------------------------------------------------------------------ #
    #  Signals & Timer                                                     #
    # ------------------------------------------------------------------ #

    def _connect_signals(self) -> None:
        """Set up the one-second auto-refresh timer."""
        self._timer.setInterval(1000)
        self._timer.timeout.connect(self._refresh)
        self._timer.start()

    # ------------------------------------------------------------------ #
    #  Data Refresh                                                        #
    # ------------------------------------------------------------------ #

    def _refresh(self) -> None:
        """Pull current values from services and update all cards."""
        state = app_state.snapshot()

        # App status
        app_status_str = state["app_status"]
        self._cards["app_status"].set_value(app_status_str)
        self._cards["app_status"].set_value_colour(
            theme_service.get_status_colour(app_status_str)
        )

        # DB status
        db_status_str = state["db_status"]
        self._cards["db_status"].set_value(db_status_str)
        self._cards["db_status"].set_value_colour(
            theme_service.get_status_colour(db_status_str)
        )

        # Network interface
        self._cards["interface"].set_value(
            config_service.get("selected_interface", "—")
        )

        # Packet counters
        self._cards["captured"].set_value(str(state["packets_captured"]))
        self._cards["allowed"].set_value(str(state["packets_allowed"]))
        self._cards["blocked"].set_value(str(state["packets_blocked"]))

        # System time
        self._cards["time"].set_value(state["system_time"])

        # Version
        self._cards["version"].set_value(
            f"v{config_service.get('app_version', '1.0.0')}"
        )

    def stop_timer(self) -> None:
        """Stop the refresh timer. Call this when the page is hidden."""
        self._timer.stop()

    def start_timer(self) -> None:
        """Restart the refresh timer when the page becomes visible."""
        if not self._timer.isActive():
            self._timer.start()
