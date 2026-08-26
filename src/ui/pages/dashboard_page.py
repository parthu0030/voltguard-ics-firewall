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

from typing import Optional

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QFont
from PyQt6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.core.app_state import app_state
from src.models.app_models import AlertSeverity
from src.services.alert_manager import alert_manager
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

    Displays an expanded grid of live status cards, security alert summaries,
    and a real-time security events table.
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

        # ---- Recent Security Alerts section ----------------------------- #
        layout.addWidget(self._build_alerts_section())
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

        subtitle = QLabel("Live ICS/SCADA security posture and real-time alert monitoring.")
        subtitle.setStyleSheet(
            "font-size: 13px; color: #8B949E; background: transparent;"
        )
        h_layout.addWidget(subtitle)

        return header

    def _build_cards_grid(self) -> QWidget:
        """Build the grid of status cards."""
        grid_widget = QWidget()
        grid_widget.setStyleSheet("background: transparent;")
        grid = QGridLayout(grid_widget)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(14)

        # Card definitions: (key, title, icon, initial_value, accent)
        card_defs = [
            ("app_status",     "Application Status",       "🛡",  "Idle",    "#58A6FF"),
            ("db_status",      "Database Status",           "🗄",  "—",       "#3FB950"),
            ("captured",       "Packets Captured",          "📡",  "0",       "#BC8CFF"),
            ("allowed",        "Allowed Packets",           "✅",  "0",       "#3FB950"),
            ("blocked",        "Blocked Packets",           "🚫",  "0",       "#F85149"),
            ("unack_alerts",   "Active Alerts",             "⚠️",  "0",       "#F0883E"),
            ("crit_alerts",    "Critical Violations",       "🚨",  "0",       "#FF7B72"),
            ("time",           "System Time",               "🕐",  "—",       "#58A6FF"),
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

    def _build_alerts_section(self) -> QWidget:
        """Build the recent security alerts panel."""
        panel = QFrame()
        panel.setStyleSheet(
            """
            QFrame {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 10px;
                padding: 16px;
            }
            """
        )
        layout = QVBoxLayout(panel)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(12)

        # Section Header
        hdr = QHBoxLayout()
        title = QLabel("Recent Security Alerts & Incidents")
        title.setStyleSheet("font-size: 15px; font-weight: 700; color: #E6EDF3; border: none;")
        hdr.addWidget(title)
        hdr.addStretch()

        self._ack_all_btn = QPushButton("Acknowledge All")
        self._ack_all_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        self._ack_all_btn.setStyleSheet(
            """
            QPushButton {
                background-color: #21262D;
                color: #C9D1D9;
                border: 1px solid #30363D;
                border-radius: 6px;
                padding: 5px 12px;
                font-size: 12px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #30363D;
                color: #58A6FF;
            }
            """
        )
        self._ack_all_btn.clicked.connect(self._on_ack_all_clicked)
        hdr.addWidget(self._ack_all_btn)
        layout.addLayout(hdr)

        # Table for alerts
        self._alerts_table = QTableWidget()
        self._alerts_table.setColumnCount(6)
        self._alerts_table.setHorizontalHeaderLabels([
            "Time", "Severity", "Action", "Source → Dest", "Description", "Status"
        ])
        self._alerts_table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self._alerts_table.horizontalHeader().setDefaultSectionSize(110)
        self._alerts_table.verticalHeader().setVisible(False)
        self._alerts_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._alerts_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._alerts_table.setMinimumHeight(180)
        self._alerts_table.setStyleSheet(
            """
            QTableWidget {
                background-color: #0D1117;
                color: #C9D1D9;
                gridline-color: #21262D;
                border: 1px solid #30363D;
                border-radius: 6px;
                font-size: 12px;
            }
            QHeaderView::section {
                background-color: #161B22;
                color: #8B949E;
                font-weight: 600;
                font-size: 11px;
                border: none;
                border-bottom: 1px solid #30363D;
                padding: 6px;
            }
            """
        )
        layout.addWidget(self._alerts_table)

        return panel

    def _on_ack_all_clicked(self) -> None:
        """Handler for Acknowledge All button."""
        try:
            alert_manager.acknowledge_all_alerts()
            self._refresh()
        except Exception:
            pass

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
        """Pull current values from services and update all cards and tables."""
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

        # Packet counters
        self._cards["captured"].set_value(str(state["packets_captured"]))
        self._cards["allowed"].set_value(str(state["packets_allowed"]))
        self._cards["blocked"].set_value(str(state["packets_blocked"]))

        # Alerts summary
        try:
            unack_count = alert_manager.get_unacknowledged_count()
            self._cards["unack_alerts"].set_value(str(unack_count))
            self._cards["crit_alerts"].set_value(str(app_state.critical_alerts))
        except Exception:
            self._cards["unack_alerts"].set_value("0")
            self._cards["crit_alerts"].set_value("0")

        # System time
        self._cards["time"].set_value(state["system_time"])

        # Populate Alerts Table
        try:
            alerts = alert_manager.get_recent_alerts(limit=5)
            self._alerts_table.setRowCount(len(alerts))
            for row_idx, alert in enumerate(alerts):
                # Time
                time_item = QTableWidgetItem(alert.timestamp.split("T")[-1] if "T" in alert.timestamp else alert.timestamp)
                self._alerts_table.setItem(row_idx, 0, time_item)

                # Severity
                sev_item = QTableWidgetItem(alert.severity.value)
                sev_color = {
                    AlertSeverity.CRITICAL: "#FF7B72",
                    AlertSeverity.HIGH: "#F85149",
                    AlertSeverity.MEDIUM: "#F0883E",
                    AlertSeverity.LOW: "#58A6FF",
                }.get(alert.severity, "#C9D1D9")
                sev_item.setForeground(QColor(sev_color))
                self._alerts_table.setItem(row_idx, 1, sev_item)

                # Action
                act_item = QTableWidgetItem(alert.action or "ALERT")
                act_color = "#F85149" if alert.action == "BLOCK" else "#F0883E"
                act_item.setForeground(QColor(act_color))
                self._alerts_table.setItem(row_idx, 2, act_item)

                # Endpoints
                ep_text = f"{alert.source_ip} → {alert.destination_ip}" if alert.source_ip else "—"
                self._alerts_table.setItem(row_idx, 3, QTableWidgetItem(ep_text))

                # Message
                rep = f" (×{alert.repeat_count})" if alert.repeat_count > 1 else ""
                self._alerts_table.setItem(row_idx, 4, QTableWidgetItem(f"{alert.message}{rep}"))

                # Status
                status_text = "Acknowledged" if alert.acknowledged else "Active"
                status_item = QTableWidgetItem(status_text)
                status_item.setForeground(QColor("#8B949E" if alert.acknowledged else "#F0883E"))
                self._alerts_table.setItem(row_idx, 5, status_item)
        except Exception:
            pass

    def stop_timer(self) -> None:
        """Stop the refresh timer. Call this when the page is hidden."""
        self._timer.stop()

    def start_timer(self) -> None:
        """Restart the refresh timer when the page becomes visible."""
        if not self._timer.isActive():
            self._timer.start()
