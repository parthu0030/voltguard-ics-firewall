"""
VoltGuard — Main Window
=========================
Implements the application's top-level ``QMainWindow``.

Layout:
  ┌─────────────────────────────────────────────┐
  │  Toolbar (App Title + Status Indicator)      │
  ├───────────┬─────────────────────────────────┤
  │  Sidebar  │   Central Content Area          │
  │ (220 px)  │   (QStackedWidget — 6 pages)    │
  ├───────────┴─────────────────────────────────┤
  │  Status Bar (DB status · Interface · Time)  │
  └─────────────────────────────────────────────┘

Architecture:
  - MainWindow is responsible only for window assembly and signal wiring.
  - All business logic lives in the service layer.
  - All data display logic lives in individual page widgets.
  - The MainWindow never reads from the database directly.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QAction, QFont, QIcon
from PyQt6.QtWidgets import (
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QStackedWidget,
    QStatusBar,
    QToolBar,
    QWidget,
)

from src.core.app_state import app_state
from src.services.config_service import config_service
from src.ui.pages.analytics_page import AnalyticsPage
from src.ui.pages.dashboard_page import DashboardPage
from src.ui.pages.packet_monitor_page import PacketMonitorPage
from src.ui.pages.physics_monitor_page import PhysicsMonitorPage
from src.ui.pages.reports_page import ReportsPage
from src.ui.pages.settings_page import SettingsPage
from src.ui.sidebar import Sidebar


class MainWindow(QMainWindow):
    """
    VoltGuard main application window.

    Assembles the toolbar, sidebar, content area, and status bar.
    Wires the sidebar's ``page_changed`` signal to the stacked widget
    so navigation switches pages correctly.
    """

    WINDOW_TITLE = (
        "VoltGuard — Physics-Aware ICS/SCADA Intrusion Prevention System"
    )
    WINDOW_MIN_WIDTH  = 1200
    WINDOW_MIN_HEIGHT = 720
    STATUS_REFRESH_MS = 1000  # Status bar refresh interval.

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._build_window()
        self._build_toolbar()
        self._build_central_area()
        self._build_status_bar()
        self._connect_signals()
        self._start_status_timer()

    # ------------------------------------------------------------------ #
    #  Window Setup                                                        #
    # ------------------------------------------------------------------ #

    def _build_window(self) -> None:
        """Configure the top-level window properties."""
        self.setWindowTitle(self.WINDOW_TITLE)
        self.setMinimumSize(self.WINDOW_MIN_WIDTH, self.WINDOW_MIN_HEIGHT)
        self.resize(1400, 860)

    # ------------------------------------------------------------------ #
    #  Toolbar                                                             #
    # ------------------------------------------------------------------ #

    def _build_toolbar(self) -> None:
        """Build and add the top application toolbar."""
        toolbar = QToolBar("Main Toolbar")
        toolbar.setMovable(False)
        toolbar.setFloatable(False)
        toolbar.setObjectName("MainToolbar")
        toolbar.setStyleSheet(
            """
            QToolBar#MainToolbar {
                background-color: #161B22;
                border-bottom: 1px solid #30363D;
                padding: 6px 16px;
                spacing: 0px;
            }
            """
        )
        toolbar.setToolButtonStyle(Qt.ToolButtonStyle.ToolButtonTextBesideIcon)

        # App identity block
        toolbar.addWidget(self._build_toolbar_brand())
        toolbar.addSeparator()

        # Stretch spacer
        spacer = QWidget()
        spacer.setSizePolicy(
            spacer.sizePolicy().horizontalPolicy().Expanding,  # type: ignore[attr-defined]
            spacer.sizePolicy().verticalPolicy(),
        )
        from PyQt6.QtWidgets import QSizePolicy as SP
        spacer.setSizePolicy(SP.Policy.Expanding, SP.Policy.Preferred)
        toolbar.addWidget(spacer)

        # Status indicator
        self._toolbar_status_indicator = self._build_status_indicator()
        toolbar.addWidget(self._toolbar_status_indicator)

        self.addToolBar(toolbar)

    def _build_toolbar_brand(self) -> QWidget:
        """Build the application title block for the toolbar."""
        brand = QWidget()
        brand.setStyleSheet("background: transparent;")
        layout = QHBoxLayout(brand)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        shield_label = QLabel("🛡")
        shield_label.setStyleSheet("font-size: 22px; background: transparent;")
        layout.addWidget(shield_label)

        title_label = QLabel("VoltGuard")
        title_label.setStyleSheet(
            "font-size: 16px; font-weight: 800; color: #E6EDF3; "
            "letter-spacing: -0.3px; background: transparent;"
        )
        layout.addWidget(title_label)

        subtitle_label = QLabel(" — Physics-Aware ICS/SCADA IPS")
        subtitle_label.setStyleSheet(
            "font-size: 12px; color: #8B949E; background: transparent;"
        )
        layout.addWidget(subtitle_label)

        return brand

    def _build_status_indicator(self) -> QWidget:
        """Build the traffic-light style status indicator in the toolbar."""
        indicator = QWidget()
        indicator.setStyleSheet("background: transparent;")
        layout = QHBoxLayout(indicator)
        layout.setContentsMargins(0, 0, 8, 0)
        layout.setSpacing(8)

        self._indicator_dot = QLabel("●")
        self._indicator_dot.setStyleSheet(
            "color: #3FB950; font-size: 14px; background: transparent;"
        )
        layout.addWidget(self._indicator_dot)

        self._indicator_label = QLabel("System Ready")
        self._indicator_label.setStyleSheet(
            "font-size: 12px; color: #8B949E; background: transparent;"
        )
        layout.addWidget(self._indicator_label)

        return indicator

    # ------------------------------------------------------------------ #
    #  Central Area (Sidebar + Pages)                                      #
    # ------------------------------------------------------------------ #

    def _build_central_area(self) -> None:
        """Build the sidebar + stacked content area and set as central widget."""
        central = QWidget()
        central.setObjectName("CentralWidget")
        central.setStyleSheet("#CentralWidget { background-color: #0D1117; }")
        layout = QHBoxLayout(central)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Sidebar
        self._sidebar = Sidebar()
        layout.addWidget(self._sidebar)

        # Stacked pages
        self._stack = QStackedWidget()
        self._stack.setObjectName("PageStack")
        self._stack.setStyleSheet(
            "#PageStack { background-color: #0D1117; }"
        )
        layout.addWidget(self._stack, 1)

        # Instantiate all pages in order matching sidebar indices.
        self._dashboard_page = DashboardPage()
        self._packet_page    = PacketMonitorPage()
        self._physics_page   = PhysicsMonitorPage()
        self._analytics_page = AnalyticsPage()
        self._reports_page   = ReportsPage()
        self._settings_page  = SettingsPage()

        for page in [
            self._dashboard_page,
            self._packet_page,
            self._physics_page,
            self._analytics_page,
            self._reports_page,
            self._settings_page,
        ]:
            self._stack.addWidget(page)

        self.setCentralWidget(central)

    # ------------------------------------------------------------------ #
    #  Status Bar                                                          #
    # ------------------------------------------------------------------ #

    def _build_status_bar(self) -> None:
        """Build the bottom status bar with DB, interface, and time labels."""
        status_bar = QStatusBar()
        status_bar.setObjectName("AppStatusBar")
        status_bar.setSizeGripEnabled(False)

        # DB status indicator
        self._sb_db_label = QLabel("DB: Connecting…")
        self._sb_db_label.setStyleSheet("color: #8B949E; padding: 0 12px;")
        status_bar.addPermanentWidget(self._sb_db_label)

        self._sb_sep1 = QLabel("|")
        self._sb_sep1.setStyleSheet("color: #30363D;")
        status_bar.addPermanentWidget(self._sb_sep1)

        # Network interface
        self._sb_iface_label = QLabel("Interface: —")
        self._sb_iface_label.setStyleSheet("color: #8B949E; padding: 0 12px;")
        status_bar.addPermanentWidget(self._sb_iface_label)

        self._sb_sep2 = QLabel("|")
        self._sb_sep2.setStyleSheet("color: #30363D;")
        status_bar.addPermanentWidget(self._sb_sep2)

        # System time
        self._sb_time_label = QLabel("Time: —")
        self._sb_time_label.setStyleSheet("color: #8B949E; padding: 0 12px;")
        status_bar.addPermanentWidget(self._sb_time_label)

        self.setStatusBar(status_bar)

    # ------------------------------------------------------------------ #
    #  Signal Wiring                                                       #
    # ------------------------------------------------------------------ #

    def _connect_signals(self) -> None:
        """Wire sidebar navigation to the stacked widget page switcher."""
        self._sidebar.page_changed.connect(self._on_page_changed)

    def _on_page_changed(self, index: int) -> None:
        """
        Switch the central content area to the page at ``index``.

        Args:
            index: Zero-based page index from the sidebar signal.
        """
        self._stack.setCurrentIndex(index)

    # ------------------------------------------------------------------ #
    #  Status Bar Auto-refresh                                             #
    # ------------------------------------------------------------------ #

    def _start_status_timer(self) -> None:
        """Start the status bar refresh timer."""
        self._status_timer = QTimer(self)
        self._status_timer.setInterval(self.STATUS_REFRESH_MS)
        self._status_timer.timeout.connect(self._refresh_status_bar)
        self._status_timer.start()
        # Refresh once immediately.
        self._refresh_status_bar()

    def _refresh_status_bar(self) -> None:
        """Update all status bar labels from live service data."""
        state = app_state.snapshot()

        # DB status label
        db_txt = state["db_status"]
        db_colour = "#3FB950" if "connected" in db_txt.lower() else "#F85149"
        self._sb_db_label.setText(f"DB: {db_txt}")
        self._sb_db_label.setStyleSheet(
            f"color: {db_colour}; padding: 0 12px; font-size: 12px;"
        )

        # Interface
        iface = config_service.get("selected_interface", "—")
        self._sb_iface_label.setText(f"Interface: {iface}")

        # Time
        self._sb_time_label.setText(f"Time: {state['system_time']}")

        # Toolbar indicator
        app_status = state["app_status"]
        if "error" in app_status.lower() or "fail" in app_status.lower():
            dot_colour = "#F85149"
        elif "idle" in app_status.lower() or "ready" in app_status.lower():
            dot_colour = "#3FB950"
        else:
            dot_colour = "#D29922"
        self._indicator_dot.setStyleSheet(
            f"color: {dot_colour}; font-size: 14px; background: transparent;"
        )
        self._indicator_label.setText(app_status)

    # ------------------------------------------------------------------ #
    #  Clean Shutdown                                                      #
    # ------------------------------------------------------------------ #

    def closeEvent(self, event) -> None:
        """
        Perform clean shutdown tasks before the window closes.

        Stops all running timers and allows the event to propagate.
        """
        self._status_timer.stop()
        self._dashboard_page.stop_timer()
        event.accept()
