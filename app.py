"""
VoltGuard – Physics-Aware ICS/SCADA Intrusion Detection System
================================================================
Main application entry point.

Responsibilities:
  - Bootstrap logging and the database connection
  - Construct the main window (navigation sidebar + content stack)
  - Apply the global dark theme stylesheet
  - Start the Qt event loop
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Optional

from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QFont, QFontDatabase, QIcon, QColor, QPalette
from PySide6.QtWidgets import (
    QApplication,
    QFrame,
    QHBoxLayout,
    QLabel,
    QMainWindow,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QStackedWidget,
    QVBoxLayout,
    QWidget,
)

# ---------------------------------------------------------------------------
# Ensure the project root is on sys.path when launched directly
# ---------------------------------------------------------------------------
_ROOT = Path(__file__).resolve().parent
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

# ---------------------------------------------------------------------------
# Initialise core services (logging → database)
# ---------------------------------------------------------------------------
from core.logger import setup_root_logging, get_logger
from database.database import get_db
from config.config_manager import get_config, APP_VERSION

setup_root_logging()
log = get_logger(__name__)

# ---------------------------------------------------------------------------
# UI pages
# ---------------------------------------------------------------------------
from ui.dashboard import DashboardPage
from ui.packet_monitor import PacketMonitorPage
from ui.physics_monitor import PhysicsMonitorPage
from ui.analytics import AnalyticsPage
from ui.reports import ReportsPage
from ui.settings import SettingsPage


# ===========================================================================
# Dark theme stylesheet
# ===========================================================================

DARK_STYLESHEET = """
/* ─── Palette ─────────────────────────────────────────── */
/* bg-deep:    #0D1117  bg-card:  #1A1F2E  bg-hover: #21283B */
/* border:     #2D3748  text:     #E2E8F0  muted:    #6B7280 */
/* accent:     #00D4FF  green:    #00E676  red:      #EF4444 */
/* amber:      #F59E0B  purple:   #8B5CF6  orange:   #F97316 */

QMainWindow, QWidget {
    background-color: #0D1117;
    color: #E2E8F0;
    font-family: "Inter", "Segoe UI", "SF Pro Display", sans-serif;
    font-size: 13px;
}

QScrollArea {
    background: transparent;
    border: none;
}
QScrollArea > QWidget > QWidget {
    background: transparent;
}
QScrollBar:vertical {
    background: #161B27;
    width: 8px;
    border-radius: 4px;
}
QScrollBar::handle:vertical {
    background: #2D3748;
    border-radius: 4px;
    min-height: 24px;
}
QScrollBar::handle:vertical:hover {
    background: #4A5568;
}
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QScrollBar::add-page:vertical, QScrollBar::sub-page:vertical { background: none; }

/* ─── Sidebar ──────────────────────────────────────────── */
#Sidebar {
    background-color: #111827;
    border-right: 1px solid #1F2937;
    min-width: 220px;
    max-width: 220px;
}

#AppLogoBox {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                 stop:0 #0A2540, stop:1 #0D1B2A);
    border-bottom: 1px solid #1F2937;
    padding: 4px;
}

#AppName {
    font-size: 18px;
    font-weight: 700;
    color: #00D4FF;
    letter-spacing: 1px;
}
#AppSubtitle {
    font-size: 10px;
    color: #4B5563;
    letter-spacing: 0.5px;
}

#NavButton {
    background: transparent;
    color: #9CA3AF;
    border: none;
    border-radius: 8px;
    padding: 10px 16px;
    text-align: left;
    font-size: 13px;
    font-weight: 500;
}
#NavButton:hover {
    background-color: #1F2937;
    color: #E2E8F0;
}
#NavButton[active="true"] {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                 stop:0 #0A2540, stop:1 transparent);
    color: #00D4FF;
    border-left: 3px solid #00D4FF;
    font-weight: 600;
}

#SidebarVersion {
    color: #374151;
    font-size: 10px;
    padding: 8px 16px;
}

/* ─── Page titles ──────────────────────────────────────── */
#PageTitle {
    font-size: 24px;
    font-weight: 700;
    color: #F1F5F9;
    letter-spacing: -0.3px;
}
#SectionLabel {
    font-size: 13px;
    font-weight: 600;
    color: #9CA3AF;
    text-transform: uppercase;
    letter-spacing: 0.8px;
}
#FieldLabel {
    color: #9CA3AF;
    font-size: 12px;
}
#SmallMuted {
    color: #6B7280;
    font-size: 12px;
}
#StatusText {
    font-size: 13px;
    font-weight: 600;
    color: #6B7280;
}

/* ─── Cards ────────────────────────────────────────────── */
#StatCard, #GaugeCard, #SettingsCard {
    background-color: #1A1F2E;
    border: 1px solid #252D3D;
    border-radius: 10px;
}
#StatCard:hover, #GaugeCard:hover {
    border-color: #2D3748;
}
#StatCardTitle {
    font-size: 11px;
    color: #6B7280;
    font-weight: 500;
    text-transform: uppercase;
    letter-spacing: 0.6px;
}
#StatCardValue {
    font-size: 28px;
    font-weight: 700;
    letter-spacing: -0.5px;
}
#StatCardSub {
    font-size: 11px;
    color: #4B5563;
}

/* ─── Status banner ────────────────────────────────────── */
#StatusBanner {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                 stop:0 #0A2540, stop:1 #1A1F2E);
    border: 1px solid #00D4FF30;
    border-radius: 8px;
}
#BannerText {
    font-size: 13px;
    font-weight: 600;
    color: #00D4FF;
}
#BannerVersion {
    font-size: 12px;
    color: #4B5563;
}

/* ─── Activity feed ────────────────────────────────────── */
#ActivityHeader {
    background-color: #161B27;
    border: 1px solid #252D3D;
    border-radius: 6px;
}
#ActivityHeaderLabel {
    font-size: 11px;
    font-weight: 600;
    color: #6B7280;
    text-transform: uppercase;
    letter-spacing: 0.5px;
}
#ActivityRow {
    background-color: #1A1F2E;
    border: 1px solid #1F2937;
    border-radius: 5px;
}
#ActivityRow:hover {
    background-color: #21283B;
    border-color: #2D3748;
}
#ActivityTs {
    font-size: 11px;
    color: #6B7280;
    font-family: "Courier New", monospace;
}
#ActivityText {
    font-size: 12px;
    color: #CBD5E1;
}
#ActivityAction {
    font-size: 12px;
}

/* ─── Controls bar ─────────────────────────────────────── */
#ControlsBar {
    background-color: #161B27;
    border: 1px solid #252D3D;
    border-radius: 8px;
}

/* ─── Buttons ──────────────────────────────────────────── */
#PrimaryButton {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                 stop:0 #0070C0, stop:1 #00A8E8);
    color: #FFFFFF;
    border: none;
    border-radius: 7px;
    padding: 8px 18px;
    font-size: 13px;
    font-weight: 600;
}
#PrimaryButton:hover {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                 stop:0 #0080D8, stop:1 #00C0FF);
}
#PrimaryButton:pressed {
    background-color: #005EA0;
}
#PrimaryButton:disabled {
    background-color: #1F2937;
    color: #4B5563;
}

#DangerButton {
    background-color: #7F1D1D;
    color: #FCA5A5;
    border: none;
    border-radius: 7px;
    padding: 8px 18px;
    font-size: 13px;
    font-weight: 600;
}
#DangerButton:hover {
    background-color: #991B1B;
    color: #FECACA;
}
#DangerButton:disabled {
    background-color: #1F2937;
    color: #4B5563;
}

#SecondaryButton {
    background-color: #1F2937;
    color: #9CA3AF;
    border: 1px solid #374151;
    border-radius: 7px;
    padding: 8px 16px;
    font-size: 13px;
}
#SecondaryButton:hover {
    background-color: #374151;
    color: #E2E8F0;
    border-color: #4B5563;
}

/* ─── Tables ───────────────────────────────────────────── */
#PacketTable {
    background-color: #161B27;
    alternate-background-color: #1A1F2E;
    border: 1px solid #252D3D;
    border-radius: 8px;
    gridline-color: #1F2937;
    selection-background-color: #1E3A5F;
    selection-color: #E2E8F0;
    font-size: 12px;
}
#PacketTable QHeaderView::section {
    background-color: #0F1420;
    color: #6B7280;
    border: none;
    border-bottom: 1px solid #252D3D;
    border-right: 1px solid #1F2937;
    padding: 8px 12px;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.4px;
}
#PacketTable::item {
    padding: 6px 12px;
    border: none;
}
#PacketTable::item:selected {
    background-color: #1E3A5F;
}

/* ─── Form controls ────────────────────────────────────── */
QComboBox#VGCombo {
    background-color: #1F2937;
    color: #E2E8F0;
    border: 1px solid #374151;
    border-radius: 6px;
    padding: 6px 10px;
    font-size: 13px;
    min-height: 30px;
}
QComboBox#VGCombo:hover {
    border-color: #4B5563;
}
QComboBox#VGCombo::drop-down {
    border: none;
    width: 24px;
}
QComboBox#VGCombo QAbstractItemView {
    background-color: #1F2937;
    border: 1px solid #374151;
    color: #E2E8F0;
    selection-background-color: #2D3748;
}

QDoubleSpinBox#VGSpinBox {
    background-color: #1F2937;
    color: #E2E8F0;
    border: 1px solid #374151;
    border-radius: 6px;
    padding: 5px 8px;
    font-size: 13px;
    min-width: 90px;
}
QDoubleSpinBox#VGSpinBox:focus {
    border-color: #00D4FF;
}

QCheckBox#VGCheckBox {
    color: #E2E8F0;
    font-size: 13px;
    spacing: 8px;
}
QCheckBox#VGCheckBox::indicator {
    width: 18px;
    height: 18px;
    border: 2px solid #374151;
    border-radius: 4px;
    background-color: #1F2937;
}
QCheckBox#VGCheckBox::indicator:checked {
    background-color: #00D4FF;
    border-color: #00D4FF;
}

/* ─── Gauge section ────────────────────────────────────── */
#GaugeStatus {
    font-size: 12px;
}

/* ─── Message boxes ────────────────────────────────────── */
QMessageBox {
    background-color: #1A1F2E;
    color: #E2E8F0;
}
QMessageBox QPushButton {
    background-color: #1F2937;
    color: #E2E8F0;
    border: 1px solid #374151;
    border-radius: 6px;
    padding: 6px 16px;
    min-width: 70px;
}
QMessageBox QPushButton:hover {
    background-color: #374151;
}
"""


# ===========================================================================
# Navigation button
# ===========================================================================

class NavButton(QPushButton):
    """Sidebar navigation button with active-state styling."""

    def __init__(self, icon: str, label: str, parent: Optional[QWidget] = None) -> None:
        super().__init__(f"  {icon}  {label}", parent)
        self.setObjectName("NavButton")
        self.setCheckable(False)
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(42)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def set_active(self, active: bool) -> None:
        """Toggle the visual active state."""
        self.setProperty("active", "true" if active else "false")
        self.style().unpolish(self)
        self.style().polish(self)


# ===========================================================================
# Main window
# ===========================================================================

class MainWindow(QMainWindow):
    """VoltGuard main application window.

    Layout:
      ┌─────────────┬──────────────────────────────────────┐
      │  Sidebar    │  Content stack (one page per nav btn) │
      │  (nav btns) │                                       │
      └─────────────┴──────────────────────────────────────┘
    """

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"VoltGuard IDS  v{APP_VERSION}")
        self.setMinimumSize(1200, 720)
        self.resize(1400, 850)
        self._setup_ui()
        self._navigate(0)  # open dashboard

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QHBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        root.addWidget(self._build_sidebar())
        root.addWidget(self._build_content())

    def _build_sidebar(self) -> QWidget:
        sidebar = QWidget()
        sidebar.setObjectName("Sidebar")
        layout = QVBoxLayout(sidebar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Logo area
        logo_box = QWidget()
        logo_box.setObjectName("AppLogoBox")
        logo_box.setFixedHeight(72)
        logo_layout = QVBoxLayout(logo_box)
        logo_layout.setContentsMargins(16, 10, 16, 10)
        logo_layout.setSpacing(2)
        logo_name = QLabel("⚡ VoltGuard")
        logo_name.setObjectName("AppName")
        logo_sub = QLabel("ICS/SCADA IDS")
        logo_sub.setObjectName("AppSubtitle")
        logo_layout.addWidget(logo_name)
        logo_layout.addWidget(logo_sub)
        layout.addWidget(logo_box)

        layout.addSpacing(12)

        # Navigation buttons
        nav_items = [
            ("🏠", "Dashboard"),
            ("📡", "Packet Monitor"),
            ("⚙️", "Physics Monitor"),
            ("📊", "Analytics"),
            ("📋", "Reports"),
            ("🔧", "Settings"),
        ]
        self._nav_buttons: list[NavButton] = []
        for icon, label in nav_items:
            btn = NavButton(icon, label)
            btn.clicked.connect(lambda checked, idx=len(self._nav_buttons): self._navigate(idx))
            self._nav_buttons.append(btn)
            btn_wrapper = QWidget()
            wrapper_layout = QHBoxLayout(btn_wrapper)
            wrapper_layout.setContentsMargins(8, 2, 8, 2)
            wrapper_layout.addWidget(btn)
            layout.addWidget(btn_wrapper)

        layout.addStretch()

        # Version footer
        ver_label = QLabel(f"VoltGuard v{APP_VERSION}")
        ver_label.setObjectName("SidebarVersion")
        layout.addWidget(ver_label)

        return sidebar

    def _build_content(self) -> QWidget:
        self._stack = QStackedWidget()

        # Instantiate all pages
        self._page_dashboard = DashboardPage()
        self._page_packets = PacketMonitorPage()
        self._page_physics = PhysicsMonitorPage()
        self._page_analytics = AnalyticsPage()
        self._page_reports = ReportsPage()
        self._page_settings = SettingsPage()

        for page in (
            self._page_dashboard,
            self._page_packets,
            self._page_physics,
            self._page_analytics,
            self._page_reports,
            self._page_settings,
        ):
            self._stack.addWidget(page)

        return self._stack

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------

    def _navigate(self, index: int) -> None:
        """Switch to the page at *index* and update nav button states.

        Args:
            index: Zero-based index into :attr:`_nav_buttons` and :attr:`_stack`.
        """
        self._stack.setCurrentIndex(index)
        for i, btn in enumerate(self._nav_buttons):
            btn.set_active(i == index)

        # Sync dashboard capture indicator with live packet monitor state
        capture = self._page_packets.get_capture()
        self._page_dashboard.set_capture_state(capture.is_running)

        log.debug("Navigated to page index %d", index)


# ===========================================================================
# Application bootstrap
# ===========================================================================

def main() -> None:
    """Application entry point."""
    # Initialise database singleton (creates tables if first run)
    db = get_db()
    log.info("VoltGuard starting — version %s", APP_VERSION)

    app = QApplication(sys.argv)
    app.setApplicationName("VoltGuard")
    app.setApplicationVersion(APP_VERSION)
    app.setOrganizationName("VoltGuard IDS")
    app.setStyle("Fusion")  # Consistent cross-platform base

    # Apply dark palette baseline so native widgets inherit it
    palette = QPalette()
    palette.setColor(QPalette.Window, QColor("#0D1117"))
    palette.setColor(QPalette.WindowText, QColor("#E2E8F0"))
    palette.setColor(QPalette.Base, QColor("#161B27"))
    palette.setColor(QPalette.AlternateBase, QColor("#1A1F2E"))
    palette.setColor(QPalette.Text, QColor("#E2E8F0"))
    palette.setColor(QPalette.Button, QColor("#1F2937"))
    palette.setColor(QPalette.ButtonText, QColor("#E2E8F0"))
    palette.setColor(QPalette.Highlight, QColor("#00D4FF"))
    palette.setColor(QPalette.HighlightedText, QColor("#0D1117"))
    app.setPalette(palette)

    # Apply full stylesheet
    app.setStyleSheet(DARK_STYLESHEET)

    window = MainWindow()
    window.show()

    log.info("VoltGuard GUI launched successfully.")
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
