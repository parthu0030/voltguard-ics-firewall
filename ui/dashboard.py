"""
VoltGuard Dashboard UI
-----------------------
Live dashboard showing system status, packet counters, recent activity,
and a live status indicator. Refreshes every 2 seconds via a QTimer.
"""

from __future__ import annotations

from datetime import datetime
from typing import Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QColor, QFont, QPainter
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from database.database import get_db
from config.config_manager import get_config, APP_VERSION


# ---------------------------------------------------------------------------
# Reusable card widget
# ---------------------------------------------------------------------------

class StatCard(QFrame):
    """Metric card displaying a title, large value, and optional subtitle."""

    def __init__(
        self,
        title: str,
        value: str = "0",
        subtitle: str = "",
        accent: str = "#00D4FF",
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._accent = accent
        self.setObjectName("StatCard")
        self.setFixedHeight(110)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 14, 20, 14)
        layout.setSpacing(4)

        self._title_label = QLabel(title)
        self._title_label.setObjectName("StatCardTitle")

        self._value_label = QLabel(value)
        self._value_label.setObjectName("StatCardValue")
        self._value_label.setStyleSheet(f"color: {accent};")

        self._sub_label = QLabel(subtitle)
        self._sub_label.setObjectName("StatCardSub")

        layout.addWidget(self._title_label)
        layout.addWidget(self._value_label)
        layout.addWidget(self._sub_label)

    def set_value(self, value: str) -> None:
        """Update the primary numeric/text value displayed."""
        self._value_label.setText(value)

    def set_subtitle(self, subtitle: str) -> None:
        """Update the subtitle line."""
        self._sub_label.setText(subtitle)


class LiveIndicator(QWidget):
    """Animated pulsing dot that indicates live / stopped capture state."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setFixedSize(14, 14)
        self._active = False
        self._alpha = 255
        self._increasing = False

        self._anim_timer = QTimer(self)
        self._anim_timer.timeout.connect(self._pulse)
        self._anim_timer.start(60)

    def set_active(self, active: bool) -> None:
        """Switch between live (green pulsing) and stopped (red static) states."""
        self._active = active

    def _pulse(self) -> None:
        if not self._active:
            self._alpha = 180
            self.update()
            return
        step = 8
        if self._increasing:
            self._alpha = min(255, self._alpha + step)
            if self._alpha >= 255:
                self._increasing = False
        else:
            self._alpha = max(80, self._alpha - step)
            if self._alpha <= 80:
                self._increasing = True
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.Antialiasing)
        color = QColor(0, 230, 118, self._alpha) if self._active else QColor(239, 68, 68, self._alpha)
        painter.setBrush(color)
        painter.setPen(Qt.NoPen)
        painter.drawEllipse(0, 0, 14, 14)


class ActivityRow(QFrame):
    """Single row in the Recent Activity feed."""

    def __init__(
        self,
        timestamp: str,
        src: str,
        dst: str,
        protocol: str,
        action: str,
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("ActivityRow")
        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 6, 12, 6)
        layout.setSpacing(12)

        action_color = "#00E676" if action == "ALLOWED" else "#EF4444"

        ts_label = QLabel(timestamp)
        ts_label.setObjectName("ActivityTs")
        ts_label.setFixedWidth(145)

        src_label = QLabel(src or "—")
        src_label.setObjectName("ActivityText")
        src_label.setFixedWidth(120)

        dst_label = QLabel(dst or "—")
        dst_label.setObjectName("ActivityText")
        dst_label.setFixedWidth(120)

        proto_label = QLabel(protocol or "—")
        proto_label.setObjectName("ActivityText")
        proto_label.setFixedWidth(80)

        action_label = QLabel(action)
        action_label.setObjectName("ActivityAction")
        action_label.setStyleSheet(f"color: {action_color}; font-weight: 600;")

        for w in (ts_label, src_label, dst_label, proto_label, action_label):
            layout.addWidget(w)
        layout.addStretch()


# ---------------------------------------------------------------------------
# Dashboard page
# ---------------------------------------------------------------------------

class DashboardPage(QWidget):
    """Main dashboard page.

    Displays:
    - System Status banner
    - Stat cards: Total / Blocked / Allowed packets + interface + version
    - Live status indicator
    - Recent Activity feed (last 20 packets)
    """

    REFRESH_MS = 2000  # refresh interval in milliseconds

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._db = get_db()
        self._config = get_config()
        self._capture_running: bool = False
        self._setup_ui()
        self._start_refresh()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)
        outer.setSpacing(0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        container = QWidget()
        self._main_layout = QVBoxLayout(container)
        self._main_layout.setContentsMargins(28, 24, 28, 24)
        self._main_layout.setSpacing(20)

        scroll.setWidget(container)
        outer.addWidget(scroll)

        self._build_header()
        self._build_status_banner()
        self._build_stat_cards()
        self._build_activity_section()
        self._main_layout.addStretch()

    def _build_header(self) -> None:
        row = QHBoxLayout()
        row.setSpacing(10)

        title = QLabel("Dashboard")
        title.setObjectName("PageTitle")

        self._indicator = LiveIndicator()
        self._status_text = QLabel("Capture Stopped")
        self._status_text.setObjectName("StatusText")

        self._last_updated = QLabel("")
        self._last_updated.setObjectName("SmallMuted")

        row.addWidget(title)
        row.addStretch()
        row.addWidget(self._indicator)
        row.addWidget(self._status_text)
        row.addSpacing(20)
        row.addWidget(self._last_updated)

        self._main_layout.addLayout(row)

    def _build_status_banner(self) -> None:
        self._banner = QFrame()
        self._banner.setObjectName("StatusBanner")
        self._banner.setFixedHeight(52)

        banner_layout = QHBoxLayout(self._banner)
        banner_layout.setContentsMargins(20, 0, 20, 0)

        self._banner_label = QLabel("⚡  VoltGuard IDS — System Initialised")
        self._banner_label.setObjectName("BannerText")
        banner_layout.addWidget(self._banner_label)
        banner_layout.addStretch()

        version_label = QLabel(f"v{APP_VERSION}")
        version_label.setObjectName("BannerVersion")
        banner_layout.addWidget(version_label)

        self._main_layout.addWidget(self._banner)

    def _build_stat_cards(self) -> None:
        cfg = self._config.load()

        row1 = QHBoxLayout()
        row1.setSpacing(16)

        self._card_total = StatCard("Total Packets", "0", "All captured traffic", "#00D4FF")
        self._card_blocked = StatCard("Blocked Packets", "0", "Policy violations", "#EF4444")
        self._card_allowed = StatCard("Allowed Packets", "0", "Permitted traffic", "#00E676")

        for card in (self._card_total, self._card_blocked, self._card_allowed):
            row1.addWidget(card)

        row2 = QHBoxLayout()
        row2.setSpacing(16)

        iface = cfg.interface if cfg.interface != "auto" else "System Default"
        self._card_interface = StatCard("Network Interface", iface, "Selected interface", "#F59E0B")
        self._card_version = StatCard("App Version", f"v{cfg.app_version}", "VoltGuard IDS", "#8B5CF6")
        self._card_alerts = StatCard("Active Alerts", "0", "Unacknowledged", "#F97316")

        for card in (self._card_interface, self._card_version, self._card_alerts):
            row2.addWidget(card)

        self._main_layout.addLayout(row1)
        self._main_layout.addLayout(row2)

    def _build_activity_section(self) -> None:
        section_label = QLabel("Recent Activity")
        section_label.setObjectName("SectionLabel")
        self._main_layout.addWidget(section_label)

        # Column header row
        header = QFrame()
        header.setObjectName("ActivityHeader")
        h_layout = QHBoxLayout(header)
        h_layout.setContentsMargins(12, 6, 12, 6)
        h_layout.setSpacing(12)

        for col, width in (
            ("Timestamp", 145),
            ("Source IP", 120),
            ("Destination IP", 120),
            ("Protocol", 80),
            ("Action", 80),
        ):
            lbl = QLabel(col)
            lbl.setObjectName("ActivityHeaderLabel")
            lbl.setFixedWidth(width)
            h_layout.addWidget(lbl)
        h_layout.addStretch()

        self._main_layout.addWidget(header)

        # Scrollable activity feed container
        self._activity_container = QWidget()
        self._activity_layout = QVBoxLayout(self._activity_container)
        self._activity_layout.setContentsMargins(0, 0, 0, 0)
        self._activity_layout.setSpacing(2)
        self._activity_layout.addStretch()

        self._main_layout.addWidget(self._activity_container)

    # ------------------------------------------------------------------
    # Data refresh
    # ------------------------------------------------------------------

    def _start_refresh(self) -> None:
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(self.REFRESH_MS)
        self._refresh()  # immediate first paint

    def _refresh(self) -> None:
        """Pull fresh data from the database and update all widgets."""
        try:
            stats = self._db.get_packet_stats()
            alert_count = self._db.get_unacknowledged_alert_count()

            self._card_total.set_value(str(stats["total"]))
            self._card_blocked.set_value(str(stats["blocked"]))
            self._card_allowed.set_value(str(stats["allowed"]))
            self._card_alerts.set_value(str(alert_count))

            # Update interface label
            iface = self._config.get_interface()
            display_iface = iface if iface != "auto" else "System Default"
            self._card_interface.set_value(display_iface)

            # Update live indicator
            self._indicator.set_active(self._capture_running)
            self._status_text.setText("Capture Running" if self._capture_running else "Capture Stopped")

            # Timestamp
            self._last_updated.setText(
                "Updated " + datetime.utcnow().strftime("%H:%M:%S") + " UTC"
            )

            # Update activity feed
            self._refresh_activity()

        except Exception as exc:
            # Swallow errors to keep the UI alive
            pass

    def _refresh_activity(self) -> None:
        """Rebuild the recent-activity list from the latest 20 packet records."""
        packets = self._db.get_recent_packets(limit=20)

        # Remove all existing rows (keep the stretch at the end)
        while self._activity_layout.count() > 1:
            item = self._activity_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        for pkt in reversed(packets):
            row = ActivityRow(
                timestamp=str(pkt["timestamp"] or ""),
                src=str(pkt["src_ip"] or ""),
                dst=str(pkt["dst_ip"] or ""),
                protocol=str(pkt["protocol"] or ""),
                action=str(pkt["action"] or "ALLOWED"),
            )
            self._activity_layout.insertWidget(0, row)

        if not packets:
            placeholder = QLabel("No traffic captured yet — start a capture session.")
            placeholder.setObjectName("SmallMuted")
            placeholder.setAlignment(Qt.AlignCenter)
            self._activity_layout.insertWidget(0, placeholder)

    # ------------------------------------------------------------------
    # External control
    # ------------------------------------------------------------------

    def set_capture_state(self, running: bool) -> None:
        """Notify the dashboard whether capture is currently active.

        Args:
            running: ``True`` if packet capture is running.
        """
        self._capture_running = running
