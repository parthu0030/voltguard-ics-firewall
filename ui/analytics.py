"""
VoltGuard Analytics UI
------------------------
Displays aggregate protocol distribution, packet timelines, and alert summary
using Matplotlib embedded in a PySide6 widget.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

try:
    from matplotlib.backends.backend_qtagg import FigureCanvasQTAgg as FigureCanvas
    from matplotlib.figure import Figure
    import matplotlib.pyplot as plt

    _MPL_OK = True
except Exception:
    _MPL_OK = False

from database.database import get_db
from core.logger import get_logger

log = get_logger(__name__)

_DARK_BG = "#0D1117"
_CARD_BG = "#1A1F2E"
_TEXT = "#E2E8F0"
_ACCENT_COLORS = [
    "#00D4FF", "#00E676", "#F59E0B", "#8B5CF6",
    "#F97316", "#EF4444", "#06B6D4", "#84CC16",
]


class AnalyticsPage(QWidget):
    """Analytics page with protocol distribution pie, timeline bar, and alert table."""

    REFRESH_MS = 5000

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._db = get_db()
        self._setup_ui()
        self._start_refresh()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(16)

        # Header
        header = QHBoxLayout()
        title = QLabel("Analytics")
        title.setObjectName("PageTitle")
        header.addWidget(title)
        header.addStretch()

        self._refresh_btn = QPushButton("↻  Refresh")
        self._refresh_btn.setObjectName("SecondaryButton")
        self._refresh_btn.clicked.connect(self._refresh)
        header.addWidget(self._refresh_btn)

        layout.addLayout(header)

        desc = QLabel(
            "Protocol distribution, traffic timeline, and security alert analysis. "
            "Data updates every 5 seconds."
        )
        desc.setObjectName("SmallMuted")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        if _MPL_OK:
            self._build_matplotlib_charts(layout)
        else:
            placeholder = QLabel("Matplotlib not available — install it to enable charts.")
            placeholder.setObjectName("SmallMuted")
            placeholder.setAlignment(Qt.AlignCenter)
            layout.addWidget(placeholder)

        self._build_summary_cards(layout)
        layout.addStretch()

    def _build_matplotlib_charts(self, parent_layout: QVBoxLayout) -> None:
        """Embed a Matplotlib figure with two subplots."""
        self._figure = Figure(figsize=(12, 4), facecolor=_CARD_BG)
        self._canvas = FigureCanvas(self._figure)
        self._canvas.setMinimumHeight(300)
        parent_layout.addWidget(self._canvas)
        self._ax_pie = None
        self._ax_bar = None

    def _build_summary_cards(self, parent_layout: QVBoxLayout) -> None:
        row = QHBoxLayout()
        row.setSpacing(14)

        self._card_protocols = _SummaryCard("Protocols Seen", "0")
        self._card_alerts = _SummaryCard("Total Alerts", "0")
        self._card_blocked = _SummaryCard("Blocked Packets", "0")
        self._card_sessions = _SummaryCard("Scan Sessions", "0")

        for card in (
            self._card_protocols,
            self._card_alerts,
            self._card_blocked,
            self._card_sessions,
        ):
            row.addWidget(card)

        parent_layout.addLayout(row)

    # ------------------------------------------------------------------
    # Data refresh
    # ------------------------------------------------------------------

    def _start_refresh(self) -> None:
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._refresh)
        self._timer.start(self.REFRESH_MS)
        self._refresh()

    def _refresh(self) -> None:
        """Pull data from the database and redraw charts."""
        try:
            self._refresh_summary()
            if _MPL_OK:
                self._refresh_charts()
        except Exception as exc:
            log.error("Analytics refresh error: %s", exc)

    def _refresh_summary(self) -> None:
        stats = self._db.get_packet_stats()
        sessions = self._db.get_scan_history(limit=1000)
        alerts = self._db.get_recent_alerts(limit=1000)

        # Count distinct protocols
        packets = self._db.get_recent_packets(limit=10000)
        protocols = {str(p["protocol"]) for p in packets if p["protocol"]}

        self._card_protocols.set_value(str(len(protocols)))
        self._card_alerts.set_value(str(len(alerts)))
        self._card_blocked.set_value(str(stats["blocked"]))
        self._card_sessions.set_value(str(len(sessions)))

    def _refresh_charts(self) -> None:
        self._figure.clear()

        packets = self._db.get_recent_packets(limit=10000)
        if not packets:
            self._figure.text(
                0.5, 0.5,
                "No packet data yet.\nStart a capture session to see analytics.",
                ha="center", va="center",
                color=_TEXT, fontsize=13,
            )
            self._canvas.draw()
            return

        # --- Protocol distribution (pie) ---
        proto_counts: dict[str, int] = {}
        for p in packets:
            proto = str(p["protocol"] or "UNKNOWN")
            proto_counts[proto] = proto_counts.get(proto, 0) + 1

        labels = list(proto_counts.keys())
        sizes = list(proto_counts.values())
        colors = _ACCENT_COLORS[: len(labels)]

        ax_pie = self._figure.add_subplot(121)
        ax_pie.set_facecolor(_CARD_BG)
        wedges, texts, autotexts = ax_pie.pie(
            sizes,
            labels=labels,
            colors=colors,
            autopct="%1.1f%%",
            pctdistance=0.8,
            startangle=90,
            wedgeprops={"linewidth": 0.5, "edgecolor": _DARK_BG},
        )
        for t in texts + autotexts:
            t.set_color(_TEXT)
            t.set_fontsize(9)
        ax_pie.set_title("Protocol Distribution", color=_TEXT, pad=10)

        # --- Action breakdown (bar) ---
        stats = self._db.get_packet_stats()
        ax_bar = self._figure.add_subplot(122)
        ax_bar.set_facecolor(_CARD_BG)
        categories = ["Total", "Allowed", "Blocked"]
        values = [stats["total"], stats["allowed"], stats["blocked"]]
        bar_colors = ["#00D4FF", "#00E676", "#EF4444"]
        bars = ax_bar.bar(categories, values, color=bar_colors, width=0.5)
        ax_bar.set_facecolor(_CARD_BG)
        ax_bar.tick_params(colors=_TEXT)
        ax_bar.spines["bottom"].set_color("#2D3748")
        ax_bar.spines["left"].set_color("#2D3748")
        ax_bar.spines["top"].set_visible(False)
        ax_bar.spines["right"].set_visible(False)
        ax_bar.set_title("Packet Actions", color=_TEXT, pad=10)
        ax_bar.yaxis.label.set_color(_TEXT)

        for bar, val in zip(bars, values):
            ax_bar.text(
                bar.get_x() + bar.get_width() / 2,
                bar.get_height() + max(values) * 0.02,
                str(val),
                ha="center", va="bottom",
                color=_TEXT, fontsize=9,
            )

        self._figure.tight_layout(pad=2.0)
        self._canvas.draw()


# ---------------------------------------------------------------------------
# Reusable summary card
# ---------------------------------------------------------------------------

class _SummaryCard(QFrame):
    def __init__(self, title: str, value: str = "0", parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self.setObjectName("StatCard")
        self.setFixedHeight(88)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 10, 16, 10)
        layout.setSpacing(4)
        self._title = QLabel(title)
        self._title.setObjectName("StatCardTitle")
        self._value = QLabel(value)
        self._value.setObjectName("StatCardValue")
        self._value.setStyleSheet("color: #00D4FF; font-size: 26px;")
        layout.addWidget(self._title)
        layout.addWidget(self._value)

    def set_value(self, value: str) -> None:
        self._value.setText(value)
