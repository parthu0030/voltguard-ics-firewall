"""
VoltGuard — Analytics Page
============================
Placeholder page for the security analytics and trend analysis view.

Analytics will aggregate packet log data, alert history, and physics
simulation results to present actionable insights to security analysts
and SCADA operators.

Implementation is scheduled for Week 2 milestones.
"""

from __future__ import annotations

from PyQt6.QtWidgets import QVBoxLayout, QWidget

from src.ui.pages.packet_monitor_page import _build_feature_list, _build_page_header


class AnalyticsPage(QWidget):
    """
    Analytics placeholder page.

    Will provide time-series charts of packet volume, threat trends,
    blocked command categories, and physics violation frequency.
    """

    PAGE_TITLE = "Analytics"
    PAGE_ICON  = "📊"
    PAGE_DESC  = (
        "Security analytics, trends, and historical data visualisation.\n"
        "Powered by Qt Charts with data sourced from the SQLite database.\n\n"
        "Implementation scheduled for Week 2 — Dashboard & Analytics Milestone."
    )
    FEATURES = [
        "Packet volume time-series chart (hourly / daily / weekly)",
        "Threat count trend with severity breakdown",
        "Blocked vs. allowed ratio pie chart",
        "Physics violation frequency histogram",
        "Top source IP threat ranking",
        "Alert severity distribution chart",
    ]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        """Construct the placeholder layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.setSpacing(20)

        layout.addWidget(
            _build_page_header(self.PAGE_ICON, self.PAGE_TITLE, self.PAGE_DESC)
        )
        layout.addWidget(_build_feature_list(self.FEATURES))
        layout.addStretch()
