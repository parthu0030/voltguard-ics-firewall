"""
VoltGuard — Reports Page
==========================
Placeholder page for report generation and export functionality.

Reports will allow SCADA operators and security analysts to export
incident summaries, packet logs, and physics violation records in
PDF and CSV formats for regulatory compliance and post-incident review.

Implementation is scheduled for Week 4 milestones.
"""

from __future__ import annotations

from PyQt6.QtWidgets import QVBoxLayout, QWidget

from src.ui.pages.packet_monitor_page import _build_feature_list, _build_page_header


class ReportsPage(QWidget):
    """
    Reports placeholder page.

    Will provide one-click PDF and CSV export of incident logs,
    alert history, and physics simulation summaries.
    """

    PAGE_TITLE = "Reports"
    PAGE_ICON  = "📋"
    PAGE_DESC  = (
        "Generate and export security incident reports.\n"
        "Supports PDF and CSV formats for compliance and audit purposes.\n\n"
        "Implementation scheduled for Week 4 — Reporting & Packaging Milestone."
    )
    FEATURES = [
        "PDF report generation with VoltGuard branding",
        "CSV export of packet logs with full metadata",
        "Alert summary report with severity breakdown",
        "Physics violation incident report",
        "Custom date-range filtering before export",
        "Automatic report archiving to the reports/ directory",
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
