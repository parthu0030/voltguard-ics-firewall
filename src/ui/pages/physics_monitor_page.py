"""
VoltGuard — Physics Monitor Page
==================================
Placeholder page for the real-time physics simulation viewer.

The physics engine will simulate industrial process states (pressure,
flow rate, valve position, temperature) based on incoming commands and
predict whether the resulting state violates safety constraints.

Implementation is scheduled for Week 1 milestones as per the
development plan in ``07_DEVELOPMENT_PLAN.md``.
"""

from __future__ import annotations

from PyQt6.QtWidgets import QVBoxLayout, QWidget

from src.ui.pages.packet_monitor_page import _build_feature_list, _build_page_header


class PhysicsMonitorPage(QWidget):
    """
    Physics Monitor placeholder page.

    Will display real-time physics simulation graphs (pressure, flow,
    temperature, valve state) and show the safety constraint evaluation
    result for each incoming industrial command.
    """

    PAGE_TITLE = "Physics Monitor"
    PAGE_ICON  = "⚙"
    PAGE_DESC  = (
        "Real-time physics simulation of the industrial process.\n"
        "Each incoming command is simulated before being allowed to execute.\n\n"
        "Implementation scheduled for Week 1 — Physics Simulation Milestone."
    )
    FEATURES = [
        "Pressure simulation with configurable safety bounds",
        "Flow rate prediction from valve commands",
        "Temperature modelling for thermal processes",
        "Valve position state tracking",
        "Safety constraint violation detection",
        "Real-time Qt Charts integration (pressure, flow, temperature)",
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
