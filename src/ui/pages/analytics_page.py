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

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import QComboBox, QGridLayout, QHBoxLayout, QLabel, QPushButton, QPlainTextEdit, QVBoxLayout, QWidget
from src.services.database_service import database_service
from src.services.security_analytics_service import SecurityAnalyticsService
from src.ui.widgets.charts import BarChartWidget, LineChartWidget, PieChartWidget


class AnalyticsPage(QWidget):
    """
    Analytics placeholder page.

    Will provide time-series charts of packet volume, threat trends,
    blocked command categories, and physics violation frequency.
    """

    PAGE_TITLE = "Analytics"
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._service = SecurityAnalyticsService()
        self._build_ui()
        self._timer = QTimer(self)
        self._timer.setInterval(3000)
        self._timer.timeout.connect(self.refresh)
        self._timer.start()
        self.refresh()

    def _build_ui(self) -> None:
        """Construct a filterable, database-backed view."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 28, 28, 28)
        title = QLabel("📊  Analytics")
        title.setStyleSheet("font-size:22px;font-weight:700;color:#E6EDF3")
        layout.addWidget(title)
        controls = QHBoxLayout()
        self._period = QComboBox(); self._period.addItems(["1h", "24h", "7d", "30d"])
        self._severity = QComboBox(); self._severity.addItems(["All", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
        self._decision = QComboBox(); self._decision.addItems(["All", "ALLOW", "ALERT", "BLOCK"])
        for name, control in (("Period", self._period), ("Severity", self._severity), ("Decision", self._decision)):
            controls.addWidget(QLabel(name)); controls.addWidget(control); control.currentIndexChanged.connect(self.refresh)
        refresh = QPushButton("Refresh"); refresh.clicked.connect(self.refresh); controls.addWidget(refresh); controls.addStretch()
        layout.addLayout(controls)
        charts = QGridLayout()
        self._decision_chart = PieChartWidget("ALLOW / ALERT / BLOCK")
        self._severity_chart = BarChartWidget("Events by Severity")
        self._physics_chart = LineChartWidget("Pressure Trend", "#58A6FF")
        self._flow_chart = LineChartWidget("Flow Trend", "#3FB950")
        charts.addWidget(self._decision_chart, 0, 0); charts.addWidget(self._severity_chart, 0, 1)
        charts.addWidget(self._physics_chart, 1, 0); charts.addWidget(self._flow_chart, 1, 1)
        layout.addLayout(charts)
        self._output = QPlainTextEdit(); self._output.setReadOnly(True)
        self._output.setStyleSheet("background:#161B22;color:#C9D1D9;font-family:monospace;")
        layout.addWidget(self._output, 1)

    def refresh(self) -> None:
        try:
            if not database_service.is_ready:
                database_service.initialize()
            start, end = self._service.resolve_time_window(self._period.currentText())
            summary = self._service.get_summary_metrics(start_time=start, end_time=end)
            events = database_service.load_recent_security_events(500)
            severity, decision = self._severity.currentText(), self._decision.currentText()
            events = [e for e in events if (severity == "All" or e.severity.value == severity) and (decision == "All" or e.final_action == decision)]
            readings = database_service.get_physics_readings(start, end)
            self._decision_chart.set_data({key: sum(e.final_action == key for e in events) for key in ("ALLOW", "ALERT", "BLOCK")})
            self._severity_chart.set_data({key: sum(e.severity.value == key for e in events) for key in ("LOW", "MEDIUM", "HIGH", "CRITICAL")})
            self._physics_chart.set_data([{"time_bucket": item["timestamp"], "value": item["pressure_bar"]} for item in readings])
            self._flow_chart.set_data([{"time_bucket": item["timestamp"], "value": item["flow_lps"]} for item in readings])
            lines = [f"Period: {self._period.currentText()} (persisted data)", "", f"Packets: {summary.total_packets} | Matching events: {len(events)}", f"ALLOW {sum(e.final_action == 'ALLOW' for e in events)} | ALERT {sum(e.final_action == 'ALERT' for e in events)} | BLOCK {sum(e.final_action == 'BLOCK' for e in events)}", f"Physics anomalies: {sum(e.event_type == 'PHYSICS_VIOLATION' for e in events)} | Readings: {len(readings)}", f"Risk: avg {summary.average_risk_score:.1f}, max {summary.maximum_risk_score}", "", f"Severity distribution: {summary.events_by_severity}", f"Protocol distribution: {summary.events_by_protocol}"]
            if readings:
                item = readings[-1]
                lines += ["", "Latest physics state:", "pressure={pressure_bar:.2f} bar | flow={flow_lps:.3f} L/s | temp={temperature_celsius:.1f} °C".format(**item), "pump={pump_on} | rpm={pump_rpm:.0f} | valve={valve_position:.0%} | tank={tank_level_m3:.2f} m³".format(**item)]
            self._output.setPlainText("\n".join(lines))
        except Exception as exc:
            self._output.setPlainText(f"Analytics unavailable: {exc}")
