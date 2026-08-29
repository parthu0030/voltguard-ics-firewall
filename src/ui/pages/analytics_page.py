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
from PyQt6.QtWidgets import QComboBox, QGridLayout, QHBoxLayout, QLabel, QPushButton, QScrollArea, QVBoxLayout, QWidget
from src.services.database_service import database_service
from src.services.security_analytics_service import SecurityAnalyticsService
from src.ui.widgets.charts import BarChartWidget, LineChartWidget, PieChartWidget
from src.ui.widgets.stat_card import StatCard


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
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        root.addWidget(scroll)
        content = QWidget(); scroll.setWidget(content)
        layout = QVBoxLayout(content)
        layout.setContentsMargins(28, 28, 28, 28)
        title = QLabel("📊  Analytics")
        title.setStyleSheet("font-size:22px;font-weight:700;color:#E6EDF3")
        layout.addWidget(title)
        subtitle = QLabel("Security & Physical System Intelligence")
        subtitle.setStyleSheet("color:#8B949E;font-size:13px;")
        layout.addWidget(subtitle)
        controls = QHBoxLayout()
        self._period = QComboBox(); self._period.addItems(["1h", "6h", "24h", "7d", "30d"])
        self._severity = QComboBox(); self._severity.addItems(["All", "LOW", "MEDIUM", "HIGH", "CRITICAL"])
        self._decision = QComboBox(); self._decision.addItems(["All", "ALLOW", "ALERT", "BLOCK"])
        for name, control in (("Period", self._period), ("Severity", self._severity), ("Decision", self._decision)):
            controls.addWidget(QLabel(name)); controls.addWidget(control); control.currentIndexChanged.connect(self.refresh)
        refresh = QPushButton("Refresh"); refresh.clicked.connect(self.refresh); controls.addWidget(refresh); controls.addStretch()
        layout.addLayout(controls)
        self._summary_cards = {
            "events": StatCard("TOTAL EVENTS", "◈", accent_colour="#58A6FF"),
            "allow": StatCard("ALLOWED", "✓", accent_colour="#3FB950"),
            "alert": StatCard("ALERTS", "!", accent_colour="#F0883E"),
            "block": StatCard("BLOCKED", "×", accent_colour="#F85149"),
        }
        layout.addWidget(self._section_title("Security Overview"))
        overview = QGridLayout(); overview.setHorizontalSpacing(14); overview.setVerticalSpacing(14)
        for index, card in enumerate(self._summary_cards.values()): overview.addWidget(card, 0, index)
        layout.addLayout(overview)

        charts = QGridLayout(); charts.setHorizontalSpacing(16); charts.setVerticalSpacing(16)
        self._decision_chart = PieChartWidget("ALLOW / ALERT / BLOCK")
        self._severity_chart = BarChartWidget("Events by Severity")
        self._physics_chart = LineChartWidget("Pressure Trend (bar)", "#58A6FF")
        self._flow_chart = LineChartWidget("Flow Rate Trend (L/s)", "#3FB950")
        self._events_chart = LineChartWidget("Security Events over Time", "#BC8CFF")
        self._risk_chart = BarChartWidget("Risk Score Distribution")
        self._protocol_chart = BarChartWidget("Protocol Distribution", horizontal=True)
        self._modbus_chart = BarChartWidget("Modbus Function Distribution", horizontal=True)
        self._rpm_chart = LineChartWidget("Pump RPM Trend (RPM)", "#F0883E")
        self._valve_chart = LineChartWidget("Valve Position Trend (%)", "#D29922")
        self._tank_chart = LineChartWidget("Tank Level Trend (m³)", "#BC8CFF")
        self._temp_chart = LineChartWidget("Temperature Trend (°C)", "#F85149")
        self._correlation_chart = BarChartWidget("Security Events vs Physics Anomalies")
        layout.addWidget(self._section_title("Security Events"))
        charts.addWidget(self._decision_chart, 0, 0); charts.addWidget(self._severity_chart, 0, 1)
        layout.addLayout(charts)
        risk = QGridLayout(); risk.setHorizontalSpacing(16)
        risk.addWidget(self._events_chart, 0, 0); risk.addWidget(self._risk_chart, 0, 1)
        layout.addWidget(self._section_title("Risk Analytics")); layout.addLayout(risk)
        protocol = QGridLayout(); protocol.setHorizontalSpacing(16)
        protocol.addWidget(self._protocol_chart, 0, 0); protocol.addWidget(self._modbus_chart, 0, 1)
        layout.addWidget(self._section_title("Protocol Analytics")); layout.addLayout(protocol)
        physical = QGridLayout(); physical.setHorizontalSpacing(16); physical.setVerticalSpacing(16)
        for i, chart in enumerate((self._physics_chart, self._flow_chart, self._rpm_chart, self._valve_chart, self._tank_chart, self._temp_chart)):
            physical.addWidget(chart, i // 3, i % 3)
        layout.addWidget(self._section_title("Physical System Trends")); layout.addLayout(physical)
        layout.addWidget(self._section_title("Cyber-Physical Correlation")); layout.addWidget(self._correlation_chart)
        self._status = QLabel(); self._status.setStyleSheet("color:#8B949E;font-size:12px;padding:8px 0;")
        layout.addWidget(self._status); layout.addStretch()

    @staticmethod
    def _section_title(text: str) -> QLabel:
        label = QLabel(text.upper())
        label.setStyleSheet("color:#E6EDF3;font-size:14px;font-weight:700;margin-top:12px;")
        return label

    def refresh(self) -> None:
        try:
            if not database_service.is_ready:
                database_service.initialize()
            start, end = self._service.resolve_time_window(self._period.currentText())
            summary = self._service.get_summary_metrics(start_time=start, end_time=end)
            severity, decision = self._severity.currentText(), self._decision.currentText()
            events = database_service.get_security_events(
                start_time=start, end_time=end, limit=500,
                severity=severity, final_action=decision,
            )
            readings = database_service.get_physics_readings(start, end)
            self._summary_cards["events"].set_value(str(len(events)))
            self._summary_cards["allow"].set_value(str(sum(e.final_action == "ALLOW" for e in events)))
            self._summary_cards["alert"].set_value(str(sum(e.final_action == "ALERT" for e in events)))
            self._summary_cards["block"].set_value(str(sum(e.final_action == "BLOCK" for e in events)))
            self._decision_chart.set_data({key: sum(e.final_action == key for e in events) for key in ("ALLOW", "ALERT", "BLOCK")})
            self._severity_chart.set_data({key: sum(e.severity.value == key for e in events) for key in ("LOW", "MEDIUM", "HIGH", "CRITICAL")})
            self._physics_chart.set_data([{"time_bucket": item["timestamp"], "value": item["pressure_bar"]} for item in readings])
            self._flow_chart.set_data([{"time_bucket": item["timestamp"], "value": item["flow_lps"]} for item in readings])
            self._events_chart.set_data(self._service.get_events_time_series(start_time=start, end_time=end))
            self._risk_chart.set_data(self._service.get_risk_score_distribution(start, end))
            # Protocol and Modbus distributions are database aggregations.
            # They are deliberately queried from the same filtered source as
            # the rest of this page rather than from a missing service API.
            self._protocol_chart.set_data(database_service.get_protocol_distribution(start, end))
            self._modbus_chart.set_data({
                f"FC {key}": value
                for key, value in database_service.get_modbus_function_distribution(start, end).items()
            })
            for chart, field in ((self._rpm_chart, "pump_rpm"), (self._valve_chart, "valve_position"), (self._tank_chart, "tank_level_m3"), (self._temp_chart, "temperature_celsius")):
                chart.set_data([{"time_bucket": item["timestamp"], "value": item[field]} for item in readings])
            anomalies = sum(e.event_type == "PHYSICS_VIOLATION" for e in events)
            self._correlation_chart.set_data({"Security events": len(events) - anomalies, "Physics anomalies": anomalies})
            self._status.setText(f"Period: {self._period.currentText()} · {len(readings)} persisted physical samples · average risk {summary.average_risk_score:.1f}")
        except Exception as exc:
            self._status.setText(f"Analytics unavailable: {exc}")
