"""
VoltGuard — Security & Physical Analytics Page
=================================================
Live monitoring and trend analysis dashboard aggregating security events,
packet inspection logs, firewall policy decisions, and industrial physics
telemetry.
"""

from __future__ import annotations

from PyQt6.QtCore import QTimer
from PyQt6.QtWidgets import (
    QComboBox,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from src.services.database_service import database_service
from src.services.security_analytics_service import SecurityAnalyticsService
from src.ui.widgets.charts import BarChartWidget, LineChartWidget, PieChartWidget
from src.ui.widgets.stat_card import StatCard


class AnalyticsPage(QWidget):
    """
    Live Security & Physical Analytics Dashboard.

    Aggregates packet traffic, firewall policy actions, risk scores,
    protocol metrics, and industrial water-system physical telemetry.
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

    # ------------------------------------------------------------------ #
    #  UI Construction                                                     #
    # ------------------------------------------------------------------ #

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        root.addWidget(scroll)

        content = QWidget()
        content.setObjectName("analyticsContent")
        content.setStyleSheet("#analyticsContent { background: transparent; }")
        scroll.setWidget(content)

        layout = QVBoxLayout(content)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.setSpacing(20)

        # Header
        layout.addWidget(self._build_header())
        layout.addLayout(self._build_controls())

        # Security Overview Stat Cards
        layout.addWidget(self._section_title("🛡  Security Overview"))
        layout.addLayout(self._build_stat_cards())

        # Executive Intelligence Insights
        layout.addWidget(self._section_title("💡  Executive Security Insights"))
        self._insights_container = QWidget()
        self._insights_layout = QVBoxLayout(self._insights_container)
        self._insights_layout.setContentsMargins(0, 0, 0, 0)
        self._insights_layout.setSpacing(8)
        layout.addWidget(self._insights_container)

        # Security & Risk Charts
        layout.addWidget(self._section_title("🎯  Security Events & Risk Distribution"))
        sec_grid = QGridLayout()
        sec_grid.setHorizontalSpacing(16)
        sec_grid.setVerticalSpacing(16)

        self._decision_chart = PieChartWidget("Enforcement Decisions (ALLOW / ALERT / BLOCK)")
        self._severity_chart = BarChartWidget("Events by Severity Level")
        self._events_chart = LineChartWidget("Security Events Time-Series", "#BC8CFF", unit="events")
        self._risk_chart = BarChartWidget("Risk Score Distribution (0–100)")

        sec_grid.addWidget(self._decision_chart, 0, 0)
        sec_grid.addWidget(self._severity_chart, 0, 1)
        sec_grid.addWidget(self._events_chart, 1, 0)
        sec_grid.addWidget(self._risk_chart, 1, 1)
        layout.addLayout(sec_grid)

        # Protocol & Threat Intelligence Charts
        layout.addWidget(self._section_title("🌐  Protocol & Threat Intelligence"))
        proto_grid = QGridLayout()
        proto_grid.setHorizontalSpacing(16)
        proto_grid.setVerticalSpacing(16)

        self._protocol_chart = BarChartWidget("Protocol Distribution", horizontal=True)
        self._modbus_chart = BarChartWidget("Modbus Function Code Distribution", horizontal=True)
        self._top_sources_chart = BarChartWidget("Top Threat Source IPs", horizontal=True)
        self._correlation_chart = BarChartWidget("Cyber-Physical Correlation", horizontal=False)

        proto_grid.addWidget(self._protocol_chart, 0, 0)
        proto_grid.addWidget(self._modbus_chart, 0, 1)
        proto_grid.addWidget(self._top_sources_chart, 1, 0)
        proto_grid.addWidget(self._correlation_chart, 1, 1)
        layout.addLayout(proto_grid)

        # Physical System Trends (6 Line Charts)
        layout.addWidget(self._section_title("⚙  Physical Process Telemetry Trends"))
        phys_grid = QGridLayout()
        phys_grid.setHorizontalSpacing(16)
        phys_grid.setVerticalSpacing(16)

        self._physics_chart = LineChartWidget("Pipeline Pressure Trend", "#58A6FF", unit="bar")
        self._flow_chart = LineChartWidget("Flow Rate Trend", "#3FB950", unit="L/s")
        self._rpm_chart = LineChartWidget("Pump Speed Trend", "#F0883E", unit="RPM")
        self._valve_chart = LineChartWidget("Valve Position Trend", "#D29922", unit="%")
        self._tank_chart = LineChartWidget("Tank Level Trend", "#BC8CFF", unit="m³")
        self._temp_chart = LineChartWidget("Process Temperature Trend", "#F85149", unit="°C")

        phys_charts = [
            self._physics_chart,
            self._flow_chart,
            self._rpm_chart,
            self._valve_chart,
            self._tank_chart,
            self._temp_chart,
        ]
        for idx, chart in enumerate(phys_charts):
            phys_grid.addWidget(chart, idx // 3, idx % 3)

        layout.addLayout(phys_grid)

        # Status Footer
        self._status = QLabel("Initializing analytics engine…")
        self._status.setStyleSheet("color: #8B949E; font-size: 12px; padding: 8px 0;")
        layout.addWidget(self._status)
        layout.addStretch()

    def _build_header(self) -> QWidget:
        header = QWidget()
        header.setStyleSheet("background: transparent;")
        h_layout = QVBoxLayout(header)
        h_layout.setContentsMargins(0, 0, 0, 0)
        h_layout.setSpacing(4)

        title = QLabel("📊  Analytics Dashboard")
        title.setStyleSheet("font-size: 22px; font-weight: 700; color: #E6EDF3;")
        h_layout.addWidget(title)

        subtitle = QLabel("Real-time intelligence aggregation across network telemetry, firewall policy decisions, and industrial physics.")
        subtitle.setStyleSheet("color: #8B949E; font-size: 13px;")
        h_layout.addWidget(subtitle)

        return header

    def _build_controls(self) -> QHBoxLayout:
        controls = QHBoxLayout()
        controls.setSpacing(12)

        self._period = QComboBox()
        self._period.addItems(["1h", "6h", "24h", "7d", "30d"])

        self._severity = QComboBox()
        self._severity.addItems(["All", "LOW", "MEDIUM", "HIGH", "CRITICAL"])

        self._decision = QComboBox()
        self._decision.addItems(["All", "ALLOW", "ALERT", "BLOCK"])

        for name, control in (("Time Window:", self._period), ("Severity:", self._severity), ("Decision:", self._decision)):
            lbl = QLabel(name)
            lbl.setStyleSheet("color: #8B949E; font-size: 12px; font-weight: 600;")
            controls.addWidget(lbl)
            controls.addWidget(control)
            control.currentIndexChanged.connect(self.refresh)

        btn_refresh = QPushButton("🔄  Refresh")
        btn_refresh.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_refresh.setStyleSheet(
            """
            QPushButton {
                background-color: #21262D;
                color: #58A6FF;
                border: 1px solid #30363D;
                border-radius: 6px;
                padding: 6px 14px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #30363D;
                color: #79C0FF;
            }
            """
        )
        btn_refresh.clicked.connect(self.refresh)
        controls.addWidget(btn_refresh)
        controls.addStretch()

        return controls

    def _build_stat_cards(self) -> QGridLayout:
        self._summary_cards = {
            "events": StatCard("TOTAL EVENTS", "◈", accent_colour="#58A6FF"),
            "allow": StatCard("ALLOWED", "✓", accent_colour="#3FB950"),
            "alert": StatCard("ALERTS", "!", accent_colour="#F0883E"),
            "block": StatCard("BLOCKED", "×", accent_colour="#F85149"),
        }
        grid = QGridLayout()
        grid.setHorizontalSpacing(14)
        grid.setVerticalSpacing(14)
        for idx, card in enumerate(self._summary_cards.values()):
            grid.addWidget(card, 0, idx)
        return grid

    @staticmethod
    def _section_title(text: str) -> QLabel:
        label = QLabel(text.upper())
        label.setStyleSheet("color: #E6EDF3; font-size: 13px; font-weight: 700; margin-top: 12px; letter-spacing: 0.5px;")
        return label

    # ------------------------------------------------------------------ #
    #  Data Refresh                                                        #
    # ------------------------------------------------------------------ #

    def refresh(self) -> None:
        try:
            if not database_service.is_ready:
                database_service.initialize()

            window_text = self._period.currentText()
            start, end = self._service.resolve_time_window(window_text)
            summary = self._service.get_summary_metrics(start_time=start, end_time=end)

            sev_filter = self._severity.currentText()
            dec_filter = self._decision.currentText()

            events = database_service.get_security_events(
                start_time=start,
                end_time=end,
                limit=500,
                severity=sev_filter,
                final_action=dec_filter,
            )
            readings = database_service.get_physics_readings(start, end, limit=500)

            # Update Stat Cards
            self._summary_cards["events"].set_value(str(summary.total_security_events))
            self._summary_cards["allow"].set_value(str(summary.total_allowed_events))
            self._summary_cards["alert"].set_value(str(summary.total_alert_actions))
            self._summary_cards["block"].set_value(str(summary.total_blocked_events))

            # Render Executive Insights
            self._render_insights(start, end)

            # Security & Risk Charts
            self._decision_chart.set_data(summary.events_by_action)
            self._severity_chart.set_data(summary.events_by_severity)
            self._events_chart.set_data(self._service.get_events_time_series(start_time=start, end_time=end))
            self._risk_chart.set_data(self._service.get_risk_score_distribution(start_time=start, end_time=end))

            # Protocol & Threat Charts
            self._protocol_chart.set_data(database_service.get_protocol_distribution(start, end))

            modbus_raw = database_service.get_modbus_function_distribution(start, end)
            fc_mapped = {f"FC {k}": v for k, v in modbus_raw.items()}
            self._modbus_chart.set_data(fc_mapped)

            top_srcs = self._service.get_top_source_ips(limit=5, start_time=start, end_time=end)
            self._top_sources_chart.set_data({item["source_ip"]: item["event_count"] for item in top_srcs})

            anomalies = sum(e.event_type == "PHYSICS_VIOLATION" for e in events)
            net_events = len(events) - anomalies
            self._correlation_chart.set_data({"Network Events": net_events, "Physics Anomalies": anomalies})

            # Physical Telemetry Trends (scale valve position to 0–100%)
            self._physics_chart.set_data([{"time_bucket": item["timestamp"], "value": item["pressure_bar"]} for item in readings])
            self._flow_chart.set_data([{"time_bucket": item["timestamp"], "value": item["flow_lps"]} for item in readings])
            self._rpm_chart.set_data([{"time_bucket": item["timestamp"], "value": item["pump_rpm"]} for item in readings])
            self._valve_chart.set_data([{"time_bucket": item["timestamp"], "value": item["valve_position"] * 100.0} for item in readings])
            self._tank_chart.set_data([{"time_bucket": item["timestamp"], "value": item["tank_level_m3"]} for item in readings])
            self._temp_chart.set_data([{"time_bucket": item["timestamp"], "value": item["temperature_celsius"]} for item in readings])

            self._status.setText(
                f"Window: {window_text} · {len(events)} security events evaluated · "
                f"{len(readings)} physical samples persisted · Average Risk: {summary.average_risk_score:.1f}/100"
            )
        except Exception as exc:  # noqa: BLE001
            self._status.setText(f"Analytics query error: {exc}")

    def _render_insights(self, start_time: str | None, end_time: str | None) -> None:
        """Dynamically build Executive Security Insights cards."""
        # Clear existing insight widgets
        while self._insights_layout.count():
            item = self._insights_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        insights = self._service.generate_security_insights(start_time=start_time, end_time=end_time)

        for ins in insights:
            card = QFrame()
            card.setStyleSheet(
                """
                QFrame {
                    background-color: #161B22;
                    border: 1px solid #30363D;
                    border-radius: 8px;
                    padding: 10px 14px;
                }
                """
            )
            c_layout = QVBoxLayout(card)
            c_layout.setContentsMargins(10, 8, 10, 8)
            c_layout.setSpacing(4)

            # Badge color
            sev_colours = {
                "CRITICAL": "#F85149",
                "HIGH": "#F0883E",
                "MEDIUM": "#D29922",
                "LOW": "#3FB950",
                "INFO": "#58A6FF",
            }
            colour = sev_colours.get(ins.severity.value, "#58A6FF")

            header_lbl = QLabel(f"[{ins.severity.value}]  {ins.title}")
            header_lbl.setStyleSheet(f"color: {colour}; font-weight: 700; font-size: 13px; background: transparent;")
            c_layout.addWidget(header_lbl)

            desc_lbl = QLabel(ins.description)
            desc_lbl.setStyleSheet("color: #E6EDF3; font-size: 12px; background: transparent;")
            desc_lbl.setWordWrap(True)
            c_layout.addWidget(desc_lbl)

            if ins.recommendation:
                rec_lbl = QLabel(f"💡 Recommendation: {ins.recommendation}")
                rec_lbl.setStyleSheet("color: #8B949E; font-size: 11px; font-style: italic; background: transparent;")
                rec_lbl.setWordWrap(True)
                c_layout.addWidget(rec_lbl)

            self._insights_layout.addWidget(card)

    def cleanup(self) -> None:
        """Stop background refresh timer."""
        if hasattr(self, "_timer") and self._timer.isActive():
            self._timer.stop()

