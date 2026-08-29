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

from datetime import datetime, timezone
from PyQt6.QtWidgets import QComboBox, QFileDialog, QHBoxLayout, QLabel, QPushButton, QPlainTextEdit, QVBoxLayout, QWidget
from src.services.database_service import database_service
from src.services.security_analytics_service import SecurityAnalyticsService


class ReportsPage(QWidget):
    """
    Reports placeholder page.

    Will provide one-click PDF and CSV export of incident logs,
    alert history, and physics simulation summaries.
    """

    PAGE_TITLE = "Reports"
    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._analytics = SecurityAnalyticsService()
        self._build_ui()
        self.generate()

    def _build_ui(self) -> None:
        """Construct a current operational report from persisted data."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 28, 28, 28)
        title = QLabel("📋  Operational Report")
        title.setStyleSheet("font-size:22px;font-weight:700;color:#E6EDF3")
        layout.addWidget(title)
        controls = QHBoxLayout(); self._period = QComboBox(); self._period.addItems(["1h", "6h", "24h", "7d", "30d"])
        controls.addWidget(QLabel("Period")); controls.addWidget(self._period)
        generate = QPushButton("Generate report"); generate.clicked.connect(self.generate); controls.addWidget(generate); controls.addStretch(); layout.addLayout(controls)
        download = QPushButton("Download PDF Report"); download.clicked.connect(self.download_pdf); controls.addWidget(download)
        self._report = QPlainTextEdit(); self._report.setReadOnly(True); self._report.setStyleSheet("background:#161B22;color:#C9D1D9;font-family:monospace;")
        layout.addWidget(self._report, 1)

    def generate(self) -> None:
        try:
            if not database_service.is_ready:
                database_service.initialize()
            start, end = self._analytics.resolve_time_window(self._period.currentText())
            summary = self._analytics.get_summary_metrics(start_time=start, end_time=end)
            events = database_service.get_security_events(start_time=start, end_time=end, limit=500)
            readings = database_service.get_physics_readings(start, end)
            anomalies = [event for event in events if event.event_type == "PHYSICS_VIOLATION"]
            incidents = sorted(events, key=lambda event: event.risk_score, reverse=True)[:10]
            protocol_stats = database_service.get_protocol_distribution(start, end)
            modbus_stats = database_service.get_modbus_function_distribution(start, end)
            correlations = [event for event in events if event.event_type == "PHYSICS_VIOLATION" or event.function_code is not None][-10:]
            recommendations = ["Review blocked commands and validate controller authorization."] if any(e.final_action == "BLOCK" for e in events) else ["No blocked command in this period; continue monitoring."]
            if anomalies:
                recommendations.append("Investigate physics anomalies and confirm valve/pump interlocks.")
            lines = ["VoltGuard — Physics-Aware ICS/SCADA Security Report", f"Generated: {datetime.now(timezone.utc).isoformat(timespec='seconds')}", f"Selected period: {self._period.currentText()} ({start or 'beginning'} to {end or 'now'})", "", "Security summary", f"Packets: {summary.total_packets}", f"Decisions: ALLOW {summary.total_allowed_events} | ALERT {summary.total_alert_actions} | BLOCK {summary.total_blocked_events}", f"High-risk events: {summary.high_risk_events + summary.critical_events}", f"Risk: average {summary.average_risk_score:.1f}, max {summary.maximum_risk_score}", f"Physics: {len(readings)} readings | {len(anomalies)} anomalies", "", f"Protocol statistics: {protocol_stats or 'None recorded'}", f"Modbus statistics: {modbus_stats or 'None recorded'}"]
            if readings:
                latest = readings[-1]
                lines += ["", "Physical system summary", "pressure={pressure_bar:.2f} bar | flow={flow_lps:.3f} L/s | temperature={temperature_celsius:.1f} C".format(**latest), "pump={pump_on} | rpm={pump_rpm:.0f} | valve={valve_position:.0%} | tank={tank_level_m3:.2f} m3".format(**latest)]
            lines += ["", "Major incidents:"]
            lines += [f"- {event.timestamp} | {event.final_action} | risk {event.risk_score} | {event.reason}" for event in incidents] or ["- None recorded"]
            lines += ["", "Cyber-physical correlations:"]
            lines += [f"- {event.timestamp} | {event.event_id} | {event.protocol} | FC {event.function_code if event.function_code is not None else 'n/a'} | {event.event_type} | {event.final_action}" for event in correlations] or ["- No correlated security or physics events recorded"]
            lines += ["", "Recommendations:"] + [f"- {item}" for item in recommendations]
            self._report.setPlainText("\n".join(lines))
        except Exception as exc:
            self._report.setPlainText(f"Report generation failed: {exc}")

    def download_pdf(self) -> None:
        """Create a real PDF containing the currently selected report data."""
        path, _ = QFileDialog.getSaveFileName(self, "Save VoltGuard report", "voltguard-report.pdf", "PDF files (*.pdf)")
        if not path:
            return
        if not path.lower().endswith(".pdf"):
            path += ".pdf"
        try:
            from reportlab.lib.colors import HexColor
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
            from reportlab.lib.units import mm
            from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
            styles = getSampleStyleSheet()
            title = ParagraphStyle("voltguard-title", parent=styles["Title"], textColor=HexColor("#15395B"), fontSize=18, spaceAfter=12)
            body = ParagraphStyle("voltguard-body", parent=styles["BodyText"], fontSize=9, leading=13, spaceAfter=5)
            story = [Paragraph("VoltGuard - Physics-Aware ICS/SCADA Security Report", title)]
            for line in self._report.toPlainText().splitlines():
                story.append(Spacer(1, 2) if not line else Paragraph(line.replace("&", "&amp;").replace("<", "&lt;"), body))
            SimpleDocTemplate(path, pagesize=A4, leftMargin=18*mm, rightMargin=18*mm, topMargin=18*mm, bottomMargin=18*mm).build(story)
            self._report.appendPlainText(f"\nPDF saved: {path}")
        except ImportError:
            self._report.appendPlainText("\nPDF export unavailable: install dependencies with `python3 -m pip install -r requirements.txt`.")
        except Exception as exc:
            self._report.appendPlainText(f"\nPDF export failed: {exc}")
