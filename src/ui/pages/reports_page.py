"""
VoltGuard — Operational Security & Physical System Reports Page
===============================================================
Database-backed operational reporting view aggregating security events,
protocol distributions, Modbus commands, industrial physical telemetry,
and cyber-physical correlation incidents into exportable reports.
"""

from __future__ import annotations

from html import escape
from typing import Iterable, Optional

from PyQt6.QtCore import QMarginsF, Qt
from PyQt6.QtGui import QPageLayout, QPageSize, QPdfWriter, QTextDocument
from PyQt6.QtWidgets import (
    QComboBox,
    QFileDialog,
    QGridLayout,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QScrollArea,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.services.database_service import database_service
from src.services.reporting_service import OperationalReport, ReportingService
from src.ui.widgets.stat_card import StatCard


class ReportsPage(QWidget):
    """
    Visual, database-backed operational reporting view.

    Generates on-demand reports for specified time windows and exports
    formatted PDF reports reflecting real system security and physics data.
    """

    PAGE_TITLE = "Reports"

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._service = ReportingService()
        self._current_report: Optional[OperationalReport] = None

        self._build_ui()
        self.generate()

    # ------------------------------------------------------------------ #
    #  UI Assembly                                                         #
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
        content.setObjectName("reportsContent")
        content.setStyleSheet("#reportsContent { background: transparent; }")
        scroll.setWidget(content)

        layout = QVBoxLayout(content)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.setSpacing(16)

        # Header Title
        title = QLabel("📋  Operational Security & Physics Report")
        title.setStyleSheet("font-size: 22px; font-weight: 700; color: #E6EDF3;")
        layout.addWidget(title)

        self._status = QLabel("Generating operational report…")
        self._status.setStyleSheet("color: #8B949E; font-size: 12px;")
        layout.addWidget(self._status)

        # Controls Bar
        controls = QHBoxLayout()
        controls.setSpacing(12)

        lbl_period = QLabel("Time Window:")
        lbl_period.setStyleSheet("color: #8B949E; font-size: 12px; font-weight: 600;")
        controls.addWidget(lbl_period)

        self._period = QComboBox()
        self._period.addItems(["1h", "6h", "24h", "7d", "30d"])
        self._period.currentTextChanged.connect(self.generate)
        controls.addWidget(self._period)

        btn_generate = QPushButton("🔄  Generate Report")
        btn_generate.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_generate.setStyleSheet(
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
        btn_generate.clicked.connect(self.generate)
        controls.addWidget(btn_generate)

        btn_pdf = QPushButton("📄  Download PDF Report")
        btn_pdf.setCursor(Qt.CursorShape.PointingHandCursor)
        btn_pdf.setStyleSheet(
            """
            QPushButton {
                background-color: #238636;
                color: #FFFFFF;
                border: 1px solid #2EA043;
                border-radius: 6px;
                padding: 6px 16px;
                font-weight: 600;
            }
            QPushButton:hover {
                background-color: #2EA043;
            }
            """
        )
        btn_pdf.clicked.connect(self.download_pdf)
        controls.addWidget(btn_pdf)

        controls.addStretch()
        layout.addLayout(controls)

        # Report Summary Cards
        layout.addWidget(self._section("Report Overview"))
        cards_grid = QGridLayout()
        cards_grid.setHorizontalSpacing(14)

        self._cards = {
            "packets": StatCard("TOTAL EVENTS", "◈", accent_colour="#58A6FF"),
            "allow": StatCard("ALLOWED", "✓", accent_colour="#3FB950"),
            "alert": StatCard("ALERTS", "!", accent_colour="#F0883E"),
            "block": StatCard("BLOCKED", "×", accent_colour="#F85149"),
        }
        for i, card in enumerate(self._cards.values()):
            cards_grid.addWidget(card, 0, i)
        layout.addLayout(cards_grid)

        # Risk Summary Panel
        layout.addWidget(self._section("Risk & Severity Summary"))
        self._risk_panel = self._panel()
        layout.addWidget(self._risk_panel)

        # Protocol & Modbus Distribution Tables
        layout.addWidget(self._section("Protocol & Modbus Function Analysis"))
        tables_grid = QGridLayout()
        tables_grid.setHorizontalSpacing(16)

        self._protocol_table = self._table(["Protocol", "Event Count", "Share (%)"])
        self._modbus_table = self._table(["Code", "Function Name", "Count", "Decision", "Avg Risk"])
        tables_grid.addWidget(self._protocol_table, 0, 0)
        tables_grid.addWidget(self._modbus_table, 0, 1)
        layout.addLayout(tables_grid)

        # Physical System Summary Table & Notes
        layout.addWidget(self._section("Physical Telemetry Summary"))
        self._physics_table = self._table(["Process Variable", "Minimum", "Maximum", "Average", "Latest Value"])
        layout.addWidget(self._physics_table)

        self._physics_note = QLabel()
        self._physics_note.setStyleSheet("color: #8B949E; font-size: 12px; padding: 2px 0;")
        layout.addWidget(self._physics_note)

        # Major Incidents Table
        layout.addWidget(self._section("Major Security & Physical Incidents"))
        self._incident_table = self._table(
            ["Timestamp", "Source IP", "Destination IP", "Protocol", "Function", "Risk", "Severity", "Action", "Policy", "Reason"]
        )
        layout.addWidget(self._incident_table)

        # Cyber-Physical Correlation Table
        layout.addWidget(self._section("Cyber-Physical Correlation"))
        self._correlation_table = self._table(["Network Event", "Risk / Action", "Physical System Response"])
        layout.addWidget(self._correlation_table)

        # Operational Recommendations Panel
        layout.addWidget(self._section("Actionable Security Recommendations"))
        self._recommendations_panel = self._panel()
        self._recommendations_panel.setWordWrap(True)
        layout.addWidget(self._recommendations_panel)

        layout.addStretch()

    # ------------------------------------------------------------------ #
    #  Widget Generators                                                   #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _section(text: str) -> QLabel:
        label = QLabel(text.upper())
        label.setStyleSheet("color: #E6EDF3; font-size: 13px; font-weight: 700; margin-top: 12px; letter-spacing: 0.5px;")
        return label

    @staticmethod
    def _panel() -> QLabel:
        label = QLabel()
        label.setStyleSheet(
            "background: #161B22; border: 1px solid #30363D; border-radius: 10px; color: #C9D1D9; padding: 14px; font-size: 13px;"
        )
        return label

    @staticmethod
    def _table(headers: list[str]) -> QTableWidget:
        table = QTableWidget(0, len(headers))
        table.setHorizontalHeaderLabels(headers)
        table.verticalHeader().setVisible(False)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(True)
        table.setMinimumHeight(160)
        table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        table.horizontalHeader().setStretchLastSection(True)
        table.setStyleSheet(
            """
            QTableWidget {
                background: #0D1117;
                color: #C9D1D9;
                gridline-color: #21262D;
                border: 1px solid #30363D;
                border-radius: 8px;
                font-size: 12px;
            }
            QHeaderView::section {
                background: #161B22;
                color: #8B949E;
                font-weight: 600;
                border: none;
                border-bottom: 1px solid #30363D;
                padding: 7px;
            }
            """
        )
        return table

    @staticmethod
    def _populate(table: QTableWidget, rows: Iterable[Iterable[str]]) -> None:
        materialized = list(rows)
        table.setRowCount(len(materialized))
        for row_index, values in enumerate(materialized):
            for column, value in enumerate(values):
                table.setItem(row_index, column, QTableWidgetItem(str(value)))

    # ------------------------------------------------------------------ #
    #  Report Generation & Rendering                                       #
    # ------------------------------------------------------------------ #

    def generate(self) -> None:
        """Fetch fresh data from the database and render the report."""
        try:
            if not database_service.is_ready and not database_service.initialize():
                raise RuntimeError("Database initialization failed")

            period_text = self._period.currentText()
            self._current_report = self._service.generate(period_text)
            self._render(self._current_report)
        except Exception as exc:  # noqa: BLE001
            self._status.setText(f"Report generation error: {exc}")

    def _render(self, report: OperationalReport) -> None:
        """Populate report widgets with OperationalReport fields."""
        s = report.summary

        # Overview Stat Cards
        self._cards["packets"].set_value(str(s.total_security_events))
        self._cards["allow"].set_value(str(s.total_allowed_events))
        self._cards["alert"].set_value(str(s.total_alert_actions))
        self._cards["block"].set_value(str(s.total_blocked_events))

        # Risk Summary Panel
        levels = s.events_by_severity
        self._risk_panel.setText(
            f"Average Risk Score: <b>{s.average_risk_score:.1f}</b> &nbsp;&nbsp;&nbsp;&nbsp; "
            f"Maximum Risk Score: <b>{s.maximum_risk_score}</b> &nbsp;&nbsp;&nbsp;&nbsp; "
            f"High / Critical Events: <b>{s.high_risk_events + s.critical_events}</b><br>"
            f"<span style='color:#8B949E; font-size:12px;'>"
            f"LOW: {levels.get('LOW', 0)} &nbsp;&nbsp; "
            f"MEDIUM: {levels.get('MEDIUM', 0)} &nbsp;&nbsp; "
            f"HIGH: {levels.get('HIGH', 0)} &nbsp;&nbsp; "
            f"CRITICAL: {levels.get('CRITICAL', 0)}</span>"
        )

        # Protocol Distribution Table
        total_proto = sum(report.protocol_statistics.values())
        protocols = [
            (name, str(count), f"{(count / total_proto * 100.0):.1f}%")
            for name, count in report.protocol_statistics.items()
        ] or [("No protocols recorded", "—", "—")]
        self._populate(self._protocol_table, protocols)

        # Modbus Statistics Table
        modbus = [
            (f"0x{r['code']:02X}", r["name"], str(r["count"]), r["decision"], f"{r['average_risk']:.1f}")
            for r in report.modbus_statistics
        ] or [("No Modbus functions recorded", "—", "—", "—", "—")]
        self._populate(self._modbus_table, modbus)

        # Physical Telemetry Summary Table
        physics = [
            (
                r["label"],
                f"{r['minimum']:.2f} {r['unit']}",
                f"{r['maximum']:.2f} {r['unit']}",
                f"{r['average']:.2f} {r['unit']}",
                f"{r['latest']:.2f} {r['unit']}",
            )
            for r in report.physics_statistics
        ] or [("No persisted physical telemetry readings", "—", "—", "—", "—")]
        self._populate(self._physics_table, physics)

        note_text = f"Persisted Physical Samples: <b>{report.physics_reading_count}</b>"
        if report.anomalies:
            note_text += f" &nbsp;●&nbsp; Physical Anomalies Detected: <b style='color:#F85149'>{len(report.anomalies)}</b>"
        else:
            note_text += " &nbsp;●&nbsp; <span style='color:#3FB950'>No physical anomalies detected in this period.</span>"
        self._physics_note.setText(note_text)

        # Major Incidents Table
        incidents = [
            (
                e.timestamp,
                e.source_ip,
                e.destination_ip,
                e.protocol,
                e.function_name or (f"0x{e.function_code:02X}" if e.function_code is not None else "—"),
                str(e.risk_score),
                e.severity.value,
                e.final_action,
                e.matched_policy_name or "—",
                e.reason,
            )
            for e in report.incidents
        ] or [("No major incidents recorded during this period.", "—", "—", "—", "—", "—", "—", "—", "—", "—")]
        self._populate(self._incident_table, incidents)

        # Cyber-Physical Correlation Table
        correlations = [
            (
                f"{p['network'].timestamp} · {p['network'].protocol} · {p['network'].function_name or 'Modbus activity'}",
                f"{p['network'].final_action} (Risk {p['network'].risk_score})",
                p["physics"].reason,
            )
            for p in report.correlations
        ] or [("No confirmed cyber-physical correlations recorded during this period.", "—", "—")]
        self._populate(self._correlation_table, correlations)

        # Recommendations Panel
        recs = "<br>".join(f"• {escape(item)}" for item in report.recommendations)
        self._recommendations_panel.setText(recs)

        self._status.setText(
            f"Period: <b>{report.period}</b> · Generated: {report.generated_at} · "
            f"Persisted data active"
        )

    # ------------------------------------------------------------------ #
    #  PDF Export                                                          #
    # ------------------------------------------------------------------ #

    def download_pdf(self) -> None:
        """Export the current OperationalReport to a PDF file."""
        if not self._current_report:
            self.generate()
        report = self._current_report
        if not report:
            return

        path, _ = QFileDialog.getSaveFileName(
            self, "Save VoltGuard Report", "voltguard-security-report.pdf", "PDF files (*.pdf)"
        )
        if not path:
            return
        if not path.lower().endswith(".pdf"):
            path += ".pdf"

        try:
            # 1. Primary PDF Export: Native PyQt6 QPdfWriter + QTextDocument
            from PyQt6.QtCore import QMarginsF
            from PyQt6.QtGui import QPageLayout, QPageSize, QPdfWriter, QTextDocument

            html_content = self._build_pdf_html(report)
            doc = QTextDocument()
            doc.setHtml(html_content)

            writer = QPdfWriter(path)
            writer.setPageLayout(
                QPageLayout(
                    QPageSize(QPageSize.PageSizeId.A4),
                    QPageLayout.Orientation.Portrait,
                    QMarginsF(12, 12, 12, 12),
                )
            )
            doc.print(writer)
            self._status.setText(f"PDF exported successfully: {path}")
        except Exception as exc:  # noqa: BLE001
            self._status.setText(f"PDF export failed: {exc}")

    @staticmethod
    def _build_pdf_html(report: OperationalReport) -> str:
        """Construct formatted HTML string for PDF rendering."""
        s = report.summary
        levels = s.events_by_severity

        # Protocol rows
        total_proto = sum(report.protocol_statistics.values())
        proto_rows = ""
        for name, count in report.protocol_statistics.items():
            pct = (count / total_proto * 100.0) if total_proto > 0 else 0
            proto_rows += f"<tr><td>{escape(name)}</td><td>{count}</td><td>{pct:.1f}%</td></tr>"
        if not proto_rows:
            proto_rows = "<tr><td colspan='3'>No protocol statistics recorded for this period.</td></tr>"

        # Modbus rows
        modbus_rows = ""
        for r in report.modbus_statistics:
            modbus_rows += f"<tr><td>0x{r['code']:02X}</td><td>{escape(r['name'])}</td><td>{r['count']}</td><td>{r['decision']}</td><td>{r['average_risk']:.1f}</td></tr>"
        if not modbus_rows:
            modbus_rows = "<tr><td colspan='5'>No Modbus function statistics recorded for this period.</td></tr>"

        # Physics rows
        physics_rows = ""
        for r in report.physics_statistics:
            physics_rows += f"<tr><td>{escape(r['label'])}</td><td>{r['minimum']:.2f} {r['unit']}</td><td>{r['maximum']:.2f} {r['unit']}</td><td>{r['average']:.2f} {r['unit']}</td><td>{r['latest']:.2f} {r['unit']}</td></tr>"
        if not physics_rows:
            physics_rows = "<tr><td colspan='5'>No physical telemetry readings recorded for this period.</td></tr>"

        # Incident rows
        incident_rows = ""
        for e in report.incidents:
            fn = e.function_name or (f"0x{e.function_code:02X}" if e.function_code is not None else "—")
            policy = e.matched_policy_name or "—"
            incident_rows += f"<tr><td>{escape(e.timestamp)}</td><td>{escape(e.source_ip)}</td><td>{escape(e.destination_ip)}</td><td>{escape(e.protocol)}</td><td>{escape(fn)}</td><td>{e.risk_score}</td><td>{escape(e.severity.value)}</td><td>{escape(e.final_action)}</td><td>{escape(policy)}</td><td>{escape(e.reason)}</td></tr>"
        if not incident_rows:
            incident_rows = "<tr><td colspan='10'>No major incidents recorded during this period.</td></tr>"

        # Recommendations
        recs = "".join(f"<li>{escape(r)}</li>" for r in report.recommendations)

        return f"""
        <!DOCTYPE html>
        <html>
        <head>
        <meta charset="utf-8">
        <style>
            body {{ font-family: Arial, sans-serif; margin: 15px; color: #1e293b; font-size: 11px; }}
            h1 {{ color: #0f172a; font-size: 20px; border-bottom: 2px solid #3b82f6; padding-bottom: 4px; margin-bottom: 4px; }}
            .subtitle {{ color: #64748b; font-size: 11px; margin-bottom: 16px; }}
            h2 {{ font-size: 12px; color: #0f172a; border-bottom: 1px solid #cbd5e1; padding-bottom: 3px; margin-top: 14px; text-transform: uppercase; }}
            table.data-table {{ width: 100%; border-collapse: collapse; margin-bottom: 12px; font-size: 10px; }}
            table.data-table th {{ background: #f1f5f9; color: #475569; text-align: left; padding: 5px 6px; border-bottom: 2px solid #cbd5e1; font-weight: bold; }}
            table.data-table td {{ padding: 5px 6px; border-bottom: 1px solid #e2e8f0; }}
            ul {{ margin-top: 4px; padding-left: 20px; }}
            li {{ margin-bottom: 4px; }}
        </style>
        </head>
        <body>
            <h1>VoltGuard — Operational Security & Physics Report</h1>
            <div class="subtitle">Time Window: <b>{escape(report.period)}</b> | Generated: <b>{escape(report.generated_at)}</b></div>

            <h2>Report Summary</h2>
            <div style="background: #f8fafc; border: 1px solid #cbd5e1; padding: 10px; border-radius: 4px; margin-bottom: 14px;">
                <b>Total Events Evaluated:</b> {s.total_security_events} &nbsp;&nbsp;|&nbsp;&nbsp;
                <b>Allowed:</b> {s.total_allowed_events} &nbsp;&nbsp;|&nbsp;&nbsp;
                <b>Alerts:</b> {s.total_alert_actions} &nbsp;&nbsp;|&nbsp;&nbsp;
                <b>Blocked:</b> {s.total_blocked_events}<br>
                <b>Average Risk Score:</b> {s.average_risk_score:.1f}/100 &nbsp;&nbsp;|&nbsp;&nbsp;
                <b>Maximum Risk Score:</b> {s.maximum_risk_score}/100<br>
                <b>Severity Breakdown:</b> LOW ({levels.get('LOW', 0)}), MEDIUM ({levels.get('MEDIUM', 0)}), HIGH ({levels.get('HIGH', 0)}), CRITICAL ({levels.get('CRITICAL', 0)})
            </div>

            <h2>Protocol & Modbus Analytics</h2>
            <table class="data-table">
                <tr><th>Protocol</th><th>Count</th><th>Share</th></tr>
                {proto_rows}
            </table>

            <table class="data-table">
                <tr><th>Code</th><th>Function Name</th><th>Count</th><th>Decision</th><th>Avg Risk</th></tr>
                {modbus_rows}
            </table>

            <h2>Physical System Telemetry Summary</h2>
            <table class="data-table">
                <tr><th>Process Variable</th><th>Minimum</th><th>Maximum</th><th>Average</th><th>Latest</th></tr>
                {physics_rows}
            </table>
            <div style="color: #64748b; font-size: 10px; margin-bottom: 12px;">
                Persisted Telemetry Samples: {report.physics_reading_count} | Physics Anomalies: {len(report.anomalies)}
            </div>

            <h2>Major Incidents Log</h2>
            <table class="data-table">
                <tr><th>Timestamp</th><th>Source</th><th>Dest</th><th>Protocol</th><th>Function</th><th>Risk</th><th>Sev</th><th>Action</th><th>Policy</th><th>Reason</th></tr>
                {incident_rows}
            </table>

            <h2>Security Recommendations</h2>
            <ul>{recs}</ul>
        </body>
        </html>
        """

