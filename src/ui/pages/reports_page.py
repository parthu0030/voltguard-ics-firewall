"""Operational security reports built from VoltGuard's persisted telemetry."""
from __future__ import annotations

from html import escape
from typing import Iterable
from PyQt6.QtWidgets import QComboBox, QFileDialog, QGridLayout, QHBoxLayout, QLabel, QPushButton, QScrollArea, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget
from src.services.database_service import database_service
from src.services.reporting_service import OperationalReport, ReportingService
from src.ui.widgets.stat_card import StatCard


class ReportsPage(QWidget):
    """Visual, fresh, database-backed operational reporting view."""
    PAGE_TITLE = "Reports"

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._service, self._current_report = ReportingService(), None
        self._build_ui(); self.generate()

    def _build_ui(self) -> None:
        root = QVBoxLayout(self); root.setContentsMargins(0, 0, 0, 0)
        scroll = QScrollArea(); scroll.setWidgetResizable(True); scroll.setFrameShape(QScrollArea.Shape.NoFrame); root.addWidget(scroll)
        content = QWidget(); scroll.setWidget(content)
        layout = QVBoxLayout(content); layout.setContentsMargins(28, 28, 28, 28); layout.setSpacing(12)
        title = QLabel("📋  Operational Security Report"); title.setStyleSheet("font-size:22px;font-weight:700;color:#E6EDF3"); layout.addWidget(title)
        self._status = QLabel("Generating current report…"); self._status.setStyleSheet("color:#8B949E;font-size:12px;"); layout.addWidget(self._status)
        controls = QHBoxLayout(); controls.addWidget(QLabel("Period"))
        self._period = QComboBox(); self._period.addItems(["1h", "6h", "24h", "7d", "30d"]); self._period.currentTextChanged.connect(self.generate); controls.addWidget(self._period)
        button = QPushButton("Generate Report"); button.clicked.connect(self.generate); controls.addWidget(button)
        button = QPushButton("Download PDF Report"); button.clicked.connect(self.download_pdf); controls.addWidget(button); controls.addStretch(); layout.addLayout(controls)
        layout.addWidget(self._section("Report Overview")); cards = QGridLayout(); cards.setSpacing(14)
        self._cards = {"packets": StatCard("TOTAL PACKETS", "◈", accent_colour="#58A6FF"), "allow": StatCard("ALLOWED", "✓", accent_colour="#3FB950"), "alert": StatCard("ALERTS", "!", accent_colour="#F0883E"), "block": StatCard("BLOCKED", "×", accent_colour="#F85149")}
        for i, card in enumerate(self._cards.values()): cards.addWidget(card, 0, i)
        layout.addLayout(cards)
        layout.addWidget(self._section("Risk Summary")); self._risk = self._panel(); layout.addWidget(self._risk)
        layout.addWidget(self._section("Protocol & Modbus")); tables = QGridLayout(); tables.setSpacing(14)
        self._protocol_table = self._table(["Protocol", "Packets", "Share"]); self._modbus_table = self._table(["Function", "Name", "Count", "Decision", "Avg. Risk"])
        tables.addWidget(self._protocol_table, 0, 0); tables.addWidget(self._modbus_table, 0, 1); layout.addLayout(tables)
        layout.addWidget(self._section("Physical System Summary")); self._physics_table = self._table(["Metric", "Minimum", "Maximum", "Average", "Latest"]); layout.addWidget(self._physics_table)
        self._physics_note = QLabel(); self._physics_note.setStyleSheet("color:#8B949E;padding:4px;"); layout.addWidget(self._physics_note)
        layout.addWidget(self._section("Major Incidents")); self._incident_table = self._table(["Timestamp", "Source", "Destination", "Protocol", "Function", "Risk", "Severity", "Decision", "Policy", "Reason"]); layout.addWidget(self._incident_table)
        layout.addWidget(self._section("Cyber-Physical Correlation")); self._correlation_table = self._table(["Network activity", "Decision / Risk", "Physical response"]); layout.addWidget(self._correlation_table)
        layout.addWidget(self._section("Recommendations")); self._recommendations = self._panel(); self._recommendations.setWordWrap(True); layout.addWidget(self._recommendations); layout.addStretch()

    @staticmethod
    def _section(text: str) -> QLabel:
        label = QLabel(text.upper()); label.setStyleSheet("color:#E6EDF3;font-size:14px;font-weight:700;margin-top:12px;"); return label

    @staticmethod
    def _panel() -> QLabel:
        label = QLabel(); label.setStyleSheet("background:#161B22;border:1px solid #30363D;border-radius:10px;color:#C9D1D9;padding:14px;font-size:13px;"); return label

    @staticmethod
    def _table(headers: list[str]) -> QTableWidget:
        table = QTableWidget(0, len(headers)); table.setHorizontalHeaderLabels(headers); table.verticalHeader().setVisible(False); table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers); table.setAlternatingRowColors(True); table.setMinimumHeight(150); table.horizontalHeader().setStretchLastSection(True)
        table.setStyleSheet("QTableWidget{background:#0D1117;color:#C9D1D9;gridline-color:#21262D;border:1px solid #30363D;border-radius:8px;font-size:12px}QHeaderView::section{background:#161B22;color:#8B949E;font-weight:600;border:none;border-bottom:1px solid #30363D;padding:7px}")
        return table

    @staticmethod
    def _populate(table: QTableWidget, rows: Iterable[Iterable[str]]) -> None:
        materialized = list(rows); table.setRowCount(len(materialized))
        for row_index, values in enumerate(materialized):
            for column, value in enumerate(values): table.setItem(row_index, column, QTableWidgetItem(str(value)))

    def generate(self) -> None:
        try:
            if not database_service.is_ready and not database_service.initialize(): raise RuntimeError("database initialization failed")
            self._current_report = self._service.generate(self._period.currentText()); self._render(self._current_report)
        except Exception as exc: self._status.setText(f"Report generation failed: {exc}")

    def _render(self, report: OperationalReport) -> None:
        s = report.summary
        for key, value in (("packets", s.total_packets), ("allow", s.total_allowed_events), ("alert", s.total_alert_actions), ("block", s.total_blocked_events)): self._cards[key].set_value(str(value))
        levels = s.events_by_severity
        self._risk.setText(f"Average Risk  <b>{s.average_risk_score:.1f}</b> &nbsp;&nbsp; Maximum Risk  <b>{s.maximum_risk_score}</b> &nbsp;&nbsp; High / Critical  <b>{s.high_risk_events + s.critical_events}</b><br><span style='color:#8B949E'>SAFE / LOW: {levels.get('LOW', 0)} &nbsp; MEDIUM: {levels.get('MEDIUM', 0)} &nbsp; HIGH: {levels.get('HIGH', 0)} &nbsp; CRITICAL: {levels.get('CRITICAL', 0)}</span>")
        total = sum(report.protocol_statistics.values()); protocols = [(name, count, f"{count / total * 100:.1f}%") for name, count in report.protocol_statistics.items()] or [("No protocols recorded", "—", "—")]; self._populate(self._protocol_table, protocols)
        modbus = [(f"0x{r['code']:02X}", r['name'], r['count'], r['decision'], f"{r['average_risk']:.1f}") for r in report.modbus_statistics] or [("No Modbus functions recorded", "—", "—", "—", "—")]; self._populate(self._modbus_table, modbus)
        physics = [(r['label'], *[f"{r[key]:.2f} {r['unit']}" for key in ('minimum', 'maximum', 'average', 'latest')]) for r in report.physics_statistics] or [("No persisted physics readings", "—", "—", "—", "—")]; self._populate(self._physics_table, physics)
        self._physics_note.setText(f"{report.physics_reading_count} persisted physical samples · " + (f"{len(report.anomalies)} recorded anomalies." if report.anomalies else "No physical anomalies detected during this period."))
        incidents = [(e.timestamp, e.source_ip, e.destination_ip, e.protocol, e.function_name or (f"0x{e.function_code:02X}" if e.function_code is not None else "—"), e.risk_score, e.severity.value, e.final_action, e.matched_policy_name or "—", e.reason) for e in report.incidents] or [("No major incidents recorded during this period.", "", "", "", "", "", "", "", "", "")]; self._populate(self._incident_table, incidents)
        correlations = [(f"{p['network'].timestamp} · {p['network'].protocol} · {p['network'].function_name or 'Modbus activity'}", f"{p['network'].final_action} · risk {p['network'].risk_score}", p['physics'].reason) for p in report.correlations] or [("No confirmed cyber-physical correlations recorded during this period.", "", "")]; self._populate(self._correlation_table, correlations)
        self._recommendations.setText("<br>".join(f"• {escape(item)}" for item in report.recommendations)); self._status.setText(f"Selected period: {report.period} · Generated {report.generated_at} · current persisted data")

    def download_pdf(self) -> None:
        if not self._current_report: self.generate()
        report = self._current_report
        if not report: return
        path, _ = QFileDialog.getSaveFileName(self, "Save VoltGuard report", "voltguard-report.pdf", "PDF files (*.pdf)")
        if not path: return
        if not path.lower().endswith(".pdf"): path += ".pdf"
        try:
            from reportlab.lib.pagesizes import A4
            from reportlab.lib.styles import getSampleStyleSheet
            from reportlab.lib.units import mm
            from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer
            styles, story = getSampleStyleSheet(), []
            def add(value: str, style: str = "BodyText") -> None: story.append(Paragraph(escape(value), styles[style]))
            s = report.summary; add("VoltGuard — Operational Security Report", "Title"); add(f"Period: {report.period} | Generated: {report.generated_at}"); story.append(Spacer(1, 8)); add("Security Summary", "Heading2"); add(f"Packets: {s.total_packets}; ALLOW: {s.total_allowed_events}; ALERT: {s.total_alert_actions}; BLOCK: {s.total_blocked_events}; Average risk: {s.average_risk_score:.1f}; Maximum risk: {s.maximum_risk_score}")
            for heading, values, empty in (("Protocol Statistics", [f"{k}: {v}" for k, v in report.protocol_statistics.items()], "None recorded"), ("Modbus Statistics", [f"0x{r['code']:02X} {r['name']}: {r['count']} ({r['decision']}, average risk {r['average_risk']:.1f})" for r in report.modbus_statistics], "None recorded"), ("Physics Statistics", [f"{r['label']}: min {r['minimum']:.2f}, max {r['maximum']:.2f}, average {r['average']:.2f}, latest {r['latest']:.2f} {r['unit']}" for r in report.physics_statistics], "No persisted readings"), ("Major Incidents", [f"{e.timestamp}: {e.final_action}, risk {e.risk_score}, {e.reason}" for e in report.incidents], "No major incidents recorded during this period."), ("Cyber-Physical Correlations", [f"{p['network'].timestamp}: {p['network'].reason} → {p['physics'].reason}" for p in report.correlations], "No confirmed cyber-physical correlations recorded during this period."), ("Recommendations", report.recommendations, "No recommendations")):
                add(heading, "Heading2"); [add(value) for value in values] or add(empty)
            SimpleDocTemplate(path, pagesize=A4, leftMargin=16*mm, rightMargin=16*mm, topMargin=16*mm, bottomMargin=16*mm).build(story); self._status.setText(f"PDF saved: {path}")
        except ImportError: self._status.setText("PDF export unavailable: install reportlab.")
        except Exception as exc: self._status.setText(f"PDF export failed: {exc}")
