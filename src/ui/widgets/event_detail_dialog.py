"""
VoltGuard — Event Detail Dialog (Day 9)
========================================
Detailed, explainable view of a single security event.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QDialog,
    QFormLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
)

from src.models.security_event import SecurityEvent
from src.ui.widgets.severity_styles import action_colour, format_timestamp, severity_colour


class EventDetailDialog(QDialog):
    """Modal dialog showing full audit details for a security event."""

    def __init__(
        self,
        event: SecurityEvent,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.setWindowTitle("Security Event Details")
        self.setMinimumSize(520, 480)
        self.setStyleSheet(
            """
            QDialog { background-color: #0D1117; }
            QLabel { background: transparent; }
            """
        )
        self._build_ui(event)

    def _build_ui(self, event: SecurityEvent) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(16)

        title = QLabel("Security Event Details")
        title.setStyleSheet("font-size: 18px; font-weight: 700; color: #E6EDF3;")
        root.addWidget(title)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QScrollArea.Shape.NoFrame)
        scroll.setStyleSheet("background: transparent; border: none;")
        root.addWidget(scroll, 1)

        container = QWidget()
        form = QFormLayout(container)
        form.setContentsMargins(0, 0, 8, 0)
        form.setSpacing(10)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)

        fc_display = event.function_name or (
            f"0x{event.function_code:02X}" if event.function_code is not None else "—"
        )
        rows = [
            ("Timestamp", format_timestamp(event.timestamp) + f"  ({event.timestamp})"),
            ("Event ID", event.event_id),
            ("Source", f"{event.source_ip}:{event.source_port}"),
            ("Destination", f"{event.destination_ip}:{event.destination_port}"),
            ("Protocol", event.protocol),
            ("Modbus Function", fc_display),
            ("Risk Score", str(event.risk_score)),
            ("Risk Level", event.risk_level),
            ("Severity", event.severity.value),
            ("Original Decision", event.original_decision),
            ("Matched Policy", event.matched_policy_id or "—"),
            ("Policy Name", event.matched_policy_name or "—"),
            ("Final Action", event.final_action),
            ("Event Type", event.event_type),
            ("Status", "Acknowledged" if event.acknowledged else "Active"),
            ("Reason", event.reason or "—"),
        ]

        for label_text, value_text in rows:
            lbl = QLabel(label_text)
            lbl.setStyleSheet("color: #8B949E; font-size: 12px; font-weight: 600;")
            val = QLabel(str(value_text))
            val.setWordWrap(True)
            val.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse)

            if label_text == "Severity":
                val.setStyleSheet(f"color: {severity_colour(str(value_text))}; font-size: 13px; font-weight: 600;")
            elif label_text == "Final Action":
                val.setStyleSheet(f"color: {action_colour(str(value_text))}; font-size: 13px; font-weight: 600;")
            else:
                val.setStyleSheet("color: #E6EDF3; font-size: 13px;")

            form.addRow(lbl, val)

        scroll.setWidget(container)

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        close_btn = QPushButton("Close")
        close_btn.setCursor(Qt.CursorShape.PointingHandCursor)
        close_btn.clicked.connect(self.accept)
        btn_row.addWidget(close_btn)
        root.addLayout(btn_row)


class AlertDetailDialog(QDialog):
    """Modal dialog showing alert inspection details."""

    def __init__(self, alert, on_acknowledge=None, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._alert = alert
        self._on_acknowledge = on_acknowledge
        self.setWindowTitle("Alert Details")
        self.setMinimumSize(480, 400)
        self.setStyleSheet("QDialog { background-color: #0D1117; }")
        self._build_ui()

    def _build_ui(self) -> None:
        a = self._alert
        root = QVBoxLayout(self)
        root.setContentsMargins(20, 20, 20, 20)
        root.setSpacing(12)

        title = QLabel(f"[{a.severity.value}] Security Alert")
        title.setStyleSheet(
            f"font-size: 16px; font-weight: 700; color: {severity_colour(a.severity.value)};"
        )
        root.addWidget(title)

        form = QFormLayout()
        form.setSpacing(8)
        rows = [
            ("Time", format_timestamp(a.timestamp)),
            ("Message", a.message),
            ("Action", a.action or "ALERT"),
            ("Source", a.source_ip or "—"),
            ("Destination", a.destination_ip or "—"),
            ("Protocol", a.protocol or "—"),
            ("Risk Score", str(a.risk_score)),
            ("Policy", a.policy_id or "—"),
            ("Repeat Count", str(a.repeat_count)),
            ("Status", "Acknowledged" if a.acknowledged else "Active"),
        ]
        for lbl_text, val_text in rows:
            lbl = QLabel(lbl_text)
            lbl.setStyleSheet("color: #8B949E; font-size: 12px;")
            val = QLabel(str(val_text))
            val.setWordWrap(True)
            val.setStyleSheet("color: #E6EDF3; font-size: 13px;")
            form.addRow(lbl, val)
        root.addLayout(form)
        root.addStretch()

        btn_row = QHBoxLayout()
        btn_row.addStretch()
        if not a.acknowledged and self._on_acknowledge and a.id is not None:
            ack_btn = QPushButton("Acknowledge")
            ack_btn.clicked.connect(self._do_ack)
            btn_row.addWidget(ack_btn)
        close_btn = QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        btn_row.addWidget(close_btn)
        root.addLayout(btn_row)

    def _do_ack(self) -> None:
        if self._on_acknowledge and self._alert.id is not None:
            self._on_acknowledge(self._alert.id)
        self.accept()
