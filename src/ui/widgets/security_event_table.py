"""
VoltGuard — Security Event Table Widget (Day 9)
"""

from __future__ import annotations

from typing import Callable, Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.models.security_event import SecurityEvent
from src.ui.widgets.event_detail_dialog import EventDetailDialog
from src.ui.widgets.severity_styles import action_qcolor, format_timestamp, severity_qcolor


class SecurityEventTable(QFrame):
    """
    Operator-friendly security event table with sorting and filtering.

    Emits selection via ``event_selected`` callback on double-click.
    """

    COLUMNS = [
        "Time", "Source", "Destination", "Protocol", "Function",
        "Risk", "Severity", "Policy", "Action", "Status",
    ]

    def __init__(
        self,
        on_event_open: Optional[Callable[[SecurityEvent], None]] = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._on_event_open = on_event_open
        self._events: list[SecurityEvent] = []
        self._build_ui()

    def _build_ui(self) -> None:
        self.setStyleSheet(
            """
            QFrame {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 10px;
            }
            """
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        hdr = QHBoxLayout()
        title = QLabel("Security Events")
        title.setStyleSheet("font-size: 15px; font-weight: 700; color: #E6EDF3; border: none;")
        hdr.addWidget(title)
        hdr.addStretch()

        hdr.addWidget(QLabel("Severity:"))
        self._sev_filter = QComboBox()
        self._sev_filter.addItems(["All", "CRITICAL", "HIGH", "MEDIUM", "LOW"])
        self._sev_filter.setFixedWidth(110)
        self._sev_filter.currentTextChanged.connect(self._emit_filter_changed)
        hdr.addWidget(self._sev_filter)

        hdr.addWidget(QLabel("Action:"))
        self._act_filter = QComboBox()
        self._act_filter.addItems(["All", "BLOCK", "ALERT", "ALLOW"])
        self._act_filter.setFixedWidth(100)
        self._act_filter.currentTextChanged.connect(self._emit_filter_changed)
        hdr.addWidget(self._act_filter)

        layout.addLayout(hdr)

        self._empty_label = QLabel("No security events recorded.")
        self._empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_label.setStyleSheet("color: #484F58; font-size: 13px; padding: 24px;")
        self._empty_label.hide()
        layout.addWidget(self._empty_label)

        self._table = QTableWidget()
        self._table.setColumnCount(len(self.COLUMNS))
        self._table.setHorizontalHeaderLabels(self.COLUMNS)
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        self._table.horizontalHeader().setStretchLastSection(True)
        self._table.setSortingEnabled(True)
        self._table.verticalHeader().setVisible(False)
        self._table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self._table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self._table.setAlternatingRowColors(True)
        self._table.setMinimumHeight(220)
        self._table.doubleClicked.connect(self._on_double_click)
        self._table.setStyleSheet(
            """
            QTableWidget {
                background-color: #0D1117;
                color: #C9D1D9;
                gridline-color: #21262D;
                border: 1px solid #30363D;
                border-radius: 6px;
                font-size: 12px;
            }
            QHeaderView::section {
                background-color: #161B22;
                color: #8B949E;
                font-weight: 600;
                font-size: 11px;
                border: none;
                border-bottom: 1px solid #30363D;
                padding: 6px;
            }
            """
        )
        layout.addWidget(self._table)

        self._filter_callback: Optional[Callable[[Optional[str], Optional[str]], None]] = None

    def set_filter_callback(
        self,
        callback: Callable[[Optional[str], Optional[str]], None],
    ) -> None:
        """Register callback invoked when filters change (for external reload)."""
        self._filter_callback = callback

    def _emit_filter_changed(self) -> None:
        if self._filter_callback:
            self._filter_callback(self.get_severity_filter(), self.get_action_filter())

    def get_severity_filter(self) -> Optional[str]:
        val = self._sev_filter.currentText()
        return None if val == "All" else val

    def get_action_filter(self) -> Optional[str]:
        val = self._act_filter.currentText()
        return None if val == "All" else val

    def populate(self, events: list[SecurityEvent]) -> None:
        """Fill the table with security events."""
        self._events = events
        self._table.setSortingEnabled(False)
        self._table.setRowCount(len(events))

        if not events:
            self._empty_label.show()
            self._table.hide()
        else:
            self._empty_label.hide()
            self._table.show()

        for row_idx, ev in enumerate(events):
            fc = ev.function_name or (
                f"0x{ev.function_code:02X}" if ev.function_code is not None else "—"
            )
            policy = ev.matched_policy_id or "—"
            status = "Acknowledged" if ev.acknowledged else "Active"

            cells = [
                format_timestamp(ev.timestamp),
                ev.source_ip,
                ev.destination_ip,
                ev.protocol,
                fc,
                str(ev.risk_score),
                ev.severity.value,
                policy,
                ev.final_action,
                status,
            ]
            for col_idx, text in enumerate(cells):
                item = QTableWidgetItem(text)
                if col_idx in (5, 6, 8):
                    item.setTextAlignment(Qt.AlignmentFlag.AlignCenter)
                if col_idx == 6:
                    item.setForeground(severity_qcolor(ev.severity.value))
                if col_idx == 8:
                    item.setForeground(action_qcolor(ev.final_action))
                self._table.setItem(row_idx, col_idx, item)

            # Store row id for lookup
            id_item = QTableWidgetItem(str(ev.id or ""))
            id_item.setData(Qt.ItemDataRole.UserRole, ev.id)
            self._table.setItem(row_idx, 0, self._table.item(row_idx, 0))
            self._table.item(row_idx, 0).setData(Qt.ItemDataRole.UserRole, ev)

        self._table.setSortingEnabled(True)

    def _on_double_click(self) -> None:
        row = self._table.currentRow()
        if row < 0 or row >= len(self._events):
            return
        event = self._events[row]
        if self._on_event_open:
            self._on_event_open(event)
        else:
            EventDetailDialog(event, parent=self).exec()
