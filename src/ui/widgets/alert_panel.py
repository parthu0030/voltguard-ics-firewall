"""
VoltGuard — Alert Panel Widget (Day 9)
=======================================
Dedicated alert section reusing Day 7 AlertManager.
"""

from __future__ import annotations

from typing import Callable, Optional

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QTabWidget,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from src.models.app_models import Alert
from src.ui.widgets.event_detail_dialog import AlertDetailDialog
from src.ui.widgets.severity_styles import action_qcolor, format_timestamp, severity_qcolor


class AlertPanel(QFrame):
    """Tabbed alert panel: Critical, High, Unacknowledged, Recent."""

    def __init__(
        self,
        on_acknowledge: Optional[Callable[[int], None]] = None,
        on_acknowledge_all: Optional[Callable[[], None]] = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._on_acknowledge = on_acknowledge
        self._on_ack_all = on_acknowledge_all
        self._alert_maps: dict[str, list[Alert]] = {}
        self._build_ui()

    def _build_ui(self) -> None:
        self.setStyleSheet(
            """
            QFrame {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 10px;
            }
            QTabWidget::pane { border: none; background: transparent; }
            QTabBar::tab {
                background: #21262D;
                color: #8B949E;
                padding: 6px 14px;
                border-radius: 4px;
                margin-right: 4px;
            }
            QTabBar::tab:selected { background: #1F6FEB; color: #E6EDF3; }
            """
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 16, 16, 16)
        layout.setSpacing(10)

        hdr = QHBoxLayout()
        title = QLabel("Security Alerts")
        title.setStyleSheet("font-size: 15px; font-weight: 700; color: #E6EDF3;")
        hdr.addWidget(title)
        hdr.addStretch()

        self._summary_label = QLabel("")
        self._summary_label.setStyleSheet("color: #8B949E; font-size: 11px;")
        hdr.addWidget(self._summary_label)

        ack_all = QPushButton("Acknowledge All")
        ack_all.setCursor(Qt.CursorShape.PointingHandCursor)
        ack_all.clicked.connect(self._ack_all)
        hdr.addWidget(ack_all)
        layout.addLayout(hdr)

        self._tabs = QTabWidget()
        self._tables: dict[str, QTableWidget] = {}
        for tab_name in ("Critical", "High", "Unacknowledged", "Recent"):
            table = self._make_table(tab_name)
            self._tables[tab_name.lower()] = table
            self._tabs.addTab(table, tab_name)
        layout.addWidget(self._tabs)

        self._empty_label = QLabel("No alerts recorded.")
        self._empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self._empty_label.setStyleSheet("color: #484F58; font-size: 13px; padding: 16px;")
        self._empty_label.hide()
        layout.addWidget(self._empty_label)

    def _make_table(self, tab_key: str) -> QTableWidget:
        table = QTableWidget()
        table.setColumnCount(5)
        table.setHorizontalHeaderLabels(["Time", "Severity", "Action", "Source → Dest", "Message"])
        table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        table.verticalHeader().setVisible(False)
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setMinimumHeight(160)
        table.setStyleSheet(
            """
            QTableWidget {
                background-color: #0D1117;
                color: #C9D1D9;
                gridline-color: #21262D;
                border: none;
                font-size: 12px;
            }
            """
        )
        table.doubleClicked.connect(lambda: self._inspect_alert(tab_key.lower()))
        return table

    def populate(
        self,
        critical: list[Alert],
        high: list[Alert],
        unack: list[Alert],
        recent: list[Alert],
        counts: dict[str, int],
    ) -> None:
        """Update all alert tabs from live data."""
        self._alert_maps = {
            "critical": critical,
            "high": high,
            "unacknowledged": unack,
            "recent": recent,
        }
        self._fill_table("critical", critical)
        self._fill_table("high", high)
        self._fill_table("unacknowledged", unack)
        self._fill_table("recent", recent)

        total = counts.get("total", 0)
        unack_n = counts.get("unacknowledged", 0)
        self._summary_label.setText(f"{total} total · {unack_n} active")

        any_alerts = bool(critical or high or unack or recent)
        self._empty_label.setVisible(not any_alerts)
        self._tabs.setVisible(any_alerts)

    def _fill_table(self, key: str, alerts: list[Alert]) -> None:
        table = self._tables[key]
        table.setRowCount(len(alerts))
        for row, alert in enumerate(alerts):
            table.setItem(row, 0, QTableWidgetItem(format_timestamp(alert.timestamp)))
            sev_item = QTableWidgetItem(alert.severity.value)
            sev_item.setForeground(severity_qcolor(alert.severity.value))
            table.setItem(row, 1, sev_item)
            act_item = QTableWidgetItem(alert.action or "ALERT")
            act_item.setForeground(action_qcolor(alert.action or "ALERT"))
            table.setItem(row, 2, act_item)
            ep = f"{alert.source_ip} → {alert.destination_ip}" if alert.source_ip else "—"
            table.setItem(row, 3, QTableWidgetItem(ep))
            rep = f" (×{alert.repeat_count})" if alert.repeat_count > 1 else ""
            msg_item = QTableWidgetItem(f"{alert.message}{rep}")
            msg_item.setData(Qt.ItemDataRole.UserRole, alert)
            table.setItem(row, 4, msg_item)

    def _inspect_alert(self, tab_key: str) -> None:
        table = self._tables.get(tab_key)
        if not table:
            return
        row = table.currentRow()
        if row < 0:
            return
        item = table.item(row, 4)
        if not item:
            return
        alert = item.data(Qt.ItemDataRole.UserRole)
        if alert:
            AlertDetailDialog(
                alert,
                on_acknowledge=self._on_acknowledge,
                parent=self,
            ).exec()

    def _ack_all(self) -> None:
        if self._on_ack_all:
            self._on_ack_all()
