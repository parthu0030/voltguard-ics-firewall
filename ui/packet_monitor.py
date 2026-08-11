"""
VoltGuard Packet Monitor UI
-----------------------------
Live table view of captured packets with start/stop capture controls,
interface selection, and real-time row insertion via Qt signals.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt, QTimer, Signal, QObject
from PySide6.QtWidgets import (
    QComboBox,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QPushButton,
    QSizePolicy,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from core.packet_capture import PacketCapture
from core.protocol_parser import ParsedPacket
from database.database import get_db
from config.config_manager import get_config
from core.logger import get_logger

log = get_logger(__name__)

MAX_TABLE_ROWS = 500  # keep the table manageable


# ---------------------------------------------------------------------------
# Qt signal bridge (moves captured data onto the GUI thread)
# ---------------------------------------------------------------------------

class _CaptureSignals(QObject):
    packet_received = Signal(object)  # emits ParsedPacket


# ---------------------------------------------------------------------------
# Packet Monitor page
# ---------------------------------------------------------------------------

class PacketMonitorPage(QWidget):
    """Packet monitor page with live capture table and start/stop controls."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._db = get_db()
        self._config = get_config()
        self._capture = PacketCapture()
        self._signals = _CaptureSignals()
        self._signals.packet_received.connect(self._on_packet_received)
        self._capture.add_callback(self._signals.packet_received.emit)
        self._setup_ui()
        self._load_interfaces()
        self._load_history()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(16)

        # Header
        header_row = QHBoxLayout()
        title = QLabel("Packet Monitor")
        title.setObjectName("PageTitle")
        header_row.addWidget(title)
        header_row.addStretch()

        self._status_label = QLabel("● Idle")
        self._status_label.setObjectName("StatusText")
        self._status_label.setStyleSheet("color: #6B7280;")
        header_row.addWidget(self._status_label)

        layout.addLayout(header_row)

        # Controls bar
        controls = QFrame()
        controls.setObjectName("ControlsBar")
        controls_layout = QHBoxLayout(controls)
        controls_layout.setContentsMargins(16, 10, 16, 10)
        controls_layout.setSpacing(12)

        iface_label = QLabel("Interface:")
        iface_label.setObjectName("FieldLabel")
        self._iface_combo = QComboBox()
        self._iface_combo.setObjectName("VGCombo")
        self._iface_combo.setMinimumWidth(180)

        self._start_btn = QPushButton("▶  Start Capture")
        self._start_btn.setObjectName("PrimaryButton")
        self._start_btn.clicked.connect(self._start_capture)

        self._stop_btn = QPushButton("■  Stop Capture")
        self._stop_btn.setObjectName("DangerButton")
        self._stop_btn.setEnabled(False)
        self._stop_btn.clicked.connect(self._stop_capture)

        self._clear_btn = QPushButton("Clear Table")
        self._clear_btn.setObjectName("SecondaryButton")
        self._clear_btn.clicked.connect(self._clear_table)

        self._pkt_count_label = QLabel("Packets: 0")
        self._pkt_count_label.setObjectName("SmallMuted")

        controls_layout.addWidget(iface_label)
        controls_layout.addWidget(self._iface_combo)
        controls_layout.addWidget(self._start_btn)
        controls_layout.addWidget(self._stop_btn)
        controls_layout.addWidget(self._clear_btn)
        controls_layout.addStretch()
        controls_layout.addWidget(self._pkt_count_label)

        layout.addWidget(controls)

        # Packet table
        self._table = QTableWidget(0, 7)
        self._table.setObjectName("PacketTable")
        self._table.setHorizontalHeaderLabels(
            ["Timestamp", "Source IP", "Destination IP", "Protocol", "FC", "Length", "Action"]
        )
        self._table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self._table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self._table.verticalHeader().setVisible(False)
        self._table.setEditTriggers(QTableWidget.NoEditTriggers)
        self._table.setSelectionBehavior(QTableWidget.SelectRows)
        self._table.setAlternatingRowColors(True)
        self._table.setSortingEnabled(False)

        layout.addWidget(self._table)

    # ------------------------------------------------------------------
    # Interface loading
    # ------------------------------------------------------------------

    def _load_interfaces(self) -> None:
        """Populate the interface combo box."""
        self._iface_combo.clear()
        self._iface_combo.addItem("auto (default)")

        interfaces = self._capture.get_available_interfaces()
        for iface in interfaces:
            self._iface_combo.addItem(iface)

        # Pre-select saved interface
        saved = self._config.get_interface()
        idx = self._iface_combo.findText(saved)
        if idx >= 0:
            self._iface_combo.setCurrentIndex(idx)

    # ------------------------------------------------------------------
    # Capture control
    # ------------------------------------------------------------------

    def _start_capture(self) -> None:
        """Begin packet capture on the selected interface."""
        raw = self._iface_combo.currentText()
        iface = None if raw.startswith("auto") else raw

        # Persist selected interface
        self._config.set_interface(raw)

        success = self._capture.start(interface=iface)
        if success:
            self._start_btn.setEnabled(False)
            self._stop_btn.setEnabled(True)
            self._iface_combo.setEnabled(False)
            self._status_label.setText("● Live")
            self._status_label.setStyleSheet("color: #00E676; font-weight: 600;")
            log.info("Capture started from UI on interface: %s", iface or "default")
        else:
            self._status_label.setText("● Error — see logs")
            self._status_label.setStyleSheet("color: #EF4444;")

    def _stop_capture(self) -> None:
        """Stop the active packet capture session."""
        self._capture.stop()
        self._start_btn.setEnabled(True)
        self._stop_btn.setEnabled(False)
        self._iface_combo.setEnabled(True)
        self._status_label.setText("● Stopped")
        self._status_label.setStyleSheet("color: #6B7280;")
        log.info("Capture stopped from UI.")

    # ------------------------------------------------------------------
    # Table management
    # ------------------------------------------------------------------

    def _on_packet_received(self, pkt: ParsedPacket) -> None:
        """Insert a new row for every captured packet (GUI thread callback)."""
        action = pkt.extra.get("action", "ALLOWED")
        action_color = "#00E676" if action == "ALLOWED" else "#EF4444"

        row = self._table.rowCount()

        # Evict oldest row when the cap is reached to keep the UI responsive
        if row >= MAX_TABLE_ROWS:
            self._table.removeRow(0)
            row = self._table.rowCount()

        self._table.insertRow(row)
        cells = [
            pkt.timestamp,
            pkt.src_ip,
            pkt.dst_ip,
            pkt.protocol,
            str(pkt.function_code) if pkt.function_code is not None else "—",
            str(pkt.payload_length),
            action,
        ]
        for col, text in enumerate(cells):
            item = QTableWidgetItem(text)
            item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
            if col == 6:  # action column
                item.setForeground(Qt.GlobalColor.white)
            self._table.setItem(row, col, item)

        # Colour the action cell
        action_item = self._table.item(row, 6)
        if action_item:
            from PySide6.QtGui import QColor
            action_item.setForeground(QColor(action_color))

        self._table.scrollToBottom()
        stats = self._capture.get_stats()
        self._pkt_count_label.setText(f"Packets: {stats['total']}")

    def _clear_table(self) -> None:
        """Remove all rows from the display table."""
        self._table.setRowCount(0)
        self._pkt_count_label.setText("Packets: 0")

    def _load_history(self) -> None:
        """Populate the table with the last 100 stored packets on page open."""
        rows = self._db.get_recent_packets(limit=100)
        for pkt in reversed(rows):
            row = self._table.rowCount()
            self._table.insertRow(row)
            cells = [
                str(pkt["timestamp"] or ""),
                str(pkt["src_ip"] or ""),
                str(pkt["dst_ip"] or ""),
                str(pkt["protocol"] or ""),
                str(pkt["function_code"]) if pkt["function_code"] else "—",
                str(pkt["payload_length"] or 0),
                str(pkt["action"] or "ALLOWED"),
            ]
            for col, text in enumerate(cells):
                item = QTableWidgetItem(text)
                item.setTextAlignment(Qt.AlignVCenter | Qt.AlignLeft)
                self._table.setItem(row, col, item)

    # ------------------------------------------------------------------
    # External state sync
    # ------------------------------------------------------------------

    def get_capture(self) -> PacketCapture:
        """Return the :class:`PacketCapture` instance for use by the main window."""
        return self._capture
