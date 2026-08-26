"""
VoltGuard — Packet Monitor Page (Day 5)
=========================================
Live packet capture and security pipeline monitoring page.

Connects to the ``PacketPipeline`` (Day 5) to display:
  - Live counters: Captured / ALLOW / ALERT / BLOCK
  - Scrolling event table with per-packet risk scores and decisions
  - Start/Stop controls for simulation mode

Architecture
------------
The ``PacketPipeline`` runs on a background thread.  This page polls the
pipeline every 500 ms via a ``QTimer`` (safe UI thread update) rather than
using cross-thread signals, keeping the implementation simple.

Events are displayed newest-first in a scrollable table.  Up to 50 events
are shown at once.
"""

from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

from src.core.app_state import app_state
from src.logger import get_logger

_log = get_logger(__name__)

# Decision colours (matches the GitHub-dark theme)
_COLOUR_ALLOW = "#3FB950"   # Green
_COLOUR_ALERT = "#F0883E"   # Orange
_COLOUR_BLOCK = "#F85149"   # Red
_COLOUR_SKIP  = "#8B949E"   # Gray

# Max events to show in the table
_MAX_TABLE_ROWS = 50


def _decision_colour(decision: str) -> str:
    if decision == "ALLOW":
        return _COLOUR_ALLOW
    if decision == "ALERT":
        return _COLOUR_ALERT
    if decision == "BLOCK":
        return _COLOUR_BLOCK
    return _COLOUR_SKIP


def _build_page_header(icon: str, title: str, description: str) -> QWidget:
    """Build the shared header used by the placeholder pages."""
    widget = QWidget()
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(6)

    heading = QLabel(f"{icon}  {title}")
    heading.setStyleSheet(
        "font-size: 24px; font-weight: 700; color: #E6EDF3; background: transparent;"
    )
    layout.addWidget(heading)

    detail = QLabel(description)
    detail.setWordWrap(True)
    detail.setStyleSheet("font-size: 13px; color: #8B949E; background: transparent;")
    layout.addWidget(detail)
    return widget


def _build_feature_list(features: list[str]) -> QWidget:
    """Build the shared feature list used by the placeholder pages."""
    frame = QFrame()
    frame.setStyleSheet(
        "QFrame { background: #161B22; border: 1px solid #30363D; border-radius: 8px; }"
    )
    layout = QVBoxLayout(frame)
    layout.setContentsMargins(18, 14, 18, 14)
    layout.setSpacing(8)
    for feature in features:
        item = QLabel(f"•  {feature}")
        item.setStyleSheet("font-size: 13px; color: #C9D1D9; background: transparent;")
        layout.addWidget(item)
    return frame


class PacketMonitorPage(QWidget):
    """
    Live packet monitor page — Day 5 implementation.

    Displays the real-time output of the ``PacketPipeline`` including
    per-packet ALLOW / ALERT / BLOCK decisions and risk scores.
    """

    PAGE_TITLE = "Packet Monitor"
    PAGE_ICON  = "📡"

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._pipeline = None
        self._timer: Optional[QTimer] = None
        self._build_ui()
        self._try_connect_pipeline()

    # ------------------------------------------------------------------
    # UI Construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        """Construct the live monitor layout."""
        root = QVBoxLayout(self)
        root.setContentsMargins(24, 24, 24, 24)
        root.setSpacing(16)

        # ── Header ───────────────────────────────────────────────────────
        root.addWidget(self._build_header())

        # ── Counter cards ─────────────────────────────────────────────────
        self._counter_row = self._build_counter_row()
        root.addWidget(self._counter_row)

        # ── Control bar ───────────────────────────────────────────────────
        root.addWidget(self._build_control_bar())

        # ── Status label ─────────────────────────────────────────────────
        self._status_label = QLabel("Pipeline: Idle — click Start Simulation to begin.")
        self._status_label.setStyleSheet(
            "font-size: 12px; color: #8B949E; background: transparent; "
            "padding: 4px 0px;"
        )
        root.addWidget(self._status_label)

        # ── Event table ───────────────────────────────────────────────────
        root.addWidget(self._build_event_table(), stretch=1)

    def _build_header(self) -> QWidget:
        widget = QWidget()
        widget.setStyleSheet("background: transparent;")
        layout = QVBoxLayout(widget)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)

        row = QHBoxLayout()
        row.setSpacing(12)

        icon = QLabel(self.PAGE_ICON)
        icon.setStyleSheet("font-size: 28px; background: transparent; color: #E6EDF3;")
        row.addWidget(icon)

        title = QLabel(self.PAGE_TITLE)
        title.setStyleSheet(
            "font-size: 22px; font-weight: 700; color: #E6EDF3; background: transparent;"
        )
        row.addWidget(title)

        self._mode_badge = QLabel("SIMULATION")
        self._mode_badge.setStyleSheet(
            "font-size: 10px; font-weight: 600; color: #58A6FF; "
            "background: #1F2D3D; border: 1px solid #1F6FEB; "
            "border-radius: 4px; padding: 2px 8px;"
        )
        row.addWidget(self._mode_badge)
        row.addStretch()
        layout.addLayout(row)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet("color: #30363D; background-color: #30363D; max-height: 1px;")
        layout.addWidget(sep)

        return widget

    def _build_counter_row(self) -> QWidget:
        row = QHBoxLayout()
        row.setSpacing(12)

        self._lbl_captured = self._make_counter_card("Captured",  "0", "#8B949E")
        self._lbl_allowed  = self._make_counter_card("ALLOW",     "0", _COLOUR_ALLOW)
        self._lbl_alerted  = self._make_counter_card("ALERT",     "0", _COLOUR_ALERT)
        self._lbl_blocked  = self._make_counter_card("BLOCK",     "0", _COLOUR_BLOCK)

        row.addWidget(self._lbl_captured[0])
        row.addWidget(self._lbl_allowed[0])
        row.addWidget(self._lbl_alerted[0])
        row.addWidget(self._lbl_blocked[0])

        wrapper = QWidget()
        wrapper.setStyleSheet("background: transparent;")
        wrapper.setLayout(row)
        return wrapper

    def _make_counter_card(
        self, label: str, initial: str, colour: str
    ) -> tuple[QFrame, QLabel]:
        """Build a single counter card. Returns (frame, value_label)."""
        card = QFrame()
        card.setStyleSheet(f"""
            QFrame {{
                background: #161B22;
                border: 1px solid #30363D;
                border-radius: 10px;
            }}
        """)
        card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

        vbox = QVBoxLayout(card)
        vbox.setContentsMargins(16, 12, 16, 12)
        vbox.setSpacing(4)

        lbl_name = QLabel(label)
        lbl_name.setStyleSheet(
            f"font-size: 11px; font-weight: 600; color: {colour}; "
            "background: transparent; letter-spacing: 0.5px;"
        )
        lbl_name.setAlignment(Qt.AlignmentFlag.AlignCenter)
        vbox.addWidget(lbl_name)

        lbl_val = QLabel(initial)
        lbl_val.setStyleSheet(
            f"font-size: 28px; font-weight: 700; color: {colour}; "
            "background: transparent;"
        )
        lbl_val.setAlignment(Qt.AlignmentFlag.AlignCenter)
        vbox.addWidget(lbl_val)

        return card, lbl_val

    def _build_control_bar(self) -> QWidget:
        bar = QWidget()
        bar.setStyleSheet("background: transparent;")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        self._btn_start = QPushButton("▶  Start Simulation")
        self._btn_start.setObjectName("btnStart")
        self._btn_start.setStyleSheet("""
            QPushButton#btnStart {
                background: #1F6FEB;
                color: #FFFFFF;
                border: none;
                border-radius: 6px;
                font-size: 13px;
                font-weight: 600;
                padding: 8px 20px;
            }
            QPushButton#btnStart:hover { background: #388BFD; }
            QPushButton#btnStart:pressed { background: #1158C7; }
            QPushButton#btnStart:disabled { background: #30363D; color: #6E7681; }
        """)
        self._btn_start.clicked.connect(self._on_start)
        layout.addWidget(self._btn_start)

        self._btn_stop = QPushButton("■  Stop")
        self._btn_stop.setObjectName("btnStop")
        self._btn_stop.setEnabled(False)
        self._btn_stop.setStyleSheet("""
            QPushButton#btnStop {
                background: #21262D;
                color: #F85149;
                border: 1px solid #F85149;
                border-radius: 6px;
                font-size: 13px;
                font-weight: 600;
                padding: 8px 20px;
            }
            QPushButton#btnStop:hover { background: #2D1F1E; }
            QPushButton#btnStop:pressed { background: #F85149; color: #FFFFFF; }
            QPushButton#btnStop:disabled { border-color: #30363D; color: #6E7681; }
        """)
        self._btn_stop.clicked.connect(self._on_stop)
        layout.addWidget(self._btn_stop)

        self._btn_clear = QPushButton("🗑  Clear Events")
        self._btn_clear.setObjectName("btnClear")
        self._btn_clear.setStyleSheet("""
            QPushButton#btnClear {
                background: #21262D;
                color: #8B949E;
                border: 1px solid #30363D;
                border-radius: 6px;
                font-size: 13px;
                padding: 8px 16px;
            }
            QPushButton#btnClear:hover { background: #30363D; color: #E6EDF3; }
        """)
        self._btn_clear.clicked.connect(self._on_clear)
        layout.addWidget(self._btn_clear)

        layout.addStretch()
        return bar

    def _build_event_table(self) -> QWidget:
        """Build a scrollable live event table."""
        outer = QFrame()
        outer.setStyleSheet("""
            QFrame {
                background: #0D1117;
                border: 1px solid #30363D;
                border-radius: 10px;
            }
        """)
        outer_layout = QVBoxLayout(outer)
        outer_layout.setContentsMargins(0, 0, 0, 0)
        outer_layout.setSpacing(0)

        # Table header
        header = self._build_table_header()
        outer_layout.addWidget(header)

        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        sep.setStyleSheet(
            "color: #30363D; background-color: #30363D; max-height: 1px; margin: 0px;"
        )
        outer_layout.addWidget(sep)

        # Scroll area for rows
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setStyleSheet("""
            QScrollArea { background: transparent; border: none; }
            QScrollBar:vertical {
                background: #0D1117; width: 8px; border: none;
            }
            QScrollBar::handle:vertical {
                background: #30363D; border-radius: 4px; min-height: 20px;
            }
        """)

        self._event_container = QWidget()
        self._event_container.setStyleSheet("background: transparent;")
        self._event_layout = QVBoxLayout(self._event_container)
        self._event_layout.setContentsMargins(0, 0, 0, 0)
        self._event_layout.setSpacing(0)
        self._event_layout.addStretch()

        scroll.setWidget(self._event_container)
        outer_layout.addWidget(scroll, stretch=1)

        self._empty_label = QLabel("  No events yet — start the simulation to capture packets.")
        self._empty_label.setStyleSheet(
            "color: #6E7681; font-size: 13px; padding: 24px; background: transparent;"
        )
        self._event_layout.insertWidget(0, self._empty_label)

        return outer

    def _build_table_header(self) -> QWidget:
        header = QWidget()
        header.setStyleSheet("background: #161B22;")
        header.setFixedHeight(34)
        layout = QHBoxLayout(header)
        layout.setContentsMargins(12, 0, 12, 0)
        layout.setSpacing(0)

        cols = [
            ("Timestamp",       120),
            ("Source",          130),
            ("Destination",     130),
            ("Protocol",         90),
            ("Function",        160),
            ("Decision",         80),
            ("Risk",             50),
            ("Level",            80),
        ]
        for name, width in cols:
            lbl = QLabel(name)
            lbl.setFixedWidth(width)
            lbl.setStyleSheet(
                "font-size: 10px; font-weight: 600; color: #6E7681; "
                "letter-spacing: 0.5px; background: transparent;"
            )
            layout.addWidget(lbl)
        layout.addStretch()
        return header

    # ------------------------------------------------------------------
    # Pipeline integration
    # ------------------------------------------------------------------

    def _try_connect_pipeline(self) -> None:
        """
        Attempt to import and connect to the PacketPipeline.
        Silently skips if the pipeline package is unavailable.
        """
        try:
            from src.pipeline.packet_pipeline import PacketPipeline
            from src.capture.capture_mode import CaptureMode
            self._pipeline = PacketPipeline(mode=CaptureMode.SIMULATION)
            _log.debug("PacketMonitorPage: PacketPipeline connected.")
        except Exception as exc:
            _log.warning(
                "PacketMonitorPage: could not initialise pipeline: %s", exc
            )
            self._pipeline = None

    def _on_start(self) -> None:
        """Start the pipeline and begin polling."""
        if self._pipeline is None:
            self._try_connect_pipeline()
        if self._pipeline is None:
            self._status_label.setText("⚠ Pipeline unavailable — check logs.")
            return

        try:
            self._pipeline.start()
        except Exception as exc:
            _log.error("PacketMonitorPage: pipeline start error: %s", exc)
            self._status_label.setText(f"⚠ Pipeline error: {exc}")
            return

        self._btn_start.setEnabled(False)
        self._btn_stop.setEnabled(True)
        self._status_label.setText("Pipeline: Running — SIMULATION mode")
        self._mode_badge.setText("SIMULATION ▶")
        self._mode_badge.setStyleSheet(
            "font-size: 10px; font-weight: 600; color: #3FB950; "
            "background: #1C2B1E; border: 1px solid #3FB950; "
            "border-radius: 4px; padding: 2px 8px;"
        )

        # Start polling timer
        self._timer = QTimer(self)
        self._timer.setInterval(500)  # 500 ms refresh
        self._timer.timeout.connect(self._refresh_ui)
        self._timer.start()
        _log.info("PacketMonitorPage: pipeline started, polling every 500 ms.")

    def _on_stop(self) -> None:
        """Stop the pipeline and polling timer."""
        if self._timer is not None:
            self._timer.stop()
            self._timer = None

        if self._pipeline is not None:
            try:
                self._pipeline.stop()
            except Exception as exc:
                _log.error("PacketMonitorPage: pipeline stop error: %s", exc)

        self._btn_start.setEnabled(True)
        self._btn_stop.setEnabled(False)
        self._status_label.setText("Pipeline: Stopped.")
        self._mode_badge.setText("SIMULATION")
        self._mode_badge.setStyleSheet(
            "font-size: 10px; font-weight: 600; color: #58A6FF; "
            "background: #1F2D3D; border: 1px solid #1F6FEB; "
            "border-radius: 4px; padding: 2px 8px;"
        )
        _log.info("PacketMonitorPage: pipeline stopped.")

    def _on_clear(self) -> None:
        """Clear the event table and reset counters."""
        if self._pipeline is not None:
            try:
                self._pipeline.clear_events()
            except Exception:
                pass
        self._clear_event_rows(show_empty=True)
        app_state.reset_counters()
        self._update_counters()

    def _refresh_ui(self) -> None:
        """Poll the pipeline and refresh the UI. Called by QTimer."""
        if self._pipeline is None:
            return
        try:
            self._update_counters()
            self._update_event_table()
        except Exception as exc:
            _log.warning("PacketMonitorPage: refresh error: %s", exc)

    def _update_counters(self) -> None:
        """Refresh the four counter cards from AppState."""
        self._lbl_captured[1].setText(str(app_state.packets_captured))
        self._lbl_allowed[1].setText(str(app_state.packets_allowed))
        self._lbl_alerted[1].setText(str(app_state.packets_alerted))
        self._lbl_blocked[1].setText(str(app_state.packets_blocked))

    def _update_event_table(self) -> None:
        """Pull the latest events from the pipeline and render them."""
        if self._pipeline is None:
            return
        events = self._pipeline.get_recent_events(limit=_MAX_TABLE_ROWS)
        if not events:
            return

        # Rebuild the table if event count changed
        current_count = self._event_layout.count() - 1  # subtract stretch
        if len(events) == current_count:
            return  # No new events

        self._clear_event_rows()
        for evt in events:
            row = self._build_event_row(evt)
            self._event_layout.insertWidget(0, row)

    def _clear_event_rows(self, show_empty: bool = False) -> None:
        """Remove event rows and optionally restore the empty-state message."""
        while self._event_layout.count() > 1:
            item = self._event_layout.takeAt(0)
            if item and item.widget():
                item.widget().deleteLater()

        self._empty_label = None
        if show_empty:
            self._empty_label = QLabel(
                "  No events yet — start the simulation to capture packets."
            )
            self._empty_label.setStyleSheet(
                "font-size: 12px; color: #8B949E; background: transparent; padding: 16px;"
            )
            self._event_layout.insertWidget(0, self._empty_label)

    def _build_event_row(self, evt) -> QWidget:
        """Build a single event row widget."""
        from src.pipeline.pipeline_event import PipelineEvent

        row = QWidget()
        colour = _decision_colour(evt.decision)
        row.setStyleSheet(
            f"background: transparent; border-bottom: 1px solid #21262D;"
        )

        layout = QHBoxLayout(row)
        layout.setContentsMargins(12, 6, 12, 6)
        layout.setSpacing(0)

        def _cell(text: str, width: int, align=Qt.AlignmentFlag.AlignLeft,
                  style: str = "") -> QLabel:
            lbl = QLabel(text)
            lbl.setFixedWidth(width)
            lbl.setAlignment(align)
            lbl.setStyleSheet(
                f"font-size: 11px; color: #C9D1D9; background: transparent; {style}"
            )
            lbl.setWordWrap(False)
            return lbl

        # Truncate timestamp to time-only portion for readability
        ts = evt.timestamp.split("T")[-1] if "T" in evt.timestamp else evt.timestamp

        # Decision badge
        decision_style = (
            f"color: {colour}; font-weight: 700; background: transparent;"
        )

        fc_str = evt.modbus_function or "—"

        layout.addWidget(_cell(ts[:8],           120))
        layout.addWidget(_cell(evt.source_ip or "—",    130))
        layout.addWidget(_cell(evt.destination_ip or "—", 130))
        layout.addWidget(_cell(evt.protocol,     90))
        layout.addWidget(_cell(fc_str,           160))
        layout.addWidget(_cell(evt.decision,     80,  style=decision_style))
        layout.addWidget(_cell(str(evt.risk_score), 50,
                               align=Qt.AlignmentFlag.AlignRight))
        layout.addWidget(_cell(evt.risk_level,   80,
                               style=f"color: {colour};"))
        layout.addStretch()

        return row

    # ------------------------------------------------------------------
    # Cleanup
    # ------------------------------------------------------------------

    def closeEvent(self, event) -> None:
        """Stop the pipeline when the window is closed."""
        if self._timer is not None:
            self._timer.stop()
        if self._pipeline is not None and self._pipeline.is_running:
            self._pipeline.stop()
        super().closeEvent(event)
