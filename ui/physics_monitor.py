"""
VoltGuard Physics Monitor UI
------------------------------
Displays real-time simulated values for pressure, flow, temperature, and RPM.
Uses PyQtGraph for live scrolling charts and a QTimer for simulation ticks.
"""

from __future__ import annotations

import math
import time
from typing import Deque, Optional
from collections import deque

import numpy as np
from PySide6.QtCore import Qt, QTimer
from PySide6.QtWidgets import (
    QFrame,
    QGridLayout,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)

try:
    import pyqtgraph as pg

    _PYQTGRAPH_OK = True
except Exception:
    _PYQTGRAPH_OK = False

from core.physics_engine import PhysicsEngine, PhysicsThresholds
from config.config_manager import get_config
from core.logger import get_logger

log = get_logger(__name__)

HISTORY_LEN = 120  # data points kept in rolling window


# ---------------------------------------------------------------------------
# Gauge card
# ---------------------------------------------------------------------------

class GaugeCard(QFrame):
    """Card showing current value, unit, and a coloured bar indicator."""

    def __init__(
        self,
        title: str,
        unit: str,
        lo: float,
        hi: float,
        accent: str = "#00D4FF",
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self.setObjectName("GaugeCard")
        self._lo = lo
        self._hi = hi
        self._accent = accent

        vbox = QVBoxLayout(self)
        vbox.setContentsMargins(16, 12, 16, 12)
        vbox.setSpacing(6)

        top_row = QHBoxLayout()
        self._title_lbl = QLabel(title)
        self._title_lbl.setObjectName("StatCardTitle")
        self._unit_lbl = QLabel(unit)
        self._unit_lbl.setObjectName("SmallMuted")
        top_row.addWidget(self._title_lbl)
        top_row.addStretch()
        top_row.addWidget(self._unit_lbl)
        vbox.addLayout(top_row)

        self._value_lbl = QLabel("0.00")
        self._value_lbl.setObjectName("StatCardValue")
        self._value_lbl.setStyleSheet(f"color: {accent};")
        vbox.addWidget(self._value_lbl)

        self._range_lbl = QLabel(f"Range: {lo} – {hi}")
        self._range_lbl.setObjectName("SmallMuted")
        vbox.addWidget(self._range_lbl)

        self._status_lbl = QLabel("● Normal")
        self._status_lbl.setObjectName("GaugeStatus")
        self._status_lbl.setStyleSheet("color: #00E676; font-weight: 600;")
        vbox.addWidget(self._status_lbl)

    def update_value(self, value: float) -> None:
        """Refresh the displayed value and update the status badge."""
        self._value_lbl.setText(f"{value:.2f}")
        in_range = self._lo <= value <= self._hi
        if in_range:
            self._status_lbl.setText("● Normal")
            self._status_lbl.setStyleSheet("color: #00E676; font-weight: 600;")
        else:
            self._status_lbl.setText("⚠ Anomaly")
            self._status_lbl.setStyleSheet("color: #EF4444; font-weight: 600;")


# ---------------------------------------------------------------------------
# Chart widget
# ---------------------------------------------------------------------------

class RollingChart(QWidget):
    """PyQtGraph rolling line chart with a fixed history window."""

    def __init__(
        self,
        title: str,
        color: str = "#00D4FF",
        parent: Optional[QWidget] = None,
    ) -> None:
        super().__init__(parent)
        self._data: Deque[float] = deque([0.0] * HISTORY_LEN, maxlen=HISTORY_LEN)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)

        if _PYQTGRAPH_OK:
            pg.setConfigOption("background", "#1A1F2E")
            pg.setConfigOption("foreground", "#E2E8F0")
            self._plot_widget = pg.PlotWidget(title=title)
            self._plot_widget.setMinimumHeight(160)
            self._plot_widget.showGrid(x=False, y=True, alpha=0.15)
            self._plot_widget.getPlotItem().hideAxis("bottom")
            r, g, b = _hex_to_rgb(color)
            self._curve = self._plot_widget.plot(
                list(self._data),
                pen=pg.mkPen(color=(r, g, b), width=2),
            )
            layout.addWidget(self._plot_widget)
        else:
            placeholder = QLabel(f"[{title} chart — pyqtgraph unavailable]")
            placeholder.setObjectName("SmallMuted")
            placeholder.setAlignment(Qt.AlignCenter)
            layout.addWidget(placeholder)
            self._curve = None

    def push(self, value: float) -> None:
        """Append a new data point and redraw."""
        self._data.append(value)
        if self._curve is not None:
            self._curve.setData(list(self._data))


# ---------------------------------------------------------------------------
# Physics Monitor page
# ---------------------------------------------------------------------------

class PhysicsMonitorPage(QWidget):
    """Physics monitor page: live gauges + scrolling charts for all 4 variables."""

    TICK_MS = 1000  # simulation tick interval

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._config = get_config()
        thresholds_cfg = self._config.get_physics_thresholds()
        self._thresholds = PhysicsThresholds(
            pressure_min=thresholds_cfg.pressure_min,
            pressure_max=thresholds_cfg.pressure_max,
            flow_min=thresholds_cfg.flow_min,
            flow_max=thresholds_cfg.flow_max,
            temperature_min=thresholds_cfg.temperature_min,
            temperature_max=thresholds_cfg.temperature_max,
            rpm_min=thresholds_cfg.rpm_min,
            rpm_max=thresholds_cfg.rpm_max,
        )
        self._engine = PhysicsEngine(thresholds=self._thresholds)
        self._tick_count: int = 0
        self._running: bool = False
        self._setup_ui()

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(16)

        # Header
        header_row = QHBoxLayout()
        title = QLabel("Physics Monitor")
        title.setObjectName("PageTitle")
        header_row.addWidget(title)
        header_row.addStretch()

        self._toggle_btn = QPushButton("▶  Start Simulation")
        self._toggle_btn.setObjectName("PrimaryButton")
        self._toggle_btn.clicked.connect(self._toggle_simulation)
        header_row.addWidget(self._toggle_btn)

        layout.addLayout(header_row)

        desc = QLabel(
            "Real-time physics simulation of ICS process variables. "
            "Anomalies are highlighted when values exceed safe thresholds."
        )
        desc.setObjectName("SmallMuted")
        desc.setWordWrap(True)
        layout.addWidget(desc)

        # Gauge grid (2 × 2)
        gauge_grid = QGridLayout()
        gauge_grid.setSpacing(14)

        t = self._thresholds
        self._gauge_pressure = GaugeCard(
            "Pressure", "bar", t.pressure_min, t.pressure_max, "#00D4FF"
        )
        self._gauge_flow = GaugeCard(
            "Flow Rate", "m³/h", t.flow_min, t.flow_max, "#00E676"
        )
        self._gauge_temp = GaugeCard(
            "Temperature", "°C", t.temperature_min, t.temperature_max, "#F59E0B"
        )
        self._gauge_rpm = GaugeCard(
            "RPM", "rpm", t.rpm_min, t.rpm_max, "#8B5CF6"
        )

        gauge_grid.addWidget(self._gauge_pressure, 0, 0)
        gauge_grid.addWidget(self._gauge_flow, 0, 1)
        gauge_grid.addWidget(self._gauge_temp, 1, 0)
        gauge_grid.addWidget(self._gauge_rpm, 1, 1)
        layout.addLayout(gauge_grid)

        # Charts row
        chart_row = QHBoxLayout()
        chart_row.setSpacing(14)

        self._chart_pressure = RollingChart("Pressure (bar)", "#00D4FF")
        self._chart_flow = RollingChart("Flow Rate (m³/h)", "#00E676")
        self._chart_temp = RollingChart("Temperature (°C)", "#F59E0B")
        self._chart_rpm = RollingChart("RPM", "#8B5CF6")

        for chart in (
            self._chart_pressure,
            self._chart_flow,
            self._chart_temp,
            self._chart_rpm,
        ):
            chart_row.addWidget(chart)

        layout.addLayout(chart_row)
        layout.addStretch()

        # Simulation timer
        self._sim_timer = QTimer(self)
        self._sim_timer.timeout.connect(self._simulation_tick)

    # ------------------------------------------------------------------
    # Simulation control
    # ------------------------------------------------------------------

    def _toggle_simulation(self) -> None:
        if self._running:
            self._sim_timer.stop()
            self._running = False
            self._toggle_btn.setText("▶  Start Simulation")
            log.info("Physics simulation stopped.")
        else:
            self._sim_timer.start(self.TICK_MS)
            self._running = True
            self._toggle_btn.setText("■  Stop Simulation")
            log.info("Physics simulation started.")

    def _simulation_tick(self) -> None:
        """Advance simulation by one tick and refresh all gauges / charts."""
        t = self._tick_count
        self._tick_count += 1

        # Generate smooth sinusoidal demo data so the charts look alive
        pressure = 50.0 + 30.0 * math.sin(t * 0.08)
        flow = 25.0 + 15.0 * math.cos(t * 0.06)
        temperature = 20.0 + 10.0 * math.sin(t * 0.04 + 1.0)
        rpm = 1800.0 + 600.0 * math.sin(t * 0.05 + 2.0)

        # Feed through the physics engine (validation + anomaly detection)
        self._engine.simulate_pressure(pressure)
        self._engine.simulate_flow(flow)
        self._engine.simulate_temperature(temperature)
        self._engine.simulate_rpm(rpm)

        # Update gauges
        self._gauge_pressure.update_value(pressure)
        self._gauge_flow.update_value(flow)
        self._gauge_temp.update_value(temperature)
        self._gauge_rpm.update_value(rpm)

        # Update charts
        self._chart_pressure.push(pressure)
        self._chart_flow.push(flow)
        self._chart_temp.push(temperature)
        self._chart_rpm.push(rpm)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _hex_to_rgb(hex_color: str) -> tuple[int, int, int]:
    """Convert ``#RRGGBB`` to an ``(r, g, b)`` tuple."""
    h = hex_color.lstrip("#")
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)
