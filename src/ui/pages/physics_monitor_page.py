"""
VoltGuard — Physics Monitor Page
==================================
Live monitoring page for the physics simulation engine.

Displays real-time simulated process variables in a dashboard of stat
cards and provides controls to start, stop, and reset the simulation,
and to command the pump and valve.

Layout
------
  ┌─ Header (title + simulation status) ──────────────────────────────┐
  ├─ Control Bar (Start | Stop | Reset | Pump ON | Pump OFF | Valve ──┤
  ├─ Status Cards (7 cards) ──────────────────────────────────────────┤
  │  Pressure | Flow Rate | Temperature | Pump Status                 │
  │  Pump RPM | Valve Position | Tank Level                           │
  ├─ Warnings Panel (live constraint violation list) ─────────────────┤
  └────────────────────────────────────────────────────────────────────┘

Architecture
------------
  - No business logic here — all values come from ``SimulationRunner``.
  - ``SimulationRunner.state_updated`` signal drives card updates.
  - This page is a pure view; it never touches the engine directly.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtWidgets import (
    QComboBox,
    QFrame,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QSizePolicy,
    QSlider,
    QVBoxLayout,
    QWidget,
)

from src.physics.simulation_runner import SimulationRunner
from src.physics.system_state import SystemState

# Lazy import of config to avoid Qt ordering issues.
from src.config import config_loader
from src.physics.physics_config import PhysicsConfig


# ---------------------------------------------------------------------------
# _PhysStatCard  — a single telemetry display card
# ---------------------------------------------------------------------------

class _PhysStatCard(QFrame):
    """
    A dashboard card that displays one physics variable.

    Attributes:
        _value_label:  Large central value label.
        _unit_label:   Small unit string beneath the value.
        _warn_label:   Warning indicator (hidden when safe).
    """

    def __init__(
        self,
        title: str,
        icon: str,
        unit: str,
        initial_value: str = "—",
        accent: str = "#58A6FF",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._accent = accent
        self._unit = unit
        self._build_ui(title, icon, unit, initial_value)
        self._apply_style()

    def _build_ui(
        self, title: str, icon: str, unit: str, initial_value: str
    ) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(16, 14, 16, 14)
        layout.setSpacing(4)

        # Header row
        header = QHBoxLayout()
        header.setSpacing(8)
        icon_lbl = QLabel(icon)
        icon_lbl.setStyleSheet("font-size: 18px; background: transparent;")
        header.addWidget(icon_lbl)

        title_lbl = QLabel(title.upper())
        title_lbl.setStyleSheet(
            "color: #8B949E; font-size: 10px; font-weight: 600; "
            "letter-spacing: 0.8px; background: transparent;"
        )
        header.addWidget(title_lbl, 1)

        # Warning dot (hidden by default)
        self._warn_dot = QLabel("⚠")
        self._warn_dot.setStyleSheet(
            "color: #F85149; font-size: 12px; background: transparent;"
        )
        self._warn_dot.setVisible(False)
        header.addWidget(self._warn_dot)

        layout.addLayout(header)

        # Value
        self._value_label = QLabel(initial_value)
        self._value_label.setStyleSheet(
            f"color: {self._accent}; font-size: 28px; font-weight: 700; "
            f"background: transparent; letter-spacing: -0.5px;"
        )
        self._value_label.setAlignment(Qt.AlignmentFlag.AlignLeft)
        layout.addWidget(self._value_label)

        # Unit
        unit_lbl = QLabel(unit)
        unit_lbl.setStyleSheet(
            "color: #8B949E; font-size: 11px; background: transparent;"
        )
        layout.addWidget(unit_lbl)

    def _apply_style(self) -> None:
        self.setStyleSheet(
            """
            _PhysStatCard, QFrame#physcard {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 10px;
            }
            _PhysStatCard:hover, QFrame#physcard:hover {
                border-color: #388BFD;
            }
            """
        )
        self.setObjectName("physcard")
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setMinimumHeight(120)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    def set_value(self, text: str) -> None:
        """Update the displayed numeric value."""
        self._value_label.setText(text)

    def set_accent(self, hex_colour: str) -> None:
        """Change the value label colour (e.g. for warning/critical states)."""
        self._accent = hex_colour
        self._value_label.setStyleSheet(
            f"color: {hex_colour}; font-size: 28px; font-weight: 700; "
            f"background: transparent; letter-spacing: -0.5px;"
        )

    def set_warning(self, active: bool) -> None:
        """Show or hide the warning indicator dot."""
        self._warn_dot.setVisible(active)
        if active:
            self.setStyleSheet(
                """
                QFrame#physcard {
                    background-color: #1C1410;
                    border: 1px solid #F85149;
                    border-radius: 10px;
                }
                """
            )
        else:
            self._apply_style()


# ---------------------------------------------------------------------------
# PhysicsMonitorPage
# ---------------------------------------------------------------------------

class PhysicsMonitorPage(QWidget):
    """
    Live Physics Monitor dashboard page.

    Receives ``SystemState`` objects from ``SimulationRunner`` via Qt
    signals and updates seven stat cards and a warnings panel in real
    time.
    """

    PAGE_TITLE = "Physics Monitor"

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)

        # Ensure config is loaded before creating the runner.
        if not config_loader.is_loaded:
            config_loader.load()
        self._phys_config = PhysicsConfig.from_config(config_loader)

        self._runner: SimulationRunner | None = None
        self._cards: dict[str, _PhysStatCard] = {}
        self._last_state: SystemState | None = None

        self._build_ui()
        self._init_runner()

    # ------------------------------------------------------------------ #
    #  UI Construction                                                     #
    # ------------------------------------------------------------------ #

    def _build_ui(self) -> None:
        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        # Scrollable container
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.Shape.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("QScrollArea { background: transparent; border: none; }")
        root.addWidget(scroll)

        container = QWidget()
        container.setObjectName("physContainer")
        container.setStyleSheet("#physContainer { background: transparent; }")
        scroll.setWidget(container)

        layout = QVBoxLayout(container)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.setSpacing(20)

        layout.addWidget(self._build_header())
        layout.addWidget(self._build_control_bar())
        layout.addWidget(self._build_cards_grid())
        layout.addWidget(self._build_warnings_panel())
        layout.addWidget(self._build_valve_control())
        layout.addStretch()

    def _build_header(self) -> QWidget:
        """Build the page title/subtitle header."""
        header = QWidget()
        header.setStyleSheet("background: transparent;")
        layout = QVBoxLayout(header)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(4)

        title = QLabel("⚙  Physics Monitor")
        title.setStyleSheet(
            "font-size: 22px; font-weight: 700; color: #E6EDF3; background: transparent;"
        )
        layout.addWidget(title)

        self._subtitle = QLabel(
            "Real-time industrial water-system simulation  ●  Status: Stopped"
        )
        self._subtitle.setStyleSheet(
            "font-size: 13px; color: #8B949E; background: transparent;"
        )
        layout.addWidget(self._subtitle)

        return header

    def _build_control_bar(self) -> QWidget:
        """Build simulation and process control buttons."""
        bar = QWidget()
        bar.setStyleSheet("background: transparent;")
        layout = QHBoxLayout(bar)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(10)

        # --- Simulation controls ---
        self._btn_start = self._make_button(
            "▶  Start Sim", "#238636", "#2EA043", "btn_start_sim"
        )
        self._btn_stop = self._make_button(
            "⏹  Stop Sim", "#6E1B1B", "#F85149", "btn_stop_sim"
        )
        self._btn_reset = self._make_button(
            "↺  Reset", "#1C3055", "#58A6FF", "btn_reset_sim"
        )

        self._btn_start.clicked.connect(self._on_start)
        self._btn_stop.clicked.connect(self._on_stop)
        self._btn_reset.clicked.connect(self._on_reset)

        layout.addWidget(self._btn_start)
        layout.addWidget(self._btn_stop)
        layout.addWidget(self._btn_reset)

        # Separator
        sep = QLabel("|")
        sep.setStyleSheet("color: #30363D; font-size: 18px; padding: 0 4px;")
        layout.addWidget(sep)

        # --- Pump controls ---
        self._btn_pump_on = self._make_button(
            "🔄  Pump ON", "#1B3825", "#3FB950", "btn_pump_on"
        )
        self._btn_pump_off = self._make_button(
            "⏸  Pump OFF", "#3B1E1E", "#F0883E", "btn_pump_off"
        )

        self._btn_pump_on.clicked.connect(lambda: self._send_pump(True))
        self._btn_pump_off.clicked.connect(lambda: self._send_pump(False))
        self._btn_pump_on.setEnabled(False)
        self._btn_pump_off.setEnabled(False)

        layout.addWidget(self._btn_pump_on)
        layout.addWidget(self._btn_pump_off)

        self._scenario_combo = QComboBox()
        self._scenario_combo.addItem("Training scenario…", "")
        self._scenario_combo.addItem("Pressure spike", "pressure_spike")
        self._scenario_combo.addItem("Pump overspeed", "pump_overspeed")
        self._scenario_combo.addItem("High temperature", "temperature_high")
        self._scenario_combo.addItem("Pump with no flow", "pump_no_flow")
        self._scenario_combo.addItem("Low tank level", "tank_low")
        self._scenario_combo.setEnabled(False)
        layout.addWidget(self._scenario_combo)
        self._btn_trigger_scenario = self._make_button(
            "Trigger", "#3B1E1E", "#F85149", "btn_trigger_scenario"
        )
        self._btn_trigger_scenario.clicked.connect(self._on_trigger_scenario)
        self._btn_trigger_scenario.setEnabled(False)
        layout.addWidget(self._btn_trigger_scenario)

        layout.addStretch()

        # Tick counter
        self._tick_label = QLabel("Ticks: 0")
        self._tick_label.setStyleSheet(
            "color: #8B949E; font-size: 12px; background: transparent;"
        )
        layout.addWidget(self._tick_label)

        return bar

    def _make_button(
        self, text: str, bg: str, hover_bg: str, object_name: str
    ) -> QPushButton:
        """Create a styled control button."""
        btn = QPushButton(text)
        btn.setObjectName(object_name)
        btn.setCursor(Qt.CursorShape.PointingHandCursor)
        btn.setStyleSheet(
            f"""
            QPushButton#{object_name} {{
                background-color: {bg};
                color: #E6EDF3;
                border: 1px solid #30363D;
                border-radius: 6px;
                padding: 8px 16px;
                font-size: 12px;
                font-weight: 600;
            }}
            QPushButton#{object_name}:hover {{
                background-color: {hover_bg};
                border-color: {hover_bg};
                color: #FFFFFF;
            }}
            QPushButton#{object_name}:pressed {{
                opacity: 0.8;
            }}
            """
        )
        return btn

    def _build_cards_grid(self) -> QWidget:
        """Build the 7-card telemetry grid."""
        grid_w = QWidget()
        grid_w.setStyleSheet("background: transparent;")
        grid = QGridLayout(grid_w)
        grid.setContentsMargins(0, 0, 0, 0)
        grid.setSpacing(12)

        # (key, title, icon, unit, initial, accent)
        defs = [
            ("pressure",    "Pressure",       "🔵", "bar",  "0.00",  "#58A6FF"),
            ("flow",        "Flow Rate",      "💧", "L/s",  "0.00",  "#3FB950"),
            ("temperature", "Temperature",    "🌡", "°C",   "22.0",  "#F0883E"),
            ("pump_status", "Pump Status",    "⚙",  "",     "OFF",   "#8B949E"),
            ("pump_rpm",    "Pump RPM",       "🔄", "RPM",  "0",     "#BC8CFF"),
            ("valve",       "Valve Position", "🔧", "open", "0.00",  "#D29922"),
            ("tank",        "Tank Level",     "🪣", "m³",   "75.0",  "#58A6FF"),
        ]

        positions = [
            (0, 0), (0, 1), (0, 2), (0, 3),
            (1, 0), (1, 1), (1, 2),
        ]

        for (key, title, icon, unit, init, accent), (row, col) in zip(defs, positions):
            card = _PhysStatCard(title, icon, unit, init, accent)
            self._cards[key] = card
            grid.addWidget(card, row, col)

        for col in range(4):
            grid.setColumnStretch(col, 1)

        return grid_w

    def _build_warnings_panel(self) -> QGroupBox:
        """Build the warnings / constraint violations panel."""
        box = QGroupBox("⚠  Active Warnings")
        box.setStyleSheet(
            """
            QGroupBox {
                color: #8B949E;
                font-size: 12px;
                font-weight: 600;
                border: 1px solid #30363D;
                border-radius: 8px;
                margin-top: 8px;
                padding-top: 10px;
                background: #161B22;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 4px;
                color: #D29922;
            }
            """
        )
        layout = QVBoxLayout(box)
        layout.setContentsMargins(12, 8, 12, 8)
        self._warnings_label = QLabel("✅  All systems nominal — no active warnings.")
        self._warnings_label.setStyleSheet(
            "color: #3FB950; font-size: 12px; background: transparent;"
        )
        self._warnings_label.setWordWrap(True)
        layout.addWidget(self._warnings_label)
        return box

    def _build_valve_control(self) -> QGroupBox:
        """Build a slider-based valve control widget."""
        box = QGroupBox("🔧  Valve Control")
        box.setStyleSheet(
            """
            QGroupBox {
                color: #8B949E;
                font-size: 12px;
                font-weight: 600;
                border: 1px solid #30363D;
                border-radius: 8px;
                margin-top: 8px;
                padding-top: 10px;
                background: #161B22;
            }
            QGroupBox::title {
                subcontrol-origin: margin;
                left: 12px;
                padding: 0 4px;
                color: #D29922;
            }
            """
        )
        layout = QHBoxLayout(box)
        layout.setContentsMargins(12, 8, 12, 8)
        layout.setSpacing(12)

        lbl_closed = QLabel("Closed")
        lbl_closed.setStyleSheet("color: #8B949E; font-size: 11px; background: transparent;")
        layout.addWidget(lbl_closed)

        self._valve_slider = QSlider(Qt.Orientation.Horizontal)
        self._valve_slider.setMinimum(0)
        self._valve_slider.setMaximum(100)
        self._valve_slider.setValue(0)
        self._valve_slider.setObjectName("valve_slider")
        self._valve_slider.setStyleSheet(
            """
            QSlider#valve_slider::groove:horizontal {
                height: 6px;
                background: #30363D;
                border-radius: 3px;
            }
            QSlider#valve_slider::handle:horizontal {
                background: #58A6FF;
                border: 2px solid #388BFD;
                width: 16px;
                height: 16px;
                border-radius: 8px;
                margin: -5px 0;
            }
            QSlider#valve_slider::sub-page:horizontal {
                background: #388BFD;
                border-radius: 3px;
            }
            """
        )
        self._valve_slider.valueChanged.connect(self._on_valve_changed)
        self._valve_slider.setEnabled(False)
        layout.addWidget(self._valve_slider, 1)

        lbl_open = QLabel("Open")
        lbl_open.setStyleSheet("color: #8B949E; font-size: 11px; background: transparent;")
        layout.addWidget(lbl_open)

        self._valve_pct_label = QLabel("0 %")
        self._valve_pct_label.setFixedWidth(40)
        self._valve_pct_label.setStyleSheet(
            "color: #D29922; font-weight: 700; font-size: 13px; background: transparent;"
        )
        layout.addWidget(self._valve_pct_label)

        return box

    # ------------------------------------------------------------------ #
    #  Runner Initialisation                                               #
    # ------------------------------------------------------------------ #

    def _init_runner(self) -> None:
        """Create and wire the SimulationRunner."""
        try:
            self._runner = SimulationRunner(parent=self)
            self._runner.state_updated.connect(self._on_state_updated)
            self._runner.simulation_started.connect(
                lambda: self._update_subtitle("Running")
            )
            self._runner.simulation_stopped.connect(
                lambda: self._update_subtitle("Stopped")
            )
            self._runner.simulation_error.connect(self._on_sim_error)
            self._runner.physics_violation.connect(self._on_physics_violation)
        except Exception as exc:  # noqa: BLE001
            self._subtitle.setText(f"Engine Error: {exc}")

    # ------------------------------------------------------------------ #
    #  Signal Handlers                                                     #
    # ------------------------------------------------------------------ #

    def _on_start(self) -> None:
        """Start the simulation."""
        if self._runner and not self._runner.is_running():
            self._runner.start_simulation()
            self._set_process_controls_enabled(True)

    def _on_stop(self) -> None:
        """Stop the simulation."""
        if self._runner and self._runner.is_running():
            self._runner.stop_simulation()
        self._set_process_controls_enabled(False)

    def _on_reset(self) -> None:
        """Reset the simulation to initial state."""
        if self._runner:
            self._runner.reset_simulation()
            # Reset card displays
            self._cards["pressure"].set_value("0.00")
            self._cards["flow"].set_value("0.00")
            self._cards["pump_rpm"].set_value("0")
            self._cards["pump_status"].set_value("OFF")
            self._cards["pump_status"].set_accent("#8B949E")
            self._cards["valve"].set_value("0.00")
            self._tick_label.setText("Ticks: 0")

    def _send_pump(self, on: bool) -> None:
        """Send a pump command to the runner."""
        if self._runner:
            self._runner.set_pump(on)

    def _set_process_controls_enabled(self, enabled: bool) -> None:
        """Allow pump and valve commands only while the worker is running."""
        self._btn_pump_on.setEnabled(enabled)
        self._btn_pump_off.setEnabled(enabled)
        self._valve_slider.setEnabled(enabled)
        self._scenario_combo.setEnabled(enabled)
        self._btn_trigger_scenario.setEnabled(enabled)

    def _on_valve_changed(self, value: int) -> None:
        """Handle valve slider movement."""
        pct = value / 100.0
        self._valve_pct_label.setText(f"{value} %")
        if self._runner:
            self._runner.set_valve(pct)

    def _on_trigger_scenario(self) -> None:
        """Queue the selected safe, in-memory anomaly training scenario."""
        scenario = self._scenario_combo.currentData()
        if scenario and self._runner and self._runner.trigger_anomaly(str(scenario)):
            self._warnings_label.setText(
                f"⚠  Training scenario queued: {self._scenario_combo.currentText()}"
            )
            self._warnings_label.setStyleSheet(
                "color: #D29922; font-size: 12px; background: transparent;"
            )

    def _on_physics_violation(self, violation) -> None:
        """Present the structured violation that entered the alert pipeline."""
        self._warnings_label.setText(
            f"⚠  {violation.severity.value}: {violation.description}\n"
            f"Rule {violation.rule_id} · risk {violation.risk_score}/100"
        )
        self._warnings_label.setStyleSheet(
            "color: #F85149; font-size: 12px; background: transparent;"
        )

    def _on_state_updated(self, state: SystemState) -> None:
        """Update all dashboard cards from a new SystemState."""
        self._last_state = state

        cfg = self._phys_config

        # ---- Pressure ----
        p = state.pressure_bar
        p_pct = p / cfg.pressure_max_bar
        p_colour = self._threshold_colour(p_pct)
        self._cards["pressure"].set_value(f"{p:.2f}")
        self._cards["pressure"].set_accent(p_colour)
        self._cards["pressure"].set_warning(p_pct >= 0.9)

        # ---- Flow ----
        f = state.flow_lps
        f_pct = f / cfg.flow_max_lps
        self._cards["flow"].set_value(f"{f:.2f}")
        self._cards["flow"].set_accent(self._threshold_colour(f_pct))

        # ---- Temperature ----
        t = state.temperature_celsius
        t_range = cfg.temp_max_celsius - cfg.temp_min_celsius
        t_pct = (t - cfg.temp_min_celsius) / t_range if t_range > 0 else 0
        t_colour = self._threshold_colour(t_pct)
        self._cards["temperature"].set_value(f"{t:.1f}")
        self._cards["temperature"].set_accent(t_colour)
        self._cards["temperature"].set_warning(t_pct >= 0.9)

        # ---- Pump Status ----
        if state.pump_on:
            self._cards["pump_status"].set_value("ON")
            self._cards["pump_status"].set_accent("#3FB950")
        else:
            self._cards["pump_status"].set_value("OFF")
            self._cards["pump_status"].set_accent("#8B949E")

        # ---- Pump RPM ----
        rpm = state.pump_rpm
        rpm_pct = rpm / cfg.pump_rpm_max
        self._cards["pump_rpm"].set_value(f"{rpm:.0f}")
        self._cards["pump_rpm"].set_accent(self._threshold_colour(rpm_pct))

        # ---- Valve Position ----
        vp = state.valve_position
        self._cards["valve"].set_value(f"{vp:.2f}")

        # ---- Tank Level ----
        lvl = state.tank_level_m3
        lvl_range = cfg.tank_max_m3 - cfg.tank_min_m3
        lvl_pct = (lvl - cfg.tank_min_m3) / lvl_range if lvl_range > 0 else 0
        # Invert — low tank level is the danger here.
        lvl_colour = "#3FB950" if lvl_pct > 0.3 else (
            "#D29922" if lvl_pct > 0.1 else "#F85149"
        )
        # A 0.1 m³ display rounded out normal per-tick water balance and
        # made a changing tank look static.  Preserve useful process detail.
        self._cards["tank"].set_value(f"{lvl:.2f}")
        self._cards["tank"].set_accent(lvl_colour)
        self._cards["tank"].set_warning(lvl_pct <= 0.1)

        # ---- Tick counter ----
        if self._runner:
            self._tick_label.setText(f"Ticks: {self._runner.engine.tick_count}")

        # ---- Warnings ----
        warnings = state.has_warnings(cfg)
        if warnings:
            self._warnings_label.setText("\n".join(f"⚠  {w}" for w in warnings))
            self._warnings_label.setStyleSheet(
                "color: #F85149; font-size: 12px; background: transparent;"
            )
        else:
            self._warnings_label.setText("✅  All systems nominal — no active warnings.")
            self._warnings_label.setStyleSheet(
                "color: #3FB950; font-size: 12px; background: transparent;"
            )

    def _on_sim_error(self, message: str) -> None:
        """Display simulation engine errors."""
        self._warnings_label.setText(f"❌  Engine Error: {message}")
        self._warnings_label.setStyleSheet(
            "color: #F85149; font-size: 12px; background: transparent;"
        )

    # ------------------------------------------------------------------ #
    #  Helpers                                                             #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _threshold_colour(fraction: float) -> str:
        """
        Return a colour hex string based on how close a value is to its limit.

        - < 70 % → green
        - 70–89 % → amber
        - ≥ 90 % → red
        """
        if fraction >= 0.9:
            return "#F85149"   # Red — critical
        elif fraction >= 0.7:
            return "#D29922"   # Amber — warning
        return "#3FB950"       # Green — safe

    def _update_subtitle(self, status: str) -> None:
        self._subtitle.setText(
            f"Real-time industrial water-system simulation  ●  Status: {status}"
        )

    # ------------------------------------------------------------------ #
    #  Cleanup                                                             #
    # ------------------------------------------------------------------ #

    def cleanup(self) -> None:
        """Stop the runner when the page is closed."""
        if self._runner:
            self._runner.cleanup()
