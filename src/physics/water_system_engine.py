"""
VoltGuard — Water System Physics Engine
=========================================
Implements ``WaterSystemEngine``, the primary physics simulation model
for VoltGuard.  The engine models a simple industrial water-distribution
system with a pump, a motorised valve, a storage tank, and a pipeline.

Industrial System Description
----------------------------------------------------------------------
The simulated plant consists of:

  ┌────────────┐    ┌──────────┐    ┌──────────────┐    ┌──────────┐
  │ Water Tank │───►│   Pump   │───►│  Main Valve  │───►│ Pipeline │
  └────────────┘    └──────────┘    └──────────────┘    └──────────┘

  - The **pump** accelerates water through the valve into the pipeline.
  - The **valve** position (0–1) governs flow restriction.
  - **Pressure** builds in the pipeline as the pump spins.
  - **Flow** (litres/second) depends on pressure × valve opening.
  - The **tank** drains proportionally to flow rate.
  - **Temperature** rises from pump friction and drops when idle.

Physics Model
----------------------------------------------------------------------
All differential equations use a simple Euler forward-integration step
(dt = simulation_interval_sec).  The model intentionally avoids
over-engineering: it is realistic enough for anomaly detection without
requiring partial-differential-equation solvers.

Architecture
----------------------------------------------------------------------
- Implements ``BasePhysicsEngine`` from ``src/interfaces/base_physics.py``.
- State is encapsulated in ``SystemState``; no mutable fields outside it.
- All thresholds come from ``PhysicsConfig``; nothing is hard-coded here.
- Thread safety: the engine itself is NOT thread-safe.  The caller
  (``SimulationRunner``) must serialise access.

Usage::

    from src.physics.water_system_engine import WaterSystemEngine
    from src.physics.physics_config import PhysicsConfig
    from src.config import config_loader

    config_loader.load()
    cfg = PhysicsConfig.from_config(config_loader)
    engine = WaterSystemEngine(cfg)

    engine.apply_command("SET_PUMP", 1.0)   # pump ON
    engine.apply_command("SET_VALVE", 0.8)  # 80 % open
    state = engine.update_state()
    print(state)
"""

from __future__ import annotations

import copy
import math
from datetime import datetime, timezone
from threading import Lock
from typing import Any, Optional

from src.exceptions import PhysicsError, SafetyConstraintViolation
from src.interfaces.base_physics import BasePhysicsEngine, PhysicsState
from src.logger import get_logger
from src.physics.physics_config import PhysicsConfig
from src.physics.system_state import SystemState

_log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Command Types
# ---------------------------------------------------------------------------

class CommandType:
    """
    String constants for command types accepted by ``apply_command()``.

    All command values are normalised floats.  The mapping is:

    ``SET_PUMP``    — 1.0 = ON, 0.0 = OFF
    ``SET_VALVE``   — 0.0 (fully closed) to 1.0 (fully open)
    """
    SET_PUMP: str = "SET_PUMP"
    SET_VALVE: str = "SET_VALVE"


# ---------------------------------------------------------------------------
# WaterSystemEngine
# ---------------------------------------------------------------------------

class WaterSystemEngine(BasePhysicsEngine):
    """
    Physics simulation engine for an industrial water-distribution system.

    Maintains the current ``SystemState`` and advances it every simulation
    tick using Euler integration of the governing equations.

    The engine accepts external commands (pump on/off, valve position)
    via ``apply_command()`` between ticks and applies them on the next
    call to ``update_state()``.

    Constraints are enforced *after* every integration step: values are
    clamped to their configured limits, and violations are logged as
    warnings.

    Parameters
    ----------
    config : PhysicsConfig
        Fully validated configuration object providing all thresholds
        and rate parameters.
    """

    def __init__(self, config: PhysicsConfig) -> None:
        """
        Initialise the engine with the given configuration.

        Args:
            config: Validated ``PhysicsConfig`` with all thresholds.
        """
        self._config: PhysicsConfig = config
        self._state: SystemState = self._make_initial_state()
        self._pending_commands: list[tuple[str, float]] = []
        self._pending_anomaly: Optional[str] = None
        self._valve_target: float = 0.0
        self._lock: Lock = Lock()
        self._tick_count: int = 0

        _log.info(
            "WaterSystemEngine initialised. Config: %s", self._config
        )

    # ------------------------------------------------------------------ #
    #  BasePhysicsEngine Contract                                          #
    # ------------------------------------------------------------------ #

    def simulate(self, command_value: float, delta_t: float) -> PhysicsState:
        """
        Advance the simulation by ``delta_t`` seconds with a generic control input.

        This method satisfies the ``BasePhysicsEngine`` contract.  For
        richer control, prefer ``apply_command()`` + ``update_state()``.

        The ``command_value`` is interpreted as a valve position (0.0–1.0).

        Args:
            command_value: Valve opening fraction 0.0–1.0.
            delta_t:       Time step in seconds.

        Returns:
            ``PhysicsState`` snapshot of the predicted state.
        """
        self.apply_command(CommandType.SET_VALVE, command_value)
        new_state = self.update_state(dt=delta_t)
        return self._to_physics_state(new_state)

    def get_state(self) -> PhysicsState:
        """
        Return the current simulated state as a ``PhysicsState`` DTO
        (satisfies ``BasePhysicsEngine`` contract).

        Returns:
            ``PhysicsState`` snapshot without advancing the simulation.
        """
        with self._lock:
            return self._to_physics_state(self._state)

    def check_constraints(self, state: PhysicsState) -> bool:
        """
        Evaluate whether a ``PhysicsState`` violates any safety constraint.

        Populates ``state.violations`` and sets ``state.is_safe = False``
        for each violation.

        Args:
            state: The ``PhysicsState`` to validate (mutated in-place).

        Returns:
            ``True`` if the state is safe, ``False`` if any violation exists.
        """
        cfg = self._config

        if state.pressure_bar is not None:
            if state.pressure_bar > cfg.pressure_max_bar:
                state.mark_violation(
                    f"pressure {state.pressure_bar:.3f} bar > max {cfg.pressure_max_bar:.2f} bar"
                )
            elif state.pressure_bar < cfg.pressure_min_bar and state.pressure_bar > 0:
                # Only warn on low pressure when the pump is supposed to be running.
                pass

        if state.flow_lps is not None:
            if state.flow_lps > cfg.flow_max_lps:
                state.mark_violation(
                    f"flow {state.flow_lps:.3f} L/s > max {cfg.flow_max_lps:.2f} L/s"
                )
            if state.flow_lps < 0:
                state.mark_violation(f"flow {state.flow_lps:.3f} L/s is negative (invalid)")

        if state.temperature_celsius is not None:
            if state.temperature_celsius > cfg.temp_max_celsius:
                state.mark_violation(
                    f"temperature {state.temperature_celsius:.2f} °C > max "
                    f"{cfg.temp_max_celsius:.2f} °C"
                )
            if state.temperature_celsius < cfg.temp_min_celsius:
                state.mark_violation(
                    f"temperature {state.temperature_celsius:.2f} °C < min "
                    f"{cfg.temp_min_celsius:.2f} °C"
                )

        if state.rpm is not None:
            if state.rpm > cfg.pump_rpm_max:
                state.mark_violation(
                    f"pump RPM {state.rpm:.0f} > max {cfg.pump_rpm_max:.0f}"
                )

        return state.is_safe

    def reset(self) -> None:
        """
        Reset the engine to its nominal initial operating state.

        Clears all pending commands and restores the ``SystemState``
        to the values defined by ``PhysicsConfig.tank_initial_m3``
        and ambient temperature.
        """
        with self._lock:
            self._state = self._make_initial_state()
            self._pending_commands.clear()
            self._pending_anomaly = None
            self._valve_target = 0.0
            self._tick_count = 0
        _log.info("WaterSystemEngine reset to initial state.")

    # ------------------------------------------------------------------ #
    #  Command Interface                                                   #
    # ------------------------------------------------------------------ #

    def apply_command(self, cmd_type: str, value: float) -> None:
        """
        Queue a control command to be applied on the next simulation tick.

        Commands are applied in FIFO order at the start of ``update_state()``.

        Supported command types (use ``CommandType.*`` constants):
          - ``SET_PUMP``    — 1.0 turns pump ON, 0.0 turns it OFF.
          - ``SET_VALVE``   — Sets valve target position 0.0–1.0.

        Args:
            cmd_type: One of the ``CommandType`` string constants.
            value:    Command argument (float).

        Raises:
            PhysicsError: If ``cmd_type`` is not recognised.
        """
        valid_types = {CommandType.SET_PUMP, CommandType.SET_VALVE}
        if cmd_type not in valid_types:
            raise PhysicsError(
                f"Unknown command type: '{cmd_type}'",
                detail=f"valid_types={valid_types}",
            )
        with self._lock:
            self._pending_commands.append((cmd_type, value))
        _log.debug("Command queued: %s = %s", cmd_type, value)

    def inject_anomaly(self, scenario: str) -> None:
        """Queue one safe, simulated process anomaly for operator training.

        This affects only the in-memory demonstration model and is never
        connected to host controls or a physical device.
        """
        allowed = {"pressure_spike", "pump_overspeed", "temperature_high", "pump_no_flow", "tank_low"}
        if scenario not in allowed:
            raise PhysicsError(f"Unknown anomaly scenario: '{scenario}'")
        with self._lock:
            self._pending_anomaly = scenario

    # ------------------------------------------------------------------ #
    #  State Update (Main Simulation Loop)                                 #
    # ------------------------------------------------------------------ #

    def update_state(self, dt: Optional[float] = None) -> SystemState:
        """
        Advance the simulation by one time step and return the new state.

        The update sequence is:
          1. Apply all queued commands.
          2. Simulate pump RPM (ramp up/down).
          3. Simulate pressure (from RPM).
          4. Simulate flow (from pressure × valve).
          5. Simulate temperature (from pump + ambient).
          6. Simulate tank level (drain from flow).
          7. Clamp all values to configured limits.
          8. Record warnings; log the diff.

        Args:
            dt: Override the time step in seconds.  Defaults to
                ``config.simulation_interval_sec``.

        Returns:
            The newly computed ``SystemState``.

        Raises:
            PhysicsError: If any computed value is NaN or Inf.
        """
        with self._lock:
            delta_t = dt if dt is not None else self._config.simulation_interval_sec
            prev_state = copy.copy(self._state)

            # ---- 1. Apply queued commands --------------------------------
            self._apply_pending_commands()

            # ---- 2–6. Sub-simulations ------------------------------------
            # The actuator keeps moving toward its target on every tick.
            valve_position = self.simulate_valve_position(
                self._state.valve_position, self._valve_target, delta_t
            )
            self._state.valve_position = valve_position
            new_rpm   = self.simulate_pump_speed(self._state, delta_t)
            new_press = self.simulate_pressure(self._state, new_rpm, delta_t)
            # Build the remaining process variables from the values calculated
            # in this same tick (never a stale previous snapshot).
            flow_state = copy.copy(self._state)
            flow_state.pump_rpm = new_rpm
            new_flow  = self.simulate_flow(flow_state, new_press) if self._state.pump_on else 0.0
            temp_state = copy.copy(flow_state)
            new_temp  = self.simulate_temperature(temp_state, delta_t)
            new_tank  = self.simulate_tank_level(self._state, new_flow, delta_t)

            # ---- 7. Build new state & clamp ------------------------------
            from datetime import datetime, timezone
            self._state = SystemState(
                pressure_bar        = self._clamp_pressure(new_press),
                flow_lps            = self._clamp_flow(new_flow),
                temperature_celsius = self._clamp_temperature(new_temp),
                pump_on             = self._state.pump_on,
                pump_rpm            = self._clamp_rpm(new_rpm),
                valve_position      = self._state.valve_position,
                tank_level_m3       = self._clamp_tank(new_tank),
                timestamp           = datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
            )

            self._apply_pending_anomaly()

            self._tick_count += 1

            # ---- 8. Guard against NaN/Inf --------------------------------
            self._check_numeric_validity(self._state)

            # ---- 9. Log update ------------------------------------------
            self._log_update(prev_state, self._state)

            return copy.copy(self._state)

    # ------------------------------------------------------------------ #
    #  Sub-Simulation Methods                                              #
    # ------------------------------------------------------------------ #

    def simulate_pump_speed(self, state: SystemState, dt: float) -> float:
        """
        Calculate the new pump RPM for the next simulation tick.

        When the pump is ON, a demand controller derives an operating target
        from the *actual* valve opening.  This represents increasing
        hydraulic demand as the downstream path opens; it is not a manual
        RPM setpoint.  RPM ramps toward that target at
        ``pump_ramp_rate_rpm_per_sec``.  When OFF, it decays toward 0
        at ``pump_decay_rate_rpm_per_sec``.

        Args:
            state: Current simulation state.
            dt:    Time step in seconds.

        Returns:
            New pump RPM (unclamped; clamping applied in ``update_state``).
        """
        cfg = self._config
        if state.pump_on:
            # Equal-percentage valve behaviour gives finer low-demand
            # control than a linear mapping.  The valve actuator state,
            # rather than its requested target, is authoritative here.
            demand = max(0.0, min(1.0, state.valve_position)) ** 0.7
            target_rpm = min(cfg.pump_rpm_nominal * demand, cfg.pump_rpm_max)
            ramp = cfg.pump_ramp_rate_rpm_per_sec * dt
            if state.pump_rpm < target_rpm:
                new_rpm = min(state.pump_rpm + ramp, target_rpm)
            else:
                # Closing the valve unloads the pump; use a controlled
                # deceleration instead of an implausible instantaneous drop.
                new_rpm = max(state.pump_rpm - cfg.pump_decay_rate_rpm_per_sec * dt, target_rpm)
        else:
            # Decay toward 0 — pump coasting down.
            delta = cfg.pump_decay_rate_rpm_per_sec * dt
            new_rpm = max(state.pump_rpm - delta, 0.0)
        return new_rpm

    def simulate_pressure(
        self, state: SystemState, new_rpm: float, dt: float
    ) -> float:
        """
        Calculate the new pipeline pressure for the next tick.

        Pressure is proportional to pump RPM.  When the pump is ON,
        pressure rises toward ``new_rpm × pressure_ramp_bar_per_rpm``.
        When the pump is OFF (RPM ≈ 0), pressure decays at
        ``pressure_decay_rate_bar_per_sec``.

        The valve position does NOT directly affect pressure in this
        simple model (it affects flow).

        Args:
            state:   Current simulation state.
            new_rpm: The already-computed new pump RPM.
            dt:      Time step in seconds.

        Returns:
            New pressure in bar (unclamped).
        """
        cfg = self._config

        if state.pump_on and new_rpm > 0:
            # Target pressure is proportional to RPM.
            # A restricted downstream valve creates upstream back-pressure;
            # a fully open valve relieves a portion of that pressure.
            restriction = 1.0 - state.valve_position
            target_pressure = new_rpm * cfg.pressure_ramp_bar_per_rpm * (0.65 + 0.35 * restriction)
            # Move toward target with a lag.
            gap = target_pressure - state.pressure_bar
            new_pressure = state.pressure_bar + gap * min(dt * 0.5, 1.0)
        else:
            # Pressure bleeds off when pump is not running.
            decay = cfg.pressure_decay_rate_bar_per_sec * dt
            new_pressure = max(state.pressure_bar - decay, 0.0)

        return new_pressure

    def simulate_flow(self, state: SystemState, new_pressure: float) -> float:
        """
        Calculate the volumetric flow rate through the valve.

        Flow rate is proportional to the product of pressure and valve
        opening fraction.  A closed valve (position = 0) produces zero
        flow regardless of pressure.  Flow cannot be negative.

        Formula:
            flow_lps = pressure_bar × valve_position × flow_coefficient

        Args:
            state:        Current simulation state.
            new_pressure: The already-computed new pressure (bar).

        Returns:
            New flow rate in litres/second (unclamped).
        """
        # This helper is also used for isolated model analysis; pump-off
        # behaviour is enforced by update_state before calling it.
        if state.valve_position <= 0.0 or new_pressure <= 0.0:
            return 0.0

        rpm_ratio = min(1.0, state.pump_rpm / self._config.pump_rpm_max) if state.pump_rpm > 0 else 1.0
        # Centrifugal pump affinity laws: flow grows with speed while the
        # available head grows with speed².  The valve characteristic is
        # equal-percentage-ish (opening ** .7), so low openings remain a
        # meaningful restriction rather than making every value linear.
        head_ratio = min(1.0, max(0.0, new_pressure / self._config.pressure_max_bar))
        valve_characteristic = state.valve_position ** 0.7
        flow = self._config.flow_max_lps * rpm_ratio * math.sqrt(head_ratio) * valve_characteristic
        return max(flow, 0.0)

    def simulate_temperature(self, state: SystemState, dt: float) -> float:
        """
        Calculate the fluid temperature for the next tick.

        When the pump is running, friction heats the fluid at
        ``temp_rise_rate_celsius_per_sec``.  When idle, temperature
        decays toward the ambient environment temperature at
        ``temp_cool_rate_celsius_per_sec``.

        Args:
            state: Current simulation state.
            dt:    Time step in seconds.

        Returns:
            New temperature in °C (unclamped).
        """
        cfg = self._config
        if state.pump_on and state.pump_rpm > 0:
            # Temperature rises — proportional to pump load (approximated by RPM ratio).
            rpm_factor = state.pump_rpm / cfg.pump_rpm_max
            rise = cfg.temp_rise_rate_celsius_per_sec * rpm_factor * dt
            new_temp = state.temperature_celsius + rise
        else:
            # Cool toward ambient.
            gap = state.temperature_celsius - cfg.temp_ambient_celsius
            if gap > 0:
                cool = cfg.temp_cool_rate_celsius_per_sec * dt
                new_temp = max(state.temperature_celsius - cool, cfg.temp_ambient_celsius)
            else:
                # Already at or below ambient — warm slightly toward ambient.
                warm = cfg.temp_cool_rate_celsius_per_sec * 0.5 * dt
                new_temp = min(state.temperature_celsius + warm, cfg.temp_ambient_celsius)

        return new_temp

    def simulate_tank_level(
        self, state: SystemState, new_flow: float, dt: float
    ) -> float:
        """
        Calculate the new water volume in the storage tank.

        Water drains from the tank at the current flow rate.  When the
        tank drops below ``tank_fill_threshold_m3``, an automatic refill
        source replenishes it at ``tank_fill_rate_m3_per_sec``.

        Args:
            state:    Current simulation state.
            new_flow: The already-computed new flow rate (L/s).
            dt:       Time step in seconds.

        Returns:
            New tank volume in m³ (unclamped).
        """
        cfg = self._config

        # Convert flow from L/s to m³/s (1 L = 0.001 m³).
        flow_m3_per_sec = new_flow * 0.001 * cfg.tank_drain_factor
        drain = flow_m3_per_sec * dt
        new_level = state.tank_level_m3 - drain

        # Auto-refill when tank is critically low.
        if new_level < cfg.tank_fill_threshold_m3:
            fill = cfg.tank_fill_rate_m3_per_sec * dt
            new_level += fill

        return new_level

    def simulate_valve_position(
        self, current_position: float, target_position: float, dt: float
    ) -> float:
        """
        Move the valve toward ``target_position`` at the configured rate.

        The valve actuator has a finite speed (``valve_speed_per_sec``),
        so position changes are gradual rather than instantaneous.

        Args:
            current_position: Current valve fraction 0.0–1.0.
            target_position:  Desired valve fraction 0.0–1.0.
            dt:               Time step in seconds.

        Returns:
            New valve position fraction (clamped to 0.0–1.0).
        """
        max_delta = self._config.valve_speed_per_sec * dt
        gap = target_position - current_position
        if abs(gap) <= max_delta:
            new_pos = target_position
        else:
            new_pos = current_position + math.copysign(max_delta, gap)
        return max(0.0, min(1.0, new_pos))

    # ------------------------------------------------------------------ #
    #  Public State Accessors                                              #
    # ------------------------------------------------------------------ #

    def get_system_state(self) -> SystemState:
        """
        Return a copy of the current ``SystemState``.

        Thread-safe: acquires the internal lock before copying.

        Returns:
            Shallow copy of the current state.
        """
        with self._lock:
            return copy.copy(self._state)

    @property
    def tick_count(self) -> int:
        """Number of simulation ticks completed since initialisation or reset."""
        return self._tick_count

    @property
    def config(self) -> PhysicsConfig:
        """The ``PhysicsConfig`` used by this engine instance."""
        return self._config

    # ------------------------------------------------------------------ #
    #  Internal Helpers                                                    #
    # ------------------------------------------------------------------ #

    def _make_initial_state(self) -> SystemState:
        """Construct the nominal initial simulation state from config."""
        return SystemState(
            pressure_bar        = 0.0,
            flow_lps            = 0.0,
            temperature_celsius = self._config.temp_ambient_celsius,
            pump_on             = False,
            pump_rpm            = 0.0,
            valve_position      = 0.0,
            tank_level_m3       = self._config.tank_initial_m3,
        )

    def _apply_pending_commands(self) -> None:
        """
        Process all queued commands and update the current state.

        Called at the start of ``update_state()`` while the lock is held.
        """
        for cmd_type, value in self._pending_commands:
            if cmd_type == CommandType.SET_PUMP:
                self._state.pump_on = value >= 0.5
                if not self._state.pump_on:
                    _log.debug("Pump commanded OFF.")
                else:
                    _log.debug("Pump commanded ON.")

            elif cmd_type == CommandType.SET_VALVE:
                target = max(0.0, min(1.0, value))
                self._valve_target = target
                _log.debug("Valve target set to %.3f", target)

        self._pending_commands.clear()

    def _apply_pending_anomaly(self) -> None:
        """Apply one operator-selected, in-memory anomaly after a normal tick."""
        scenario = self._pending_anomaly
        self._pending_anomaly = None
        if scenario is None:
            return

        cfg = self._config
        if scenario == "pressure_spike":
            self._state.pressure_bar = cfg.pressure_max_bar * 1.20
        elif scenario == "pump_overspeed":
            self._state.pump_on = True
            self._state.pump_rpm = cfg.pump_rpm_max * 1.15
        elif scenario == "temperature_high":
            self._state.temperature_celsius = cfg.temp_max_celsius + 10.0
        elif scenario == "pump_no_flow":
            self._state.pump_on = True
            self._state.pump_rpm = cfg.pump_rpm_max * 0.50
            self._state.valve_position = 0.50
            self._state.flow_lps = 0.0
        elif scenario == "tank_low":
            self._state.tank_level_m3 = cfg.tank_min_m3 + 1.0
        _log.warning("Applied safe simulated anomaly scenario: %s", scenario)

    def _clamp_pressure(self, pressure: float) -> float:
        """Clamp pressure to [0, pressure_max_bar]."""
        return max(0.0, min(pressure, self._config.pressure_max_bar))

    def _clamp_flow(self, flow: float) -> float:
        """Clamp flow to [0, flow_max_lps]. Flow cannot be negative."""
        return max(0.0, min(flow, self._config.flow_max_lps))

    def _clamp_temperature(self, temp: float) -> float:
        """Clamp temperature to [temp_min_celsius, temp_max_celsius]."""
        return max(
            self._config.temp_min_celsius,
            min(temp, self._config.temp_max_celsius),
        )

    def _clamp_rpm(self, rpm: float) -> float:
        """Clamp RPM to [0, pump_rpm_max]."""
        return max(0.0, min(rpm, self._config.pump_rpm_max))

    def _clamp_tank(self, level: float) -> float:
        """Clamp tank level to [tank_min_m3, tank_max_m3]."""
        return max(
            self._config.tank_min_m3,
            min(level, self._config.tank_max_m3),
        )

    def _check_numeric_validity(self, state: SystemState) -> None:
        """
        Raise ``PhysicsError`` if any state value is NaN or Inf.

        Guards against degenerate simulation states that could
        propagate silently and corrupt subsequent calculations.

        Args:
            state: The newly computed state to validate.

        Raises:
            PhysicsError: If any float field is NaN or Inf.
        """
        checks = {
            "pressure_bar":        state.pressure_bar,
            "flow_lps":            state.flow_lps,
            "temperature_celsius": state.temperature_celsius,
            "pump_rpm":            state.pump_rpm,
            "valve_position":      state.valve_position,
            "tank_level_m3":       state.tank_level_m3,
        }
        for name, value in checks.items():
            if math.isnan(value) or math.isinf(value):
                raise PhysicsError(
                    f"Simulation produced invalid value for '{name}': {value}",
                    detail=f"tick={self._tick_count} field={name} value={value}",
                )

    def _log_update(self, prev: SystemState, new: SystemState) -> None:
        """
        Emit a structured log line for every simulation tick.

        Logs: timestamp, changed parameters, and any active warnings.

        Warning severity is inferred from the prefix of each warning string:
          - ``CRITICAL:`` / ``ERROR:`` / ``WARNING:`` → logged at WARNING level.
          - ``INFO:``                                  → logged at DEBUG level.
        """
        changed = new.diff(prev)
        warnings = new.has_warnings(self._config)
        changed_keys = list(changed.keys())

        for w in warnings:
            prefix = w.split(":")[0].upper()
            if prefix in {"CRITICAL", "ERROR", "WARNING"}:
                _log.warning("[PHYSICS tick=%d] %s", self._tick_count, w)
            else:
                # INFO-level messages (e.g. "running at rated RPM") go to debug
                _log.debug("[PHYSICS tick=%d] %s", self._tick_count, w)

        if changed_keys:
            _log.debug(
                "[PHYSICS tick=%d] ts=%s | changed=%s | warnings=%d",
                self._tick_count,
                new.timestamp,
                changed_keys,
                len(warnings),
            )
        else:
            _log.debug(
                "[PHYSICS tick=%d] ts=%s | state unchanged | warnings=%d",
                self._tick_count,
                new.timestamp,
                len(warnings),
            )

    def _to_physics_state(self, state: SystemState) -> PhysicsState:
        """
        Convert a ``SystemState`` to the legacy ``PhysicsState`` DTO
        required by ``BasePhysicsEngine``.

        Args:
            state: Current ``SystemState``.

        Returns:
            Equivalent ``PhysicsState`` instance.
        """
        ps = PhysicsState(
            pressure_bar        = state.pressure_bar,
            flow_lps            = state.flow_lps,
            temperature_celsius = state.temperature_celsius,
            rpm                 = state.pump_rpm,
            timestamp           = state.timestamp,
        )
        # Evaluate constraints on the returned state.
        self.check_constraints(ps)
        return ps

    def reset_simulation(self) -> None:
        """
        Public alias for ``reset()``.

        Resets the simulation state to initial conditions.
        Exposed as a distinct name to match the task specification.
        """
        self.reset()

    def __repr__(self) -> str:
        return (
            f"<WaterSystemEngine ticks={self._tick_count} "
            f"state={self._state!r}>"
        )
