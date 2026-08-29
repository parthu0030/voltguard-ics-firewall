"""
VoltGuard — Day 3 Unit Test Suite
====================================
Comprehensive tests for the Physics Simulation Engine.

Coverage:
  - PhysicsConfig: loading, defaults, validation, invalid values
  - SystemState: initialisation, to_dict, diff, has_warnings
  - WaterSystemEngine:
      - simulate_pressure (pump ON/OFF, ramp, decay, clamping)
      - simulate_flow (open/closed valve, no negative flow)
      - simulate_temperature (rise, cool, ambient)
      - simulate_tank_level (drain, refill, floor)
      - simulate_pump_speed (ramp up, decay)
      - simulate_valve_position (gradual movement, clamping)
  - Valve behaviour (open/close commands)
  - Pump behaviour (ON/OFF commands)
  - Constraint checking (violations recorded)
  - reset_simulation (state returns to nominal)
  - Boundary conditions (all edge cases)
  - BasePhysicsEngine interface compliance

Run with:
    python3 -m pytest tests/test_day3_physics.py -v
Or directly:
    python3 tests/test_day3_physics.py
"""

from __future__ import annotations

import sys
import unittest
from pathlib import Path

# ── Ensure project root is on sys.path ────────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ── Bootstrap config so tests can run headlessly ──────────────────────────
from src.config import config_loader
if not config_loader.is_loaded:
    config_loader.load()

from src.exceptions import ConfigurationError, PhysicsError
from src.interfaces.base_physics import BasePhysicsEngine, PhysicsState
from src.physics.physics_config import PhysicsConfig
from src.physics.system_state import SystemState
from src.physics.water_system_engine import CommandType, WaterSystemEngine


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _default_config() -> PhysicsConfig:
    """Return a standard PhysicsConfig loaded from config.json."""
    return PhysicsConfig.from_config(config_loader)


def _minimal_config(**overrides) -> PhysicsConfig:
    """
    Return a PhysicsConfig with known defaults for isolated testing.
    Pass keyword arguments to override specific fields.
    """
    # Because PhysicsConfig is frozen, we build it with dataclasses.replace.
    import dataclasses
    base = PhysicsConfig()
    return dataclasses.replace(base, **overrides)


def _engine(cfg: PhysicsConfig | None = None) -> WaterSystemEngine:
    """Return a fresh WaterSystemEngine with the given (or default) config."""
    return WaterSystemEngine(cfg or _default_config())


# ===========================================================================
# TestPhysicsConfig
# ===========================================================================

class TestPhysicsConfig(unittest.TestCase):
    """Tests for PhysicsConfig loading and validation."""

    def test_load_from_config_loader(self) -> None:
        """Should load a valid PhysicsConfig from config.json."""
        cfg = _default_config()
        self.assertIsInstance(cfg, PhysicsConfig)

    def test_default_pressure_max(self) -> None:
        cfg = _default_config()
        self.assertGreater(cfg.pressure_max_bar, 0.0)

    def test_default_flow_max(self) -> None:
        cfg = _default_config()
        self.assertGreater(cfg.flow_max_lps, 0.0)

    def test_default_rpm_max(self) -> None:
        cfg = _default_config()
        self.assertGreater(cfg.pump_rpm_max, 0.0)

    def test_default_simulation_interval(self) -> None:
        cfg = _default_config()
        self.assertGreater(cfg.simulation_interval_sec, 0.0)

    def test_pressure_min_less_than_max(self) -> None:
        cfg = _default_config()
        self.assertLess(cfg.pressure_min_bar, cfg.pressure_max_bar)

    def test_temp_min_less_than_max(self) -> None:
        cfg = _default_config()
        self.assertLess(cfg.temp_min_celsius, cfg.temp_max_celsius)

    def test_tank_min_less_than_max(self) -> None:
        cfg = _default_config()
        self.assertLess(cfg.tank_min_m3, cfg.tank_max_m3)

    def test_tank_initial_within_bounds(self) -> None:
        cfg = _default_config()
        self.assertGreaterEqual(cfg.tank_initial_m3, cfg.tank_min_m3)
        self.assertLessEqual(cfg.tank_initial_m3, cfg.tank_max_m3)

    def test_invalid_pressure_range_raises(self) -> None:
        """pressure_min >= pressure_max must raise ConfigurationError."""
        import dataclasses
        bad_cfg = dataclasses.replace(
            PhysicsConfig(), pressure_min_bar=15.0, pressure_max_bar=10.0
        )
        with self.assertRaises(ConfigurationError):
            bad_cfg._validate()

    def test_invalid_temp_range_raises(self) -> None:
        import dataclasses
        bad_cfg = dataclasses.replace(
            PhysicsConfig(), temp_min_celsius=200.0, temp_max_celsius=100.0
        )
        with self.assertRaises(ConfigurationError):
            bad_cfg._validate()

    def test_invalid_tank_range_raises(self) -> None:
        import dataclasses
        bad_cfg = dataclasses.replace(
            PhysicsConfig(), tank_min_m3=200.0, tank_max_m3=100.0
        )
        with self.assertRaises(ConfigurationError):
            bad_cfg._validate()

    def test_zero_simulation_interval_raises(self) -> None:
        import dataclasses
        bad_cfg = dataclasses.replace(PhysicsConfig(), simulation_interval_sec=0.0)
        with self.assertRaises(ConfigurationError):
            bad_cfg._validate()

    def test_config_is_frozen(self) -> None:
        """PhysicsConfig must be immutable."""
        cfg = _default_config()
        with self.assertRaises(Exception):
            cfg.pressure_max_bar = 999.0  # type: ignore[misc]

    def test_str_representation(self) -> None:
        cfg = _default_config()
        s = str(cfg)
        self.assertIn("PhysicsConfig", s)

    def test_invalid_tank_initial_out_of_range(self) -> None:
        import dataclasses
        bad_cfg = dataclasses.replace(
            PhysicsConfig(), tank_initial_m3=150.0, tank_max_m3=100.0
        )
        with self.assertRaises(ConfigurationError):
            bad_cfg._validate()


# ===========================================================================
# TestSystemState
# ===========================================================================

class TestSystemState(unittest.TestCase):
    """Tests for SystemState DTO."""

    def test_default_initialisation(self) -> None:
        s = SystemState()
        self.assertEqual(s.pressure_bar, 0.0)
        self.assertEqual(s.flow_lps, 0.0)
        self.assertFalse(s.pump_on)
        self.assertEqual(s.pump_rpm, 0.0)
        self.assertEqual(s.valve_position, 0.0)
        self.assertGreater(len(s.timestamp), 0)

    def test_to_dict_keys(self) -> None:
        s = SystemState()
        d = s.to_dict()
        expected_keys = {
            "pressure_bar", "flow_lps", "temperature_celsius",
            "pump_on", "pump_rpm", "valve_position", "tank_level_m3",
            "timestamp",
        }
        self.assertEqual(set(d.keys()), expected_keys)

    def test_to_dict_values_rounded(self) -> None:
        s = SystemState(pressure_bar=3.141592653)
        d = s.to_dict()
        self.assertEqual(d["pressure_bar"], 3.1416)

    def test_diff_unchanged(self) -> None:
        s1 = SystemState(pressure_bar=5.0)
        s2 = SystemState(pressure_bar=5.0)
        delta = s1.diff(s2)
        self.assertNotIn("pressure_bar", delta)

    def test_diff_changed_float(self) -> None:
        s1 = SystemState(pressure_bar=5.0)
        s2 = SystemState(pressure_bar=3.0)
        delta = s1.diff(s2)
        self.assertIn("pressure_bar", delta)
        self.assertEqual(delta["pressure_bar"]["prev"], 3.0)
        self.assertEqual(delta["pressure_bar"]["new"], 5.0)

    def test_diff_changed_bool(self) -> None:
        s1 = SystemState(pump_on=True)
        s2 = SystemState(pump_on=False)
        delta = s1.diff(s2)
        self.assertIn("pump_on", delta)

    def test_diff_ignores_timestamp(self) -> None:
        s1 = SystemState()
        import time; time.sleep(0.01)
        s2 = SystemState()
        delta = s1.diff(s2)
        self.assertNotIn("timestamp", delta)

    def test_has_warnings_pressure_critical(self) -> None:
        cfg = _default_config()
        s = SystemState(pressure_bar=cfg.pressure_max_bar + 1.0)
        warnings = s.has_warnings(cfg)
        self.assertTrue(any("Pressure" in w for w in warnings))

    def test_has_warnings_pressure_approaching(self) -> None:
        cfg = _default_config()
        s = SystemState(pressure_bar=cfg.pressure_max_bar * 0.95)
        warnings = s.has_warnings(cfg)
        self.assertTrue(any("Pressure" in w for w in warnings))

    def test_has_warnings_no_warnings(self) -> None:
        cfg = _default_config()
        s = SystemState(
            pressure_bar=2.0,
            flow_lps=5.0,
            temperature_celsius=50.0,
            pump_rpm=1000.0,
            tank_level_m3=80.0,
        )
        warnings = s.has_warnings(cfg)
        self.assertEqual(warnings, [])

    def test_has_warnings_tank_empty(self) -> None:
        cfg = _default_config()
        s = SystemState(tank_level_m3=cfg.tank_min_m3)
        warnings = s.has_warnings(cfg)
        self.assertTrue(any("Tank" in w or "tank" in w.lower() for w in warnings))

    def test_has_warnings_temp_max(self) -> None:
        cfg = _default_config()
        s = SystemState(temperature_celsius=cfg.temp_max_celsius + 1.0)
        warnings = s.has_warnings(cfg)
        self.assertTrue(any("Temperature" in w for w in warnings))

    def test_repr(self) -> None:
        s = SystemState()
        r = repr(s)
        self.assertIn("SystemState", r)
        self.assertIn("pump=OFF", r)


# ===========================================================================
# TestPressureSimulation
# ===========================================================================

class TestPressureSimulation(unittest.TestCase):
    """Tests for simulate_pressure()."""

    def test_pump_on_increases_pressure(self) -> None:
        eng = _engine()
        state = SystemState(pump_on=True, pump_rpm=1800.0, pressure_bar=0.0)
        new_p = eng.simulate_pressure(state, new_rpm=1800.0, dt=1.0)
        self.assertGreater(new_p, 0.0)

    def test_pump_off_decays_pressure(self) -> None:
        eng = _engine()
        state = SystemState(pump_on=False, pump_rpm=0.0, pressure_bar=5.0)
        new_p = eng.simulate_pressure(state, new_rpm=0.0, dt=1.0)
        self.assertLess(new_p, 5.0)

    def test_pump_off_pressure_cannot_go_negative(self) -> None:
        eng = _engine()
        state = SystemState(pump_on=False, pump_rpm=0.0, pressure_bar=0.0)
        new_p = eng.simulate_pressure(state, new_rpm=0.0, dt=100.0)
        self.assertGreaterEqual(new_p, 0.0)

    def test_update_state_clamps_pressure_at_max(self) -> None:
        cfg = _minimal_config(pressure_max_bar=10.0, pump_rpm_max=3600.0)
        eng = WaterSystemEngine(cfg)
        # Force pressure near max before clamping.
        eng._state.pump_on = True
        eng._state.pump_rpm = cfg.pump_rpm_max
        eng._state.pressure_bar = 11.0  # Above max
        state = eng.update_state()
        self.assertLessEqual(state.pressure_bar, cfg.pressure_max_bar)

    def test_pressure_rises_proportional_to_rpm(self) -> None:
        eng = _engine()
        state_low  = SystemState(pump_on=True, pump_rpm=900.0,  pressure_bar=0.0)
        state_high = SystemState(pump_on=True, pump_rpm=3600.0, pressure_bar=0.0)
        new_p_low  = eng.simulate_pressure(state_low,  new_rpm=900.0,  dt=10.0)
        new_p_high = eng.simulate_pressure(state_high, new_rpm=3600.0, dt=10.0)
        self.assertGreater(new_p_high, new_p_low)

    def test_full_update_pump_on_raises_pressure_over_time(self) -> None:
        eng = _engine()
        eng.apply_command(CommandType.SET_VALVE, 1.0)
        eng.apply_command(CommandType.SET_PUMP, 1.0)
        initial_p = eng.update_state().pressure_bar
        for _ in range(5):
            eng.update_state()
        final_p = eng.get_system_state().pressure_bar
        self.assertGreater(final_p, initial_p)


# ===========================================================================
# TestFlowSimulation
# ===========================================================================

class TestFlowSimulation(unittest.TestCase):
    """Tests for simulate_flow()."""

    def test_closed_valve_produces_zero_flow(self) -> None:
        eng = _engine()
        state = SystemState(pump_on=True, pump_rpm=3600.0,
                            pressure_bar=8.0, valve_position=0.0)
        flow = eng.simulate_flow(state, new_pressure=8.0)
        self.assertEqual(flow, 0.0)

    def test_open_valve_increases_flow(self) -> None:
        eng = _engine()
        state_half = SystemState(valve_position=0.5, pressure_bar=8.0)
        state_full = SystemState(valve_position=1.0, pressure_bar=8.0)
        flow_half = eng.simulate_flow(state_half, new_pressure=8.0)
        flow_full = eng.simulate_flow(state_full, new_pressure=8.0)
        self.assertGreater(flow_full, flow_half)

    def test_flow_cannot_be_negative(self) -> None:
        eng = _engine()
        state = SystemState(valve_position=1.0, pressure_bar=-1.0)
        flow = eng.simulate_flow(state, new_pressure=-1.0)
        self.assertGreaterEqual(flow, 0.0)

    def test_flow_capped_at_max(self) -> None:
        cfg = _minimal_config(flow_max_lps=50.0, flow_coefficient=10.0)
        eng = WaterSystemEngine(cfg)
        state = SystemState(valve_position=1.0, pressure_bar=9.0)
        eng._state = state
        result = eng.update_state()
        self.assertLessEqual(result.flow_lps, cfg.flow_max_lps)

    def test_zero_pressure_produces_zero_flow(self) -> None:
        eng = _engine()
        state = SystemState(valve_position=1.0, pressure_bar=0.0)
        flow = eng.simulate_flow(state, new_pressure=0.0)
        self.assertEqual(flow, 0.0)

    def test_flow_increases_with_more_pressure(self) -> None:
        eng = _engine()
        s_low  = SystemState(valve_position=0.5, pressure_bar=2.0)
        s_high = SystemState(valve_position=0.5, pressure_bar=8.0)
        f_low  = eng.simulate_flow(s_low,  new_pressure=2.0)
        f_high = eng.simulate_flow(s_high, new_pressure=8.0)
        self.assertGreater(f_high, f_low)


# ===========================================================================
# TestTemperatureSimulation
# ===========================================================================

class TestTemperatureSimulation(unittest.TestCase):
    """Tests for simulate_temperature()."""

    def test_pump_on_raises_temperature(self) -> None:
        eng = _engine()
        state = SystemState(pump_on=True, pump_rpm=3600.0, temperature_celsius=22.0)
        new_t = eng.simulate_temperature(state, dt=10.0)
        self.assertGreater(new_t, 22.0)

    def test_pump_off_cools_toward_ambient(self) -> None:
        cfg = _default_config()
        eng = WaterSystemEngine(cfg)
        state = SystemState(pump_on=False, pump_rpm=0.0,
                            temperature_celsius=80.0)
        new_t = eng.simulate_temperature(state, dt=10.0)
        self.assertLess(new_t, 80.0)

    def test_temperature_never_below_min(self) -> None:
        cfg = _default_config()
        eng = WaterSystemEngine(cfg)
        # Simulate many cooling ticks from a very high temperature.
        eng._state.pump_on = False
        eng._state.pump_rpm = 0.0
        eng._state.temperature_celsius = 200.0  # above max (will be clamped)
        for _ in range(1000):
            eng.update_state()
        self.assertGreaterEqual(
            eng.get_system_state().temperature_celsius,
            cfg.temp_min_celsius,
        )

    def test_temperature_never_exceeds_max(self) -> None:
        cfg = _default_config()
        eng = WaterSystemEngine(cfg)
        eng._state.pump_on = True
        eng._state.pump_rpm = cfg.pump_rpm_max
        for _ in range(10000):
            eng.update_state()
        self.assertLessEqual(
            eng.get_system_state().temperature_celsius,
            cfg.temp_max_celsius,
        )

    def test_temperature_stable_at_ambient_when_idle(self) -> None:
        cfg = _default_config()
        eng = WaterSystemEngine(cfg)
        # Start at ambient, pump OFF — should stay near ambient.
        eng._state.temperature_celsius = cfg.temp_ambient_celsius
        eng._state.pump_on = False
        for _ in range(20):
            eng.update_state()
        t_final = eng.get_system_state().temperature_celsius
        self.assertAlmostEqual(t_final, cfg.temp_ambient_celsius, delta=5.0)


# ===========================================================================
# TestTankLevel
# ===========================================================================

class TestTankLevel(unittest.TestCase):
    """Tests for simulate_tank_level()."""

    def test_tank_drains_with_flow(self) -> None:
        cfg = _default_config()
        eng = WaterSystemEngine(cfg)
        # Disable auto-refill by setting threshold to 0.
        import dataclasses
        cfg2 = dataclasses.replace(cfg, tank_fill_threshold_m3=0.0, tank_initial_m3=50.0)
        eng2 = WaterSystemEngine(cfg2)
        initial = eng2.get_system_state().tank_level_m3
        new_level = eng2.simulate_tank_level(
            eng2.get_system_state(), new_flow=10.0, dt=10.0
        )
        self.assertLess(new_level, initial)

    def test_tank_level_cannot_go_negative(self) -> None:
        cfg = _default_config()
        import dataclasses
        cfg2 = dataclasses.replace(cfg, tank_fill_threshold_m3=0.0)
        eng = WaterSystemEngine(cfg2)
        eng._state.tank_level_m3 = 0.01
        result = eng.update_state()
        self.assertGreaterEqual(result.tank_level_m3, cfg2.tank_min_m3)

    def test_tank_auto_refills_when_low(self) -> None:
        cfg = _default_config()
        eng = WaterSystemEngine(cfg)
        # Force tank to just below fill threshold.
        eng._state.tank_level_m3 = cfg.tank_fill_threshold_m3 - 0.1
        # With flow=0, drain=0, refill should take over.
        new_level = eng.simulate_tank_level(eng._state, new_flow=0.0, dt=1.0)
        self.assertGreater(new_level, eng._state.tank_level_m3)

    def test_tank_does_not_exceed_max(self) -> None:
        cfg = _default_config()
        eng = WaterSystemEngine(cfg)
        # Simulate thousands of ticks with pump OFF (no drain) and low initial level.
        eng._state.tank_level_m3 = 5.0
        for _ in range(500):
            eng.update_state()
        self.assertLessEqual(
            eng.get_system_state().tank_level_m3, cfg.tank_max_m3
        )

    def test_tank_drain_proportional_to_flow(self) -> None:
        cfg = _default_config()
        import dataclasses
        cfg2 = dataclasses.replace(cfg, tank_fill_threshold_m3=0.0)
        eng = WaterSystemEngine(cfg2)
        state = SystemState(tank_level_m3=50.0)

        level_low  = eng.simulate_tank_level(state, new_flow=5.0,  dt=1.0)
        level_high = eng.simulate_tank_level(state, new_flow=20.0, dt=1.0)
        self.assertGreater(level_low, level_high)


# ===========================================================================
# TestPumpSpeed
# ===========================================================================

class TestPumpSpeed(unittest.TestCase):
    """Tests for simulate_pump_speed()."""

    def test_pump_on_rpm_increases(self) -> None:
        eng = _engine()
        state = SystemState(pump_on=True, pump_rpm=0.0, valve_position=0.5)
        new_rpm = eng.simulate_pump_speed(state, dt=1.0)
        self.assertGreater(new_rpm, 0.0)

    def test_pump_off_rpm_decays(self) -> None:
        eng = _engine()
        state = SystemState(pump_on=False, pump_rpm=1800.0)
        new_rpm = eng.simulate_pump_speed(state, dt=1.0)
        self.assertLess(new_rpm, 1800.0)

    def test_rpm_cannot_go_negative(self) -> None:
        eng = _engine()
        state = SystemState(pump_on=False, pump_rpm=0.0)
        new_rpm = eng.simulate_pump_speed(state, dt=100.0)
        self.assertGreaterEqual(new_rpm, 0.0)

    def test_rpm_capped_at_max(self) -> None:
        cfg = _default_config()
        eng = WaterSystemEngine(cfg)
        eng._state.pump_on = True
        eng._state.pump_rpm = cfg.pump_rpm_max - 10.0
        for _ in range(100):
            eng.update_state()
        self.assertLessEqual(eng.get_system_state().pump_rpm, cfg.pump_rpm_max)

    def test_pump_off_rpm_eventually_reaches_zero(self) -> None:
        cfg = _default_config()
        eng = WaterSystemEngine(cfg)
        eng._state.pump_on = False
        eng._state.pump_rpm = 3600.0
        for _ in range(500):
            eng.update_state()
        self.assertAlmostEqual(eng.get_system_state().pump_rpm, 0.0, delta=1.0)


# ===========================================================================
# TestValveBehaviour
# ===========================================================================

class TestValveBehaviour(unittest.TestCase):
    """Tests for valve control commands."""

    def test_set_valve_to_zero_closes(self) -> None:
        """
        Valve should reach 0.0 when commanded to 0.0 on every tick.

        Commands are consumed each update_state() call, so the target
        position must be re-queued each tick (as the SimulationRunner
        worker does via continuous SET_VALVE commands).
        """
        eng = _engine()
        eng._state.valve_position = 1.0
        # Send the command every tick, mirroring how the runner works.
        for _ in range(100):
            eng.apply_command(CommandType.SET_VALVE, 0.0)
            eng.update_state()
        self.assertAlmostEqual(eng.get_system_state().valve_position, 0.0, delta=0.05)

    def test_set_valve_to_one_opens(self) -> None:
        eng = _engine()
        eng._state.valve_position = 0.0
        for _ in range(100):
            eng.apply_command(CommandType.SET_VALVE, 1.0)
            eng.update_state()
        self.assertAlmostEqual(eng.get_system_state().valve_position, 1.0, delta=0.1)

    def test_valve_clamped_to_zero_to_one(self) -> None:
        eng = _engine()
        eng.apply_command(CommandType.SET_VALVE, 5.0)
        eng.update_state()
        pos = eng.get_system_state().valve_position
        self.assertLessEqual(pos, 1.0)
        self.assertGreaterEqual(pos, 0.0)

    def test_valve_negative_value_clamped(self) -> None:
        eng = _engine()
        eng.apply_command(CommandType.SET_VALVE, -10.0)
        eng.update_state()
        self.assertGreaterEqual(eng.get_system_state().valve_position, 0.0)

    def test_valve_changes_gradually(self) -> None:
        """Valve should not jump instantly from 0 to 1."""
        cfg = _minimal_config(valve_speed_per_sec=0.1, simulation_interval_sec=1.0)
        eng = WaterSystemEngine(cfg)
        eng._state.valve_position = 0.0
        eng.apply_command(CommandType.SET_VALVE, 1.0)
        eng.update_state()
        pos = eng.get_system_state().valve_position
        self.assertLess(pos, 1.0)   # Did not jump instantly.
        self.assertGreater(pos, 0.0)


# ===========================================================================
# TestPumpBehaviour
# ===========================================================================

class TestPumpBehaviour(unittest.TestCase):
    """Tests for pump ON/OFF control commands."""

    def test_pump_on_command(self) -> None:
        eng = _engine()
        eng.apply_command(CommandType.SET_PUMP, 1.0)
        eng.update_state()
        self.assertTrue(eng.get_system_state().pump_on)

    def test_pump_off_command(self) -> None:
        eng = _engine()
        eng._state.pump_on = True
        eng.apply_command(CommandType.SET_PUMP, 0.0)
        eng.update_state()
        self.assertFalse(eng.get_system_state().pump_on)

    def test_pump_on_increases_rpm(self) -> None:
        eng = _engine()
        eng.apply_command(CommandType.SET_VALVE, 1.0)
        eng.apply_command(CommandType.SET_PUMP, 1.0)
        for _ in range(20):
            state = eng.update_state()
        self.assertGreater(state.pump_rpm, 0.0)

    def test_pump_off_flow_goes_to_zero(self) -> None:
        """With pump OFF and valve CLOSED, flow should be 0."""
        eng = _engine()
        # Ensure valve is closed and pump is off.
        eng._state.pump_on = False
        eng._state.valve_position = 0.0
        eng._state.pump_rpm = 0.0
        eng._state.pressure_bar = 0.0
        state = eng.update_state()
        self.assertEqual(state.flow_lps, 0.0)

    def test_unknown_command_raises_physics_error(self) -> None:
        eng = _engine()
        with self.assertRaises(PhysicsError):
            eng.apply_command("INVALID_CMD", 1.0)

    def test_rpm_increases_with_valve_demand(self) -> None:
        eng = _engine()
        eng.apply_command(CommandType.SET_PUMP, 1.0)
        eng.apply_command(CommandType.SET_VALVE, 0.25)
        for _ in range(20):
            low = eng.update_state()
        eng.apply_command(CommandType.SET_VALVE, 1.0)
        for _ in range(20):
            high = eng.update_state()
        self.assertGreater(high.pump_rpm, low.pump_rpm)
        self.assertGreater(high.flow_lps, low.flow_lps)

    def test_rpm_ramps_down_when_valve_closes(self) -> None:
        eng = _engine()
        eng.apply_command(CommandType.SET_PUMP, 1.0)
        eng.apply_command(CommandType.SET_VALVE, 1.0)
        for _ in range(25):
            open_state = eng.update_state()
        eng.apply_command(CommandType.SET_VALVE, 0.0)
        closed_state = eng.update_state()
        self.assertLess(closed_state.pump_rpm, open_state.pump_rpm)
        self.assertGreater(closed_state.pump_rpm, 0.0)  # controlled ramp, not a jump


# ===========================================================================
# TestConstraintChecking
# ===========================================================================

class TestConstraintChecking(unittest.TestCase):
    """Tests for check_constraints() and violation recording."""

    def test_safe_state_returns_true(self) -> None:
        eng = _engine()
        ps = PhysicsState(pressure_bar=3.0, flow_lps=10.0,
                          temperature_celsius=50.0, rpm=1000.0)
        result = eng.check_constraints(ps)
        self.assertTrue(result)
        self.assertTrue(ps.is_safe)
        self.assertEqual(ps.violations, [])

    def test_over_pressure_violation(self) -> None:
        cfg = _default_config()
        eng = WaterSystemEngine(cfg)
        ps = PhysicsState(pressure_bar=cfg.pressure_max_bar + 5.0)
        result = eng.check_constraints(ps)
        self.assertFalse(result)
        self.assertFalse(ps.is_safe)
        self.assertGreater(len(ps.violations), 0)

    def test_over_flow_violation(self) -> None:
        cfg = _default_config()
        eng = WaterSystemEngine(cfg)
        ps = PhysicsState(flow_lps=cfg.flow_max_lps + 10.0)
        result = eng.check_constraints(ps)
        self.assertFalse(result)

    def test_over_temperature_violation(self) -> None:
        cfg = _default_config()
        eng = WaterSystemEngine(cfg)
        ps = PhysicsState(temperature_celsius=cfg.temp_max_celsius + 20.0)
        result = eng.check_constraints(ps)
        self.assertFalse(result)

    def test_negative_flow_violation(self) -> None:
        eng = _engine()
        ps = PhysicsState(flow_lps=-5.0)
        result = eng.check_constraints(ps)
        self.assertFalse(result)

    def test_over_rpm_violation(self) -> None:
        cfg = _default_config()
        eng = WaterSystemEngine(cfg)
        ps = PhysicsState(rpm=cfg.pump_rpm_max + 500.0)
        result = eng.check_constraints(ps)
        self.assertFalse(result)

    def test_multiple_violations_all_recorded(self) -> None:
        cfg = _default_config()
        eng = WaterSystemEngine(cfg)
        ps = PhysicsState(
            pressure_bar=cfg.pressure_max_bar + 5.0,
            flow_lps=cfg.flow_max_lps + 10.0,
        )
        eng.check_constraints(ps)
        self.assertGreaterEqual(len(ps.violations), 2)


# ===========================================================================
# TestResetSimulation
# ===========================================================================

class TestResetSimulation(unittest.TestCase):
    """Tests for reset() and reset_simulation()."""

    def test_reset_restores_initial_state(self) -> None:
        cfg = _default_config()
        eng = WaterSystemEngine(cfg)

        # Run the engine and change state significantly.
        eng.apply_command(CommandType.SET_PUMP, 1.0)
        eng.apply_command(CommandType.SET_VALVE, 1.0)
        for _ in range(20):
            eng.update_state()

        # Reset and verify we're back to nominal.
        eng.reset()
        s = eng.get_system_state()

        self.assertFalse(s.pump_on)
        self.assertEqual(s.pump_rpm, 0.0)
        self.assertEqual(s.pressure_bar, 0.0)
        self.assertEqual(s.flow_lps, 0.0)
        self.assertEqual(s.valve_position, 0.0)
        self.assertAlmostEqual(s.temperature_celsius, cfg.temp_ambient_celsius, delta=1.0)
        self.assertAlmostEqual(s.tank_level_m3, cfg.tank_initial_m3, delta=0.1)

    def test_reset_clears_tick_count(self) -> None:
        eng = _engine()
        for _ in range(10):
            eng.update_state()
        self.assertEqual(eng.tick_count, 10)
        eng.reset()
        self.assertEqual(eng.tick_count, 0)

    def test_reset_simulation_alias(self) -> None:
        """reset_simulation() should behave identically to reset()."""
        eng = _engine()
        eng._state.pump_on = True
        eng._state.pressure_bar = 8.0
        eng.reset_simulation()
        s = eng.get_system_state()
        self.assertFalse(s.pump_on)
        self.assertEqual(s.pressure_bar, 0.0)

    def test_reset_clears_pending_commands(self) -> None:
        eng = _engine()
        eng.apply_command(CommandType.SET_PUMP, 1.0)
        eng.apply_command(CommandType.SET_VALVE, 0.8)
        eng.reset()
        # After reset, pending commands should be gone — state stays at nominal.
        s = eng.update_state()
        self.assertFalse(s.pump_on)


# ===========================================================================
# TestBoundaryConditions
# ===========================================================================

class TestBoundaryConditions(unittest.TestCase):
    """Edge-case boundary condition tests."""

    def test_very_small_dt(self) -> None:
        """Tiny time steps should not crash or produce NaN."""
        eng = _engine()
        eng._state.pump_on = True
        for _ in range(10):
            eng.update_state(dt=0.001)
        s = eng.get_system_state()
        import math
        self.assertFalse(math.isnan(s.pressure_bar))
        self.assertFalse(math.isnan(s.flow_lps))

    def test_very_large_dt(self) -> None:
        """Large time steps should clamp values, not crash."""
        eng = _engine()
        eng._state.pump_on = True
        eng.update_state(dt=10000.0)
        s = eng.get_system_state()
        cfg = _default_config()
        self.assertLessEqual(s.pressure_bar, cfg.pressure_max_bar)
        self.assertLessEqual(s.flow_lps, cfg.flow_max_lps)
        self.assertLessEqual(s.temperature_celsius, cfg.temp_max_celsius)

    def test_valve_fully_open_fully_closed_toggle(self) -> None:
        """Repeated valve open/close should not corrupt state."""
        eng = _engine()
        eng._state.pump_on = True
        for i in range(20):
            cmd = 1.0 if i % 2 == 0 else 0.0
            eng.apply_command(CommandType.SET_VALVE, cmd)
            eng.update_state()
        s = eng.get_system_state()
        self.assertGreaterEqual(s.valve_position, 0.0)
        self.assertLessEqual(s.valve_position, 1.0)

    def test_pump_rapid_on_off(self) -> None:
        """Rapid pump toggling should not diverge."""
        eng = _engine()
        for i in range(50):
            cmd = 1.0 if i % 3 == 0 else 0.0
            eng.apply_command(CommandType.SET_PUMP, cmd)
            eng.update_state()
        s = eng.get_system_state()
        self.assertGreaterEqual(s.pump_rpm, 0.0)
        self.assertLessEqual(s.pump_rpm, _default_config().pump_rpm_max)

    def test_multiple_resets_do_not_break_engine(self) -> None:
        eng = _engine()
        for _ in range(5):
            eng.apply_command(CommandType.SET_PUMP, 1.0)
            for _ in range(10):
                eng.update_state()
            eng.reset()
        s = eng.get_system_state()
        self.assertEqual(s.pressure_bar, 0.0)
        self.assertFalse(s.pump_on)

    def test_update_state_without_any_commands(self) -> None:
        """Engine should advance correctly with no commands queued."""
        eng = _engine()
        s = eng.update_state()
        self.assertIsInstance(s, SystemState)

    def test_state_after_10000_ticks_still_bounded(self) -> None:
        """Run for 10 000 ticks; all values must stay within config limits."""
        cfg = _default_config()
        eng = WaterSystemEngine(cfg)
        eng.apply_command(CommandType.SET_PUMP, 1.0)
        eng.apply_command(CommandType.SET_VALVE, 0.7)
        for _ in range(10_000):
            eng.update_state()
        s = eng.get_system_state()
        self.assertLessEqual(s.pressure_bar, cfg.pressure_max_bar)
        self.assertLessEqual(s.flow_lps, cfg.flow_max_lps)
        self.assertLessEqual(s.temperature_celsius, cfg.temp_max_celsius)
        self.assertGreaterEqual(s.temperature_celsius, cfg.temp_min_celsius)
        self.assertLessEqual(s.pump_rpm, cfg.pump_rpm_max)
        self.assertGreaterEqual(s.pump_rpm, 0.0)
        self.assertLessEqual(s.tank_level_m3, cfg.tank_max_m3)
        self.assertGreaterEqual(s.tank_level_m3, cfg.tank_min_m3)


# ===========================================================================
# TestEngineInterface
# ===========================================================================

class TestEngineInterface(unittest.TestCase):
    """Verify BasePhysicsEngine contract is fully satisfied."""

    def test_engine_is_base_physics_engine_subclass(self) -> None:
        eng = _engine()
        self.assertIsInstance(eng, BasePhysicsEngine)

    def test_simulate_returns_physics_state(self) -> None:
        eng = _engine()
        result = eng.simulate(command_value=0.5, delta_t=1.0)
        self.assertIsInstance(result, PhysicsState)

    def test_get_state_returns_physics_state(self) -> None:
        eng = _engine()
        result = eng.get_state()
        self.assertIsInstance(result, PhysicsState)

    def test_reset_is_callable(self) -> None:
        eng = _engine()
        eng.reset()  # Should not raise.

    def test_check_constraints_returns_bool(self) -> None:
        eng = _engine()
        ps = PhysicsState(pressure_bar=3.0)
        result = eng.check_constraints(ps)
        self.assertIsInstance(result, bool)

    def test_get_system_state_returns_system_state(self) -> None:
        eng = _engine()
        result = eng.get_system_state()
        self.assertIsInstance(result, SystemState)

    def test_engine_repr(self) -> None:
        eng = _engine()
        r = repr(eng)
        self.assertIn("WaterSystemEngine", r)

    def test_tick_count_increments(self) -> None:
        eng = _engine()
        for i in range(1, 6):
            eng.update_state()
            self.assertEqual(eng.tick_count, i)

    def test_config_property(self) -> None:
        cfg = _default_config()
        eng = WaterSystemEngine(cfg)
        self.assertIs(eng.config, cfg)


# ===========================================================================
# Main
# ===========================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
