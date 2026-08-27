"""Regression tests for standalone physics-safety detection."""

from src.decision_engine.models import SeverityLevel
from src.physics.physics_config import PhysicsConfig
from src.physics.safety_monitor import PhysicsSafetyMonitor
from src.physics.system_state import SystemState


def test_detects_critical_temperature_and_deduplicates_active_state() -> None:
    cfg = PhysicsConfig()
    monitor = PhysicsSafetyMonitor(cfg, cooldown_sec=60)
    state = SystemState(temperature_celsius=cfg.temp_max_celsius + 1)

    first = monitor.evaluate(state)
    second = monitor.evaluate(state)

    assert any(v.rule_id == "PHYS_TEMPERATURE_HIGH" for v in first)
    assert not second


def test_detects_running_pump_with_open_valve_and_no_flow() -> None:
    monitor = PhysicsSafetyMonitor(PhysicsConfig())
    violations = monitor.evaluate(SystemState(
        pressure_bar=2.0, flow_lps=0.0, pump_on=True, pump_rpm=1200,
        valve_position=0.5,
    ))

    no_flow = next(v for v in violations if v.rule_id == "PHYS_PUMP_NO_FLOW")
    assert no_flow.severity == SeverityLevel.HIGH
    assert no_flow.risk_score == 75


def test_detects_unrealistic_pressure_step() -> None:
    monitor = PhysicsSafetyMonitor(PhysicsConfig())
    monitor.evaluate(SystemState(pressure_bar=1.0))
    violations = monitor.evaluate(SystemState(pressure_bar=6.0))

    assert any(v.rule_id == "PHYS_PRESSURE_RATE" for v in violations)
