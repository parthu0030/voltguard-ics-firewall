"""Deterministic safety evaluation for standalone physics simulation states.

This module deliberately has no Qt, database, or UI dependencies.  It turns
one ``SystemState`` snapshot into explainable violations that can be sent to
the existing security-event and alert pipeline by ``SimulationRunner``.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from src.decision_engine.models import SeverityLevel
from src.physics.physics_config import PhysicsConfig
from src.physics.system_state import SystemState


@dataclass(frozen=True)
class PhysicsViolation:
    """One explainable physical safety-rule violation."""

    rule_id: str
    parameter: str
    current_value: float
    safe_range: str
    severity: SeverityLevel
    risk_score: int
    description: str
    timestamp: str
    state: dict[str, object] = field(default_factory=dict)


class PhysicsSafetyMonitor:
    """Evaluate process safety rules and suppress repeated unchanged events."""

    def __init__(self, config: PhysicsConfig, cooldown_sec: float = 10.0) -> None:
        self._config = config
        self._cooldown_sec = max(0.0, cooldown_sec)
        self._previous: Optional[SystemState] = None
        self._last_emitted: dict[str, float] = {}
        self._active_rules: set[str] = set()

    def reset(self) -> None:
        """Clear transient state after a simulation reset."""
        self._previous = None
        self._last_emitted.clear()
        self._active_rules.clear()

    def evaluate(self, state: SystemState) -> list[PhysicsViolation]:
        """Return new or cooldown-expired violations for ``state``."""
        cfg = self._config
        found: list[PhysicsViolation] = []

        def add(rule_id: str, parameter: str, value: float, safe_range: str,
                severity: SeverityLevel, risk: int, description: str) -> None:
            found.append(PhysicsViolation(
                rule_id=rule_id, parameter=parameter, current_value=value,
                safe_range=safe_range, severity=severity, risk_score=risk,
                description=description, timestamp=state.timestamp,
                state=state.to_dict(),
            ))

        if state.pressure_bar > cfg.pressure_max_bar:
            add("PHYS_PRESSURE_HIGH", "pressure_bar", state.pressure_bar,
                f"< {cfg.pressure_max_bar:.2f} bar", SeverityLevel.HIGH, 75,
                "Pipeline pressure reached the configured maximum.")
        if state.pump_on and state.pump_rpm >= cfg.pump_rpm_max * 0.25 and state.pressure_bar < cfg.pressure_min_bar:
            add("PHYS_PRESSURE_LOW", "pressure_bar", state.pressure_bar,
                f">= {cfg.pressure_min_bar:.2f} bar while pump is running", SeverityLevel.HIGH, 70,
                "Pump is running but pipeline pressure is below the safe minimum.")
        if state.flow_lps > cfg.flow_max_lps:
            add("PHYS_FLOW_HIGH", "flow_lps", state.flow_lps,
                f"< {cfg.flow_max_lps:.2f} L/s", SeverityLevel.HIGH, 70,
                "Flow reached the configured maximum.")
        if state.pump_on and state.pump_rpm >= cfg.pump_rpm_max * 0.75 and state.valve_position <= 0.10:
            add("PHYS_HIGH_RPM_CLOSED_VALVE", "valve_position", state.valve_position * 100,
                "> 10% open at high RPM", SeverityLevel.HIGH, 80,
                "High pump speed against a nearly closed valve can cause damaging dead-head pressure.")
        if not state.pump_on and state.flow_lps > max(0.1, cfg.flow_max_lps * 0.02):
            add("PHYS_PUMP_OFF_FLOW", "flow_lps", state.flow_lps,
                "near 0 L/s while pump is OFF", SeverityLevel.HIGH, 70,
                "Significant flow was observed although the pump is commanded OFF.")
        if state.pump_on and state.pump_rpm >= cfg.pump_rpm_max * 0.25 and state.valve_position >= 0.10 and state.flow_lps <= 0.05:
            add("PHYS_PUMP_NO_FLOW", "flow_lps", state.flow_lps,
                "> 0.05 L/s with running pump and open valve", SeverityLevel.HIGH, 75,
                "Pump/valve state is inconsistent with near-zero process flow.")
        if state.temperature_celsius > cfg.temp_max_celsius:
            add("PHYS_TEMPERATURE_HIGH", "temperature_celsius", state.temperature_celsius,
                f"< {cfg.temp_max_celsius:.1f} °C", SeverityLevel.CRITICAL, 95,
                "Process temperature reached the configured maximum.")
        if state.pump_rpm > cfg.pump_rpm_max:
            add("PHYS_PUMP_OVERSPEED", "pump_rpm", state.pump_rpm,
                f"< {cfg.pump_rpm_max:.0f} RPM", SeverityLevel.HIGH, 80,
                "Pump RPM reached the configured rated maximum.")
        if state.tank_level_m3 <= cfg.tank_min_m3 + (cfg.tank_max_m3 - cfg.tank_min_m3) * 0.10:
            add("PHYS_TANK_LOW", "tank_level_m3", state.tank_level_m3,
                f"> {cfg.tank_min_m3 + (cfg.tank_max_m3 - cfg.tank_min_m3) * 0.10:.1f} m³", SeverityLevel.MEDIUM, 50,
                "Tank level is in the configured low-level safety zone.")
        if self._previous is not None:
            pressure_step = abs(state.pressure_bar - self._previous.pressure_bar)
            if pressure_step > max(0.5, cfg.pressure_max_bar * 0.35):
                add("PHYS_PRESSURE_RATE", "pressure_bar", pressure_step,
                    f"change <= {max(0.5, cfg.pressure_max_bar * 0.35):.2f} bar/tick", SeverityLevel.MEDIUM, 55,
                    "Pressure changed faster than the configured physical plausibility limit.")

        active = {item.rule_id for item in found}
        now = time.monotonic()
        emit: list[PhysicsViolation] = []
        for item in found:
            last = self._last_emitted.get(item.rule_id)
            if item.rule_id not in self._active_rules or last is None or now - last >= self._cooldown_sec:
                emit.append(item)
                self._last_emitted[item.rule_id] = now
        self._active_rules = active
        self._previous = state
        return emit
