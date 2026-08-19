"""
VoltGuard — Physics-Aware Safety Rules
========================================
Evaluates the *current physical system state* (from the Day 3 physics
engine) against configured safety limits to determine whether the
observed Modbus command is safe to execute.

Rules defined here:
  - ``PRESSURE_LIMIT_EXCEEDED``       — Current pressure ≥ 95% of max
  - ``PRESSURE_APPROACHING_LIMIT``    — Current pressure ≥ 80% of max
  - ``UNSAFE_VALVE_OPEN_PUMP_OFF``    — Valve open but pump off (impossible flow intent)
  - ``FLOW_LIMIT_EXCEEDED``           — Current flow ≥ warning fraction of max
  - ``TEMPERATURE_APPROACHING_LIMIT`` — Current temperature ≥ warning fraction of max
  - ``WRITE_WOULD_EXCEED_PRESSURE``   — Predicted post-write pressure > safe max
  - ``WRITE_WHILE_UNSAFE``            — Any write command while physics is unsafe

Key design principle:
  These rules use the *current* ``SystemState`` snapshot, not a simulation
  of the future state.  They flag commands that are dangerous *given* the
  current conditions, following the real-world ICS security model.

Usage::

    from src.decision_engine.rules.physics_rules import evaluate_physics_rules

    reasons = evaluate_physics_rules(packet, state, physics_cfg, decision_cfg)
"""

from __future__ import annotations

from typing import Optional

from src.decision_engine.decision_config import DecisionConfig
from src.decision_engine.models import DecisionReason, SeverityLevel
from src.parser.packet_models import FullPacket, ModbusFunctionCode
from src.physics.physics_config import PhysicsConfig
from src.physics.system_state import SystemState


# ---------------------------------------------------------------------------
# Helper: Is this a write command?
# ---------------------------------------------------------------------------

_WRITE_FCS = frozenset({
    ModbusFunctionCode.WRITE_SINGLE_COIL,
    ModbusFunctionCode.WRITE_SINGLE_REGISTER,
    ModbusFunctionCode.WRITE_MULTIPLE_REGISTERS,
})


def _is_write(packet: FullPacket) -> bool:
    """Return True if the packet carries a write-type Modbus command."""
    return (
        packet.modbus is not None
        and packet.modbus.function_code in _WRITE_FCS
    )


# ---------------------------------------------------------------------------
# Individual Physics Rules
# ---------------------------------------------------------------------------

def _rule_pressure_limit_exceeded(
    state: SystemState,
    physics_cfg: PhysicsConfig,
    decision_cfg: DecisionConfig,
) -> Optional[DecisionReason]:
    """
    PRESSURE_LIMIT_EXCEEDED — the current pipeline pressure is at or above
    ``pressure_critical_fraction × pressure_max_bar``.

    Any write command in this state is dangerous because it could push
    the system further above the safety limit.

    Risk: 85 points (CRITICAL).
    """
    threshold = physics_cfg.pressure_max_bar * decision_cfg.pressure_critical_fraction
    if state.pressure_bar < threshold:
        return None

    return DecisionReason(
        rule_id="PRESSURE_LIMIT_EXCEEDED",
        description=(
            f"Current pipeline pressure {state.pressure_bar:.2f} bar "
            f"is at or above the critical threshold "
            f"({decision_cfg.pressure_critical_fraction:.0%} of max "
            f"{physics_cfg.pressure_max_bar:.2f} bar = {threshold:.2f} bar). "
            f"Any write operation in this state risks a safety event."
        ),
        risk_contribution=85,
        severity=SeverityLevel.CRITICAL,
        metadata={
            "current_pressure_bar": state.pressure_bar,
            "threshold_bar":        round(threshold, 3),
            "max_bar":              physics_cfg.pressure_max_bar,
        },
    )


def _rule_pressure_approaching_limit(
    state: SystemState,
    physics_cfg: PhysicsConfig,
    decision_cfg: DecisionConfig,
) -> Optional[DecisionReason]:
    """
    PRESSURE_APPROACHING_LIMIT — the current pressure is between the
    warning fraction and the critical fraction of the safe maximum.

    Risk: 40 points (MEDIUM).
    """
    warn_threshold  = physics_cfg.pressure_max_bar * decision_cfg.pressure_warning_fraction
    crit_threshold  = physics_cfg.pressure_max_bar * decision_cfg.pressure_critical_fraction

    if not (warn_threshold <= state.pressure_bar < crit_threshold):
        return None

    return DecisionReason(
        rule_id="PRESSURE_APPROACHING_LIMIT",
        description=(
            f"Current pipeline pressure {state.pressure_bar:.2f} bar "
            f"is approaching the safety limit "
            f"(warning threshold: {warn_threshold:.2f} bar, "
            f"max: {physics_cfg.pressure_max_bar:.2f} bar)."
        ),
        risk_contribution=40,
        severity=SeverityLevel.MEDIUM,
        metadata={
            "current_pressure_bar": state.pressure_bar,
            "warning_threshold_bar": round(warn_threshold, 3),
            "max_bar":              physics_cfg.pressure_max_bar,
        },
    )


def _rule_unsafe_valve_open_pump_off(
    packet: FullPacket,
    state: SystemState,
) -> Optional[DecisionReason]:
    """
    UNSAFE_VALVE_OPEN_PUMP_OFF — the valve is open (≥ 10%) but the pump is
    off, and a write command is being sent.

    In a real plant this could indicate an attempt to drain the pipeline
    without the pump running, or a misconfigured command sequence.

    Risk: 50 points (HIGH).  Only triggered for write operations.
    """
    if not _is_write(packet):
        return None

    # Rule requires: valve is meaningfully open AND pump is off
    if state.valve_position < 0.10:
        return None
    if state.pump_on:
        return None

    return DecisionReason(
        rule_id="UNSAFE_VALVE_OPEN_PUMP_OFF",
        description=(
            f"The valve is open at {state.valve_position:.1%} "
            f"but the pump is OFF. A write command in this state "
            f"could create an uncontrolled pressure loss or "
            f"impossible flow condition."
        ),
        risk_contribution=50,
        severity=SeverityLevel.HIGH,
        metadata={
            "valve_position": state.valve_position,
            "pump_on":        state.pump_on,
        },
    )


def _rule_flow_limit_exceeded(
    state: SystemState,
    physics_cfg: PhysicsConfig,
    decision_cfg: DecisionConfig,
) -> Optional[DecisionReason]:
    """
    FLOW_LIMIT_EXCEEDED — the current flow rate is ≥ ``flow_warning_fraction``
    of the configured maximum.

    Excessive flow can cause cavitation, water hammer, and pipeline stress.

    Risk: 45 points (MEDIUM).
    """
    threshold = physics_cfg.flow_max_lps * decision_cfg.flow_warning_fraction
    if state.flow_lps < threshold:
        return None

    return DecisionReason(
        rule_id="FLOW_LIMIT_EXCEEDED",
        description=(
            f"Current flow rate {state.flow_lps:.2f} L/s "
            f"is approaching or exceeding the safe maximum "
            f"({decision_cfg.flow_warning_fraction:.0%} of "
            f"{physics_cfg.flow_max_lps:.2f} L/s = {threshold:.2f} L/s)."
        ),
        risk_contribution=45,
        severity=SeverityLevel.MEDIUM,
        metadata={
            "current_flow_lps": state.flow_lps,
            "threshold_lps":    round(threshold, 3),
            "max_lps":          physics_cfg.flow_max_lps,
        },
    )


def _rule_temperature_approaching_limit(
    state: SystemState,
    physics_cfg: PhysicsConfig,
    decision_cfg: DecisionConfig,
) -> Optional[DecisionReason]:
    """
    TEMPERATURE_APPROACHING_LIMIT — the current fluid temperature is ≥
    ``temp_warning_fraction`` of the configured maximum.

    Elevated temperatures can indicate pump overload, heat exchanger failure,
    or incorrect operating conditions.

    Risk: 35 points (MEDIUM).
    """
    threshold = physics_cfg.temp_max_celsius * decision_cfg.temp_warning_fraction
    if state.temperature_celsius < threshold:
        return None

    return DecisionReason(
        rule_id="TEMPERATURE_APPROACHING_LIMIT",
        description=(
            f"Current temperature {state.temperature_celsius:.1f} °C "
            f"is approaching or exceeding the warning threshold "
            f"({decision_cfg.temp_warning_fraction:.0%} of "
            f"{physics_cfg.temp_max_celsius:.1f} °C = {threshold:.1f} °C)."
        ),
        risk_contribution=35,
        severity=SeverityLevel.MEDIUM,
        metadata={
            "current_temp_celsius": state.temperature_celsius,
            "threshold_celsius":    round(threshold, 2),
            "max_celsius":          physics_cfg.temp_max_celsius,
        },
    )


def _rule_write_would_exceed_pressure(
    packet: FullPacket,
    state: SystemState,
    physics_cfg: PhysicsConfig,
) -> Optional[DecisionReason]:
    """
    WRITE_WOULD_EXCEED_PRESSURE — a valve open write command combined with
    the current pump RPM would predict a pressure that exceeds the safe max.

    Physics model:
        predicted_flow = pressure_bar × valve_target × flow_coefficient
        (We use current pressure as a proxy since a full simulation step
         would require a full tick; this is a fast pre-flight check.)

    Triggered only for WRITE_SINGLE_COIL commands that open the valve
    (value = 0xFF00) when current pressure is already near the limit.

    Risk: 90 points (CRITICAL).
    """
    if not _is_write(packet):
        return None
    if packet.modbus is None:
        return None

    # Only applies to valve-open coil writes
    if packet.modbus.function_code != ModbusFunctionCode.WRITE_SINGLE_COIL:
        return None

    value = packet.modbus.register_value
    if value is None or value != 0xFF00:  # 0xFF00 = coil ON = open valve
        return None

    # If pressure is already at or above the absolute max, the valve open
    # command would maintain or worsen the over-pressure condition.
    if state.pressure_bar < physics_cfg.pressure_max_bar:
        return None

    return DecisionReason(
        rule_id="WRITE_WOULD_EXCEED_PRESSURE",
        description=(
            f"Opening the valve (coil 0xFF00) when the current pressure is "
            f"{state.pressure_bar:.2f} bar (at or above the safety limit of "
            f"{physics_cfg.pressure_max_bar:.2f} bar) would maintain or "
            f"worsen an over-pressure condition."
        ),
        risk_contribution=90,
        severity=SeverityLevel.CRITICAL,
        metadata={
            "current_pressure_bar": state.pressure_bar,
            "max_bar":              physics_cfg.pressure_max_bar,
            "valve_command":        "OPEN",
        },
    )


def _rule_write_while_unsafe(
    packet: FullPacket,
    state: SystemState,
    physics_cfg: PhysicsConfig,
) -> Optional[DecisionReason]:
    """
    WRITE_WHILE_UNSAFE — any write command issued when the current physics
    state has one or more active warnings (from ``SystemState.has_warnings()``).

    This is a catch-all for write commands during degraded physical conditions.

    Risk: 55 points (HIGH).
    """
    if not _is_write(packet):
        return None

    warnings = state.has_warnings(physics_cfg)
    if not warnings:
        return None

    warnings_text = "; ".join(warnings[:3])  # limit to first 3 for readability
    return DecisionReason(
        rule_id="WRITE_WHILE_UNSAFE",
        description=(
            f"Write command issued while the physical system has active "
            f"warnings: {warnings_text}. Writing during degraded conditions "
            f"may worsen the situation."
        ),
        risk_contribution=55,
        severity=SeverityLevel.HIGH,
        metadata={
            "active_warnings": warnings,
            "warning_count":   len(warnings),
        },
    )


# ---------------------------------------------------------------------------
# Public Evaluator
# ---------------------------------------------------------------------------

def evaluate_physics_rules(
    packet: FullPacket,
    state: SystemState,
    physics_cfg: PhysicsConfig,
    decision_cfg: DecisionConfig,
) -> list[DecisionReason]:
    """
    Evaluate all physics-aware safety rules against the current system state.

    These rules integrate the Day 3 physics engine state into the security
    decision pipeline.  They fire based on the *observed* physical state,
    not a simulated future — consistent with how real ICS security monitors
    operate (they observe, not predict, within a single decision cycle).

    Args:
        packet:       Parsed ``FullPacket`` (needed for write-command rules).
        state:        Current ``SystemState`` from the physics engine.
        physics_cfg:  ``PhysicsConfig`` with all physical limits.
        decision_cfg: ``DecisionConfig`` with fraction thresholds.

    Returns:
        List of triggered ``DecisionReason`` objects.  Empty if all is safe.
    """
    reasons: list[DecisionReason] = []

    for rule_fn in (
        lambda: _rule_pressure_limit_exceeded(state, physics_cfg, decision_cfg),
        lambda: _rule_pressure_approaching_limit(state, physics_cfg, decision_cfg),
        lambda: _rule_unsafe_valve_open_pump_off(packet, state),
        lambda: _rule_flow_limit_exceeded(state, physics_cfg, decision_cfg),
        lambda: _rule_temperature_approaching_limit(state, physics_cfg, decision_cfg),
        lambda: _rule_write_would_exceed_pressure(packet, state, physics_cfg),
        lambda: _rule_write_while_unsafe(packet, state, physics_cfg),
    ):
        reason = rule_fn()
        if reason is not None:
            reasons.append(reason)

    return reasons
