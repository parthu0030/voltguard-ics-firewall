"""
VoltGuard — Modbus Command-Level Security Rules
================================================
Evaluates the Modbus function code and payload for command-level
security concerns, independent of the physical state.

Rules defined here:
  - ``READ_OPERATION``               — Any read FC (low risk, SAFE baseline)
  - ``WRITE_COIL_SUSPICIOUS_ADDR``   — Write coil to an address outside normal range
  - ``EXCESSIVE_REGISTER_WRITE``     — Write quantity exceeds configured safe maximum
  - ``WRITE_TO_CRITICAL_REGISTER``   — Write to a register in the monitored range
  - ``PUMP_CONTROL_WRITE``           — Write to coil/register that controls the pump

All rules are deterministic and depend only on the parsed packet and
``DecisionConfig``.  No physics state is required here.

Usage::

    from src.decision_engine.rules.modbus_rules import evaluate_modbus_rules

    reasons = evaluate_modbus_rules(packet, decision_config)
"""

from __future__ import annotations

from typing import Optional

from src.decision_engine.decision_config import DecisionConfig
from src.decision_engine.models import DecisionReason, SeverityLevel
from src.parser.packet_models import FullPacket, ModbusFunctionCode


# ---------------------------------------------------------------------------
# Modbus Register Semantics
# ---------------------------------------------------------------------------
# In this simulated plant the register/coil map is:
#   Coil   0x0000  — Pump ON/OFF
#   Coil   0x00AC  — Valve actuator
#   Reg    0x0000  — Valve position setpoint (0–1000, scaled /1000)
#   Reg    0x0001  — Pump speed setpoint (RPM)
#   Reg    0x0064 (100) — Pressure override (bar × 10)
# These are representative; the decision engine uses configurable ranges.

_PUMP_COIL_ADDRESS: int = 0x0000   # Coil address for pump control
_VALVE_COIL_ADDRESS: int = 0x00AC  # Coil address for valve actuator
_PUMP_REGISTER_ADDRESS: int = 0x0001  # Holding register for pump RPM setpoint


# ---------------------------------------------------------------------------
# Individual Modbus Rules
# ---------------------------------------------------------------------------

def _rule_read_operation(packet: FullPacket) -> Optional[DecisionReason]:
    """
    READ_OPERATION — packet is a read request (FC 0x01 or 0x03).

    Read operations are the safest class of Modbus command.  They cannot
    directly alter physical state.  This rule adds a minimal (5-point)
    positive signal to confirm a read was evaluated.

    Risk: 5 points (SAFE).
    """
    if packet.modbus is None:
        return None

    read_fcs = {ModbusFunctionCode.READ_COILS, ModbusFunctionCode.READ_HOLDING_REGISTERS}
    if packet.modbus.function_code not in read_fcs:
        return None

    return DecisionReason(
        rule_id="READ_OPERATION",
        description=(
            f"Read operation detected: {packet.modbus.function_name} "
            f"(FC 0x{packet.modbus.function_code.value:02X}). "
            f"Read operations cannot directly modify physical state."
        ),
        risk_contribution=5,
        severity=SeverityLevel.SAFE,
        metadata={
            "function_code": packet.modbus.function_code.value,
            "register_address": packet.modbus.register_address,
            "quantity": packet.modbus.quantity,
        },
    )


def _rule_excessive_register_write(
    packet: FullPacket, cfg: DecisionConfig
) -> Optional[DecisionReason]:
    """
    EXCESSIVE_REGISTER_WRITE — Write Multiple Registers (FC 0x10) attempts
    to write more registers than ``max_registers_per_write``.

    Bulk writes are unusual in a well-operated SCADA environment and may
    indicate an attempt to mass-reconfigure the PLC.

    Risk: 45 points (MEDIUM).
    """
    if packet.modbus is None:
        return None
    if packet.modbus.function_code != ModbusFunctionCode.WRITE_MULTIPLE_REGISTERS:
        return None

    quantity = packet.modbus.quantity
    if quantity is None or quantity <= cfg.max_registers_per_write:
        return None

    return DecisionReason(
        rule_id="EXCESSIVE_REGISTER_WRITE",
        description=(
            f"Write Multiple Registers requests writing {quantity} registers, "
            f"which exceeds the configured safe maximum of "
            f"{cfg.max_registers_per_write}. "
            f"Bulk writes are unusual in normal SCADA operations."
        ),
        risk_contribution=45,
        severity=SeverityLevel.MEDIUM,
        metadata={
            "quantity":    quantity,
            "max_allowed": cfg.max_registers_per_write,
            "address":     packet.modbus.register_address,
        },
    )


def _rule_write_to_critical_register(
    packet: FullPacket, cfg: DecisionConfig
) -> Optional[DecisionReason]:
    """
    WRITE_TO_CRITICAL_REGISTER — Write Single/Multiple Register targets an
    address in the configured suspicious range.

    Not all writes are dangerous, but writes to registers that control
    pump speed, valve position, or pressure limits deserve closer scrutiny.

    Risk: 30 points (LOW).
    """
    if packet.modbus is None:
        return None

    write_fcs = {
        ModbusFunctionCode.WRITE_SINGLE_REGISTER,
        ModbusFunctionCode.WRITE_MULTIPLE_REGISTERS,
    }
    if packet.modbus.function_code not in write_fcs:
        return None

    addr = packet.modbus.register_address
    if addr is None:
        return None

    if not (cfg.suspicious_register_min <= addr <= cfg.suspicious_register_max):
        return None

    # FC 0x06: also check the actual written value for sanity
    value = packet.modbus.register_value
    description = (
        f"Write operation targets register 0x{addr:04X} ({addr}) "
        f"in the monitored range [{cfg.suspicious_register_min}, "
        f"{cfg.suspicious_register_max}]."
    )
    if value is not None:
        description += f" Requested value: {value} (0x{value:04X})."

    return DecisionReason(
        rule_id="WRITE_TO_CRITICAL_REGISTER",
        description=description,
        risk_contribution=30,
        severity=SeverityLevel.LOW,
        metadata={
            "register_address": addr,
            "value":            value,
            "function_code":    packet.modbus.function_code.value,
        },
    )


def _rule_pump_control_write(packet: FullPacket) -> Optional[DecisionReason]:
    """
    PUMP_CONTROL_WRITE — Write Single Coil (FC 0x05) or Write Single Register
    (FC 0x06) targets the pump control coil or register address.

    Pump state changes are the highest-impact Modbus write in this plant.
    They deserve an elevated risk signal even when they are legitimate.

    Risk: 35 points (MEDIUM).
    """
    if packet.modbus is None:
        return None

    write_fcs = {
        ModbusFunctionCode.WRITE_SINGLE_COIL,
        ModbusFunctionCode.WRITE_SINGLE_REGISTER,
    }
    if packet.modbus.function_code not in write_fcs:
        return None

    addr = packet.modbus.register_address
    if addr is None:
        return None

    is_pump = (
        packet.modbus.function_code == ModbusFunctionCode.WRITE_SINGLE_COIL
        and addr == _PUMP_COIL_ADDRESS
    ) or (
        packet.modbus.function_code == ModbusFunctionCode.WRITE_SINGLE_REGISTER
        and addr == _PUMP_REGISTER_ADDRESS
    )

    if not is_pump:
        return None

    value = packet.modbus.register_value
    action = "ON" if (value and value >= 0xFF00) else "OFF"

    return DecisionReason(
        rule_id="PUMP_CONTROL_WRITE",
        description=(
            f"Write command targets the pump control address "
            f"(0x{addr:04X}). Requested state: {action}. "
            f"Pump state changes are high-impact operations."
        ),
        risk_contribution=35,
        severity=SeverityLevel.MEDIUM,
        metadata={
            "address":       addr,
            "value":         value,
            "function_code": packet.modbus.function_code.value,
        },
    )


def _rule_valve_control_write(packet: FullPacket) -> Optional[DecisionReason]:
    """
    VALVE_CONTROL_WRITE — Write Single Coil (FC 0x05) targets the valve
    actuator coil address.

    Valve changes alter flow and pressure; they require scrutiny especially
    when the current physics state is near a limit.

    Risk: 25 points (LOW).
    """
    if packet.modbus is None:
        return None
    if packet.modbus.function_code != ModbusFunctionCode.WRITE_SINGLE_COIL:
        return None

    addr = packet.modbus.register_address
    if addr != _VALVE_COIL_ADDRESS:
        return None

    value = packet.modbus.register_value
    action = "OPEN" if (value is not None and value == 0xFF00) else "CLOSE"

    return DecisionReason(
        rule_id="VALVE_CONTROL_WRITE",
        description=(
            f"Write command targets the valve actuator address "
            f"(0x{addr:04X}). Requested action: {action}. "
            f"Valve operations affect system pressure and flow."
        ),
        risk_contribution=25,
        severity=SeverityLevel.LOW,
        metadata={
            "address":       addr,
            "value":         value,
            "function_code": packet.modbus.function_code.value,
        },
    )


# ---------------------------------------------------------------------------
# Public Evaluator
# ---------------------------------------------------------------------------

def evaluate_modbus_rules(
    packet: FullPacket, cfg: DecisionConfig
) -> list[DecisionReason]:
    """
    Evaluate all Modbus command-level security rules.

    Called after protocol rules pass; only makes sense when the Modbus
    layer is present and valid.

    Args:
        packet: The ``FullPacket`` with a valid Modbus layer.
        cfg:    ``DecisionConfig`` providing Modbus thresholds.

    Returns:
        List of triggered ``DecisionReason`` objects.  Empty if all is safe.
    """
    if packet.modbus is None:
        return []

    reasons: list[DecisionReason] = []

    for rule_fn in (
        _rule_read_operation,
        lambda p: _rule_excessive_register_write(p, cfg),
        lambda p: _rule_write_to_critical_register(p, cfg),
        _rule_pump_control_write,
        _rule_valve_control_write,
    ):
        reason = rule_fn(packet)
        if reason is not None:
            reasons.append(reason)

    return reasons
