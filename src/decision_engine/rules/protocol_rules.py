"""
VoltGuard — Protocol-Level Security Rules
==========================================
Evaluates the parsed ``FullPacket`` for structural and protocol-level
violations *before* any Modbus or physics analysis takes place.

Rules defined here:
  - ``INVALID_PACKET``        — Parse failed (malformed, truncated, etc.)
  - ``INVALID_PROTOCOL_ID``   — MBAP Protocol ID ≠ 0x0000
  - ``UNSUPPORTED_FC``        — Function code not in the supported set
  - ``MISSING_MODBUS_LAYER``  — Packet has no Modbus layer (e.g. pure TCP)

Each rule returns a ``DecisionReason`` if triggered or ``None`` if not.
The public function ``evaluate_protocol_rules()`` aggregates all results.

Usage::

    from src.decision_engine.rules.protocol_rules import evaluate_protocol_rules

    reasons = evaluate_protocol_rules(packet)
"""

from __future__ import annotations

from typing import Optional

from src.decision_engine.models import DecisionReason, SeverityLevel
from src.parser.packet_models import FullPacket, ParseStatus


# ---------------------------------------------------------------------------
# Individual Protocol Rules
# ---------------------------------------------------------------------------

def _rule_invalid_packet(packet: FullPacket) -> Optional[DecisionReason]:
    """
    INVALID_PACKET — the parser reported a non-VALID parse status.

    Covers: MALFORMED, TRUNCATED, INVALID_LENGTH, INVALID_PROTOCOL_ID,
    UNSUPPORTED_FC.  Each is handled by a more specific rule below;
    this acts as the catch-all for anything else.

    Risk: 80 points (HIGH).  A malformed packet is never normal traffic.
    """
    if packet.parse_status == ParseStatus.VALID:
        return None

    # Map specific statuses to more precise rules — they add their own reasons.
    if packet.parse_status in (
        ParseStatus.INVALID_PROTOCOL_ID,
        ParseStatus.UNSUPPORTED_FC,
    ):
        return None  # handled by dedicated rules below

    description = (
        f"Packet failed to parse: status={packet.parse_status.value}"
        + (f" | {packet.error_message}" if packet.error_message else "")
    )
    return DecisionReason(
        rule_id="INVALID_PACKET",
        description=description,
        risk_contribution=80,
        severity=SeverityLevel.HIGH,
        metadata={
            "parse_status": packet.parse_status.value,
            "error":        packet.error_message,
        },
    )


def _rule_invalid_protocol_id(packet: FullPacket) -> Optional[DecisionReason]:
    """
    INVALID_PROTOCOL_ID — MBAP Protocol ID field is not 0x0000.

    Modbus TCP mandates Protocol ID = 0x0000.  Any other value is either a
    protocol violation or deliberate evasion.

    Risk: 70 points (HIGH).
    """
    if packet.parse_status != ParseStatus.INVALID_PROTOCOL_ID:
        return None

    return DecisionReason(
        rule_id="INVALID_PROTOCOL_ID",
        description=(
            "Modbus MBAP header contains an invalid Protocol ID "
            "(expected 0x0000). Possible protocol evasion or misconfigured device."
        ),
        risk_contribution=70,
        severity=SeverityLevel.HIGH,
        metadata={"parse_status": packet.parse_status.value},
    )


def _rule_unsupported_function_code(packet: FullPacket) -> Optional[DecisionReason]:
    """
    UNSUPPORTED_FC — Modbus function code is not in the VoltGuard allowlist.

    Only FC 0x01, 0x03, 0x05, 0x06, 0x10 are expected in this plant.
    Any other code is highly suspicious.

    Risk: 60 points (MEDIUM).
    """
    if packet.parse_status != ParseStatus.UNSUPPORTED_FC:
        return None

    return DecisionReason(
        rule_id="UNSUPPORTED_FC",
        description=(
            f"Modbus function code is not in the supported set "
            f"(FC 0x01, 0x03, 0x05, 0x06, 0x10). "
            f"Error: {packet.error_message}"
        ),
        risk_contribution=60,
        severity=SeverityLevel.MEDIUM,
        metadata={
            "parse_status": packet.parse_status.value,
            "error":        packet.error_message,
        },
    )


def _rule_missing_modbus_layer(packet: FullPacket) -> Optional[DecisionReason]:
    """
    MISSING_MODBUS_LAYER — the packet parsed successfully at lower layers
    but produced no Modbus layer (e.g. empty TCP payload to port 502).

    Risk: 30 points (LOW).  Unusual but not necessarily malicious.
    """
    if packet.parse_status != ParseStatus.VALID:
        return None  # Already flagged by other rules
    if packet.modbus is not None:
        return None  # Modbus layer is present

    return DecisionReason(
        rule_id="MISSING_MODBUS_LAYER",
        description=(
            "Packet parsed successfully but contains no Modbus TCP layer. "
            "Unexpected on a Modbus port."
        ),
        risk_contribution=30,
        severity=SeverityLevel.LOW,
        metadata={},
    )


# ---------------------------------------------------------------------------
# Public Evaluator
# ---------------------------------------------------------------------------

def evaluate_protocol_rules(packet: FullPacket) -> list[DecisionReason]:
    """
    Evaluate all protocol-level security rules against a parsed packet.

    This is called first in the pipeline — protocol violations are evaluated
    before any Modbus or physics analysis, since further analysis is
    meaningless if the packet cannot be trusted.

    Args:
        packet: The ``FullPacket`` produced by ``ProtocolParser``.

    Returns:
        List of triggered ``DecisionReason`` objects.  Empty if all is safe.
    """
    reasons: list[DecisionReason] = []

    for rule_fn in (
        _rule_invalid_packet,
        _rule_invalid_protocol_id,
        _rule_unsupported_function_code,
        _rule_missing_modbus_layer,
    ):
        reason = rule_fn(packet)
        if reason is not None:
            reasons.append(reason)

    return reasons
