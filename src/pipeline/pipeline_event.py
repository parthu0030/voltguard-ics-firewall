"""
VoltGuard — Pipeline Event
============================
Defines ``PipelineEvent``, the canonical security event that the pipeline
emits after processing each packet through the full Day 2–4 stack.

``PipelineEvent`` is the single data structure the UI consumes to display:
  - Live packet counters (captured / allowed / alerted / blocked)
  - Per-packet risk score and decision badge
  - Security event table with timestamp, source, protocol, FC, reason

It is constructed from the combination of:
  - ``FullPacket``             (Day 2 parser output — provides network metadata)
  - ``SecurityDecisionResult`` (Day 4 decision output — provides risk+decision)

Design
------
- Plain Python dataclass — no Qt, no database dependency.
- Safe to pass across threads as an immutable snapshot.
- Serialisable to dict for logging and eventual DB persistence.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Optional

from src.decision_engine.models import DecisionType, SecurityDecisionResult, SeverityLevel
from src.parser.packet_models import FullPacket, ParseStatus

if TYPE_CHECKING:
    from src.policy.models import EnforcementResult


@dataclass
class PipelineEvent:
    """
    Canonical security event produced by ``PacketPipeline`` after every
    packet that reaches the decision engine.

    Attributes:
        timestamp:         ISO-8601 UTC time the decision was made.
        source_ip:         Source IP address (empty string if unknown).
        destination_ip:    Destination IP address (empty string if unknown).
        source_port:       Source TCP port (0 if unknown).
        destination_port:  Destination TCP port (0 if unknown).
        protocol:          Protocol label (e.g. ``"Modbus TCP"``).
        modbus_function:   Modbus function code name (empty if not Modbus).
        modbus_fc_int:     Integer function code (None if not Modbus).
        decision:          ALLOW / ALERT / BLOCK decision string.
        risk_score:        Integer risk score in [0, 100].
        risk_level:        Severity string (SAFE / LOW / MEDIUM / HIGH / CRITICAL).
        reason:            Human-readable explanation of the decision.
        triggered_rules:   List of rule IDs that fired during evaluation.
        parse_status:      Raw parser outcome (VALID, MALFORMED, etc.).
        parse_error:       Parser error message (empty if parse succeeded).
        is_full_frame:     ``True`` if the packet was a complete Ethernet frame.
    """

    timestamp: str
    source_ip: str
    destination_ip: str
    source_port: int
    destination_port: int
    protocol: str
    modbus_function: str
    modbus_fc_int: Optional[int]
    decision: str
    risk_score: int
    risk_level: str
    reason: str
    triggered_rules: list[str] = field(default_factory=list)
    parse_status: str = ParseStatus.VALID.value
    parse_error: str = ""
    is_full_frame: bool = False
    # ── Day 6: Policy enforcement fields (optional) ──────────────────────
    # Populated by PacketPipeline after the Policy Engine runs.
    # None when the Policy Engine has not been configured.
    policy_id: Optional[str] = None
    policy_name: Optional[str] = None
    policy_action: Optional[str] = None       # PolicyAction value: ALLOW/ALERT/BLOCK
    enforcement_reason: Optional[str] = None  # Human-readable policy reason

    # ------------------------------------------------------------------
    # Factory methods
    # ------------------------------------------------------------------

    @classmethod
    def from_decision(
        cls,
        result: SecurityDecisionResult,
        packet: FullPacket,
        enforcement: Optional["EnforcementResult"] = None,
    ) -> "PipelineEvent":
        """
        Construct a ``PipelineEvent`` from a ``SecurityDecisionResult`` and
        the corresponding ``FullPacket``.

        Args:
            result: Decision engine output with risk score, decision, reason.
            packet: Parser output with network-layer metadata.

        Returns:
            A fully populated ``PipelineEvent``.
        """
        # Extract TCP ports if the TCP layer was decoded
        src_port = packet.tcp.src_port if packet.tcp else 0
        dst_port = packet.tcp.dst_port if packet.tcp else 0

        # Determine protocol label
        protocol = "Modbus TCP" if packet.modbus is not None else "TCP/IP"

        # Use policy action as the effective decision when available
        effective_decision = (
            enforcement.final_action.value
            if enforcement is not None
            else result.decision.value
        )

        return cls(
            timestamp=result.timestamp,
            source_ip=result.src_ip or packet.src_ip or "unknown",
            destination_ip=result.dst_ip or packet.dst_ip or "unknown",
            source_port=src_port,
            destination_port=dst_port,
            protocol=protocol,
            modbus_function=result.function_name or "",
            modbus_fc_int=result.function_code,
            decision=effective_decision,
            risk_score=result.risk_score,
            risk_level=result.severity.value,
            reason=result.reason,
            triggered_rules=list(result.triggered_rules),
            parse_status=packet.parse_status.value,
            parse_error=packet.error_message,
            is_full_frame=packet.ethernet is not None,
            policy_id=enforcement.matched_policy_id if enforcement else None,
            policy_name=enforcement.matched_policy_name if enforcement else None,
            policy_action=enforcement.final_action.value if enforcement else None,
            enforcement_reason=enforcement.reason if enforcement else None,
        )

    @classmethod
    def from_parse_failure(
        cls,
        packet: FullPacket,
        timestamp: str,
    ) -> "PipelineEvent":
        """
        Construct a ``PipelineEvent`` for a packet that failed parsing.

        These events are logged but do NOT go through the decision engine.
        They represent malformed / unsupported / truncated frames.

        Args:
            packet:    The ``FullPacket`` with a non-VALID parse status.
            timestamp: ISO-8601 UTC timestamp for this event.

        Returns:
            A ``PipelineEvent`` marked as a parse failure with ALLOW decision
            (failed packets are logged but not blocked by default — they never
            reach a controlled device anyway).
        """
        return cls(
            timestamp=timestamp,
            source_ip=packet.src_ip or "unknown",
            destination_ip=packet.dst_ip or "unknown",
            source_port=0,
            destination_port=0,
            protocol="Unknown",
            modbus_function="",
            modbus_fc_int=None,
            decision=DecisionType.ALLOW.value,
            risk_score=0,
            risk_level=SeverityLevel.SAFE.value,
            reason=f"Parse failed: {packet.error_message or packet.parse_status.value}",
            triggered_rules=[],
            parse_status=packet.parse_status.value,
            parse_error=packet.error_message,
            is_full_frame=False,
        )

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict[str, Any]:
        """
        Serialise the event to a plain dictionary.

        Returns:
            Flat dict suitable for JSON serialisation, logging, or DB storage.
        """
        return {
            "timestamp":          self.timestamp,
            "source_ip":          self.source_ip,
            "destination_ip":     self.destination_ip,
            "source_port":        self.source_port,
            "destination_port":   self.destination_port,
            "protocol":           self.protocol,
            "modbus_function":    self.modbus_function,
            "modbus_fc_int":      self.modbus_fc_int,
            "decision":           self.decision,
            "risk_score":         self.risk_score,
            "risk_level":         self.risk_level,
            "reason":             self.reason,
            "triggered_rules":    self.triggered_rules,
            "parse_status":       self.parse_status,
            "parse_error":        self.parse_error,
            "is_full_frame":      self.is_full_frame,
            # Day 6 policy fields
            "policy_id":          self.policy_id,
            "policy_name":        self.policy_name,
            "policy_action":      self.policy_action,
            "enforcement_reason": self.enforcement_reason,
        }

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    @property
    def is_blocked(self) -> bool:
        """``True`` if the decision is BLOCK."""
        return self.decision == DecisionType.BLOCK.value

    @property
    def is_alerted(self) -> bool:
        """``True`` if the decision is ALERT."""
        return self.decision == DecisionType.ALERT.value

    @property
    def is_allowed(self) -> bool:
        """``True`` if the decision is ALLOW."""
        return self.decision == DecisionType.ALLOW.value

    @property
    def is_parse_failure(self) -> bool:
        """``True`` if the underlying packet failed parsing."""
        return self.parse_status != ParseStatus.VALID.value

    def __repr__(self) -> str:
        return (
            f"<PipelineEvent "
            f"ts={self.timestamp} "
            f"{self.source_ip}→{self.destination_ip} "
            f"FC={self.modbus_function!r} "
            f"decision={self.decision} "
            f"risk={self.risk_score}>"
        )
