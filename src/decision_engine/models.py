"""
VoltGuard — Decision Engine Data Models
=========================================
Defines all strongly-typed dataclasses and enumerations used by the
Day 4 physics-aware decision pipeline.

Design principles:
  - No dependencies on Qt, the database, or the dashboard.
  - Safe to import from tests, the rule engine, or any UI component.
  - All fields are explicitly type-annotated and documented.

Key types:
  - ``DecisionType``          — ALLOW / ALERT / BLOCK
  - ``SeverityLevel``         — SAFE / LOW / MEDIUM / HIGH / CRITICAL
  - ``DecisionReason``        — A single triggered rule + its risk contribution
  - ``RiskAssessment``        — Aggregated score + severity from all reasons
  - ``SecurityDecisionResult``— Full decision output (extends base interface)
  - ``SecurityEvent``         — Audit record written to the decision log

Usage::

    from src.decision_engine.models import (
        DecisionType, SeverityLevel,
        DecisionReason, RiskAssessment,
        SecurityDecisionResult, SecurityEvent,
    )
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Decision Type Enum
# ---------------------------------------------------------------------------

class DecisionType(str, Enum):
    """
    The three possible outcomes of a packet evaluation.

    Values are uppercase strings so they can be stored directly in logs
    and databases without further conversion.
    """
    ALLOW = "ALLOW"   # Packet is safe; forward to the industrial device.
    ALERT = "ALERT"   # Packet is suspicious; allow but raise an alert.
    BLOCK = "BLOCK"   # Packet is dangerous; drop immediately.


# ---------------------------------------------------------------------------
# Severity Level Enum
# ---------------------------------------------------------------------------

class SeverityLevel(str, Enum):
    """
    Risk severity assigned to a decision result.

    Ordered from lowest (SAFE) to highest (CRITICAL) risk.
    """
    SAFE     = "SAFE"
    LOW      = "LOW"
    MEDIUM   = "MEDIUM"
    HIGH     = "HIGH"
    CRITICAL = "CRITICAL"

    @property
    def rank(self) -> int:
        """Return the integer rank of this severity (higher = worse)."""
        return {
            "SAFE": 0, "LOW": 1, "MEDIUM": 2,
            "HIGH": 3, "CRITICAL": 4,
        }[self.value]

    def __lt__(self, other: "SeverityLevel") -> bool:
        return self.rank < other.rank

    def __le__(self, other: "SeverityLevel") -> bool:
        return self.rank <= other.rank

    def __gt__(self, other: "SeverityLevel") -> bool:
        return self.rank > other.rank

    def __ge__(self, other: "SeverityLevel") -> bool:
        return self.rank >= other.rank


# ---------------------------------------------------------------------------
# DecisionReason — A Single Triggered Rule
# ---------------------------------------------------------------------------

@dataclass
class DecisionReason:
    """
    Records that a specific security rule was triggered during evaluation.

    Each ``DecisionReason`` contributes a ``risk_contribution`` (integer,
    0–100) to the total risk score.  The rule engine collects all triggered
    reasons and passes them to the ``RiskScorer``.

    Attributes:
        rule_id:          Unique rule identifier (e.g. ``"PRESSURE_LIMIT_EXCEEDED"``).
        description:      Human-readable explanation of why the rule triggered.
        risk_contribution:Integer risk points contributed by this rule (0–100).
        severity:         Severity associated with this individual rule.
        metadata:         Optional extra context (register address, pressure
                          value, etc.) for log enrichment.
    """
    rule_id: str
    description: str
    risk_contribution: int
    severity: SeverityLevel
    metadata: dict[str, Any] = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            f"<DecisionReason rule={self.rule_id!r} "
            f"severity={self.severity.value} contrib={self.risk_contribution}>"
        )


# ---------------------------------------------------------------------------
# RiskAssessment — Aggregated Score from All Triggered Rules
# ---------------------------------------------------------------------------

@dataclass
class RiskAssessment:
    """
    Aggregated risk score computed from all triggered ``DecisionReason`` objects.

    Produced by ``RiskScorer.calculate()`` and consumed by the engine to
    determine the final ``DecisionType``.

    Attributes:
        risk_score:      Integer score in [0, 100]; 100 is maximum risk.
        severity:        Overall severity derived from the highest triggered rule.
        triggered_rules: Ordered list of rule IDs that contributed to the score.
        reasons:         Full list of ``DecisionReason`` objects (for explanation).
    """
    risk_score: int
    severity: SeverityLevel
    triggered_rules: list[str]
    reasons: list[DecisionReason] = field(default_factory=list)

    @property
    def is_safe(self) -> bool:
        """True if the assessment is entirely safe (risk_score == 0)."""
        return self.risk_score == 0 and self.severity == SeverityLevel.SAFE

    def summary(self) -> str:
        """Return a one-line human-readable summary of the assessment."""
        if not self.triggered_rules:
            return f"Risk={self.risk_score} | Severity=SAFE | No rules triggered"
        rules_str = ", ".join(self.triggered_rules)
        return (
            f"Risk={self.risk_score} | Severity={self.severity.value} | "
            f"Rules=[{rules_str}]"
        )


# ---------------------------------------------------------------------------
# SecurityDecisionResult — Full Decision Output
# ---------------------------------------------------------------------------

@dataclass
class SecurityDecisionResult:
    """
    Complete output of the decision pipeline for a single evaluated packet.

    This is the rich version of the interface-level ``DecisionResult``; it
    carries all the fields required by the Day 4 specification.

    Attributes:
        decision:              Final ALLOW / ALERT / BLOCK verdict.
        risk_score:            Integer risk score in [0, 100].
        severity:              Overall severity level.
        reason:                Human-readable explanation of the decision.
        triggered_rules:       List of rule IDs that contributed to the score.
        timestamp:             ISO-8601 UTC time the decision was made.
        src_ip:                Source IP address of the packet.
        dst_ip:                Destination IP address of the packet.
        function_code:         Modbus function code integer (None if not Modbus).
        function_name:         Modbus function code name (empty if not Modbus).
        relevant_physics_state:Dict snapshot of the physics state used in evaluation.
        all_reasons:           All ``DecisionReason`` objects for detailed inspection.
    """
    decision: DecisionType
    risk_score: int
    severity: SeverityLevel
    reason: str
    triggered_rules: list[str]
    timestamp: str
    src_ip: str
    dst_ip: str
    function_code: Optional[int]
    function_name: str
    relevant_physics_state: dict[str, Any]
    all_reasons: list[DecisionReason] = field(default_factory=list)

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def is_blocked(self) -> bool:
        """True if the decision is BLOCK."""
        return self.decision == DecisionType.BLOCK

    @property
    def is_alerted(self) -> bool:
        """True if the decision is ALERT."""
        return self.decision == DecisionType.ALERT

    @property
    def is_allowed(self) -> bool:
        """True if the decision is ALLOW."""
        return self.decision == DecisionType.ALLOW

    def to_dict(self) -> dict[str, Any]:
        """
        Serialise the result to a plain Python dictionary for logging
        and storage.

        Returns:
            Flat dict with all decision fields.
        """
        return {
            "decision":              self.decision.value,
            "risk_score":            self.risk_score,
            "severity":              self.severity.value,
            "reason":                self.reason,
            "triggered_rules":       self.triggered_rules,
            "timestamp":             self.timestamp,
            "src_ip":                self.src_ip,
            "dst_ip":                self.dst_ip,
            "function_code":         self.function_code,
            "function_name":         self.function_name,
            "relevant_physics_state": self.relevant_physics_state,
        }

    def __repr__(self) -> str:
        return (
            f"<SecurityDecisionResult "
            f"decision={self.decision.value} "
            f"risk={self.risk_score} "
            f"severity={self.severity.value} "
            f"rules={self.triggered_rules}>"
        )


# ---------------------------------------------------------------------------
# SecurityEvent — Audit Record
# ---------------------------------------------------------------------------

@dataclass
class SecurityEvent:
    """
    Full audit record emitted after every decision, suitable for persistence
    in a database or structured log.

    Attributes:
        event_id:     Monotonically increasing integer event identifier.
        timestamp:    ISO-8601 UTC string.
        decision:     Final ALLOW / ALERT / BLOCK verdict.
        risk_score:   Integer score in [0, 100].
        severity:     Overall severity.
        src_ip:       Source IP address.
        dst_ip:       Destination IP address.
        function_code:Modbus FC integer (None if N/A).
        function_name:Modbus FC name string.
        reason:       Human-readable explanation.
        triggered_rules: List of triggered rule ID strings.
        physics_snapshot:Snapshot of the physics state at evaluation time.
    """
    timestamp: str
    decision: DecisionType
    risk_score: int
    severity: SeverityLevel
    src_ip: str
    dst_ip: str
    reason: str
    triggered_rules: list[str]
    physics_snapshot: dict[str, Any]
    function_code: Optional[int] = None
    function_name: str = ""
    event_id: Optional[int] = None

    @staticmethod
    def utc_now() -> str:
        """Return the current UTC time as an ISO-8601 string."""
        return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")

    @classmethod
    def from_result(cls, result: SecurityDecisionResult) -> "SecurityEvent":
        """
        Construct a ``SecurityEvent`` directly from a ``SecurityDecisionResult``.

        Args:
            result: The completed decision result.

        Returns:
            A ``SecurityEvent`` audit record.
        """
        return cls(
            timestamp=result.timestamp,
            decision=result.decision,
            risk_score=result.risk_score,
            severity=result.severity,
            src_ip=result.src_ip,
            dst_ip=result.dst_ip,
            function_code=result.function_code,
            function_name=result.function_name,
            reason=result.reason,
            triggered_rules=list(result.triggered_rules),
            physics_snapshot=dict(result.relevant_physics_state),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dictionary."""
        return {
            "event_id":        self.event_id,
            "timestamp":       self.timestamp,
            "decision":        self.decision.value,
            "risk_score":      self.risk_score,
            "severity":        self.severity.value,
            "src_ip":          self.src_ip,
            "dst_ip":          self.dst_ip,
            "function_code":   self.function_code,
            "function_name":   self.function_name,
            "reason":          self.reason,
            "triggered_rules": self.triggered_rules,
            "physics_snapshot": self.physics_snapshot,
        }
