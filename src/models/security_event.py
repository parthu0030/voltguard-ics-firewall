"""
VoltGuard — Security Event Data Model (Day 7)
==============================================
Defines the strongly-typed ``SecurityEvent`` model representing a canonical,
persisted security inspection outcome from the VoltGuard ICS security pipeline.

Design principles:
  - Pure Python dataclass: No Qt or GUI dependencies.
  - Safe for thread-safe transfer and SQLite persistence.
  - Carries complete audit trail: network metadata, function codes,
    physics/risk scores, winning firewall policy, and final enforcement action.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional

from src.models.app_models import AlertSeverity

if TYPE_CHECKING:
    from src.pipeline.pipeline_event import PipelineEvent
    from src.policy.models import EnforcementResult


def _utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")


@dataclass
class SecurityEvent:
    """
    Canonical, structured security event model.

    Attributes:
        event_id:             Globally unique event identifier (UUID string).
        timestamp:            ISO-8601 UTC timestamp.
        source_ip:            Source IP address string.
        destination_ip:       Destination IP address string.
        source_port:          Source TCP/UDP port number.
        destination_port:     Destination TCP/UDP port number.
        protocol:             Protocol name (e.g. 'Modbus TCP', 'TCP/IP').
        function_code:        Modbus function code integer or None.
        function_name:        Modbus function name string.
        risk_score:           Normalized risk score in [0, 100].
        risk_level:           Severity name ('SAFE', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL').
        original_decision:    Decision recommendation from Day 4 ('ALLOW', 'ALERT', 'BLOCK').
        matched_policy_id:    Winning firewall policy ID (e.g. 'POL-006') or None.
        matched_policy_name:  Winning firewall policy name or None.
        policy_priority:      Priority value of winning policy or None.
        final_action:         Final enforced action ('ALLOW', 'ALERT', 'BLOCK').
        reason:               Human-readable explanation of decision and enforcement.
        event_type:           Categorization ('SECURITY_EVENT', 'POLICY_VIOLATION', etc.).
        severity:             Alert severity level (LOW, MEDIUM, HIGH, CRITICAL).
        acknowledged:         Whether this event/alert has been acknowledged.
        id:                   Database primary key row ID (None before insertion).
    """

    event_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=_utc_now_iso)
    source_ip: str = "unknown"
    destination_ip: str = "unknown"
    source_port: int = 0
    destination_port: int = 0
    protocol: str = "Modbus TCP"
    function_code: Optional[int] = None
    function_name: str = ""
    risk_score: int = 0
    risk_level: str = "SAFE"
    original_decision: str = "ALLOW"
    matched_policy_id: Optional[str] = None
    matched_policy_name: Optional[str] = None
    policy_priority: Optional[int] = None
    final_action: str = "ALLOW"
    reason: str = ""
    event_type: str = "SECURITY_EVENT"
    severity: AlertSeverity = AlertSeverity.LOW
    acknowledged: bool = False
    id: Optional[int] = None

    @classmethod
    def from_pipeline_event(
        cls,
        event: PipelineEvent,
        severity: Optional[AlertSeverity] = None,
        event_type: str = "SECURITY_EVENT",
    ) -> SecurityEvent:
        """
        Construct a ``SecurityEvent`` from a ``PipelineEvent``.

        Args:
            event: The pipeline event emitted by PacketPipeline.
            severity: Optional explicit AlertSeverity override.
            event_type: Event classification string.

        Returns:
            A populated ``SecurityEvent``.
        """
        if severity is None:
            # Map risk_level or risk_score to AlertSeverity
            level_str = (event.risk_level or "").upper()
            if level_str == "CRITICAL" or event.risk_score >= 90:
                calc_sev = AlertSeverity.CRITICAL
            elif level_str == "HIGH" or event.risk_score >= 70:
                calc_sev = AlertSeverity.HIGH
            elif level_str == "MEDIUM" or event.risk_score >= 40:
                calc_sev = AlertSeverity.MEDIUM
            else:
                calc_sev = AlertSeverity.LOW
        else:
            calc_sev = severity

        # If it's a block action and severity is low, bump to at least HIGH
        if event.decision == "BLOCK" and calc_sev in (AlertSeverity.LOW, AlertSeverity.MEDIUM):
            calc_sev = AlertSeverity.HIGH

        # Determine specialized event type
        if calc_sev == AlertSeverity.CRITICAL:
            event_type = "CRITICAL_PHYSICAL_VIOLATION"
        elif event.policy_id:
            event_type = "POLICY_VIOLATION" if event.decision == "BLOCK" else "POLICY_MATCH"

        return cls(
            event_id=str(uuid.uuid4()),
            timestamp=event.timestamp or _utc_now_iso(),
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            source_port=event.source_port,
            destination_port=event.destination_port,
            protocol=event.protocol,
            function_code=event.modbus_fc_int,
            function_name=event.modbus_function,
            risk_score=event.risk_score,
            risk_level=event.risk_level,
            original_decision=getattr(event, "original_decision", event.decision),
            matched_policy_id=event.policy_id,
            matched_policy_name=event.policy_name,
            policy_priority=None,
            final_action=event.decision,
            reason=event.enforcement_reason or event.reason,
            event_type=event_type,
            severity=calc_sev,
            acknowledged=False,
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dictionary."""
        return {
            "id": self.id,
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "source_port": self.source_port,
            "destination_port": self.destination_port,
            "protocol": self.protocol,
            "function_code": self.function_code,
            "function_name": self.function_name,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "original_decision": self.original_decision,
            "matched_policy_id": self.matched_policy_id,
            "matched_policy_name": self.matched_policy_name,
            "policy_priority": self.policy_priority,
            "final_action": self.final_action,
            "reason": self.reason,
            "event_type": self.event_type,
            "severity": self.severity.value,
            "acknowledged": self.acknowledged,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> SecurityEvent:
        """Instantiate a ``SecurityEvent`` from a dictionary."""
        sev_val = data.get("severity", "LOW")
        try:
            severity = AlertSeverity(sev_val)
        except ValueError:
            severity = AlertSeverity.LOW

        return cls(
            id=data.get("id"),
            event_id=str(data.get("event_id", uuid.uuid4())),
            timestamp=str(data.get("timestamp", _utc_now_iso())),
            source_ip=str(data.get("source_ip", "unknown")),
            destination_ip=str(data.get("destination_ip", "unknown")),
            source_port=int(data.get("source_port", 0)),
            destination_port=int(data.get("destination_port", 0)),
            protocol=str(data.get("protocol", "Modbus TCP")),
            function_code=data.get("function_code"),
            function_name=str(data.get("function_name", "")),
            risk_score=int(data.get("risk_score", 0)),
            risk_level=str(data.get("risk_level", "SAFE")),
            original_decision=str(data.get("original_decision", "ALLOW")),
            matched_policy_id=data.get("matched_policy_id"),
            matched_policy_name=data.get("matched_policy_name"),
            policy_priority=data.get("policy_priority"),
            final_action=str(data.get("final_action", "ALLOW")),
            reason=str(data.get("reason", "")),
            event_type=str(data.get("event_type", "SECURITY_EVENT")),
            severity=severity,
            acknowledged=bool(data.get("acknowledged", False)),
        )
