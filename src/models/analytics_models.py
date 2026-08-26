"""
VoltGuard — Security Analytics Data Models (Day 8)
===================================================
Defines strongly-typed dataclasses and enumerations for security metrics,
risk analytics, ICS/Modbus statistics, policy performance, and automated
security insights.

Design principles:
  - Pure Python dataclasses with zero GUI / external dependencies.
  - Fully serializable to dict / JSON for reporting, UI, and API export.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from src.models.app_models import AlertSeverity


def _utc_now_iso() -> str:
    """Return current UTC time as an ISO-8601 string."""
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")


class InsightSeverity(str, Enum):
    """Severity levels for generated security insights."""
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class InsightCategory(str, Enum):
    """Categorization for security insights."""
    TRAFFIC = "TRAFFIC"
    POLICY = "POLICY"
    ICS_MODBUS = "ICS_MODBUS"
    THREAT_INTEL = "THREAT_INTEL"
    PHYSICAL_SAFETY = "PHYSICAL_SAFETY"


@dataclass
class SecurityInsight:
    """
    Actionable security insight generated deterministically from analytics metrics.

    Attributes:
        title:          Short headline summary.
        description:    Detailed explanation based on observed data.
        severity:       Insight severity (INFO, LOW, MEDIUM, HIGH, CRITICAL).
        category:       Thematic category.
        recommendation: Suggested operator action or mitigation.
        generated_at:   ISO-8601 timestamp.
    """
    title: str
    description: str
    severity: InsightSeverity = InsightSeverity.INFO
    category: InsightCategory = InsightCategory.TRAFFIC
    recommendation: str = ""
    generated_at: str = field(default_factory=_utc_now_iso)

    def to_dict(self) -> dict[str, Any]:
        """Serialize insight to dictionary."""
        return {
            "title": self.title,
            "description": self.description,
            "severity": self.severity.value,
            "category": self.category.value,
            "recommendation": self.recommendation,
            "generated_at": self.generated_at,
        }


@dataclass
class SecuritySummaryMetrics:
    """High-level aggregate overview metrics."""
    total_packets: int = 0
    total_security_events: int = 0
    total_alerts: int = 0
    total_blocked_events: int = 0
    total_allowed_events: int = 0
    total_alert_actions: int = 0
    critical_events: int = 0
    high_risk_events: int = 0
    medium_risk_events: int = 0
    low_risk_events: int = 0
    average_risk_score: float = 0.0
    maximum_risk_score: int = 0
    minimum_risk_score: int = 0
    events_by_severity: dict[str, int] = field(default_factory=dict)
    events_by_action: dict[str, int] = field(default_factory=dict)
    events_by_protocol: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize summary metrics to dictionary."""
        return {
            "total_packets": self.total_packets,
            "total_security_events": self.total_security_events,
            "total_alerts": self.total_alerts,
            "total_blocked_events": self.total_blocked_events,
            "total_allowed_events": self.total_allowed_events,
            "total_alert_actions": self.total_alert_actions,
            "critical_events": self.critical_events,
            "high_risk_events": self.high_risk_events,
            "medium_risk_events": self.medium_risk_events,
            "low_risk_events": self.low_risk_events,
            "average_risk_score": self.average_risk_score,
            "maximum_risk_score": self.maximum_risk_score,
            "minimum_risk_score": self.minimum_risk_score,
            "events_by_severity": dict(self.events_by_severity),
            "events_by_action": dict(self.events_by_action),
            "events_by_protocol": dict(self.events_by_protocol),
        }


@dataclass
class ModbusAnalyticsMetrics:
    """ICS and Modbus-specific protocol analytics."""
    function_code_distribution: dict[int, int] = field(default_factory=dict)
    function_names: dict[int, str] = field(default_factory=dict)
    total_modbus_events: int = 0
    read_operations_count: int = 0
    write_operations_count: int = 0
    read_operations_percentage: float = 0.0
    write_operations_percentage: float = 0.0
    blocked_write_operations: int = 0
    high_risk_function_codes: list[int] = field(default_factory=list)
    most_frequent_function_code: Optional[int] = None
    most_frequent_function_name: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize Modbus metrics to dictionary."""
        return {
            "function_code_distribution": {str(k): v for k, v in self.function_code_distribution.items()},
            "function_names": {str(k): v for k, v in self.function_names.items()},
            "total_modbus_events": self.total_modbus_events,
            "read_operations_count": self.read_operations_count,
            "write_operations_count": self.write_operations_count,
            "read_operations_percentage": self.read_operations_percentage,
            "write_operations_percentage": self.write_operations_percentage,
            "blocked_write_operations": self.blocked_write_operations,
            "high_risk_function_codes": list(self.high_risk_function_codes),
            "most_frequent_function_code": self.most_frequent_function_code,
            "most_frequent_function_name": self.most_frequent_function_name,
        }


@dataclass
class PolicyMetric:
    """Statistics for an individual firewall policy."""
    policy_id: str
    policy_name: str
    match_count: int = 0
    block_count: int = 0
    alert_count: int = 0
    allow_count: int = 0
    percentage_of_total: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        """Serialize policy metric to dictionary."""
        return {
            "policy_id": self.policy_id,
            "policy_name": self.policy_name,
            "match_count": self.match_count,
            "block_count": self.block_count,
            "alert_count": self.alert_count,
            "allow_count": self.allow_count,
            "percentage_of_total": self.percentage_of_total,
        }


@dataclass
class PolicyAnalyticsSummary:
    """Summary of all policy activity."""
    policies: list[PolicyMetric] = field(default_factory=list)
    most_triggered_policy_id: Optional[str] = None
    most_blocking_policy_id: Optional[str] = None
    most_alerting_policy_id: Optional[str] = None

    def to_dict(self) -> dict[str, Any]:
        """Serialize policy summary to dictionary."""
        return {
            "policies": [p.to_dict() for p in self.policies],
            "most_triggered_policy_id": self.most_triggered_policy_id,
            "most_blocking_policy_id": self.most_blocking_policy_id,
            "most_alerting_policy_id": self.most_alerting_policy_id,
        }
