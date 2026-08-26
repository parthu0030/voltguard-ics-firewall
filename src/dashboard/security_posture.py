"""
VoltGuard — Security Posture Calculator (Day 9)
=================================================
Derives the operator-facing security posture indicator from real database
metrics.  No UI values or hardcoded thresholds unrelated to observed data.

Posture States
--------------
NORMAL    — Baseline operations; no significant unacknowledged threats.
ELEVATED  — Notable activity requiring awareness.
HIGH      — Active high-severity conditions needing prompt review.
CRITICAL  — Immediate operator attention required.

Calculation (evaluated top-down; first match wins)
--------------------------------------------------
Data window: primarily last 24 hours; recency checks use last 1 hour.

CRITICAL when ANY of:
  • Unacknowledged CRITICAL alerts > 0
  • Critical security events in the last 1 hour ≥ 1

HIGH when ANY of:
  • Unacknowledged HIGH alerts > 0
  • Blocked events in the last 1 hour ≥ 5
  • High-risk events in last 24 h ≥ 3 AND unacknowledged alerts ≥ 3

ELEVATED when ANY of:
  • Unacknowledged MEDIUM alerts > 0
  • Blocked events in last 24 h ≥ 1
  • Security events in the last 1 hour ≥ 10

NORMAL otherwise (including an empty database).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional

from src.services.alert_manager import AlertManager, alert_manager
from src.services.security_analytics_service import (
    SecurityAnalyticsService,
    security_analytics_service,
)


class SecurityPosture(str, Enum):
    """Operator-visible security posture levels."""

    NORMAL = "NORMAL"
    ELEVATED = "ELEVATED"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


@dataclass
class SecurityPostureResult:
    """Outcome of a posture evaluation."""

    level: SecurityPosture
    summary: str
    factors: list[str]

    def to_dict(self) -> dict[str, Any]:
        return {
            "level": self.level.value,
            "summary": self.summary,
            "factors": list(self.factors),
        }


class SecurityPostureCalculator:
    """
    Computes security posture from analytics and alert data.

    All inputs come from ``SecurityAnalyticsService`` and ``AlertManager``.
    """

    def __init__(
        self,
        analytics: Optional[SecurityAnalyticsService] = None,
        alerts: Optional[AlertManager] = None,
    ) -> None:
        self._analytics = analytics or security_analytics_service
        self._alerts = alerts or alert_manager

    def calculate(self) -> SecurityPostureResult:
        """
        Evaluate current posture from live database metrics.

        Returns:
            ``SecurityPostureResult`` with level, human summary, and factor list.
        """
        summary_24h = self._analytics.get_summary_metrics(time_window="24h")
        summary_1h = self._analytics.get_summary_metrics(time_window="1h")
        alert_counts = self._alerts.get_stats()
        unack = alert_counts.get("unacknowledged", 0)

        factors: list[str] = []

        # ── CRITICAL ────────────────────────────────────────────────────
        unack_critical = self._count_unack_by_severity("CRITICAL")
        if unack_critical > 0:
            factors.append(f"{unack_critical} unacknowledged CRITICAL alert(s)")
        if summary_1h.critical_events >= 1:
            factors.append(
                f"{summary_1h.critical_events} critical event(s) in the last hour"
            )
        if factors:
            return SecurityPostureResult(
                level=SecurityPosture.CRITICAL,
                summary="Immediate attention required — critical threats detected.",
                factors=factors,
            )

        # ── HIGH ────────────────────────────────────────────────────────
        factors = []
        unack_high = self._count_unack_by_severity("HIGH")
        if unack_high > 0:
            factors.append(f"{unack_high} unacknowledged HIGH alert(s)")
        if summary_1h.total_blocked_events >= 5:
            factors.append(
                f"{summary_1h.total_blocked_events} blocked event(s) in the last hour"
            )
        if summary_24h.high_risk_events >= 3 and unack >= 3:
            factors.append(
                f"{summary_24h.high_risk_events} high-risk events (24 h) with "
                f"{unack} unacknowledged alert(s)"
            )
        if factors:
            return SecurityPostureResult(
                level=SecurityPosture.HIGH,
                summary="Elevated threat activity — review alerts promptly.",
                factors=factors,
            )

        # ── ELEVATED ────────────────────────────────────────────────────
        factors = []
        unack_medium = self._count_unack_by_severity("MEDIUM")
        if unack_medium > 0:
            factors.append(f"{unack_medium} unacknowledged MEDIUM alert(s)")
        if summary_24h.total_blocked_events >= 1:
            factors.append(
                f"{summary_24h.total_blocked_events} blocked event(s) in 24 h"
            )
        events_1h = summary_1h.total_security_events
        if events_1h >= 10:
            factors.append(f"{events_1h} security events in the last hour")
        if factors:
            return SecurityPostureResult(
                level=SecurityPosture.ELEVATED,
                summary="Increased activity detected — monitor closely.",
                factors=factors,
            )

        # ── NORMAL ──────────────────────────────────────────────────────
        if summary_24h.total_security_events == 0:
            return SecurityPostureResult(
                level=SecurityPosture.NORMAL,
                summary="No security events recorded — system at baseline.",
                factors=["No events in the last 24 hours"],
            )
        return SecurityPostureResult(
            level=SecurityPosture.NORMAL,
            summary="Security posture is within normal operating parameters.",
            factors=["No active high-severity conditions"],
        )

    def _count_unack_by_severity(self, severity: str) -> int:
        """Count unacknowledged alerts for a given severity level."""
        unack_alerts = self._alerts.get_unacknowledged_alerts(limit=500)
        return sum(1 for a in unack_alerts if a.severity.value == severity)


# Module-level singleton
security_posture_calculator: SecurityPostureCalculator = SecurityPostureCalculator()
