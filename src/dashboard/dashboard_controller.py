"""
VoltGuard — Dashboard Data Controller (Day 9)
==============================================
Aggregates analytics, alert, and posture data for the security dashboard UI.
Keeps all data-loading logic out of Qt widgets.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Optional

from src.dashboard.security_posture import (
    SecurityPostureCalculator,
    SecurityPostureResult,
    security_posture_calculator,
)
from src.models.analytics_models import SecuritySummaryMetrics
from src.models.app_models import Alert
from src.models.security_event import SecurityEvent
from src.services.alert_manager import AlertManager, alert_manager
from src.services.security_analytics_service import (
    SecurityAnalyticsService,
    security_analytics_service,
)


@dataclass
class DashboardSnapshot:
    """Complete data bundle for rendering the security overview dashboard."""

    summary: SecuritySummaryMetrics = field(default_factory=SecuritySummaryMetrics)
    summary_1h: SecuritySummaryMetrics = field(default_factory=SecuritySummaryMetrics)
    alert_counts: dict[str, int] = field(default_factory=dict)
    posture: Optional[SecurityPostureResult] = None
    recent_events: list[SecurityEvent] = field(default_factory=list)
    recent_alerts: list[Alert] = field(default_factory=list)
    critical_alerts: list[Alert] = field(default_factory=list)
    high_alerts: list[Alert] = field(default_factory=list)
    unack_alerts: list[Alert] = field(default_factory=list)
    events_time_series: list[dict[str, Any]] = field(default_factory=list)
    alerts_time_series: list[dict[str, Any]] = field(default_factory=list)
    risk_distribution: dict[str, int] = field(default_factory=dict)
    top_source_ips: list[dict[str, Any]] = field(default_factory=list)
    top_policies: list[dict[str, Any]] = field(default_factory=list)
    modbus_fc_distribution: dict[int, int] = field(default_factory=dict)
    modbus_fc_names: dict[int, str] = field(default_factory=dict)
    load_error: Optional[str] = None

    @property
    def has_data(self) -> bool:
        return self.summary.total_security_events > 0 or self.summary.total_packets > 0


class DashboardController:
    """
    Loads and packages dashboard data from analytics and alert services.

    Designed for safe repeated polling from QTimer callbacks.
    """

    DEFAULT_TIME_WINDOW = "24h"
    DEFAULT_EVENT_LIMIT = 50
    DEFAULT_ALERT_LIMIT = 20

    def __init__(
        self,
        analytics: Optional[SecurityAnalyticsService] = None,
        alerts: Optional[AlertManager] = None,
        posture_calc: Optional[SecurityPostureCalculator] = None,
    ) -> None:
        self._analytics = analytics or security_analytics_service
        self._alerts = alerts or alert_manager
        self._posture = posture_calc or security_posture_calculator

    def load_snapshot(
        self,
        time_window: str = DEFAULT_TIME_WINDOW,
        event_limit: int = DEFAULT_EVENT_LIMIT,
        alert_limit: int = DEFAULT_ALERT_LIMIT,
    ) -> DashboardSnapshot:
        """
        Load a full dashboard snapshot from database-backed services.

        Returns:
            ``DashboardSnapshot``; on error, ``load_error`` is populated and
            other fields contain safe defaults.
        """
        snapshot = DashboardSnapshot()
        try:
            snapshot.summary = self._analytics.get_summary_metrics(time_window=time_window)
            snapshot.summary_1h = self._analytics.get_summary_metrics(time_window="1h")
            snapshot.alert_counts = self._alerts.get_stats()
            snapshot.posture = self._posture.calculate()
            snapshot.recent_events = self._analytics.get_recent_security_activity(
                limit=event_limit
            )
            snapshot.recent_alerts = self._alerts.get_recent_alerts(limit=alert_limit)
            snapshot.critical_alerts = self._alerts.get_recent_alerts(
                limit=alert_limit, severity="CRITICAL"
            )
            snapshot.high_alerts = self._alerts.get_recent_alerts(
                limit=alert_limit, severity="HIGH"
            )
            snapshot.unack_alerts = self._alerts.get_unacknowledged_alerts(
                limit=alert_limit
            )
            snapshot.events_time_series = self._analytics.get_events_time_series(
                time_window=time_window
            )
            snapshot.alerts_time_series = self._analytics.get_alerts_time_series(
                time_window=time_window
            )
            snapshot.risk_distribution = self._analytics.get_risk_score_distribution(
                time_window=time_window
            )
            snapshot.top_source_ips = self._analytics.get_top_source_ips(
                limit=8, time_window=time_window
            )
            policy_summary = self._analytics.get_policy_analytics(time_window=time_window)
            snapshot.top_policies = [
                {
                    "policy_id": p.policy_id,
                    "policy_name": p.policy_name,
                    "match_count": p.match_count,
                }
                for p in policy_summary.policies[:8]
            ]
            modbus = self._analytics.get_modbus_analytics(time_window=time_window)
            snapshot.modbus_fc_distribution = modbus.function_code_distribution
            snapshot.modbus_fc_names = modbus.function_names
        except Exception as exc:
            snapshot.load_error = str(exc)
        return snapshot

    def load_event_by_id(self, row_id: int) -> Optional[SecurityEvent]:
        """Load a single security event by database row ID."""
        try:
            return self._analytics.get_security_event(row_id)
        except Exception:
            return None

    def filter_events(
        self,
        severity: Optional[str] = None,
        action: Optional[str] = None,
        limit: int = 100,
    ) -> list[SecurityEvent]:
        """Load security events with optional severity and action filters."""
        try:
            return self._analytics.load_filtered_events(
                limit=limit,
                severity=severity,
                final_action=action,
            )
        except Exception:
            return []


dashboard_controller: DashboardController = DashboardController()
