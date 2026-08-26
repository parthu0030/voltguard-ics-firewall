"""
VoltGuard — Security Analytics & Threat Intelligence Service (Day 8)
====================================================================
Transforms stored packet logs, alerts, and security events into actionable
security metrics, time-series trends, ICS protocol statistics, policy
performance analytics, and deterministic operator insights.

Design principles:
  - Service layer logic: no UI calculations or raw SQL in the UI.
  - Database-backed: delegates aggregation to DatabaseService.
  - Pluggable threat intelligence: works with LocalThreatIntelProvider or None.
  - Strictly deterministic findings: insights are computed from real metrics.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from src.constants import (
    MODBUS_FC_READ_COILS,
    MODBUS_FC_READ_DISCRETE_INPUTS,
    MODBUS_FC_READ_HOLDING_REGISTERS,
    MODBUS_FC_READ_INPUT_REGISTERS,
    MODBUS_FC_WRITE_MULTIPLE_COILS,
    MODBUS_FC_WRITE_MULTIPLE_REGISTERS,
    MODBUS_FC_WRITE_SINGLE_COIL,
    MODBUS_FC_WRITE_SINGLE_REGISTER,
)
from src.interfaces.base_threat_intel import ThreatIntelProvider
from src.logger import get_logger
from src.models.analytics_models import (
    InsightCategory,
    InsightSeverity,
    ModbusAnalyticsMetrics,
    PolicyAnalyticsSummary,
    PolicyMetric,
    SecurityInsight,
    SecuritySummaryMetrics,
)
from src.models.app_models import AlertSeverity
from src.models.security_event import SecurityEvent
from src.models.threat_intel import ThreatReputation
from src.services.database_service import DatabaseService, database_service
from src.services.threat_intel_service import local_threat_intel_provider

_log = get_logger(__name__)

# Map Modbus Function Codes to canonical names
_MODBUS_FC_NAMES: dict[int, str] = {
    MODBUS_FC_READ_COILS: "Read Coils (0x01)",
    MODBUS_FC_READ_DISCRETE_INPUTS: "Read Discrete Inputs (0x02)",
    MODBUS_FC_READ_HOLDING_REGISTERS: "Read Holding Registers (0x03)",
    MODBUS_FC_READ_INPUT_REGISTERS: "Read Input Registers (0x04)",
    MODBUS_FC_WRITE_SINGLE_COIL: "Write Single Coil (0x05)",
    MODBUS_FC_WRITE_SINGLE_REGISTER: "Write Single Register (0x06)",
    MODBUS_FC_WRITE_MULTIPLE_COILS: "Write Multiple Coils (0x0F)",
    MODBUS_FC_WRITE_MULTIPLE_REGISTERS: "Write Multiple Registers (0x10)",
}

_READ_FUNCTION_CODES: set[int] = {
    MODBUS_FC_READ_COILS,
    MODBUS_FC_READ_DISCRETE_INPUTS,
    MODBUS_FC_READ_HOLDING_REGISTERS,
    MODBUS_FC_READ_INPUT_REGISTERS,
}

_WRITE_FUNCTION_CODES: set[int] = {
    MODBUS_FC_WRITE_SINGLE_COIL,
    MODBUS_FC_WRITE_SINGLE_REGISTER,
    MODBUS_FC_WRITE_MULTIPLE_COILS,
    MODBUS_FC_WRITE_MULTIPLE_REGISTERS,
}

_DEFAULT_THREAT_INTEL = object()


def _iso_from_relative(hours: Optional[float] = None, days: Optional[float] = None) -> str:
    """Calculate an ISO-8601 UTC timestamp offset from current time."""
    now = datetime.now(tz=timezone.utc)
    delta = timedelta(hours=hours or 0, days=days or 0)
    return (now - delta).isoformat(timespec="seconds")


class SecurityAnalyticsService:
    """
    Modular analytics service providing aggregate metrics, trends,
    ICS-specific statistics, policy analysis, and security insights.
    """

    def __init__(
        self,
        db_service: Optional[DatabaseService] = None,
        threat_intel: ThreatIntelProvider | None | object = _DEFAULT_THREAT_INTEL,
    ) -> None:
        self._db: DatabaseService = db_service or database_service
        self._threat_intel: Optional[ThreatIntelProvider] = (
            local_threat_intel_provider
            if threat_intel is _DEFAULT_THREAT_INTEL
            else threat_intel  # type: ignore[assignment]
        )

    # ------------------------------------------------------------------ #
    #  Time-Window Helper                                                  #
    # ------------------------------------------------------------------ #

    @staticmethod
    def resolve_time_window(
        time_window: Optional[str] = None,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
    ) -> tuple[Optional[str], Optional[str]]:
        """
        Resolve shorthand time windows (e.g. '1h', '24h', '7d') to ISO strings.
        """
        if time_window:
            tw = time_window.lower().strip()
            if tw == "1h" or tw == "1hour" or tw == "hour":
                return _iso_from_relative(hours=1), None
            elif tw == "24h" or tw == "24hours" or tw == "day" or tw == "1d":
                return _iso_from_relative(hours=24), None
            elif tw == "7d" or tw == "7days" or tw == "week":
                return _iso_from_relative(days=7), None
            elif tw == "30d" or tw == "month":
                return _iso_from_relative(days=30), None
        return start_time, end_time

    # ------------------------------------------------------------------ #
    #  Task 2: High-Level Overview Metrics                                 #
    # ------------------------------------------------------------------ #

    def get_summary_metrics(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        time_window: Optional[str] = None,
    ) -> SecuritySummaryMetrics:
        """
        Retrieve high-level overview security metrics.
        """
        st, et = self.resolve_time_window(time_window, start_time, end_time)
        summary_raw = self._db.get_security_summary(start_time=st, end_time=et)
        sev_dist = self._db.get_severity_distribution(start_time=st, end_time=et)
        act_dist = self._db.get_action_distribution(start_time=st, end_time=et)
        proto_dist = self._db.get_protocol_distribution(start_time=st, end_time=et)

        return SecuritySummaryMetrics(
            total_packets=summary_raw["total_packets"],
            total_security_events=summary_raw["total_security_events"],
            total_alerts=summary_raw["total_alerts"],
            total_blocked_events=summary_raw["total_blocked_events"],
            total_allowed_events=summary_raw["total_allowed_events"],
            total_alert_actions=summary_raw["total_alert_actions"],
            critical_events=summary_raw["critical_events"],
            high_risk_events=summary_raw["high_risk_events"],
            medium_risk_events=summary_raw["medium_risk_events"],
            low_risk_events=summary_raw["low_risk_events"],
            average_risk_score=summary_raw["average_risk_score"],
            maximum_risk_score=summary_raw["maximum_risk_score"],
            minimum_risk_score=summary_raw["minimum_risk_score"],
            events_by_severity=sev_dist,
            events_by_action=act_dist,
            events_by_protocol=proto_dist,
        )

    # Shorthand convenience getters
    def get_total_packets(self) -> int:
        """Return total packet log count."""
        return self._db.get_packet_count()

    def get_total_security_events(self) -> int:
        """Return total security event count."""
        return self._db.get_security_event_count()

    def get_total_alerts(self) -> int:
        """Return total alert count."""
        counts = self._db.get_alert_counts()
        return counts["total"]

    def get_recent_security_activity(self, limit: int = 15) -> list[SecurityEvent]:
        """Return recent security events."""
        return self._db.load_recent_security_events(limit=limit)

    # ------------------------------------------------------------------ #
    #  Task 3: Time-Based Security Analytics                               #
    # ------------------------------------------------------------------ #

    def get_events_last_hour(self) -> int:
        """Return count of security events in the last 1 hour."""
        st = _iso_from_relative(hours=1)
        summary = self._db.get_security_summary(start_time=st)
        return summary["total_security_events"]

    def get_events_last_24h(self) -> int:
        """Return count of security events in the last 24 hours."""
        st = _iso_from_relative(hours=24)
        summary = self._db.get_security_summary(start_time=st)
        return summary["total_security_events"]

    def get_events_last_7d(self) -> int:
        """Return count of security events in the last 7 days."""
        st = _iso_from_relative(days=7)
        summary = self._db.get_security_summary(start_time=st)
        return summary["total_security_events"]

    def get_blocked_events_time_series(
        self,
        bucket_hours: int = 1,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        time_window: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Return time-series of blocked events."""
        st, et = self.resolve_time_window(time_window, start_time, end_time)
        buckets = self._db.get_events_time_series(bucket_hours=bucket_hours, start_time=st, end_time=et)
        return [
            {"time_bucket": b["time_bucket"], "blocked_count": b["block_count"], "total_count": b["event_count"]}
            for b in buckets
        ]

    def get_alerts_time_series(
        self,
        bucket_hours: int = 1,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        time_window: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Return time-series of alert events."""
        st, et = self.resolve_time_window(time_window, start_time, end_time)
        buckets = self._db.get_events_time_series(bucket_hours=bucket_hours, start_time=st, end_time=et)
        return [
            {"time_bucket": b["time_bucket"], "alert_count": b["alert_count"], "total_count": b["event_count"]}
            for b in buckets
        ]

    def get_risk_score_trend(
        self,
        bucket_hours: int = 1,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        time_window: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Return time-series of average and maximum risk scores."""
        st, et = self.resolve_time_window(time_window, start_time, end_time)
        buckets = self._db.get_events_time_series(bucket_hours=bucket_hours, start_time=st, end_time=et)
        return [
            {
                "time_bucket": b["time_bucket"],
                "avg_risk": b["avg_risk"],
                "max_risk": b["max_risk"],
                "event_count": b["event_count"],
            }
            for b in buckets
        ]

    # ------------------------------------------------------------------ #
    #  Task 4: Risk Analytics                                              #
    # ------------------------------------------------------------------ #

    def get_highest_risk_events(
        self,
        limit: int = 10,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        time_window: Optional[str] = None,
    ) -> list[SecurityEvent]:
        """Return the highest-risk security events."""
        st, et = self.resolve_time_window(time_window, start_time, end_time)
        return self._db.get_highest_risk_events(limit=limit, start_time=st, end_time=et)

    def get_events_time_series(
        self,
        bucket_hours: int = 1,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        time_window: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Return time-series buckets of all security events."""
        st, et = self.resolve_time_window(time_window, start_time, end_time)
        buckets = self._db.get_events_time_series(
            bucket_hours=bucket_hours, start_time=st, end_time=et
        )
        return [
            {
                "time_bucket": b["time_bucket"],
                "event_count": b["event_count"],
                "block_count": b["block_count"],
                "alert_count": b["alert_count"],
                "avg_risk": b["avg_risk"],
                "max_risk": b["max_risk"],
            }
            for b in buckets
        ]

    def get_risk_score_distribution(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        time_window: Optional[str] = None,
    ) -> dict[str, int]:
        """Return risk-score bucket distribution for charting."""
        st, et = self.resolve_time_window(time_window, start_time, end_time)
        return self._db.get_risk_score_distribution(start_time=st, end_time=et)

    def get_security_event(self, row_id: int) -> Optional[SecurityEvent]:
        """Load a security event by database row ID."""
        return self._db.get_security_event(row_id)

    def load_filtered_events(
        self,
        limit: int = 100,
        severity: Optional[str] = None,
        final_action: Optional[str] = None,
    ) -> list[SecurityEvent]:
        """Load recent security events with optional filters."""
        return self._db.load_recent_security_events(
            limit=limit, severity=severity, final_action=final_action
        )

    def get_risk_distribution(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        time_window: Optional[str] = None,
    ) -> dict[str, Any]:
        """
        Return risk score distribution metrics and severity breakdown.
        """
        st, et = self.resolve_time_window(time_window, start_time, end_time)
        summary = self._db.get_security_summary(start_time=st, end_time=et)
        sev_dist = self._db.get_severity_distribution(start_time=st, end_time=et)

        return {
            "average_risk_score": summary["average_risk_score"],
            "maximum_risk_score": summary["maximum_risk_score"],
            "minimum_risk_score": summary["minimum_risk_score"],
            "critical_count": summary["critical_events"],
            "high_count": summary["high_risk_events"],
            "medium_count": summary["medium_risk_events"],
            "low_count": summary["low_risk_events"],
            "severity_distribution": sev_dist,
        }

    # ------------------------------------------------------------------ #
    #  Task 5: Source / Destination Traffic Origin Analysis                #
    # ------------------------------------------------------------------ #

    def get_top_source_ips(
        self,
        limit: int = 10,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        time_window: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Return top source IPs by total event count, enriched with threat intel if available."""
        st, et = self.resolve_time_window(time_window, start_time, end_time)
        sources = self._db.get_top_source_ips(limit=limit, start_time=st, end_time=et)
        return self._enrich_sources(sources)

    def get_top_destination_ips(
        self,
        limit: int = 10,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        time_window: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Return top destination IPs by event count."""
        st, et = self.resolve_time_window(time_window, start_time, end_time)
        return self._db.get_top_destination_ips(limit=limit, start_time=st, end_time=et)

    def get_source_ips_with_blocks(
        self,
        limit: int = 10,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        time_window: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Return source IPs associated with BLOCK enforcement actions."""
        st, et = self.resolve_time_window(time_window, start_time, end_time)
        sources = self._db.get_top_source_ips(limit=limit, action="BLOCK", start_time=st, end_time=et)
        return self._enrich_sources(sources)

    def get_source_ips_with_critical_events(
        self,
        limit: int = 10,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        time_window: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """Return source IPs associated with CRITICAL events."""
        st, et = self.resolve_time_window(time_window, start_time, end_time)
        sources = self._db.get_top_source_ips(limit=limit, severity="CRITICAL", start_time=st, end_time=et)
        return self._enrich_sources(sources)

    def get_repeated_suspicious_sources(
        self,
        min_blocked_or_alert: int = 2,
        limit: int = 10,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        time_window: Optional[str] = None,
    ) -> list[dict[str, Any]]:
        """
        Identify repeated suspicious traffic origins (sources with multiple blocks, alerts, or critical events).
        """
        st, et = self.resolve_time_window(time_window, start_time, end_time)
        all_sources = self._db.get_top_source_ips(limit=50, start_time=st, end_time=et)
        suspicious: list[dict[str, Any]] = []

        for src in all_sources:
            bad_actions = src.get("block_count", 0) + src.get("alert_count", 0)
            is_crit = src.get("critical_count", 0) > 0
            is_intel_suspicious = False
            if self._threat_intel:
                is_intel_suspicious = self._threat_intel.is_suspicious(src.get("source_ip", ""))

            if bad_actions >= min_blocked_or_alert or is_crit or is_intel_suspicious:
                suspicious.append(src)

        suspicious.sort(key=lambda s: (s.get("block_count", 0) * 2 + s.get("alert_count", 0)), reverse=True)
        return self._enrich_sources(suspicious[:limit])

    def _enrich_sources(self, sources: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """Helper to attach threat intelligence metadata to source IP summaries."""
        if not self._threat_intel:
            return sources

        enriched = []
        for src in sources:
            item = dict(src)
            ip_str = item.get("source_ip", "")
            intel = self._threat_intel.lookup_ip(ip_str)
            if intel:
                item["threat_reputation"] = intel.reputation.value
                item["threat_confidence"] = intel.confidence
                item["threat_description"] = intel.description
            else:
                item["threat_reputation"] = ThreatReputation.UNKNOWN.value
                item["threat_confidence"] = 0.0
                item["threat_description"] = ""
            enriched.append(item)
        return enriched

    # ------------------------------------------------------------------ #
    #  Task 6: Modbus / ICS Protocol Analytics                             #
    # ------------------------------------------------------------------ #

    def get_modbus_analytics(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        time_window: Optional[str] = None,
    ) -> ModbusAnalyticsMetrics:
        """
        Compute ICS & Modbus protocol specific metrics.
        """
        st, et = self.resolve_time_window(time_window, start_time, end_time)
        fc_dist = self._db.get_modbus_function_distribution(start_time=st, end_time=et)

        total_fc_events = sum(fc_dist.values())
        read_count = sum(fc_dist.get(fc, 0) for fc in _READ_FUNCTION_CODES)
        write_count = sum(fc_dist.get(fc, 0) for fc in _WRITE_FUNCTION_CODES)

        read_pct = round((read_count / total_fc_events * 100.0), 2) if total_fc_events > 0 else 0.0
        write_pct = round((write_count / total_fc_events * 100.0), 2) if total_fc_events > 0 else 0.0

        # Query blocked write operations
        blocked_counts = self._db.get_blocked_modbus_function_counts(
            start_time=st, end_time=et,
        )
        blocked_writes = 0
        high_risk_fcs: list[int] = []
        for fc in fc_dist:
            if fc in _WRITE_FUNCTION_CODES:
                b_cnt = blocked_counts.get(fc, 0)
                blocked_writes += b_cnt
                if b_cnt > 0:
                    high_risk_fcs.append(fc)

        most_frequent_fc = max(fc_dist, key=fc_dist.get) if fc_dist else None
        most_frequent_name = _MODBUS_FC_NAMES.get(most_frequent_fc, "") if most_frequent_fc else ""

        # Function names mapping
        fc_names_map = {fc: _MODBUS_FC_NAMES.get(fc, f"Function 0x{fc:02X}") for fc in fc_dist.keys()}

        return ModbusAnalyticsMetrics(
            function_code_distribution=fc_dist,
            function_names=fc_names_map,
            total_modbus_events=total_fc_events,
            read_operations_count=read_count,
            write_operations_count=write_count,
            read_operations_percentage=read_pct,
            write_operations_percentage=write_pct,
            blocked_write_operations=blocked_writes,
            high_risk_function_codes=high_risk_fcs,
            most_frequent_function_code=most_frequent_fc,
            most_frequent_function_name=most_frequent_name,
        )

    # ------------------------------------------------------------------ #
    #  Task 7: Policy Analytics                                            #
    # ------------------------------------------------------------------ #

    def get_policy_analytics(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        time_window: Optional[str] = None,
    ) -> PolicyAnalyticsSummary:
        """
        Compute firewall policy enforcement metrics and identify most active policies.
        """
        st, et = self.resolve_time_window(time_window, start_time, end_time)
        raw_stats = self._db.get_policy_statistics(start_time=st, end_time=et)

        policy_metrics: list[PolicyMetric] = [
            PolicyMetric(
                policy_id=r["policy_id"],
                policy_name=r["policy_name"],
                match_count=r["match_count"],
                block_count=r["block_count"],
                alert_count=r["alert_count"],
                allow_count=r["allow_count"],
                percentage_of_total=r["percentage_of_total"],
            )
            for r in raw_stats
        ]

        most_triggered: Optional[str] = None
        most_blocking: Optional[str] = None
        most_alerting: Optional[str] = None

        if policy_metrics:
            most_triggered = max(policy_metrics, key=lambda p: p.match_count).policy_id
            blocking_candidates = [p for p in policy_metrics if p.block_count > 0]
            if blocking_candidates:
                most_blocking = max(blocking_candidates, key=lambda p: p.block_count).policy_id
            alerting_candidates = [p for p in policy_metrics if p.alert_count > 0]
            if alerting_candidates:
                most_alerting = max(alerting_candidates, key=lambda p: p.alert_count).policy_id

        return PolicyAnalyticsSummary(
            policies=policy_metrics,
            most_triggered_policy_id=most_triggered,
            most_blocking_policy_id=most_blocking,
            most_alerting_policy_id=most_alerting,
        )

    # ------------------------------------------------------------------ #
    #  Task 9: Deterministic Security Insight Generation                  #
    # ------------------------------------------------------------------ #

    def generate_security_insights(
        self,
        start_time: Optional[str] = None,
        end_time: Optional[str] = None,
        time_window: Optional[str] = None,
    ) -> list[SecurityInsight]:
        """
        Generate actionable, metric-backed security insights for operators.
        Strictly deterministic and based on calculated metrics.
        """
        st, et = self.resolve_time_window(time_window, start_time, end_time)
        summary = self.get_summary_metrics(start_time=st, end_time=et)
        modbus_metrics = self.get_modbus_analytics(start_time=st, end_time=et)
        policy_summary = self.get_policy_analytics(start_time=st, end_time=et)
        suspicious_sources = self.get_repeated_suspicious_sources(limit=5, start_time=st, end_time=et)

        insights: list[SecurityInsight] = []

        # 1. Physical safety limit & Critical events insight
        if summary.critical_events > 0:
            insights.append(
                SecurityInsight(
                    title="Critical Physical Safety Events Detected",
                    description=(
                        f"Detected {summary.critical_events} critical security event(s) requiring immediate "
                        f"investigation. Physical limits or high-severity rules were triggered."
                    ),
                    severity=InsightSeverity.CRITICAL,
                    category=InsightCategory.PHYSICAL_SAFETY,
                    recommendation="Review physical telemetry in the Physics Monitor and inspect critical event logs.",
                )
            )

        # 2. Blocked traffic volume insight
        total_evts = summary.total_security_events
        if total_evts > 0:
            block_ratio = (summary.total_blocked_events / total_evts) * 100.0
            if block_ratio >= 25.0:
                insights.append(
                    SecurityInsight(
                        title="High Blocked Traffic Ratio",
                        description=(
                            f"Blocked traffic represents {block_ratio:.1f}% ({summary.total_blocked_events} "
                            f"of {total_evts}) of all evaluated security events in the selected period."
                        ),
                        severity=InsightSeverity.HIGH if block_ratio >= 50.0 else InsightSeverity.MEDIUM,
                        category=InsightCategory.TRAFFIC,
                        recommendation="Investigate unauthorized source endpoints or aggressive scanning patterns.",
                    )
                )
            elif summary.total_blocked_events > 0:
                insights.append(
                    SecurityInsight(
                        title="Active Enforcement Blocks Recorded",
                        description=(
                            f"Enforcement adapter blocked {summary.total_blocked_events} non-compliant "
                            f"packet(s) in accordance with active security policies."
                        ),
                        severity=InsightSeverity.LOW,
                        category=InsightCategory.TRAFFIC,
                        recommendation="Verify that blocked traffic corresponds to expected threat vectors.",
                    )
                )

        # 3. Repeated / high-frequency suspicious sources
        if suspicious_sources:
            top_src = suspicious_sources[0]
            ip_str = top_src.get("source_ip", "")
            b_cnt = top_src.get("block_count", 0)
            a_cnt = top_src.get("alert_count", 0)
            insights.append(
                SecurityInsight(
                    title="Repeated Suspicious Source Activity",
                    description=(
                        f"Source IP {ip_str} produced repeated security triggers ({b_cnt} blocks, "
                        f"{a_cnt} alerts) with a maximum risk score of {top_src.get('max_risk', 0)}."
                    ),
                    severity=InsightSeverity.HIGH if b_cnt > 0 else InsightSeverity.MEDIUM,
                    category=InsightCategory.TRAFFIC,
                    recommendation=f"Examine network traffic from source {ip_str} and consider host isolation.",
                )
            )

        # 4. Modbus write vs read operation ratio
        if modbus_metrics.total_modbus_events > 0:
            if modbus_metrics.write_operations_percentage >= 40.0:
                insights.append(
                    SecurityInsight(
                        title="Elevated Modbus Write Operations",
                        description=(
                            f"Write commands account for {modbus_metrics.write_operations_percentage:.1f}% "
                            f"({modbus_metrics.write_operations_count} operations) of all Modbus traffic. "
                            f"Typical ICS baseline is predominantly read polling."
                        ),
                        severity=InsightSeverity.MEDIUM,
                        category=InsightCategory.ICS_MODBUS,
                        recommendation="Verify if scheduled maintenance or setpoint calibration is currently active.",
                    )
                )

            if modbus_metrics.blocked_write_operations > 0:
                insights.append(
                    SecurityInsight(
                        title="Blocked Modbus Control Writes",
                        description=(
                            f"{modbus_metrics.blocked_write_operations} Modbus write command(s) were blocked by "
                            f"firewall policies due to unsafe register targets or elevated risk."
                        ),
                        severity=InsightSeverity.HIGH,
                        category=InsightCategory.ICS_MODBUS,
                        recommendation="Audit PLC register addresses and verify unauthorized setpoint modifications.",
                    )
                )

        # 5. Policy effectiveness insight
        if policy_summary.most_blocking_policy_id:
            insights.append(
                SecurityInsight(
                    title="Primary Blocking Policy Identified",
                    description=(
                        f"Firewall policy '{policy_summary.most_blocking_policy_id}' is the most active blocking "
                        f"rule, stopping unauthorized or hazardous industrial commands."
                    ),
                    severity=InsightSeverity.INFO,
                    category=InsightCategory.POLICY,
                    recommendation="Ensure policy thresholds match current plant operating modes.",
                )
            )

        # 6. Threat intelligence matches
        if self._threat_intel:
            for src in suspicious_sources:
                ip = src.get("source_ip", "")
                ind = self._threat_intel.lookup_ip(ip)
                if ind and ind.reputation in (ThreatReputation.SUSPICIOUS, ThreatReputation.MALICIOUS):
                    insights.append(
                        SecurityInsight(
                            title="Threat Intelligence Match",
                            description=(
                                f"Traffic source {ip} matches known {ind.reputation.value} indicator "
                                f"({ind.description or 'Flagged IP'}) with confidence {ind.confidence:.2f}."
                            ),
                            severity=InsightSeverity.HIGH if ind.reputation == ThreatReputation.MALICIOUS else InsightSeverity.MEDIUM,
                            category=InsightCategory.THREAT_INTEL,
                            recommendation="Check host credibility against local ICS asset inventory.",
                        )
                    )
                    break

        # If zero events exist
        if total_evts == 0:
            insights.append(
                SecurityInsight(
                    title="No Security Events Recorded",
                    description="No security events have been logged for the selected time window.",
                    severity=InsightSeverity.INFO,
                    category=InsightCategory.TRAFFIC,
                    recommendation="Ensure the capture pipeline and network simulation are running.",
                )
            )

        return insights


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
security_analytics_service: SecurityAnalyticsService = SecurityAnalyticsService()
