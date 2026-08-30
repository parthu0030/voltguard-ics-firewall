"""Database-backed operational report aggregation for VoltGuard.

This module is the single source of report data.  It deliberately reuses the
same analytics time window and database aggregations as the Analytics page so
the two views cannot drift apart.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from statistics import mean
from typing import Any, Optional

from src.models.security_event import SecurityEvent
from src.services.database_service import DatabaseService, database_service
from src.services.security_analytics_service import SecurityAnalyticsService


_PHYSICS_FIELDS = {
    "Pressure": ("pressure_bar", "bar"),
    "Flow Rate": ("flow_lps", "L/s"),
    "Pump RPM": ("pump_rpm", "RPM"),
    "Valve Position": ("valve_position", "%"),
    "Tank Level": ("tank_level_m3", "m³"),
    "Temperature": ("temperature_celsius", "°C"),
}


@dataclass(frozen=True)
class OperationalReport:
    period: str
    start_time: Optional[str]
    end_time: Optional[str]
    generated_at: str
    summary: Any
    protocol_statistics: dict[str, int]
    modbus_statistics: list[dict[str, Any]]
    physics_statistics: list[dict[str, Any]]
    physics_reading_count: int
    anomalies: list[SecurityEvent]
    incidents: list[SecurityEvent]
    correlations: list[dict[str, SecurityEvent]]
    recommendations: list[str]


class ReportingService:
    """Build a fresh report from persisted security and physics records."""

    def __init__(self, db_service: DatabaseService | None = None) -> None:
        self._db = db_service or database_service
        self._analytics = SecurityAnalyticsService(db_service=self._db)

    def generate(self, period: str) -> OperationalReport:
        """Aggregate the selected period; no cached report data is used."""
        start_time, end_time = self._analytics.resolve_time_window(period)
        summary = self._analytics.get_summary_metrics(start_time=start_time, end_time=end_time)
        events = self._db.get_security_events(start_time, end_time, limit=10_000)
        readings = self._db.get_physics_readings(start_time, end_time, limit=10_000)
        anomalies = [event for event in events if event.event_type == "PHYSICS_VIOLATION"]
        incidents = sorted(
            (event for event in events if self._is_major_incident(event)),
            key=lambda event: (event.risk_score, event.id or 0), reverse=True,
        )[:100]
        return OperationalReport(
            period=period,
            start_time=start_time,
            end_time=end_time,
            generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            summary=summary,
            protocol_statistics=self._db.get_protocol_distribution(start_time, end_time),
            modbus_statistics=self._modbus_statistics(events),
            physics_statistics=self._physics_statistics(readings),
            physics_reading_count=len(readings),
            anomalies=anomalies,
            incidents=incidents,
            correlations=self._correlations(events, anomalies),
            recommendations=self._recommendations(events, anomalies),
        )

    @staticmethod
    def _is_major_incident(event: SecurityEvent) -> bool:
        return event.final_action == "BLOCK" or event.risk_level in {"HIGH", "CRITICAL"} or event.severity.value in {"HIGH", "CRITICAL"} or event.event_type == "PHYSICS_VIOLATION"

    @staticmethod
    def _modbus_statistics(events: list[SecurityEvent]) -> list[dict[str, Any]]:
        grouped: dict[tuple[int, str, str], dict[str, Any]] = {}
        for event in events:
            if event.function_code is None:
                continue
            key = (event.function_code, event.function_name or f"Function {event.function_code}", event.final_action)
            item = grouped.setdefault(key, {"code": event.function_code, "name": key[1], "decision": event.final_action, "count": 0, "average_risk": []})
            item["count"] += 1
            item["average_risk"].append(event.risk_score)
        return [
            {**item, "average_risk": round(mean(item["average_risk"]), 1)}
            for item in sorted(grouped.values(), key=lambda row: (-row["count"], row["code"]))
        ]

    @staticmethod
    def _physics_statistics(readings: list[dict[str, Any]]) -> list[dict[str, Any]]:
        result: list[dict[str, Any]] = []
        for label, (field, unit) in _PHYSICS_FIELDS.items():
            values = [float(row[field]) * 100 if field == "valve_position" else float(row[field]) for row in readings if row[field] is not None]
            if values:
                result.append({"label": label, "unit": unit, "minimum": min(values), "maximum": max(values), "average": mean(values), "latest": values[-1]})
        return result

    @staticmethod
    def _correlations(events: list[SecurityEvent], anomalies: list[SecurityEvent]) -> list[dict[str, SecurityEvent]]:
        """Return only timestamp-backed network/physics pairs within one minute."""
        network_events = [event for event in events if event not in anomalies and event.function_code is not None and event.final_action in {"ALERT", "BLOCK"}]
        matches: list[dict[str, SecurityEvent]] = []
        for anomaly in anomalies:
            try:
                anomaly_time = datetime.fromisoformat(anomaly.timestamp.replace("Z", "+00:00"))
            except ValueError:
                continue
            candidates = []
            for network in network_events:
                try:
                    difference = abs((datetime.fromisoformat(network.timestamp.replace("Z", "+00:00")) - anomaly_time).total_seconds())
                except ValueError:
                    continue
                if difference <= 60:
                    candidates.append((difference, network))
            if candidates:
                matches.append({"network": min(candidates, key=lambda item: item[0])[1], "physics": anomaly})
        return matches

    @staticmethod
    def _recommendations(events: list[SecurityEvent], anomalies: list[SecurityEvent]) -> list[str]:
        recommendations: list[str] = []
        if any(event.final_action == "BLOCK" for event in events):
            recommendations.append("Review blocked commands and validate controller authorization.")
        if anomalies:
            recommendations.append("Investigate recorded physical anomalies and confirm pump/valve interlocks.")
        if any(event.final_action == "ALERT" for event in events):
            recommendations.append("Review alert events to determine whether policy tuning is required.")
        return recommendations or ["No security or physical anomalies require action for this period."]
