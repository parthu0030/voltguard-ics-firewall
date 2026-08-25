"""
VoltGuard — Security Alert & Event Manager (Day 7)
===================================================
Orchestrates security event persistence, intelligent alert generation,
sliding-window deduplication, and lifecycle acknowledgement.

Architecture:
  PipelineEvent / SecurityDecisionResult
               ↓
      SecurityEvent Factory
               ↓
    AlertManager.process_event()
       ┌───────┴───────┐
  [Deduplication]   [Severity Mapping]
       │               │
       └───────┬───────┘
               ↓
     Database Persistence
     (security_events & alerts)
               ↓
     UI / Dashboard Updates

Deduplication Strategy:
  - Generates a deterministic signature from:
    (source_ip, destination_ip, function_code, policy_id, final_action, severity)
  - Identical security alerts occurring within ``dedup_window_sec`` (default 10s)
    are aggregated: the existing alert's ``repeat_count`` and timestamp are updated
    rather than flooding the database with redundant rows.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Optional

from src.logger import get_logger
from src.models.app_models import Alert, AlertSeverity
from src.models.security_event import SecurityEvent
from src.services.database_service import database_service

if TYPE_CHECKING:
    from src.pipeline.pipeline_event import PipelineEvent

_log = get_logger(__name__)


def _utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")


class AlertManager:
    """
    Core security alert and event management service.

    Attributes:
        dedup_window_sec: Window in seconds for collapsing identical alerts.
    """

    DEFAULT_DEDUP_WINDOW_SEC: float = 10.0

    def __init__(self, dedup_window_sec: float = DEFAULT_DEDUP_WINDOW_SEC) -> None:
        self._dedup_window_sec: float = dedup_window_sec
        # dedup cache: signature -> (alert_id, last_timestamp_unix, repeat_count)
        self._dedup_cache: dict[tuple, tuple[int, float, int]] = {}
        self._lock: threading.Lock = threading.Lock()

    # ------------------------------------------------------------------ #
    #  Severity Mapping                                                    #
    # ------------------------------------------------------------------ #

    @staticmethod
    def map_severity(
        risk_score: int,
        risk_level: str = "SAFE",
        action: str = "ALLOW",
    ) -> AlertSeverity:
        """
        Map risk metrics and enforcement action to an AlertSeverity level.

        Rules:
          - CRITICAL: risk_level is CRITICAL or risk_score >= 90
          - HIGH: risk_level is HIGH or risk_score >= 70 or action is BLOCK
          - MEDIUM: risk_level is MEDIUM or risk_score >= 40 or action is ALERT
          - LOW: otherwise
        """
        level_upper = (risk_level or "").upper()
        action_upper = (action or "").upper()

        if level_upper == "CRITICAL" or risk_score >= 90:
            return AlertSeverity.CRITICAL
        if level_upper == "HIGH" or risk_score >= 70 or action_upper == "BLOCK":
            return AlertSeverity.HIGH
        if level_upper == "MEDIUM" or risk_score >= 40 or action_upper == "ALERT":
            return AlertSeverity.MEDIUM
        return AlertSeverity.LOW

    # ------------------------------------------------------------------ #
    #  Event & Alert Ingestion                                             #
    # ------------------------------------------------------------------ #

    def process_pipeline_event(
        self,
        pipeline_event: "PipelineEvent",
    ) -> tuple[SecurityEvent, Optional[Alert]]:
        """
        Ingest a ``PipelineEvent`` from the security pipeline.

        1. Converts to structured ``SecurityEvent`` and persists to database.
        2. Generates an ``Alert`` for ALERT and BLOCK actions (or elevated risk).
        3. Applies deduplication to prevent alert storms.

        Returns:
            Tuple of (persisted_security_event, optional_alert_or_none).
        """
        severity = self.map_severity(
            risk_score=pipeline_event.risk_score,
            risk_level=pipeline_event.risk_level,
            action=pipeline_event.decision,
        )

        security_event = SecurityEvent.from_pipeline_event(
            pipeline_event,
            severity=severity,
        )

        # Persist full security event to audit trail
        try:
            database_service.save_security_event(security_event)
        except Exception as exc:
            _log.error("AlertManager: failed to save security event: %s", exc)

        # Determine whether a security alert should be raised
        alert: Optional[Alert] = None
        action_upper = pipeline_event.decision.upper()

        if action_upper in ("ALERT", "BLOCK") or severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL):
            alert = self._create_or_dedup_alert(security_event)

        return security_event, alert

    def process_security_event(self, event: SecurityEvent) -> Optional[Alert]:
        """
        Process a pre-constructed ``SecurityEvent``, persist it, and generate an alert if needed.
        """
        try:
            database_service.save_security_event(event)
        except Exception as exc:
            _log.error("AlertManager: failed to save security event: %s", exc)

        action_upper = event.final_action.upper()
        if action_upper in ("ALERT", "BLOCK") or event.severity in (AlertSeverity.HIGH, AlertSeverity.CRITICAL):
            return self._create_or_dedup_alert(event)
        return None

    def create_alert(
        self,
        message: str,
        severity: AlertSeverity = AlertSeverity.MEDIUM,
        source_ip: str = "",
        destination_ip: str = "",
        protocol: str = "Modbus TCP",
        function_code: Optional[int] = None,
        action: str = "ALERT",
        risk_score: int = 0,
        policy_id: Optional[str] = None,
        event_id: Optional[str] = None,
    ) -> Alert:
        """
        Manually raise a standalone security alert with deduplication.
        """
        now_iso = _utc_now_iso()
        alert = Alert(
            timestamp=now_iso,
            severity=severity,
            message=message,
            acknowledged=False,
            source_ip=source_ip,
            destination_ip=destination_ip,
            protocol=protocol,
            function_code=function_code,
            action=action,
            risk_score=risk_score,
            policy_id=policy_id,
            event_id=event_id,
            repeat_count=1,
        )
        return self._persist_with_dedup(alert)

    # ------------------------------------------------------------------ #
    #  Deduplication Logic                                                 #
    # ------------------------------------------------------------------ #

    def _create_or_dedup_alert(self, event: SecurityEvent) -> Alert:
        """Build and deduplicate an alert from a SecurityEvent."""
        msg_parts = []
        if event.final_action == "BLOCK":
            msg_parts.append(f"BLOCKED: {event.reason or 'Security policy violation'}")
        else:
            msg_parts.append(f"SECURITY ALERT: {event.reason or 'Suspicious ICS activity'}")

        if event.matched_policy_id:
            msg_parts.append(f"[Policy: {event.matched_policy_id}]")

        message = " ".join(msg_parts)

        alert = Alert(
            timestamp=event.timestamp,
            severity=event.severity,
            message=message,
            acknowledged=False,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            protocol=event.protocol,
            function_code=event.function_code,
            action=event.final_action,
            risk_score=event.risk_score,
            policy_id=event.matched_policy_id,
            event_id=event.event_id,
            repeat_count=1,
        )
        return self._persist_with_dedup(alert)

    def _persist_with_dedup(self, alert: Alert) -> Alert:
        """
        Persist an alert or increment repeat count if duplicate within window.
        """
        sig = (
            alert.source_ip,
            alert.destination_ip,
            alert.function_code,
            alert.policy_id,
            alert.action,
            alert.severity.value,
        )
        now_epoch = time.time()

        with self._lock:
            if self._dedup_window_sec > 0 and sig in self._dedup_cache:
                alert_id, last_time, count = self._dedup_cache[sig]
                if (now_epoch - last_time) <= self._dedup_window_sec:
                    # Duplicate found within sliding window
                    new_count = count + 1
                    self._dedup_cache[sig] = (alert_id, now_epoch, new_count)
                    database_service.update_alert_repeat(alert_id, new_count, alert.timestamp)
                    alert.id = alert_id
                    alert.repeat_count = new_count
                    _log.debug(
                        "AlertManager: deduplicated alert id=%d count=%d sig=%s",
                        alert_id, new_count, sig,
                    )
                    return alert

            # New distinct alert
            alert_id = database_service.save_alert(alert)
            alert.id = alert_id
            if self._dedup_window_sec > 0:
                self._dedup_cache[sig] = (alert_id, now_epoch, 1)

            _log.info(
                "AlertManager: raised new alert id=%d [%s] %s (action=%s)",
                alert_id, alert.severity.value, alert.message, alert.action,
            )
            return alert

    def clear_dedup_cache(self) -> None:
        """Clear in-memory deduplication cache."""
        with self._lock:
            self._dedup_cache.clear()

    # ------------------------------------------------------------------ #
    #  Query & Management APIs                                             #
    # ------------------------------------------------------------------ #

    def get_alert(self, alert_id: int) -> Optional[Alert]:
        """Fetch alert by ID."""
        return database_service.get_alert(alert_id)

    def get_recent_alerts(
        self,
        limit: int = 50,
        offset: int = 0,
        severity: Optional[str] = None,
        action: Optional[str] = None,
    ) -> list[Alert]:
        """Fetch recent alerts with optional filtering."""
        return database_service.load_recent_alerts(
            limit=limit,
            offset=offset,
            severity=severity,
            action=action,
        )

    def get_unacknowledged_alerts(self, limit: int = 50) -> list[Alert]:
        """Fetch all unacknowledged alerts."""
        return database_service.load_unacknowledged_alerts(limit=limit)

    def acknowledge_alert(self, alert_id: int) -> bool:
        """Acknowledge a single alert by ID."""
        return database_service.acknowledge_alert(alert_id)

    def acknowledge_all_alerts(self) -> int:
        """Acknowledge all active alerts."""
        return database_service.acknowledge_all_alerts()

    def get_unacknowledged_count(self) -> int:
        """Count unacknowledged alerts."""
        return database_service.get_unacknowledged_alert_count()

    def get_stats(self) -> dict[str, int]:
        """Get aggregate alert counters breakdown."""
        return database_service.get_alert_counts()


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
alert_manager: AlertManager = AlertManager()
