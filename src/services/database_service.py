"""
VoltGuard — Database Service
==============================
Singleton service that wraps ``DatabaseManager`` and exposes typed
CRUD operations for all four schema tables.

This is the only layer that other parts of the application (UI, core)
should use to interact with the database.  No raw SQL should appear
outside this module or ``db_manager.py``.

Usage:
    from src.services.database_service import database_service

    database_service.initialize()
    database_service.save_event_log(event)
    settings = database_service.load_all_settings()
"""

from __future__ import annotations

import sqlite3
from datetime import datetime, timezone
from typing import Any, Optional

from src.database.db_manager import DatabaseManager
from src.models.app_models import (
    Alert,
    AlertSeverity,
    ApplicationSetting,
    EventLog,
    LogLevel,
    PacketAction,
    PacketLog,
)
from src.models.security_event import SecurityEvent


class _DatabaseService:
    """
    High-level database service for VoltGuard.

    Wraps ``DatabaseManager`` and provides typed, named methods for
    every database operation the application needs.  This keeps raw
    SQL confined to this single service file and keeps the rest of the
    codebase free from database concerns.
    """

    def __init__(self) -> None:
        self._db: DatabaseManager = DatabaseManager()
        self._initialized: bool = False

    # ------------------------------------------------------------------ #
    #  Lifecycle                                                           #
    # ------------------------------------------------------------------ #

    def initialize(self) -> bool:
        """
        Open the database and apply the schema.

        Returns:
            True on success, False if an error occurred.
        """
        if self._initialized:
            return True
        try:
            self._db.initialize()
            self._initialized = True
            return True
        except sqlite3.Error:
            return False

    def close(self) -> None:
        """Gracefully close the underlying database connection."""
        self._db.close()
        self._initialized = False

    @property
    def is_ready(self) -> bool:
        """True if the service has been successfully initialised."""
        return self._initialized

    @property
    def db_path(self) -> str:
        """Return the filesystem path of the database file as a string."""
        return str(self._db.db_path)

    # ------------------------------------------------------------------ #
    #  application_settings                                                #
    # ------------------------------------------------------------------ #

    def load_all_settings(self) -> dict[str, str]:
        """
        Load all key-value pairs from ``application_settings``.

        Returns:
            A plain dict mapping setting keys to their string values.
        """
        cursor = self._db.connection.execute(
            "SELECT key, value FROM application_settings;"
        )
        return {row["key"]: row["value"] for row in cursor.fetchall()}

    def save_setting(self, key: str, value: str) -> None:
        """
        Upsert a single setting into ``application_settings``.

        Args:
            key:   Setting identifier (unique).
            value: String value to store.
        """
        now = datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
        self._db.connection.execute(
            """
            INSERT INTO application_settings (key, value, updated_at)
            VALUES (?, ?, ?)
            ON CONFLICT(key) DO UPDATE SET value = excluded.value,
                                           updated_at = excluded.updated_at;
            """,
            (key, value, now),
        )
        self._db.connection.commit()

    def seed_default_settings(self, defaults: dict[str, str]) -> None:
        """
        Insert default settings only for keys that do not yet exist.

        Args:
            defaults: Mapping of setting key → default string value.
        """
        now = datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
        for key, value in defaults.items():
            self._db.connection.execute(
                """
                INSERT OR IGNORE INTO application_settings (key, value, updated_at)
                VALUES (?, ?, ?);
                """,
                (key, value, now),
            )
        self._db.connection.commit()

    # ------------------------------------------------------------------ #
    #  event_logs                                                          #
    # ------------------------------------------------------------------ #

    def save_event_log(self, event: EventLog) -> int:
        """
        Persist an event log record to the database.

        Args:
            event: Populated ``EventLog`` dataclass instance.

        Returns:
            The newly assigned row ID.
        """
        cursor = self._db.connection.execute(
            """
            INSERT INTO event_logs (timestamp, level, source, message)
            VALUES (?, ?, ?, ?);
            """,
            (event.timestamp, event.level.value, event.source, event.message),
        )
        self._db.connection.commit()
        return cursor.lastrowid

    def load_recent_events(self, limit: int = 100) -> list[EventLog]:
        """
        Retrieve the most recent event log entries.

        Args:
            limit: Maximum number of rows to return (newest first).

        Returns:
            List of ``EventLog`` instances ordered by timestamp descending.
        """
        cursor = self._db.connection.execute(
            """
            SELECT id, timestamp, level, source, message
            FROM event_logs
            ORDER BY id DESC
            LIMIT ?;
            """,
            (limit,),
        )
        return [
            EventLog(
                id=row["id"],
                timestamp=row["timestamp"],
                level=LogLevel(row["level"]),
                source=row["source"] or "",
                message=row["message"],
            )
            for row in cursor.fetchall()
        ]

    # ------------------------------------------------------------------ #
    #  packet_logs                                                         #
    # ------------------------------------------------------------------ #

    def save_packet_log(self, packet: PacketLog) -> int:
        """
        Persist a packet inspection record.

        Args:
            packet: Populated ``PacketLog`` dataclass instance.

        Returns:
            The newly assigned row ID.
        """
        cursor = self._db.connection.execute(
            """
            INSERT INTO packet_logs
                (timestamp, src_ip, dst_ip, protocol, port, action, risk_score, raw_data)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                packet.timestamp,
                packet.src_ip,
                packet.dst_ip,
                packet.protocol,
                packet.port,
                packet.action.value,
                packet.risk_score,
                packet.raw_data,
            ),
        )
        self._db.connection.commit()
        return cursor.lastrowid

    def get_packet_count(self) -> int:
        """Return the total number of packet log records in the database."""
        cursor = self._db.connection.execute(
            "SELECT COUNT(*) FROM packet_logs;"
        )
        return cursor.fetchone()[0]

    # ------------------------------------------------------------------ #
    #  alerts                                                              #
    # ------------------------------------------------------------------ #

    def save_alert(self, alert: Alert) -> int:
        """
        Persist a security alert record.

        Args:
            alert: Populated ``Alert`` dataclass instance.

        Returns:
            The newly assigned row ID.
        """
        cursor = self._db.connection.execute(
            """
            INSERT INTO alerts (
                timestamp, severity, message, acknowledged,
                source_ip, destination_ip, protocol, function_code,
                action, risk_score, policy_id, event_id, repeat_count
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                alert.timestamp,
                alert.severity.value,
                alert.message,
                int(alert.acknowledged),
                alert.source_ip,
                alert.destination_ip,
                alert.protocol,
                alert.function_code,
                alert.action,
                alert.risk_score,
                alert.policy_id,
                alert.event_id,
                alert.repeat_count,
            ),
        )
        self._db.connection.commit()
        alert.id = cursor.lastrowid
        return cursor.lastrowid

    def get_alert(self, alert_id: int) -> Optional[Alert]:
        """Retrieve a single alert by primary key ID."""
        cursor = self._db.connection.execute(
            """
            SELECT id, timestamp, severity, message, acknowledged,
                   source_ip, destination_ip, protocol, function_code,
                   action, risk_score, policy_id, event_id, repeat_count
            FROM alerts
            WHERE id = ?;
            """,
            (alert_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return self._row_to_alert(row)

    def load_recent_alerts(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: Optional[str] = None,
        action: Optional[str] = None,
    ) -> list[Alert]:
        """
        Retrieve recent alerts, optionally filtered by severity or action.

        Args:
            limit: Max records to return.
            offset: SQL offset.
            severity: Optional AlertSeverity value string.
            action: Optional action string.

        Returns:
            List of ``Alert`` objects ordered newest first.
        """
        query = """
            SELECT id, timestamp, severity, message, acknowledged,
                   source_ip, destination_ip, protocol, function_code,
                   action, risk_score, policy_id, event_id, repeat_count
            FROM alerts
        """
        conditions: list[str] = []
        params: list[Any] = []

        if severity:
            conditions.append("severity = ?")
            params.append(severity.upper())
        if action:
            conditions.append("action = ?")
            params.append(action.upper())

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY id DESC LIMIT ? OFFSET ?;"
        params.extend([limit, offset])

        cursor = self._db.connection.execute(query, tuple(params))
        return [self._row_to_alert(row) for row in cursor.fetchall()]

    def load_unacknowledged_alerts(self, limit: int = 100) -> list[Alert]:
        """Retrieve all unacknowledged alerts (newest first)."""
        cursor = self._db.connection.execute(
            """
            SELECT id, timestamp, severity, message, acknowledged,
                   source_ip, destination_ip, protocol, function_code,
                   action, risk_score, policy_id, event_id, repeat_count
            FROM alerts
            WHERE acknowledged = 0
            ORDER BY id DESC
            LIMIT ?;
            """,
            (limit,),
        )
        return [self._row_to_alert(row) for row in cursor.fetchall()]

    def acknowledge_alert(self, alert_id: int) -> bool:
        """
        Acknowledge an alert by ID.

        Returns:
            True if an alert was found and updated, False otherwise.
        """
        cursor = self._db.connection.execute(
            "UPDATE alerts SET acknowledged = 1 WHERE id = ?;",
            (alert_id,),
        )
        self._db.connection.commit()
        return cursor.rowcount > 0

    def acknowledge_all_alerts(self) -> int:
        """
        Acknowledge all unacknowledged alerts.

        Returns:
            Total number of alerts updated.
        """
        cursor = self._db.connection.execute(
            "UPDATE alerts SET acknowledged = 1 WHERE acknowledged = 0;"
        )
        self._db.connection.commit()
        return cursor.rowcount

    def update_alert_repeat(self, alert_id: int, repeat_count: int, timestamp: str) -> bool:
        """Update the repeat count and timestamp of an existing alert for deduplication."""
        cursor = self._db.connection.execute(
            "UPDATE alerts SET repeat_count = ?, timestamp = ? WHERE id = ?;",
            (repeat_count, timestamp, alert_id),
        )
        self._db.connection.commit()
        return cursor.rowcount > 0

    def get_unacknowledged_alert_count(self) -> int:
        """Return the count of unacknowledged alerts."""
        cursor = self._db.connection.execute(
            "SELECT COUNT(*) FROM alerts WHERE acknowledged = 0;"
        )
        return cursor.fetchone()[0]

    def get_alert_counts(self) -> dict[str, int]:
        """
        Return a summary dictionary of alert statistics.

        Returns:
            Dict containing total, unacknowledged, critical, high, medium, low, blocked counts.
        """
        cursor = self._db.connection.execute(
            """
            SELECT
                COUNT(*) as total,
                SUM(CASE WHEN acknowledged = 0 THEN 1 ELSE 0 END) as unack,
                SUM(CASE WHEN severity = 'CRITICAL' THEN 1 ELSE 0 END) as critical,
                SUM(CASE WHEN severity = 'HIGH' THEN 1 ELSE 0 END) as high,
                SUM(CASE WHEN severity = 'MEDIUM' THEN 1 ELSE 0 END) as medium,
                SUM(CASE WHEN severity = 'LOW' THEN 1 ELSE 0 END) as low,
                SUM(CASE WHEN action = 'BLOCK' THEN 1 ELSE 0 END) as blocked
            FROM alerts;
            """
        )
        row = cursor.fetchone()
        return {
            "total": row["total"] or 0,
            "unacknowledged": row["unack"] or 0,
            "critical": row["critical"] or 0,
            "high": row["high"] or 0,
            "medium": row["medium"] or 0,
            "low": row["low"] or 0,
            "blocked": row["blocked"] or 0,
        }

    def _row_to_alert(self, row: sqlite3.Row) -> Alert:
        """Helper to construct an Alert dataclass from an SQLite row."""
        try:
            sev = AlertSeverity(row["severity"])
        except ValueError:
            sev = AlertSeverity.LOW
        return Alert(
            id=row["id"],
            timestamp=row["timestamp"],
            severity=sev,
            message=row["message"],
            acknowledged=bool(row["acknowledged"]),
            source_ip=row["source_ip"] or "" if "source_ip" in row.keys() else "",
            destination_ip=row["destination_ip"] or "" if "destination_ip" in row.keys() else "",
            protocol=row["protocol"] or "" if "protocol" in row.keys() else "",
            function_code=row["function_code"] if "function_code" in row.keys() else None,
            action=row["action"] or "" if "action" in row.keys() else "",
            risk_score=row["risk_score"] or 0 if "risk_score" in row.keys() else 0,
            policy_id=row["policy_id"] if "policy_id" in row.keys() else None,
            event_id=row["event_id"] if "event_id" in row.keys() else None,
            repeat_count=row["repeat_count"] if "repeat_count" in row.keys() and row["repeat_count"] is not None else 1,
        )

    # ------------------------------------------------------------------ #
    #  security_events                                                     #
    # ------------------------------------------------------------------ #

    def save_security_event(self, event: SecurityEvent) -> int:
        """
        Persist a structured SecurityEvent to the database.

        Args:
            event: Populated ``SecurityEvent`` dataclass instance.

        Returns:
            Assigned database row ID.
        """
        cursor = self._db.connection.execute(
            """
            INSERT INTO security_events (
                event_id, timestamp, source_ip, destination_ip,
                source_port, destination_port, protocol, function_code,
                function_name, risk_score, risk_level, original_decision,
                matched_policy_id, matched_policy_name, policy_priority,
                final_action, reason, event_type, severity, acknowledged
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?);
            """,
            (
                event.event_id,
                event.timestamp,
                event.source_ip,
                event.destination_ip,
                event.source_port,
                event.destination_port,
                event.protocol,
                event.function_code,
                event.function_name,
                event.risk_score,
                event.risk_level,
                event.original_decision,
                event.matched_policy_id,
                event.matched_policy_name,
                event.policy_priority,
                event.final_action,
                event.reason,
                event.event_type,
                event.severity.value,
                int(event.acknowledged),
            ),
        )
        self._db.connection.commit()
        event.id = cursor.lastrowid
        return cursor.lastrowid

    def get_security_event(self, event_id: int) -> Optional[SecurityEvent]:
        """Retrieve a security event by database row ID."""
        cursor = self._db.connection.execute(
            "SELECT * FROM security_events WHERE id = ?;",
            (event_id,),
        )
        row = cursor.fetchone()
        if row is None:
            return None
        return self._row_to_security_event(row)

    def load_recent_security_events(
        self,
        limit: int = 100,
        offset: int = 0,
        severity: Optional[str] = None,
        final_action: Optional[str] = None,
    ) -> list[SecurityEvent]:
        """
        Retrieve recent security events, newest first.

        Args:
            limit: Maximum records to return.
            offset: Offset for pagination.
            severity: Optional filter by AlertSeverity.
            final_action: Optional filter by final action ('ALLOW', 'ALERT', 'BLOCK').

        Returns:
            List of ``SecurityEvent`` instances.
        """
        query = "SELECT * FROM security_events"
        conditions: list[str] = []
        params: list[Any] = []

        if severity:
            conditions.append("severity = ?")
            params.append(severity.upper())
        if final_action:
            conditions.append("final_action = ?")
            params.append(final_action.upper())

        if conditions:
            query += " WHERE " + " AND ".join(conditions)

        query += " ORDER BY id DESC LIMIT ? OFFSET ?;"
        params.extend([limit, offset])

        cursor = self._db.connection.execute(query, tuple(params))
        return [self._row_to_security_event(row) for row in cursor.fetchall()]

    def acknowledge_security_event(self, event_id: int) -> bool:
        """Acknowledge a security event by row ID."""
        cursor = self._db.connection.execute(
            "UPDATE security_events SET acknowledged = 1 WHERE id = ?;",
            (event_id,),
        )
        self._db.connection.commit()
        return cursor.rowcount > 0

    def get_security_event_count(self) -> int:
        """Return total count of security events."""
        cursor = self._db.connection.execute(
            "SELECT COUNT(*) FROM security_events;"
        )
        return cursor.fetchone()[0]

    def _row_to_security_event(self, row: sqlite3.Row) -> SecurityEvent:
        """Helper to construct a SecurityEvent from an SQLite row."""
        try:
            sev = AlertSeverity(row["severity"])
        except ValueError:
            sev = AlertSeverity.LOW
        return SecurityEvent(
            id=row["id"],
            event_id=row["event_id"],
            timestamp=row["timestamp"],
            source_ip=row["source_ip"] or "unknown",
            destination_ip=row["destination_ip"] or "unknown",
            source_port=row["source_port"] or 0,
            destination_port=row["destination_port"] or 0,
            protocol=row["protocol"] or "Modbus TCP",
            function_code=row["function_code"],
            function_name=row["function_name"] or "",
            risk_score=row["risk_score"] or 0,
            risk_level=row["risk_level"] or "SAFE",
            original_decision=row["original_decision"] or "ALLOW",
            matched_policy_id=row["matched_policy_id"],
            matched_policy_name=row["matched_policy_name"],
            policy_priority=row["policy_priority"],
            final_action=row["final_action"] or "ALLOW",
            reason=row["reason"] or "",
            event_type=row["event_type"] or "SECURITY_EVENT",
            severity=sev,
            acknowledged=bool(row["acknowledged"]),
        )

    # ------------------------------------------------------------------ #
    #  Health check                                                        #
    # ------------------------------------------------------------------ #

    def health_check(self) -> bool:
        """
        Verify the database is reachable and the schema is complete.

        Returns:
            True if all expected tables exist, False otherwise.
        """
        try:
            tables = set(self._db.get_table_names())
            expected = {"packet_logs", "alerts", "application_settings", "event_logs"}
            return expected.issubset(tables)
        except sqlite3.Error:
            return False


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
database_service: _DatabaseService = _DatabaseService()
