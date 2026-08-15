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
from datetime import datetime
from typing import Optional

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
        now = datetime.utcnow().isoformat(timespec="seconds")
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
        now = datetime.utcnow().isoformat(timespec="seconds")
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
            INSERT INTO alerts (timestamp, severity, message, acknowledged)
            VALUES (?, ?, ?, ?);
            """,
            (
                alert.timestamp,
                alert.severity.value,
                alert.message,
                int(alert.acknowledged),
            ),
        )
        self._db.connection.commit()
        return cursor.lastrowid

    def get_unacknowledged_alert_count(self) -> int:
        """Return the count of unacknowledged alerts."""
        cursor = self._db.connection.execute(
            "SELECT COUNT(*) FROM alerts WHERE acknowledged = 0;"
        )
        return cursor.fetchone()[0]

    # ------------------------------------------------------------------ #
    #  Health check                                                        #
    # ------------------------------------------------------------------ #

    def health_check(self) -> bool:
        """
        Verify the database is reachable and the schema is complete.

        Returns:
            True if all four expected tables exist, False otherwise.
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
