"""
VoltGuard Database Module
--------------------------
Manages SQLite persistence for:
  - packet_logs    — captured packet records
  - scan_history   — past scan sessions
  - alerts         — security events
  - settings       — key/value application settings
"""

import sqlite3
import threading
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from core.logger import get_logger

log = get_logger(__name__)

DB_PATH = Path(__file__).resolve().parent.parent / "database" / "voltguard.db"


# ---------------------------------------------------------------------------
# Schema definitions
# ---------------------------------------------------------------------------

SCHEMA_SQL = """
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS packet_logs (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    src_ip          TEXT    NOT NULL,
    dst_ip          TEXT    NOT NULL,
    src_port        INTEGER,
    dst_port        INTEGER,
    protocol        TEXT,
    function_code   INTEGER,
    payload_length  INTEGER,
    action          TEXT    NOT NULL DEFAULT 'ALLOWED',
    raw_summary     TEXT
);

CREATE TABLE IF NOT EXISTS scan_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id      TEXT    NOT NULL,
    interface       TEXT    NOT NULL,
    start_time      TEXT    NOT NULL,
    end_time        TEXT,
    total_packets   INTEGER DEFAULT 0,
    blocked_packets INTEGER DEFAULT 0,
    allowed_packets INTEGER DEFAULT 0,
    status          TEXT    DEFAULT 'RUNNING'
);

CREATE TABLE IF NOT EXISTS alerts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL,
    event_type      TEXT    NOT NULL,
    severity        TEXT    NOT NULL DEFAULT 'HIGH',
    src_ip          TEXT,
    dst_ip          TEXT,
    description     TEXT,
    acknowledged    INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS settings (
    key             TEXT    PRIMARY KEY,
    value           TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL
);
"""

# Default application settings
DEFAULT_SETTINGS: Dict[str, str] = {
    "interface": "auto",
    "dark_mode": "true",
    "logging_level": "INFO",
    "safe_pressure_min": "0.0",
    "safe_pressure_max": "100.0",
    "safe_flow_min": "0.0",
    "safe_flow_max": "50.0",
    "safe_temperature_min": "-20.0",
    "safe_temperature_max": "150.0",
    "safe_rpm_min": "0.0",
    "safe_rpm_max": "3600.0",
    "app_version": "1.0.0",
    "auto_start_capture": "false",
    "max_packet_log_rows": "10000",
    "alert_on_unknown_protocol": "true",
}


class DatabaseManager:
    """Thread-safe SQLite manager for VoltGuard.

    Uses a per-thread connection pool so the GUI and capture threads can
    safely share the same :class:`DatabaseManager` instance.
    """

    def __init__(self, db_path: Optional[Path] = None) -> None:
        self._db_path: Path = db_path or DB_PATH
        self._local = threading.local()  # thread-local connection storage
        self._lock = threading.Lock()    # serialise DDL / bulk writes if needed
        self._initialise()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _connection(self) -> sqlite3.Connection:
        """Return the thread-local SQLite connection, creating it if necessary."""
        if not hasattr(self._local, "conn") or self._local.conn is None:
            self._db_path.parent.mkdir(parents=True, exist_ok=True)
            conn = sqlite3.connect(str(self._db_path), check_same_thread=False)
            conn.row_factory = sqlite3.Row
            self._local.conn = conn
        return self._local.conn

    def _cursor(self) -> sqlite3.Cursor:
        return self._connection().cursor()

    def _commit(self) -> None:
        self._connection().commit()

    def _initialise(self) -> None:
        """Apply schema and seed default settings on first run."""
        log.info("Initialising SQLite database at %s", self._db_path)
        cursor = self._cursor()
        cursor.executescript(SCHEMA_SQL)
        self._commit()
        self._seed_defaults()
        log.info("Database initialised successfully.")

    def _seed_defaults(self) -> None:
        """Insert default settings only if the key does not yet exist."""
        now = _now()
        cursor = self._cursor()
        for key, value in DEFAULT_SETTINGS.items():
            cursor.execute(
                "INSERT OR IGNORE INTO settings (key, value, updated_at) VALUES (?, ?, ?)",
                (key, value, now),
            )
        self._commit()

    # ------------------------------------------------------------------
    # Settings API
    # ------------------------------------------------------------------

    def get_setting(self, key: str, default: Optional[str] = None) -> Optional[str]:
        """Retrieve a setting value by key.

        Args:
            key:     Setting name.
            default: Fallback if the key is not found.
        """
        row = self._cursor().execute(
            "SELECT value FROM settings WHERE key = ?", (key,)
        ).fetchone()
        return row["value"] if row else default

    def set_setting(self, key: str, value: str) -> None:
        """Upsert a setting value.

        Args:
            key:   Setting name.
            value: New value (always stored as text).
        """
        self._cursor().execute(
            """INSERT INTO settings (key, value, updated_at)
               VALUES (?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at""",
            (key, value, _now()),
        )
        self._commit()

    def get_all_settings(self) -> Dict[str, str]:
        """Return all settings as a plain dictionary."""
        rows = self._cursor().execute("SELECT key, value FROM settings").fetchall()
        return {row["key"]: row["value"] for row in rows}

    # ------------------------------------------------------------------
    # Packet log API
    # ------------------------------------------------------------------

    def insert_packet_log(
        self,
        src_ip: str,
        dst_ip: str,
        src_port: Optional[int],
        dst_port: Optional[int],
        protocol: Optional[str],
        function_code: Optional[int],
        payload_length: Optional[int],
        action: str = "ALLOWED",
        raw_summary: Optional[str] = None,
    ) -> int:
        """Persist a captured packet record.

        Returns:
            The ``rowid`` of the newly inserted row.
        """
        cursor = self._cursor()
        cursor.execute(
            """INSERT INTO packet_logs
               (timestamp, src_ip, dst_ip, src_port, dst_port, protocol,
                function_code, payload_length, action, raw_summary)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                _now(),
                src_ip,
                dst_ip,
                src_port,
                dst_port,
                protocol,
                function_code,
                payload_length,
                action,
                raw_summary,
            ),
        )
        self._commit()
        return cursor.lastrowid  # type: ignore[return-value]

    def get_recent_packets(self, limit: int = 100) -> List[sqlite3.Row]:
        """Fetch the most recent packet records.

        Args:
            limit: Maximum number of rows to return.
        """
        return (
            self._cursor()
            .execute(
                "SELECT * FROM packet_logs ORDER BY id DESC LIMIT ?", (limit,)
            )
            .fetchall()
        )

    def get_packet_stats(self) -> Dict[str, int]:
        """Return aggregate packet counters."""
        row = self._cursor().execute(
            """SELECT
                 COUNT(*)                            AS total,
                 SUM(action = 'ALLOWED')             AS allowed,
                 SUM(action = 'BLOCKED')             AS blocked
               FROM packet_logs"""
        ).fetchone()
        return {
            "total": row["total"] or 0,
            "allowed": row["allowed"] or 0,
            "blocked": row["blocked"] or 0,
        }

    # ------------------------------------------------------------------
    # Scan session API
    # ------------------------------------------------------------------

    def start_scan_session(self, session_id: str, interface: str) -> int:
        """Create a new scan session record.

        Args:
            session_id: Unique identifier (UUID) for the session.
            interface:  Network interface name.

        Returns:
            Primary key of the new session row.
        """
        cursor = self._cursor()
        cursor.execute(
            """INSERT INTO scan_history (session_id, interface, start_time, status)
               VALUES (?, ?, ?, 'RUNNING')""",
            (session_id, interface, _now()),
        )
        self._commit()
        return cursor.lastrowid  # type: ignore[return-value]

    def end_scan_session(
        self,
        session_id: str,
        total_packets: int,
        blocked_packets: int,
        allowed_packets: int,
    ) -> None:
        """Mark a scan session as finished.

        Args:
            session_id:      Session UUID.
            total_packets:   Grand total captured.
            blocked_packets: Number blocked.
            allowed_packets: Number allowed.
        """
        self._cursor().execute(
            """UPDATE scan_history
               SET end_time = ?, total_packets = ?, blocked_packets = ?,
                   allowed_packets = ?, status = 'FINISHED'
               WHERE session_id = ?""",
            (_now(), total_packets, blocked_packets, allowed_packets, session_id),
        )
        self._commit()

    def get_scan_history(self, limit: int = 50) -> List[sqlite3.Row]:
        """Fetch recent scan sessions."""
        return (
            self._cursor()
            .execute(
                "SELECT * FROM scan_history ORDER BY id DESC LIMIT ?", (limit,)
            )
            .fetchall()
        )

    # ------------------------------------------------------------------
    # Alerts API
    # ------------------------------------------------------------------

    def insert_alert(
        self,
        event_type: str,
        severity: str,
        src_ip: Optional[str] = None,
        dst_ip: Optional[str] = None,
        description: Optional[str] = None,
    ) -> int:
        """Record a security alert.

        Args:
            event_type:  Short category label (e.g. "MODBUS_VIOLATION").
            severity:    LOW | MEDIUM | HIGH | CRITICAL.
            src_ip:      Source IP involved in the event.
            dst_ip:      Destination IP involved in the event.
            description: Human-readable detail.

        Returns:
            Primary key of the new alert row.
        """
        cursor = self._cursor()
        cursor.execute(
            """INSERT INTO alerts (timestamp, event_type, severity, src_ip, dst_ip, description)
               VALUES (?, ?, ?, ?, ?, ?)""",
            (_now(), event_type, severity, src_ip, dst_ip, description),
        )
        self._commit()
        return cursor.lastrowid  # type: ignore[return-value]

    def get_recent_alerts(self, limit: int = 50) -> List[sqlite3.Row]:
        """Fetch the most recent alerts."""
        return (
            self._cursor()
            .execute(
                "SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,)
            )
            .fetchall()
        )

    def acknowledge_alert(self, alert_id: int) -> None:
        """Mark a single alert as acknowledged."""
        self._cursor().execute(
            "UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,)
        )
        self._commit()

    def get_unacknowledged_alert_count(self) -> int:
        """Return the number of unacknowledged alerts."""
        row = (
            self._cursor()
            .execute("SELECT COUNT(*) AS cnt FROM alerts WHERE acknowledged = 0")
            .fetchone()
        )
        return row["cnt"] if row else 0

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def close(self) -> None:
        """Close the thread-local connection if open."""
        if hasattr(self._local, "conn") and self._local.conn:
            self._local.conn.close()
            self._local.conn = None

    def __repr__(self) -> str:
        return f"<DatabaseManager path={self._db_path}>"


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_db_instance: Optional[DatabaseManager] = None
_instance_lock = threading.Lock()


def get_db() -> DatabaseManager:
    """Return the application-wide :class:`DatabaseManager` singleton."""
    global _db_instance
    if _db_instance is None:
        with _instance_lock:
            if _db_instance is None:
                _db_instance = DatabaseManager()
    return _db_instance


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _now() -> str:
    """Return current UTC timestamp as ISO-8601 string."""
    return datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S")
