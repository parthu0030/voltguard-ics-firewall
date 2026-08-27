"""
VoltGuard — Database Manager
==============================
Responsible for:
  - Locating / creating the SQLite database file (``voltguard.db``).
  - Creating all four schema tables on first run.
  - Providing a low-level connection factory used by DatabaseService.

This module does NOT contain any business logic.  It is purely a
structural layer.  All higher-level CRUD operations belong in
``DatabaseService``.

Schema tables:
    packet_logs          — Inspected packet records
    alerts               — Security alerts raised by the detection engine
    application_settings — Key-value configuration pairs
    event_logs           — Structured application event log
"""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional


# The database file lives at the project root.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
DB_PATH = _PROJECT_ROOT / "voltguard.db"

# SQL DDL for the four required tables.
_CREATE_PACKET_LOGS = """
CREATE TABLE IF NOT EXISTS packet_logs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp   TEXT    NOT NULL,
    src_ip      TEXT,
    dst_ip      TEXT,
    protocol    TEXT,
    port        INTEGER,
    action      TEXT    CHECK(action IN ('ALLOW', 'BLOCK')),
    risk_score  REAL    DEFAULT 0.0,
    raw_data    BLOB
);
"""

_CREATE_ALERTS = """
CREATE TABLE IF NOT EXISTS alerts (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp    TEXT    NOT NULL,
    severity     TEXT    CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    message      TEXT    NOT NULL,
    acknowledged INTEGER DEFAULT 0
);
"""

_CREATE_APPLICATION_SETTINGS = """
CREATE TABLE IF NOT EXISTS application_settings (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    key        TEXT    NOT NULL UNIQUE,
    value      TEXT,
    updated_at TEXT    NOT NULL
);
"""

_CREATE_EVENT_LOGS = """
CREATE TABLE IF NOT EXISTS event_logs (
    id        INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    level     TEXT CHECK(level IN ('DEBUG', 'INFO', 'WARNING', 'ERROR')),
    source    TEXT,
    message   TEXT NOT NULL
);
"""

_CREATE_SECURITY_EVENTS = """
CREATE TABLE IF NOT EXISTS security_events (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id            TEXT    NOT NULL UNIQUE,
    timestamp           TEXT    NOT NULL,
    source_ip           TEXT,
    destination_ip      TEXT,
    source_port         INTEGER DEFAULT 0,
    destination_port    INTEGER DEFAULT 0,
    protocol            TEXT,
    function_code       INTEGER,
    function_name       TEXT,
    risk_score          INTEGER DEFAULT 0,
    risk_level          TEXT,
    original_decision   TEXT,
    matched_policy_id   TEXT,
    matched_policy_name TEXT,
    policy_priority     INTEGER,
    final_action        TEXT,
    reason              TEXT,
    event_type          TEXT,
    severity            TEXT    CHECK(severity IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL')),
    acknowledged        INTEGER DEFAULT 0
);
"""

_CREATE_PHYSICS_READINGS = """
CREATE TABLE IF NOT EXISTS physics_readings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    pressure_bar REAL NOT NULL, flow_lps REAL NOT NULL,
    temperature_celsius REAL NOT NULL, pump_on INTEGER NOT NULL,
    pump_rpm REAL NOT NULL, valve_position REAL NOT NULL,
    tank_level_m3 REAL NOT NULL
);
"""

_CREATE_INDEXES = [
    "CREATE INDEX IF NOT EXISTS idx_security_events_ts ON security_events(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_security_events_sev ON security_events(severity);",
    "CREATE INDEX IF NOT EXISTS idx_security_events_action ON security_events(final_action);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(timestamp);",
    "CREATE INDEX IF NOT EXISTS idx_alerts_ack ON alerts(acknowledged);",
    "CREATE INDEX IF NOT EXISTS idx_physics_readings_ts ON physics_readings(timestamp);",
]

_ALL_TABLES: list[str] = [
    _CREATE_PACKET_LOGS,
    _CREATE_ALERTS,
    _CREATE_APPLICATION_SETTINGS,
    _CREATE_EVENT_LOGS,
    _CREATE_SECURITY_EVENTS,
    _CREATE_PHYSICS_READINGS,
]


class DatabaseManager:
    """
    Low-level SQLite database manager for VoltGuard.

    Responsibilities:
      - Open and hold a persistent connection to ``voltguard.db``.
      - Run schema migrations (``CREATE TABLE IF NOT EXISTS``).
      - Expose the raw ``sqlite3.Connection`` for use by ``DatabaseService``.
      - Provide safe teardown / close.
    """

    def __init__(self, db_path: Optional[Path | str] = None) -> None:
        self._db_path = Path(db_path) if db_path is not None else DB_PATH
        self._connection: Optional[sqlite3.Connection] = None
        self._initialized: bool = False

    # ------------------------------------------------------------------ #
    #  Lifecycle                                                           #
    # ------------------------------------------------------------------ #

    def initialize(self) -> None:
        """
        Open the database and create all schema tables.

        Safe to call multiple times — subsequent calls are no-ops.

        Raises:
            sqlite3.Error: If the database file cannot be created or opened.
        """
        if self._initialized:
            return

        # ``check_same_thread=False`` is safe here because DatabaseService
        # serialises all access behind its own method calls.
        self._connection = sqlite3.connect(
            str(self._db_path),
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row

        # Enable WAL mode for better concurrent read performance.
        try:
            self._connection.execute("PRAGMA journal_mode=WAL;")
        except sqlite3.Error:
            pass

        # Enable foreign-key constraints.
        self._connection.execute("PRAGMA foreign_keys=ON;")

        self._run_migrations()
        self._initialized = True

    def _run_migrations(self) -> None:
        """Execute all CREATE TABLE and migration statements."""
        cursor = self._connection.cursor()
        for ddl in _ALL_TABLES:
            cursor.execute(ddl)

        # Ensure alerts table has new optional columns if it was created in Day 1
        cursor.execute("PRAGMA table_info(alerts);")
        existing_cols = {row["name"] for row in cursor.fetchall()}
        optional_cols = [
            ("source_ip", "TEXT DEFAULT ''"),
            ("destination_ip", "TEXT DEFAULT ''"),
            ("protocol", "TEXT DEFAULT ''"),
            ("function_code", "INTEGER"),
            ("action", "TEXT DEFAULT ''"),
            ("risk_score", "INTEGER DEFAULT 0"),
            ("policy_id", "TEXT"),
            ("event_id", "TEXT"),
            ("repeat_count", "INTEGER DEFAULT 1"),
        ]
        for col_name, col_def in optional_cols:
            if col_name not in existing_cols:
                try:
                    cursor.execute(f"ALTER TABLE alerts ADD COLUMN {col_name} {col_def};")
                except sqlite3.OperationalError:
                    pass

        for idx_sql in _CREATE_INDEXES:
            cursor.execute(idx_sql)

        self._connection.commit()

    def close(self) -> None:
        """Gracefully close the database connection."""
        if self._connection:
            self._connection.close()
            self._connection = None
            self._initialized = False

    # ------------------------------------------------------------------ #
    #  Connection accessor                                                 #
    # ------------------------------------------------------------------ #

    @property
    def connection(self) -> sqlite3.Connection:
        """
        Return the active SQLite connection.

        Raises:
            RuntimeError: If ``initialize()`` has not been called.
        """
        if not self._initialized or self._connection is None:
            raise RuntimeError(
                "DatabaseManager.initialize() must be called before accessing "
                "the connection."
            )
        return self._connection

    @property
    def db_path(self) -> Path:
        """Return the filesystem path to the database file."""
        return self._db_path

    @property
    def is_initialized(self) -> bool:
        """True if the database has been opened and the schema applied."""
        return self._initialized

    def get_table_names(self) -> list[str]:
        """
        Return a list of all table names present in the database.
        Useful for health checks and tests.
        """
        cursor = self.connection.execute(
            "SELECT name FROM sqlite_master WHERE type='table' ORDER BY name;"
        )
        return [row[0] for row in cursor.fetchall()]
