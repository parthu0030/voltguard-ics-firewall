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

_ALL_TABLES: list[str] = [
    _CREATE_PACKET_LOGS,
    _CREATE_ALERTS,
    _CREATE_APPLICATION_SETTINGS,
    _CREATE_EVENT_LOGS,
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

    def __init__(self) -> None:
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
            str(DB_PATH),
            check_same_thread=False,
        )
        self._connection.row_factory = sqlite3.Row

        # Enable WAL mode for better concurrent read performance.
        self._connection.execute("PRAGMA journal_mode=WAL;")

        # Enable foreign-key constraints.
        self._connection.execute("PRAGMA foreign_keys=ON;")

        self._run_migrations()
        self._initialized = True

    def _run_migrations(self) -> None:
        """Execute all CREATE TABLE IF NOT EXISTS statements."""
        cursor = self._connection.cursor()
        for ddl in _ALL_TABLES:
            cursor.execute(ddl)
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
        return DB_PATH

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
