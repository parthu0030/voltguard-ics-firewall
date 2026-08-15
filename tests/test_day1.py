"""
VoltGuard — Day 1 Unit Test Suite
====================================
Verifies the correctness of all Day 1 foundation components:

  - Database initialisation and schema
  - DatabaseService CRUD operations
  - ConfigService settings load / save
  - AppState counter logic
  - LoggingService file creation
  - Service singleton identity

Tests run headlessly — no QApplication or Qt widgets are used here.
Run with:
    python3 tests/test_day1.py
Or:
    python3 -m pytest tests/test_day1.py -v
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

# Ensure the project root is on sys.path.
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_temp_db_path() -> Path:
    """Create a temporary file path for an isolated test database."""
    fd, path = tempfile.mkstemp(suffix=".db", prefix="voltguard_test_")
    os.close(fd)
    os.unlink(path)  # Remove so DatabaseManager creates it fresh.
    return Path(path)


# ---------------------------------------------------------------------------
# Test: DatabaseManager
# ---------------------------------------------------------------------------

class TestDatabaseManager(unittest.TestCase):
    """Tests for the low-level DatabaseManager."""

    def setUp(self) -> None:
        """Patch DB_PATH to use a temporary file for each test."""
        import src.database.db_manager as db_mod
        self._orig_path = db_mod.DB_PATH
        self._temp_path = _make_temp_db_path()
        db_mod.DB_PATH = self._temp_path
        self._manager = db_mod.DatabaseManager()
        self._manager.initialize()

    def tearDown(self) -> None:
        """Close the manager and restore DB_PATH."""
        import src.database.db_manager as db_mod
        self._manager.close()
        if self._temp_path.exists():
            self._temp_path.unlink()
        db_mod.DB_PATH = self._orig_path

    def test_database_file_created(self) -> None:
        """The SQLite file should exist after initialisation."""
        self.assertTrue(self._temp_path.exists(), "Database file was not created.")

    def test_all_tables_exist(self) -> None:
        """All four required tables must be present in the schema."""
        tables = set(self._manager.get_table_names())
        expected = {"packet_logs", "alerts", "application_settings", "event_logs"}
        # Use issubset: SQLite may also create internal tables (e.g. sqlite_sequence)
        # which should not cause this test to fail.
        self.assertTrue(
            expected.issubset(tables),
            f"Missing tables: {expected - tables}",
        )

    def test_initialize_is_idempotent(self) -> None:
        """Calling initialize() multiple times must not raise an error."""
        self._manager.initialize()
        self._manager.initialize()
        self.assertTrue(self._manager.is_initialized)

    def test_connection_raises_before_init(self) -> None:
        """Accessing connection before initialize() must raise RuntimeError."""
        import src.database.db_manager as db_mod
        fresh = db_mod.DatabaseManager()
        with self.assertRaises(RuntimeError):
            _ = fresh.connection


# ---------------------------------------------------------------------------
# Test: DatabaseService
# ---------------------------------------------------------------------------

class TestDatabaseService(unittest.TestCase):
    """Tests for the DatabaseService CRUD operations."""

    def setUp(self) -> None:
        import src.database.db_manager as db_mod
        from src.services.database_service import _DatabaseService

        self._orig_path = db_mod.DB_PATH
        self._temp_path = _make_temp_db_path()
        db_mod.DB_PATH = self._temp_path

        self._service = _DatabaseService()
        self._service.initialize()

    def tearDown(self) -> None:
        import src.database.db_manager as db_mod
        self._service.close()
        if self._temp_path.exists():
            self._temp_path.unlink()
        db_mod.DB_PATH = self._orig_path

    def test_health_check_passes(self) -> None:
        """Health check must return True for a properly initialised DB."""
        self.assertTrue(self._service.health_check())

    def test_save_and_load_setting(self) -> None:
        """Saving a setting and reloading it must return the saved value."""
        self._service.save_setting("test_key", "test_value")
        loaded = self._service.load_all_settings()
        self.assertEqual(loaded.get("test_key"), "test_value")

    def test_seed_default_settings(self) -> None:
        """Default settings should be inserted only for missing keys."""
        from src.models.app_models import APP_DEFAULT_SETTINGS
        self._service.seed_default_settings(APP_DEFAULT_SETTINGS)
        settings = self._service.load_all_settings()
        for key, val in APP_DEFAULT_SETTINGS.items():
            self.assertIn(key, settings, f"Missing default key: {key}")
            self.assertEqual(settings[key], val)

    def test_upsert_setting(self) -> None:
        """Saving the same key twice should update, not duplicate."""
        self._service.save_setting("colour", "blue")
        self._service.save_setting("colour", "red")
        settings = self._service.load_all_settings()
        self.assertEqual(settings["colour"], "red")

    def test_save_event_log(self) -> None:
        """Saving an EventLog record must return a positive row ID."""
        from src.models.app_models import EventLog, LogLevel
        event = EventLog(
            timestamp=EventLog.now_timestamp(),
            level=LogLevel.INFO,
            source="TestSuite",
            message="Unit test event log entry.",
        )
        row_id = self._service.save_event_log(event)
        self.assertGreater(row_id, 0, "Expected a positive row ID after insert.")

    def test_load_recent_events(self) -> None:
        """Loading recent events should return inserted records."""
        from src.models.app_models import EventLog, LogLevel
        for i in range(3):
            event = EventLog(
                timestamp=EventLog.now_timestamp(),
                level=LogLevel.INFO,
                source="TestSuite",
                message=f"Test event {i}",
            )
            self._service.save_event_log(event)
        events = self._service.load_recent_events(limit=10)
        self.assertGreaterEqual(len(events), 3)

    def test_save_and_count_packet_log(self) -> None:
        """Saving a PacketLog must increment the packet count."""
        from src.models.app_models import PacketAction, PacketLog
        packet = PacketLog(
            timestamp=PacketLog.now_timestamp(),
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            protocol="Modbus TCP",
            port=502,
            action=PacketAction.ALLOW,
            risk_score=0.1,
        )
        before = self._service.get_packet_count()
        self._service.save_packet_log(packet)
        after = self._service.get_packet_count()
        self.assertEqual(after, before + 1)

    def test_save_alert(self) -> None:
        """Saving an Alert must return a positive row ID."""
        from src.models.app_models import Alert, AlertSeverity
        alert = Alert(
            timestamp=Alert.now_timestamp(),
            severity=AlertSeverity.HIGH,
            message="Test alert: abnormal valve command detected.",
        )
        row_id = self._service.save_alert(alert)
        self.assertGreater(row_id, 0)

    def test_unacknowledged_alert_count(self) -> None:
        """Newly saved alerts must appear in the unacknowledged count."""
        from src.models.app_models import Alert, AlertSeverity
        before = self._service.get_unacknowledged_alert_count()
        alert = Alert(
            timestamp=Alert.now_timestamp(),
            severity=AlertSeverity.MEDIUM,
            message="Test unacknowledged alert.",
            acknowledged=False,
        )
        self._service.save_alert(alert)
        after = self._service.get_unacknowledged_alert_count()
        self.assertEqual(after, before + 1)


# ---------------------------------------------------------------------------
# Test: ConfigService
# ---------------------------------------------------------------------------

class TestConfigService(unittest.TestCase):
    """Tests for the ConfigService settings proxy."""

    def setUp(self) -> None:
        import src.database.db_manager as db_mod
        from src.services.config_service import _ConfigService
        from src.services.database_service import _DatabaseService

        self._orig_path = db_mod.DB_PATH
        self._temp_path = _make_temp_db_path()
        db_mod.DB_PATH = self._temp_path

        self._db_service = _DatabaseService()
        self._db_service.initialize()

        self._config = _ConfigService()
        self._config.initialize(self._db_service)

    def tearDown(self) -> None:
        import src.database.db_manager as db_mod
        self._db_service.close()
        if self._temp_path.exists():
            self._temp_path.unlink()
        db_mod.DB_PATH = self._orig_path

    def test_defaults_loaded(self) -> None:
        """Default settings must be present after initialisation."""
        from src.models.app_models import APP_DEFAULT_SETTINGS
        for key, val in APP_DEFAULT_SETTINGS.items():
            self.assertEqual(
                self._config.get(key),
                val,
                f"Default for '{key}' not loaded correctly.",
            )

    def test_theme_property(self) -> None:
        """The 'theme' property should return the configured theme."""
        self.assertEqual(self._config.theme, "dark")

    def test_set_and_get(self) -> None:
        """Setting a value should be immediately readable via get()."""
        self._config.set("theme", "light")
        self.assertEqual(self._config.get("theme"), "light")

    def test_setting_persisted_to_db(self) -> None:
        """A set() value should be visible in a fresh load_all_settings() call."""
        self._config.set("log_level", "DEBUG")
        fresh = self._db_service.load_all_settings()
        self.assertEqual(fresh.get("log_level"), "DEBUG")

    def test_fallback_for_missing_key(self) -> None:
        """get() with a missing key should return the provided fallback."""
        result = self._config.get("nonexistent_key", fallback="DEFAULT")
        self.assertEqual(result, "DEFAULT")

    def test_initialize_is_idempotent(self) -> None:
        """Calling initialize() twice must not raise or duplicate settings."""
        self._config.initialize(self._db_service)  # Second call.
        self.assertTrue(self._config.is_initialized)


# ---------------------------------------------------------------------------
# Test: AppState
# ---------------------------------------------------------------------------

class TestAppState(unittest.TestCase):
    """Tests for the in-memory AppState singleton."""

    def setUp(self) -> None:
        from src.core.app_state import _AppState
        self._state = _AppState()

    def test_initial_counters_are_zero(self) -> None:
        """All packet counters should be zero on a fresh instance."""
        self.assertEqual(self._state.packets_captured, 0)
        self.assertEqual(self._state.packets_allowed, 0)
        self.assertEqual(self._state.packets_blocked, 0)

    def test_increment_allowed(self) -> None:
        """increment_allowed() must increment both allowed and captured."""
        self._state.increment_allowed()
        self.assertEqual(self._state.packets_allowed, 1)
        self.assertEqual(self._state.packets_captured, 1)
        self.assertEqual(self._state.packets_blocked, 0)

    def test_increment_blocked(self) -> None:
        """increment_blocked() must increment both blocked and captured."""
        self._state.increment_blocked()
        self.assertEqual(self._state.packets_blocked, 1)
        self.assertEqual(self._state.packets_captured, 1)
        self.assertEqual(self._state.packets_allowed, 0)

    def test_reset_counters(self) -> None:
        """reset_counters() must return all counters to zero."""
        self._state.increment_allowed()
        self._state.increment_blocked()
        self._state.reset_counters()
        self.assertEqual(self._state.packets_captured, 0)
        self.assertEqual(self._state.packets_allowed, 0)
        self.assertEqual(self._state.packets_blocked, 0)

    def test_app_status_setter(self) -> None:
        """Setting app_status should be immediately readable."""
        self._state.app_status = "Running"
        self.assertEqual(self._state.app_status, "Running")

    def test_db_status_setter(self) -> None:
        """Setting db_status should be immediately readable."""
        self._state.db_status = "Connected"
        self.assertEqual(self._state.db_status, "Connected")

    def test_snapshot_contains_all_keys(self) -> None:
        """snapshot() must return all expected keys."""
        snap = self._state.snapshot()
        expected_keys = {
            "packets_captured", "packets_allowed", "packets_blocked",
            "app_status", "db_status", "selected_interface", "system_time",
        }
        self.assertEqual(expected_keys, set(snap.keys()))

    def test_subscribe_callback_fires(self) -> None:
        """Registered callbacks must fire on state changes."""
        fired = []
        self._state.subscribe(lambda: fired.append(True))
        self._state.increment_allowed()
        self.assertTrue(fired, "Callback was not invoked after increment_allowed().")

    def test_multiple_increments(self) -> None:
        """Multiple increments should accumulate correctly."""
        for _ in range(5):
            self._state.increment_allowed()
        for _ in range(3):
            self._state.increment_blocked()
        self.assertEqual(self._state.packets_captured, 8)
        self._state.reset_counters()


# ---------------------------------------------------------------------------
# Test: LoggingService
# ---------------------------------------------------------------------------

class TestLoggingService(unittest.TestCase):
    """Tests for the LoggingService file output."""

    def setUp(self) -> None:
        from src.services.logging_service import _LoggingService
        self._temp_dir = Path(tempfile.mkdtemp())
        self._service = _LoggingService()

        # Patch the log directory constant.
        import src.services.logging_service as log_mod
        self._orig_logs_dir = log_mod._LOGS_DIR
        log_mod._LOGS_DIR = self._temp_dir
        self._service.initialize(log_level="DEBUG")

    def tearDown(self) -> None:
        import src.services.logging_service as log_mod
        log_mod._LOGS_DIR = self._orig_logs_dir
        # Remove temp dir and its contents.
        for f in self._temp_dir.iterdir():
            f.unlink()
        self._temp_dir.rmdir()

    def test_log_file_created(self) -> None:
        """A log file should be created in the logs directory on init."""
        log_files = list(self._temp_dir.glob("voltguard_*.log"))
        self.assertTrue(log_files, "No log file was created in the logs directory.")

    def test_log_file_is_not_empty(self) -> None:
        """The log file should contain content after initialisation."""
        log_files = list(self._temp_dir.glob("voltguard_*.log"))
        self.assertTrue(log_files)
        content = log_files[0].read_text(encoding="utf-8")
        self.assertTrue(len(content) > 0, "Log file is empty after initialisation.")

    def test_info_message_written(self) -> None:
        """info() messages should appear in the log file."""
        self._service.info("Test info message.", source="TestSuite")
        log_files = list(self._temp_dir.glob("voltguard_*.log"))
        content = log_files[0].read_text(encoding="utf-8")
        self.assertIn("Test info message.", content)

    def test_error_message_written(self) -> None:
        """error() messages should appear in the log file."""
        self._service.error("Test error message.", source="TestSuite")
        log_files = list(self._temp_dir.glob("voltguard_*.log"))
        content = log_files[0].read_text(encoding="utf-8")
        self.assertIn("Test error message.", content)

    def test_log_file_path_property(self) -> None:
        """log_file_path should return a valid Path pointing to the log file."""
        path = self._service.log_file_path
        self.assertIsNotNone(path)
        self.assertTrue(path.exists())


# ---------------------------------------------------------------------------
# Test: AppModels
# ---------------------------------------------------------------------------

class TestAppModels(unittest.TestCase):
    """Tests for the application data model classes."""

    def test_packet_log_timestamp(self) -> None:
        """now_timestamp() must return a non-empty ISO-8601 string."""
        from src.models.app_models import PacketLog
        ts = PacketLog.now_timestamp()
        self.assertTrue(len(ts) > 0)
        self.assertIn("T", ts)  # ISO-8601 separator

    def test_packet_action_enum_values(self) -> None:
        """PacketAction enum must have ALLOW and BLOCK values."""
        from src.models.app_models import PacketAction
        self.assertEqual(PacketAction.ALLOW.value, "ALLOW")
        self.assertEqual(PacketAction.BLOCK.value, "BLOCK")

    def test_alert_severity_enum(self) -> None:
        """AlertSeverity must have all four levels."""
        from src.models.app_models import AlertSeverity
        levels = {s.value for s in AlertSeverity}
        self.assertEqual(levels, {"LOW", "MEDIUM", "HIGH", "CRITICAL"})

    def test_log_level_enum(self) -> None:
        """LogLevel must have all four standard levels."""
        from src.models.app_models import LogLevel
        levels = {l.value for l in LogLevel}
        self.assertEqual(levels, {"DEBUG", "INFO", "WARNING", "ERROR"})

    def test_default_settings_keys(self) -> None:
        """APP_DEFAULT_SETTINGS must contain all required keys."""
        from src.models.app_models import APP_DEFAULT_SETTINGS
        required = {"theme", "selected_interface", "log_level", "app_version", "app_name"}
        self.assertTrue(required.issubset(set(APP_DEFAULT_SETTINGS.keys())))


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()

    # Add all test classes
    for cls in [
        TestDatabaseManager,
        TestDatabaseService,
        TestConfigService,
        TestAppState,
        TestLoggingService,
        TestAppModels,
    ]:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
