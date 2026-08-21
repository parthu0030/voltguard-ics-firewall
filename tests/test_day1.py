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
            "packets_captured", "packets_allowed", "packets_alerted", "packets_blocked",
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
# Test: Constants
# ---------------------------------------------------------------------------

class TestConstants(unittest.TestCase):
    """Tests for the src/constants.py module."""

    def test_app_name_is_string(self) -> None:
        """APP_NAME must be a non-empty string."""
        from src.constants import APP_NAME
        self.assertIsInstance(APP_NAME, str)
        self.assertTrue(len(APP_NAME) > 0)

    def test_app_version_format(self) -> None:
        """APP_VERSION must follow semantic versioning (X.Y.Z)."""
        from src.constants import APP_VERSION
        parts = APP_VERSION.split(".")
        self.assertEqual(len(parts), 3, f"Expected 3 parts in version, got: {APP_VERSION}")
        for part in parts:
            self.assertTrue(part.isdigit(), f"Non-numeric version part: {part}")

    def test_project_root_exists(self) -> None:
        """PROJECT_ROOT must point to an existing directory."""
        from src.constants import PROJECT_ROOT
        self.assertTrue(PROJECT_ROOT.is_dir(), f"PROJECT_ROOT does not exist: {PROJECT_ROOT}")

    def test_required_dirs_are_paths(self) -> None:
        """REQUIRED_DIRS must be a list of Path objects."""
        from src.constants import REQUIRED_DIRS
        from pathlib import Path
        self.assertIsInstance(REQUIRED_DIRS, list)
        self.assertTrue(len(REQUIRED_DIRS) > 0)
        for item in REQUIRED_DIRS:
            self.assertIsInstance(item, Path)

    def test_modbus_port_value(self) -> None:
        """MODBUS_PORT must be 502 per the ICS standard."""
        from src.constants import MODBUS_PORT
        self.assertEqual(MODBUS_PORT, 502)

    def test_status_constants(self) -> None:
        """STATUS_PASS, FAIL, WARN must be distinct non-empty strings."""
        from src.constants import STATUS_PASS, STATUS_FAIL, STATUS_WARN
        statuses = [STATUS_PASS, STATUS_FAIL, STATUS_WARN]
        self.assertEqual(len(set(statuses)), 3, "Status constants must be unique.")
        for s in statuses:
            self.assertIsInstance(s, str)
            self.assertTrue(len(s) > 0)

    def test_log_constants(self) -> None:
        """LOG_MAX_BYTES must be positive and LOG_BACKUP_COUNT must be >= 1."""
        from src.constants import LOG_MAX_BYTES, LOG_BACKUP_COUNT
        self.assertGreater(LOG_MAX_BYTES, 0)
        self.assertGreaterEqual(LOG_BACKUP_COUNT, 1)

    def test_risk_score_ordering(self) -> None:
        """Risk score thresholds must be in ascending order."""
        from src.constants import RISK_SCORE_LOW, RISK_SCORE_MEDIUM, RISK_SCORE_HIGH
        self.assertLess(RISK_SCORE_LOW, RISK_SCORE_MEDIUM)
        self.assertLess(RISK_SCORE_MEDIUM, RISK_SCORE_HIGH)


# ---------------------------------------------------------------------------
# Test: Custom Exceptions
# ---------------------------------------------------------------------------

class TestExceptions(unittest.TestCase):
    """Tests for the custom exception hierarchy in src/exceptions.py."""

    def test_base_exception_inherits_exception(self) -> None:
        """VoltGuardError must be a subclass of Exception."""
        from src.exceptions import VoltGuardError
        self.assertTrue(issubclass(VoltGuardError, Exception))

    def test_all_exceptions_inherit_base(self) -> None:
        """All domain exceptions must inherit from VoltGuardError."""
        from src.exceptions import (
            VoltGuardError, ConfigurationError, ParserError,
            PhysicsError, DecisionEngineError, DashboardError,
            HealthCheckError, UnsupportedProtocolError,
            SafetyConstraintViolation, RuleViolationError,
        )
        for exc_class in [
            ConfigurationError, ParserError, PhysicsError,
            DecisionEngineError, DashboardError, HealthCheckError,
        ]:
            self.assertTrue(
                issubclass(exc_class, VoltGuardError),
                f"{exc_class.__name__} does not inherit from VoltGuardError",
            )

    def test_configuration_error_message(self) -> None:
        """ConfigurationError must store and display the message."""
        from src.exceptions import ConfigurationError
        exc = ConfigurationError("Missing key", detail="key=log_level")
        self.assertIn("Missing key", str(exc))
        self.assertEqual(exc.message, "Missing key")
        self.assertEqual(exc.detail, "key=log_level")

    def test_exception_without_detail(self) -> None:
        """Exceptions must work correctly without the optional detail arg."""
        from src.exceptions import ParserError
        exc = ParserError("Bad packet")
        self.assertIsNone(exc.detail)
        self.assertIn("Bad packet", str(exc))

    def test_exception_can_be_raised_and_caught(self) -> None:
        """Exceptions must be raise-able and catch-able as VoltGuardError."""
        from src.exceptions import VoltGuardError, PhysicsError
        with self.assertRaises(VoltGuardError):
            raise PhysicsError("Pressure diverged")

    def test_sub_exception_hierarchy(self) -> None:
        """Sub-exceptions must be catchable via their parent class."""
        from src.exceptions import ParserError, UnsupportedProtocolError
        with self.assertRaises(ParserError):
            raise UnsupportedProtocolError("DNP4 not supported")

    def test_safety_constraint_violation_is_physics_error(self) -> None:
        """SafetyConstraintViolation must be catchable as PhysicsError."""
        from src.exceptions import PhysicsError, SafetyConstraintViolation
        with self.assertRaises(PhysicsError):
            raise SafetyConstraintViolation("Pressure exceeded limit")


# ---------------------------------------------------------------------------
# Test: ConfigLoader
# ---------------------------------------------------------------------------

class TestConfigLoader(unittest.TestCase):
    """Tests for the ConfigLoader in src/config.py."""

    def setUp(self) -> None:
        """Create a temporary directory for isolated config file tests."""
        self._temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self) -> None:
        """Clean up the temporary directory."""
        import shutil
        shutil.rmtree(self._temp_dir, ignore_errors=True)

    def _make_loader(self, content: dict = None) -> object:
        """Create a ConfigLoader pointing at a temp config file."""
        from src.config import ConfigLoader
        config_path = self._temp_dir / "config.json"
        if content is not None:
            import json
            config_path.write_text(json.dumps(content), encoding="utf-8")
        return ConfigLoader(config_path=config_path)

    def test_auto_generate_missing_config(self) -> None:
        """ConfigLoader must auto-generate config.json if it does not exist."""
        from src.config import ConfigLoader
        config_path = self._temp_dir / "nonexistent_config.json"
        loader = ConfigLoader(config_path=config_path)
        loader.load()
        self.assertTrue(config_path.exists(), "config.json was not auto-generated.")
        self.assertTrue(loader.is_loaded)

    def test_load_valid_config(self) -> None:
        """Loading a valid config.json must populate the cache."""
        loader = self._make_loader({
            "app_version": "1.0.0",
            "log_level": "INFO",
            "selected_interface": "eth0",
            "theme": "dark",
            "db_path": "test.db",
            "physics": {"pressure_max_bar": 10.0},
        })
        loader.load()
        self.assertTrue(loader.is_loaded)
        self.assertEqual(loader.get("log_level"), "INFO")
        self.assertEqual(loader.get("selected_interface"), "eth0")

    def test_invalid_json_raises_configuration_error(self) -> None:
        """A malformed JSON file must raise ConfigurationError."""
        from src.exceptions import ConfigurationError
        config_path = self._temp_dir / "bad.json"
        config_path.write_text("{not: valid json", encoding="utf-8")
        from src.config import ConfigLoader
        loader = ConfigLoader(config_path=config_path)
        with self.assertRaises(ConfigurationError):
            loader.load()

    def test_get_with_default(self) -> None:
        """get() must return the default when a key is absent."""
        loader = self._make_loader({
            "app_version": "1.0.0", "log_level": "INFO",
            "selected_interface": "lo0", "theme": "dark",
            "db_path": "v.db", "physics": {},
        })
        loader.load()
        self.assertEqual(loader.get("nonexistent", "fallback"), "fallback")

    def test_get_int(self) -> None:
        """get_int() must coerce numeric string and int values."""
        import json
        config_path = self._temp_dir / "config.json"
        config_path.write_text(json.dumps({
            "app_version": "1.0.0", "log_level": "INFO",
            "selected_interface": "lo0", "theme": "dark",
            "db_path": "v.db", "physics": {},
            "modbus_port": 502,
        }), encoding="utf-8")
        from src.config import ConfigLoader
        loader = ConfigLoader(config_path=config_path)
        loader.load()
        self.assertEqual(loader.get_int("modbus_port", 0), 502)
        self.assertEqual(loader.get_int("missing_key", 99), 99)

    def test_get_bool(self) -> None:
        """get_bool() must handle truthy string variants."""
        import json
        config_path = self._temp_dir / "config.json"
        config_path.write_text(json.dumps({
            "app_version": "1.0.0", "log_level": "INFO",
            "selected_interface": "lo0", "theme": "dark",
            "db_path": "v.db", "physics": {},
            "debug": "true",
        }), encoding="utf-8")
        from src.config import ConfigLoader
        loader = ConfigLoader(config_path=config_path)
        loader.load()
        self.assertTrue(loader.get_bool("debug"))
        self.assertFalse(loader.get_bool("missing_bool", False))

    def test_dot_notation_access(self) -> None:
        """get() must support dot-notation for nested keys."""
        import json
        config_path = self._temp_dir / "config.json"
        config_path.write_text(json.dumps({
            "app_version": "1.0.0", "log_level": "INFO",
            "selected_interface": "lo0", "theme": "dark",
            "db_path": "v.db",
            "physics": {"pressure_max_bar": 12.5},
        }), encoding="utf-8")
        from src.config import ConfigLoader
        loader = ConfigLoader(config_path=config_path)
        loader.load()
        self.assertEqual(loader.get("physics.pressure_max_bar"), 12.5)

    def test_load_is_idempotent(self) -> None:
        """Calling load() twice must not raise an error."""
        loader = self._make_loader({
            "app_version": "1.0.0", "log_level": "INFO",
            "selected_interface": "lo0", "theme": "dark",
            "db_path": "v.db", "physics": {},
        })
        loader.load()
        loader.load()  # Second call — must be a no-op.
        self.assertTrue(loader.is_loaded)

    def test_raw_property_returns_dict(self) -> None:
        """raw property must return a dict."""
        loader = self._make_loader({
            "app_version": "1.0.0", "log_level": "DEBUG",
            "selected_interface": "lo0", "theme": "dark",
            "db_path": "v.db", "physics": {},
        })
        loader.load()
        raw = loader.raw
        self.assertIsInstance(raw, dict)
        self.assertIn("log_level", raw)


# ---------------------------------------------------------------------------
# Test: Utilities
# ---------------------------------------------------------------------------

class TestUtils(unittest.TestCase):
    """Tests for helper functions in src/utils.py."""

    def setUp(self) -> None:
        self._temp_dir = Path(tempfile.mkdtemp())

    def tearDown(self) -> None:
        import shutil
        shutil.rmtree(self._temp_dir, ignore_errors=True)

    def test_create_directories_success(self) -> None:
        """create_directories() must create missing directories and return True."""
        from src.utils import create_directories
        new_dir = self._temp_dir / "new_subdir" / "nested"
        results = create_directories([new_dir])
        self.assertTrue(results[new_dir], "Directory creation should succeed.")
        self.assertTrue(new_dir.is_dir())

    def test_create_directories_existing(self) -> None:
        """create_directories() on an existing directory must return True."""
        from src.utils import create_directories
        results = create_directories([self._temp_dir])
        self.assertTrue(results[self._temp_dir])

    def test_current_timestamp_is_iso8601(self) -> None:
        """current_timestamp() must return a string containing ISO-8601 'T' separator."""
        from src.utils import current_timestamp
        ts = current_timestamp()
        self.assertIsInstance(ts, str)
        self.assertGreater(len(ts), 0)
        self.assertIn("T", ts, "ISO-8601 format requires 'T' separator.")

    def test_current_local_timestamp(self) -> None:
        """current_local_timestamp() must return a non-empty string."""
        from src.utils import current_local_timestamp
        ts = current_local_timestamp()
        self.assertIsInstance(ts, str)
        self.assertGreater(len(ts), 0)

    def test_calculate_sha256_returns_hex(self) -> None:
        """calculate_sha256() on a known file must return a 64-char hex string."""
        from src.utils import calculate_sha256
        import hashlib
        test_file = self._temp_dir / "test.txt"
        test_file.write_bytes(b"hello world")
        digest = calculate_sha256(test_file)
        self.assertIsNotNone(digest)
        self.assertEqual(len(digest), 64)
        # Verify against hashlib's own calculation.
        expected = hashlib.sha256(b"hello world").hexdigest()
        self.assertEqual(digest, expected)

    def test_calculate_sha256_missing_file_returns_none(self) -> None:
        """calculate_sha256() on a nonexistent file must return None."""
        from src.utils import calculate_sha256
        result = calculate_sha256(self._temp_dir / "nonexistent.bin")
        self.assertIsNone(result)

    def test_file_size_returns_string(self) -> None:
        """file_size() must return a human-readable string for an existing file."""
        from src.utils import file_size
        test_file = self._temp_dir / "sized.txt"
        test_file.write_bytes(b"A" * 2048)
        size_str = file_size(test_file)
        self.assertIsInstance(size_str, str)
        self.assertIn("KB", size_str, f"Expected KB for 2 KB file, got: {size_str}")

    def test_file_size_missing_file(self) -> None:
        """file_size() on a nonexistent file must return '—'."""
        from src.utils import file_size
        result = file_size(self._temp_dir / "ghost.bin")
        self.assertEqual(result, "—")

    def test_safe_write_and_read(self) -> None:
        """safe_write() must write content that safe_read() can retrieve."""
        from src.utils import safe_write, safe_read
        target = self._temp_dir / "output.txt"
        content = "VoltGuard safe write test ✔"
        ok = safe_write(target, content)
        self.assertTrue(ok)
        read_back = safe_read(target, default="FAILED")
        self.assertEqual(read_back, content)

    def test_safe_write_creates_parent_dirs(self) -> None:
        """safe_write() must create missing parent directories."""
        from src.utils import safe_write
        nested = self._temp_dir / "a" / "b" / "c" / "file.txt"
        ok = safe_write(nested, "content")
        self.assertTrue(ok)
        self.assertTrue(nested.exists())

    def test_safe_read_default_on_missing(self) -> None:
        """safe_read() must return the default for a nonexistent file."""
        from src.utils import safe_read
        result = safe_read(self._temp_dir / "absent.txt", default="DEFAULT")
        self.assertEqual(result, "DEFAULT")

    def test_is_writable_existing_dir(self) -> None:
        """is_writable() must return True for a writable temp directory."""
        from src.utils import is_writable
        self.assertTrue(is_writable(self._temp_dir))

    def test_format_duration(self) -> None:
        """format_duration() must produce correct human-readable strings."""
        from src.utils import format_duration
        self.assertEqual(format_duration(45), "45s")
        self.assertEqual(format_duration(90), "1m 30s")
        self.assertEqual(format_duration(3661), "1h 1m 1s")
        self.assertEqual(format_duration(0), "0s")


# ---------------------------------------------------------------------------
# Test: HealthChecker
# ---------------------------------------------------------------------------

class TestHealthChecker(unittest.TestCase):
    """Tests for the HealthChecker in src/healthcheck.py."""

    def test_run_all_checks_returns_list(self) -> None:
        """run_all_checks() must return a non-empty list of HealthResult."""
        from src.healthcheck import HealthChecker
        checker = HealthChecker()
        results = checker.run_all_checks()
        self.assertIsInstance(results, list)
        self.assertGreater(len(results), 0)

    def test_health_result_has_required_fields(self) -> None:
        """Each HealthResult must have name, status, and detail fields."""
        from src.healthcheck import HealthChecker
        checker = HealthChecker()
        results = checker.run_all_checks()
        for result in results:
            self.assertIsInstance(result.name, str)
            self.assertIsInstance(result.status, str)
            self.assertIsInstance(result.detail, str)

    def test_python_version_check_passes(self) -> None:
        """Python version check must PASS on Python 3.10+."""
        from src.healthcheck import HealthChecker
        checker = HealthChecker()
        result = checker._check_python_version()
        self.assertEqual(result.status, "PASS", f"Python version check failed: {result.detail}")

    def test_required_dirs_check_passes_with_existing_dirs(self) -> None:
        """Required directories check must PASS when dirs exist."""
        from src.healthcheck import HealthChecker
        from src.constants import REQUIRED_DIRS
        # Ensure all dirs exist first.
        for d in REQUIRED_DIRS:
            d.mkdir(parents=True, exist_ok=True)
        checker = HealthChecker()
        result = checker._check_required_dirs()
        self.assertEqual(result.status, "PASS")

    def test_results_property_returns_copy(self) -> None:
        """results property must return a copy of the internal list."""
        from src.healthcheck import HealthChecker
        checker = HealthChecker()
        checker.run_all_checks()
        r1 = checker.results
        r2 = checker.results
        self.assertIsNot(r1, r2, "results should return a fresh copy each time.")

    def test_print_report_does_not_raise(self) -> None:
        """print_report() must complete without raising any exception."""
        from src.healthcheck import HealthChecker
        import io
        checker = HealthChecker()
        checker.run_all_checks()
        # Capture stdout to prevent polluting test output.
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            checker.print_report()  # Must not raise.

    def test_health_result_passed_property(self) -> None:
        """HealthResult.passed must be True for PASS and False otherwise."""
        from src.healthcheck import HealthResult
        from src.constants import STATUS_PASS, STATUS_FAIL
        r_pass = HealthResult(name="Test", status=STATUS_PASS)
        r_fail = HealthResult(name="Test", status=STATUS_FAIL)
        self.assertTrue(r_pass.passed)
        self.assertFalse(r_fail.passed)


# ---------------------------------------------------------------------------
# Test: Base Interfaces (ABCs)
# ---------------------------------------------------------------------------

class TestBaseInterfaces(unittest.TestCase):
    """Tests that ABCs cannot be instantiated without implementing abstract methods."""

    def test_base_parser_cannot_be_instantiated(self) -> None:
        """BaseParser must raise TypeError if instantiated directly."""
        from src.interfaces.base_parser import BaseParser
        with self.assertRaises(TypeError):
            BaseParser()  # type: ignore[abstract]

    def test_base_physics_engine_cannot_be_instantiated(self) -> None:
        """BasePhysicsEngine must raise TypeError if instantiated directly."""
        from src.interfaces.base_physics import BasePhysicsEngine
        with self.assertRaises(TypeError):
            BasePhysicsEngine()  # type: ignore[abstract]

    def test_base_decision_engine_cannot_be_instantiated(self) -> None:
        """BaseDecisionEngine must raise TypeError if instantiated directly."""
        from src.interfaces.base_engine import BaseDecisionEngine
        with self.assertRaises(TypeError):
            BaseDecisionEngine()  # type: ignore[abstract]

    def test_concrete_parser_can_be_created(self) -> None:
        """A class implementing all abstract methods must be instantiable."""
        from src.interfaces.base_parser import BaseParser, ParsedPacket
        from src.exceptions import ParserError

        class _ConcreteParser(BaseParser):
            def parse(self, raw_bytes: bytes) -> ParsedPacket:
                return ParsedPacket(
                    protocol="TestProto", src_ip="1.1.1.1", dst_ip="2.2.2.2",
                    src_port=1000, dst_port=502,
                )
            def validate(self, raw_bytes: bytes) -> bool:
                return len(raw_bytes) >= 6
            def get_protocol(self) -> str:
                return "TestProto"

        parser = _ConcreteParser()
        self.assertEqual(parser.get_protocol(), "TestProto")
        self.assertTrue(parser.validate(b"123456"))
        self.assertFalse(parser.validate(b"ab"))

    def test_parsed_packet_dataclass(self) -> None:
        """ParsedPacket must be constructable with required fields."""
        from src.interfaces.base_parser import ParsedPacket
        pkt = ParsedPacket(
            protocol="Modbus TCP",
            src_ip="192.168.1.10",
            dst_ip="10.0.0.5",
            src_port=54321,
            dst_port=502,
            function_code=3,
            register_addr=100,
            register_value=1234,
        )
        self.assertEqual(pkt.protocol, "Modbus TCP")
        self.assertEqual(pkt.function_code, 3)

    def test_physics_state_mark_violation(self) -> None:
        """PhysicsState.mark_violation() must set is_safe=False."""
        from src.interfaces.base_physics import PhysicsState
        state = PhysicsState(pressure_bar=12.0)
        self.assertTrue(state.is_safe)
        state.mark_violation("pressure 12.0 bar > limit 10.0 bar")
        self.assertFalse(state.is_safe)
        self.assertEqual(len(state.violations), 1)

    def test_decision_result_properties(self) -> None:
        """DecisionResult.is_blocked and is_allowed must return correct booleans."""
        from src.interfaces.base_engine import DecisionResult, DecisionAction
        blocked = DecisionResult(action=DecisionAction.BLOCK, risk_score=0.9, reason="Rule ICS-001")
        allowed = DecisionResult(action=DecisionAction.ALLOW, risk_score=0.1, reason="No violation")
        self.assertTrue(blocked.is_blocked)
        self.assertFalse(blocked.is_allowed)
        self.assertTrue(allowed.is_allowed)
        self.assertFalse(allowed.is_blocked)

    def test_firewall_rule_repr(self) -> None:
        """FirewallRule.__repr__() must return a meaningful string."""
        from src.interfaces.base_engine import FirewallRule, DecisionAction
        rule = FirewallRule(
            rule_id="ICS-001",
            description="Block write to coil 0x0001",
            priority=1,
            action=DecisionAction.BLOCK,
        )
        r = repr(rule)
        self.assertIn("ICS-001", r)
        self.assertIn("BLOCK", r)


# ---------------------------------------------------------------------------
# Test: Startup Sequence
# ---------------------------------------------------------------------------

class TestStartup(unittest.TestCase):
    """Tests for the startup sequence in src/startup.py."""

    def test_verify_dependencies_returns_bool(self) -> None:
        """verify_dependencies() must return a boolean."""
        from src.startup import verify_dependencies
        import io, contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            result = verify_dependencies()
        self.assertIsInstance(result, bool)

    def test_required_deps_present(self) -> None:
        """All required dependencies (PyQt6, dotenv) must be importable."""
        from src.startup import verify_dependencies
        import io, contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            ok = verify_dependencies()
        self.assertTrue(ok, "Required dependencies are missing.")

    def test_print_banner_does_not_raise(self) -> None:
        """print_banner() must complete without raising."""
        from src.startup import print_banner
        import io, contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            print_banner()

    def test_print_startup_info_does_not_raise(self) -> None:
        """print_startup_info() must complete without raising."""
        from src.startup import print_startup_info
        import io, contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            print_startup_info()

    def test_run_startup_sequence_returns_bool(self) -> None:
        """run_startup_sequence() must return a boolean."""
        from src.startup import run_startup_sequence
        import io, contextlib
        with contextlib.redirect_stdout(io.StringIO()):
            result = run_startup_sequence(run_health_check=True)
        self.assertIsInstance(result, bool)


# ---------------------------------------------------------------------------
# Test: Sub-package Imports
# ---------------------------------------------------------------------------

class TestSubPackages(unittest.TestCase):
    """Tests that all sub-packages can be imported without error."""

    def test_parser_package_importable(self) -> None:
        """src.parser must be importable."""
        import src.parser  # noqa: F401

    def test_physics_package_importable(self) -> None:
        """src.physics must be importable."""
        import src.physics  # noqa: F401

    def test_decision_engine_package_importable(self) -> None:
        """src.decision_engine must be importable."""
        import src.decision_engine  # noqa: F401

    def test_dashboard_package_importable(self) -> None:
        """src.dashboard must be importable."""
        import src.dashboard  # noqa: F401

    def test_interfaces_package_importable(self) -> None:
        """src.interfaces must be importable."""
        import src.interfaces  # noqa: F401

    def test_logger_module_importable(self) -> None:
        """src.logger must be importable."""
        import src.logger  # noqa: F401

    def test_utils_module_importable(self) -> None:
        """src.utils must be importable."""
        import src.utils  # noqa: F401

    def test_healthcheck_module_importable(self) -> None:
        """src.healthcheck must be importable."""
        import src.healthcheck  # noqa: F401

    def test_startup_module_importable(self) -> None:
        """src.startup must be importable."""
        import src.startup  # noqa: F401

    def test_constants_module_importable(self) -> None:
        """src.constants must be importable."""
        import src.constants  # noqa: F401

    def test_exceptions_module_importable(self) -> None:
        """src.exceptions must be importable."""
        import src.exceptions  # noqa: F401

    def test_config_module_importable(self) -> None:
        """src.config must be importable."""
        import src.config  # noqa: F401


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    loader = unittest.TestLoader()
    suite  = unittest.TestSuite()

    # Original Day 1 test classes.
    for cls in [
        TestDatabaseManager,
        TestDatabaseService,
        TestConfigService,
        TestAppState,
        TestLoggingService,
        TestAppModels,
    ]:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    # New Day 1 infrastructure test classes.
    for cls in [
        TestConstants,
        TestExceptions,
        TestConfigLoader,
        TestUtils,
        TestHealthChecker,
        TestBaseInterfaces,
        TestStartup,
        TestSubPackages,
    ]:
        suite.addTests(loader.loadTestsFromTestCase(cls))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)
    sys.exit(0 if result.wasSuccessful() else 1)
