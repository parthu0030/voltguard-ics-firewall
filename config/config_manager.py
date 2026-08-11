"""
VoltGuard Configuration Manager
---------------------------------
Reads and writes runtime configuration backed by the SQLite settings table.
Provides typed accessors and a central point for all app configuration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from database.database import get_db
from core.logger import get_logger

log = get_logger(__name__)

APP_VERSION = "1.0.0"


@dataclass
class PhysicsThresholds:
    """Safe operating ranges for the physics simulation engine."""

    pressure_min: float = 0.0
    pressure_max: float = 100.0
    flow_min: float = 0.0
    flow_max: float = 50.0
    temperature_min: float = -20.0
    temperature_max: float = 150.0
    rpm_min: float = 0.0
    rpm_max: float = 3600.0


@dataclass
class AppConfig:
    """Typed snapshot of all application settings."""

    interface: str = "auto"
    dark_mode: bool = True
    logging_level: str = "INFO"
    auto_start_capture: bool = False
    max_packet_log_rows: int = 10_000
    alert_on_unknown_protocol: bool = True
    app_version: str = APP_VERSION
    physics: PhysicsThresholds = field(default_factory=PhysicsThresholds)


class ConfigManager:
    """Central configuration manager backed by SQLite.

    All public methods perform live reads/writes against the database so
    settings are immediately durable without a separate "save" step.
    """

    def __init__(self) -> None:
        self._db = get_db()
        log.info("ConfigManager initialised.")

    # ------------------------------------------------------------------
    # Load / snapshot
    # ------------------------------------------------------------------

    def load(self) -> AppConfig:
        """Load all settings from the database and return a typed snapshot.

        Returns:
            :class:`AppConfig` populated with current values.
        """
        raw = self._db.get_all_settings()

        cfg = AppConfig(
            interface=raw.get("interface", "auto"),
            dark_mode=raw.get("dark_mode", "true").lower() == "true",
            logging_level=raw.get("logging_level", "INFO"),
            auto_start_capture=raw.get("auto_start_capture", "false").lower() == "true",
            max_packet_log_rows=_int(raw.get("max_packet_log_rows", "10000")),
            alert_on_unknown_protocol=raw.get("alert_on_unknown_protocol", "true").lower() == "true",
            app_version=raw.get("app_version", APP_VERSION),
            physics=PhysicsThresholds(
                pressure_min=_float(raw.get("safe_pressure_min", "0.0")),
                pressure_max=_float(raw.get("safe_pressure_max", "100.0")),
                flow_min=_float(raw.get("safe_flow_min", "0.0")),
                flow_max=_float(raw.get("safe_flow_max", "50.0")),
                temperature_min=_float(raw.get("safe_temperature_min", "-20.0")),
                temperature_max=_float(raw.get("safe_temperature_max", "150.0")),
                rpm_min=_float(raw.get("safe_rpm_min", "0.0")),
                rpm_max=_float(raw.get("safe_rpm_max", "3600.0")),
            ),
        )
        return cfg

    # ------------------------------------------------------------------
    # Individual accessors / mutators
    # ------------------------------------------------------------------

    def get_interface(self) -> str:
        """Return the currently selected network interface."""
        return self._db.get_setting("interface", "auto") or "auto"

    def set_interface(self, interface: str) -> None:
        """Persist the selected network interface.

        Args:
            interface: Interface name (e.g. ``"eth0"`` or ``"auto"``).
        """
        self._db.set_setting("interface", interface)
        log.info("Interface updated to: %s", interface)

    def is_dark_mode(self) -> bool:
        """Return ``True`` if dark mode is enabled."""
        return (self._db.get_setting("dark_mode", "true") or "true").lower() == "true"

    def set_dark_mode(self, enabled: bool) -> None:
        """Toggle dark mode.

        Args:
            enabled: ``True`` enables dark mode.
        """
        self._db.set_setting("dark_mode", "true" if enabled else "false")

    def get_logging_level(self) -> str:
        """Return the configured logging level string (e.g. ``"INFO"``)."""
        return self._db.get_setting("logging_level", "INFO") or "INFO"

    def set_logging_level(self, level: str) -> None:
        """Persist the logging level.

        Args:
            level: Logging level string — DEBUG, INFO, WARNING, ERROR.
        """
        self._db.set_setting("logging_level", level.upper())
        log.info("Logging level set to: %s", level)

    def get_physics_thresholds(self) -> PhysicsThresholds:
        """Return the current physics safe-operating thresholds."""
        raw = self._db.get_all_settings()
        return PhysicsThresholds(
            pressure_min=_float(raw.get("safe_pressure_min", "0.0")),
            pressure_max=_float(raw.get("safe_pressure_max", "100.0")),
            flow_min=_float(raw.get("safe_flow_min", "0.0")),
            flow_max=_float(raw.get("safe_flow_max", "50.0")),
            temperature_min=_float(raw.get("safe_temperature_min", "-20.0")),
            temperature_max=_float(raw.get("safe_temperature_max", "150.0")),
            rpm_min=_float(raw.get("safe_rpm_min", "0.0")),
            rpm_max=_float(raw.get("safe_rpm_max", "3600.0")),
        )

    def set_physics_thresholds(self, thresholds: PhysicsThresholds) -> None:
        """Persist physics thresholds to the database.

        Args:
            thresholds: Updated :class:`PhysicsThresholds` instance.
        """
        mapping = {
            "safe_pressure_min": str(thresholds.pressure_min),
            "safe_pressure_max": str(thresholds.pressure_max),
            "safe_flow_min": str(thresholds.flow_min),
            "safe_flow_max": str(thresholds.flow_max),
            "safe_temperature_min": str(thresholds.temperature_min),
            "safe_temperature_max": str(thresholds.temperature_max),
            "safe_rpm_min": str(thresholds.rpm_min),
            "safe_rpm_max": str(thresholds.rpm_max),
        }
        for key, value in mapping.items():
            self._db.set_setting(key, value)
        log.info("Physics thresholds updated.")

    def get_app_version(self) -> str:
        """Return the application version string."""
        return self._db.get_setting("app_version", APP_VERSION) or APP_VERSION

    def get_alert_on_unknown_protocol(self) -> bool:
        """Return whether unknown protocols trigger an alert."""
        return (
            self._db.get_setting("alert_on_unknown_protocol", "true") or "true"
        ).lower() == "true"

    def set_alert_on_unknown_protocol(self, enabled: bool) -> None:
        """Configure unknown-protocol alerting."""
        self._db.set_setting("alert_on_unknown_protocol", "true" if enabled else "false")


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

_config_instance: Optional[ConfigManager] = None


def get_config() -> ConfigManager:
    """Return the application-wide :class:`ConfigManager` singleton."""
    global _config_instance
    if _config_instance is None:
        _config_instance = ConfigManager()
    return _config_instance


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _float(value: str) -> float:
    try:
        return float(value)
    except (ValueError, TypeError):
        return 0.0


def _int(value: str) -> int:
    try:
        return int(value)
    except (ValueError, TypeError):
        return 0
