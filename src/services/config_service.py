"""
VoltGuard — Configuration Service
====================================
Singleton service that manages application settings.

Responsibilities:
  - Load settings from the ``application_settings`` database table on startup.
  - Provide typed getters for each known setting key.
  - Propagate value changes back to the database via ``DatabaseService``.
  - Seed default values for any missing keys on first run.

Usage:
    from src.services.config_service import config_service

    config_service.initialize(database_service)
    theme = config_service.theme          # → "dark"
    config_service.theme = "light"        # Persisted immediately.
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Optional

from src.models.app_models import APP_DEFAULT_SETTINGS

if TYPE_CHECKING:
    from src.services.database_service import _DatabaseService


class _ConfigService:
    """
    Application configuration service for VoltGuard.

    Wraps the ``application_settings`` table with strongly-typed
    Python properties so the rest of the codebase never writes raw
    SQL or magic strings for config keys.
    """

    def __init__(self) -> None:
        self._db: Optional["_DatabaseService"] = None
        self._cache: dict[str, str] = {}
        self._initialized: bool = False

    # ------------------------------------------------------------------ #
    #  Lifecycle                                                           #
    # ------------------------------------------------------------------ #

    def initialize(self, db_service: "_DatabaseService") -> None:
        """
        Attach to a ready DatabaseService, seed defaults, and load cache.

        Args:
            db_service: An already-initialised ``DatabaseService`` singleton.
        """
        if self._initialized:
            return

        self._db = db_service

        # Seed defaults for keys that do not yet exist.
        self._db.seed_default_settings(APP_DEFAULT_SETTINGS)

        # Populate in-memory cache from the database.
        self._cache = self._db.load_all_settings()

        self._initialized = True

    # ------------------------------------------------------------------ #
    #  Generic get / set                                                   #
    # ------------------------------------------------------------------ #

    def get(self, key: str, fallback: str = "") -> str:
        """
        Return the string value for ``key``, or ``fallback`` if absent.

        Args:
            key:      Setting identifier.
            fallback: Value to return if the key is not in the cache.
        """
        return self._cache.get(key, fallback)

    def set(self, key: str, value: str) -> None:
        """
        Persist a setting value and update the in-memory cache.

        Args:
            key:   Setting identifier.
            value: New string value.

        Raises:
            RuntimeError: If the service has not been initialised.
        """
        if not self._initialized or self._db is None:
            raise RuntimeError(
                "ConfigService.initialize() must be called before set()."
            )
        self._cache[key] = value
        self._db.save_setting(key, value)

    # ------------------------------------------------------------------ #
    #  Typed property accessors                                            #
    # ------------------------------------------------------------------ #

    @property
    def theme(self) -> str:
        """UI theme name. Expected values: 'dark' | 'light'."""
        return self.get("theme", APP_DEFAULT_SETTINGS["theme"])

    @theme.setter
    def theme(self, value: str) -> None:
        self.set("theme", value)

    @property
    def selected_interface(self) -> str:
        """Name of the network interface selected for monitoring."""
        return self.get(
            "selected_interface", APP_DEFAULT_SETTINGS["selected_interface"]
        )

    @selected_interface.setter
    def selected_interface(self, value: str) -> None:
        self.set("selected_interface", value)

    @property
    def log_level(self) -> str:
        """Logging verbosity level. One of 'DEBUG', 'INFO', 'WARNING', 'ERROR'."""
        return self.get("log_level", APP_DEFAULT_SETTINGS["log_level"])

    @log_level.setter
    def log_level(self, value: str) -> None:
        self.set("log_level", value)

    @property
    def app_version(self) -> str:
        """Application version string (e.g. '1.0.0')."""
        return self.get("app_version", APP_DEFAULT_SETTINGS["app_version"])

    @property
    def app_name(self) -> str:
        """Application display name."""
        return self.get("app_name", APP_DEFAULT_SETTINGS["app_name"])

    @property
    def is_initialized(self) -> bool:
        """True if the service has been successfully initialised."""
        return self._initialized


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
# Public alias retained alongside the private implementation name used by
# the original Day 1 tests.  Package-level imports expose this service as
# ``ConfigService`` just like the other service modules.
ConfigService = _ConfigService
config_service: ConfigService = ConfigService()
