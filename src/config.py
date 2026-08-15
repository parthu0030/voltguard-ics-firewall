"""
VoltGuard — Configuration Loader
===================================
Loads application configuration from ``config.json`` (project root) and
optionally from a ``.env`` file using ``python-dotenv``.

Responsibilities:
  - Read and parse ``config.json`` on first access.
  - Auto-generate ``config.json`` with defaults if the file does not exist.
  - Read ``.env`` overrides (silently skipped if absent).
  - Validate that all required keys are present and of the correct type.
  - Provide typed accessors: ``get()``, ``get_int()``, ``get_bool()``, ``get_float()``.

This module is deliberately **Qt-free** and **database-free** so it can be
imported by tests and CLI tools without a running application.

Usage:
    from src.config import config_loader

    config_loader.load()
    level = config_loader.get("log_level", "INFO")
    port  = config_loader.get_int("modbus_port", 502)
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any, Optional, Union

from src.constants import CONFIG_FILE, APP_VERSION, DEFAULT_LOG_LEVEL
from src.exceptions import ConfigurationError

# Attempt to import python-dotenv; it is optional — the app works without it.
try:
    from dotenv import load_dotenv as _load_dotenv
    _HAS_DOTENV: bool = True
except ImportError:
    _HAS_DOTENV = False

_log = logging.getLogger("VoltGuard.ConfigLoader")


# ---------------------------------------------------------------------------
# Default configuration written to config.json on first run.
# ---------------------------------------------------------------------------

_DEFAULT_CONFIG: dict[str, Any] = {
    "app_version": APP_VERSION,
    "log_level": DEFAULT_LOG_LEVEL,
    "selected_interface": "lo0",
    "theme": "dark",
    "db_path": "voltguard.db",
    "physics": {
        "pressure_max_bar": 10.0,
        "flow_max_lps": 50.0,
        "temp_max_celsius": 150.0,
        "rpm_max": 3600.0,
    },
}

# Keys that MUST be present after loading; their expected Python type.
_REQUIRED_KEYS: dict[str, type] = {
    "app_version": str,
    "log_level": str,
    "selected_interface": str,
    "theme": str,
    "db_path": str,
    "physics": dict,
}


class ConfigLoader:
    """
    Loads, validates, and exposes the VoltGuard JSON configuration.

    The load order is:
      1. ``config.json`` (primary source; auto-generated with defaults if absent)
      2. ``.env`` file (optional; values merged as string overrides)
      3. OS environment variables (highest priority; override everything)

    All values from ``.env`` and the environment are stored as strings.
    Typed accessors handle coercion.
    """

    def __init__(self, config_path: Optional[Path] = None) -> None:
        """
        Args:
            config_path: Path to ``config.json``.  Defaults to project root.
        """
        self._config_path: Path = config_path or CONFIG_FILE
        self._data: dict[str, Any] = {}
        self._loaded: bool = False
        self._dotenv_loaded: bool = False

    # ------------------------------------------------------------------ #
    #  Lifecycle                                                           #
    # ------------------------------------------------------------------ #

    def load(self) -> None:
        """
        Execute the full load sequence: JSON → .env → environment vars.

        This method is idempotent; subsequent calls are no-ops.

        Raises:
            ConfigurationError: If ``config.json`` contains invalid JSON
                                 or is missing required keys.
        """
        if self._loaded:
            return

        # Step 1: Load (or generate) config.json.
        self._data = self._load_json()

        # Step 2: Apply .env overrides (flat key-value pairs only).
        self._apply_dotenv()

        # Step 3: Apply OS environment variable overrides.
        self._apply_env_overrides()

        # Step 4: Validate the merged configuration.
        self._validate()

        self._loaded = True
        _log.info("Configuration loaded from: %s", self._config_path)

    def reload(self) -> None:
        """Force a fresh reload from disk, discarding the cached state."""
        self._loaded = False
        self._data = {}
        self.load()

    # ------------------------------------------------------------------ #
    #  Typed accessors                                                     #
    # ------------------------------------------------------------------ #

    def get(self, key: str, default: Any = None) -> Any:
        """
        Return the value for ``key`` from the loaded configuration.

        Supports dot-notation for nested keys, e.g. ``"physics.pressure_max_bar"``.

        Args:
            key:     Config key, optionally dot-separated for nesting.
            default: Value to return if the key does not exist.

        Returns:
            The config value, or ``default`` if absent.
        """
        self._ensure_loaded()
        keys = key.split(".")
        node: Any = self._data
        for k in keys:
            if isinstance(node, dict):
                node = node.get(k)
                if node is None:
                    return default
            else:
                return default
        return node

    def get_int(self, key: str, default: int = 0) -> int:
        """
        Return the value for ``key`` coerced to an integer.

        Args:
            key:     Config key (dot-notation supported).
            default: Returned if the key is absent or non-numeric.
        """
        value = self.get(key)
        if value is None:
            return default
        try:
            return int(value)
        except (ValueError, TypeError):
            _log.warning("Config key '%s' is not a valid int; using default %d", key, default)
            return default

    def get_float(self, key: str, default: float = 0.0) -> float:
        """
        Return the value for ``key`` coerced to a float.

        Args:
            key:     Config key (dot-notation supported).
            default: Returned if the key is absent or non-numeric.
        """
        value = self.get(key)
        if value is None:
            return default
        try:
            return float(value)
        except (ValueError, TypeError):
            _log.warning("Config key '%s' is not a valid float; using default %f", key, default)
            return default

    def get_bool(self, key: str, default: bool = False) -> bool:
        """
        Return the value for ``key`` coerced to a boolean.

        Truthy string values: ``"true"``, ``"1"``, ``"yes"``, ``"on"`` (case-insensitive).
        All other strings → False.

        Args:
            key:     Config key (dot-notation supported).
            default: Returned if the key is absent.
        """
        value = self.get(key)
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"true", "1", "yes", "on"}

    @property
    def is_loaded(self) -> bool:
        """True if :meth:`load` has been called successfully."""
        return self._loaded

    @property
    def config_path(self) -> Path:
        """Filesystem path of the active config.json."""
        return self._config_path

    @property
    def raw(self) -> dict[str, Any]:
        """Return a shallow copy of the raw loaded configuration dict."""
        self._ensure_loaded()
        return dict(self._data)

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _load_json(self) -> dict[str, Any]:
        """
        Read config.json.  If the file does not exist, write the defaults
        and return them.

        Returns:
            Parsed configuration dictionary.

        Raises:
            ConfigurationError: On JSON parse error or file permission issue.
        """
        if not self._config_path.exists():
            _log.info(
                "config.json not found at %s — generating defaults.",
                self._config_path,
            )
            self._write_defaults()
            return dict(_DEFAULT_CONFIG)

        try:
            text = self._config_path.read_text(encoding="utf-8")
            data = json.loads(text)
            if not isinstance(data, dict):
                raise ConfigurationError(
                    "config.json must contain a JSON object at the top level.",
                    detail=f"path={self._config_path}",
                )
            return data
        except json.JSONDecodeError as exc:
            raise ConfigurationError(
                f"config.json contains invalid JSON: {exc}",
                detail=f"path={self._config_path} line={exc.lineno}",
            ) from exc
        except OSError as exc:
            raise ConfigurationError(
                f"Cannot read config.json: {exc}",
                detail=f"path={self._config_path}",
            ) from exc

    def _write_defaults(self) -> None:
        """Serialise ``_DEFAULT_CONFIG`` to ``config.json`` with pretty formatting."""
        try:
            self._config_path.parent.mkdir(parents=True, exist_ok=True)
            self._config_path.write_text(
                json.dumps(_DEFAULT_CONFIG, indent=2),
                encoding="utf-8",
            )
            _log.info("Default config.json written to: %s", self._config_path)
        except OSError as exc:
            _log.warning("Could not write default config.json: %s", exc)

    def _apply_dotenv(self) -> None:
        """
        Load ``.env`` from the project root into the process environment.
        Silently skipped if python-dotenv is not installed or the file
        does not exist.
        """
        if not _HAS_DOTENV:
            _log.debug("python-dotenv not installed; .env file skipped.")
            return

        env_file = self._config_path.parent / ".env"
        if env_file.exists():
            _load_dotenv(dotenv_path=env_file, override=False)
            self._dotenv_loaded = True
            _log.debug(".env loaded from: %s", env_file)
        else:
            _log.debug(".env not found at %s; skipped.", env_file)

    def _apply_env_overrides(self) -> None:
        """
        Read ``VOLTGUARD_*`` environment variables and merge them into
        the config data as flat string overrides.

        For example: ``VOLTGUARD_LOG_LEVEL=DEBUG`` sets ``log_level`` = "DEBUG".
        """
        prefix = "VOLTGUARD_"
        for env_key, env_val in os.environ.items():
            if env_key.startswith(prefix):
                config_key = env_key[len(prefix):].lower()
                self._data[config_key] = env_val
                _log.debug("Env override: %s = %r", config_key, env_val)

    def _validate(self) -> None:
        """
        Ensure all required keys are present and of the expected type.

        Raises:
            ConfigurationError: On any schema violation.
        """
        for key, expected_type in _REQUIRED_KEYS.items():
            if key not in self._data:
                raise ConfigurationError(
                    f"Required configuration key '{key}' is missing.",
                    detail=f"path={self._config_path}",
                )
            actual = self._data[key]
            if not isinstance(actual, expected_type):
                raise ConfigurationError(
                    f"Config key '{key}' must be {expected_type.__name__}, "
                    f"got {type(actual).__name__}.",
                    detail=f"path={self._config_path} key={key} value={actual!r}",
                )

    def _ensure_loaded(self) -> None:
        """Raise RuntimeError if :meth:`load` has not been called yet."""
        if not self._loaded:
            raise RuntimeError(
                "ConfigLoader.load() must be called before accessing config values."
            )


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------

config_loader: ConfigLoader = ConfigLoader()
