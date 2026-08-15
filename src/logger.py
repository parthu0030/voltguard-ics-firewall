"""
VoltGuard — Rotating Logger Factory
======================================
Provides ``setup_rotating_logger()``, a factory that configures and returns
a named ``logging.Logger`` backed by:
  - A ``RotatingFileHandler`` writing to ``logs/application.log``
    (5 MB per file, up to 5 backups).
  - A ``StreamHandler`` for coloured stdout output during development.

This module is **complementary** to ``LoggingService`` (which is Qt-aware).
Use this logger anywhere you need a plain Python logger — particularly
in infrastructure code that runs before PyQt6 is initialised (config
loading, health checks, startup sequence).

Usage:
    from src.logger import setup_rotating_logger

    log = setup_rotating_logger("VoltGuard.Config")
    log.info("Configuration loaded.")

    # Or use the pre-configured module-level logger:
    from src.logger import get_logger
    log = get_logger(__name__)
"""

from __future__ import annotations

import logging
import sys
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Optional

from src.constants import (
    LOGS_DIR,
    LOG_FILE_NAME,
    LOG_FORMAT,
    LOG_DATE_FORMAT,
    LOG_MAX_BYTES,
    LOG_BACKUP_COUNT,
    DEFAULT_LOG_LEVEL,
)


# ---------------------------------------------------------------------------
# ANSI colour codes for console output
# ---------------------------------------------------------------------------

_ANSI_RESET: str = "\033[0m"
_LEVEL_COLOURS: dict[int, str] = {
    logging.DEBUG:    "\033[36m",   # Cyan
    logging.INFO:     "\033[32m",   # Green
    logging.WARNING:  "\033[33m",   # Yellow
    logging.ERROR:    "\033[31m",   # Red
    logging.CRITICAL: "\033[35m",   # Magenta
}


class _ColourFormatter(logging.Formatter):
    """
    A ``logging.Formatter`` subclass that wraps the level name in ANSI
    colour codes for terminal output.

    Falls back to plain text on non-TTY streams (e.g. file redirection).
    """

    def __init__(self, fmt: str, datefmt: str, use_colour: bool = True) -> None:
        super().__init__(fmt=fmt, datefmt=datefmt)
        self._use_colour = use_colour

    def format(self, record: logging.LogRecord) -> str:  # noqa: A003
        if self._use_colour:
            colour = _LEVEL_COLOURS.get(record.levelno, _ANSI_RESET)
            record.levelname = f"{colour}{record.levelname:<8}{_ANSI_RESET}"
        return super().format(record)


# ---------------------------------------------------------------------------
# Internal registry to avoid adding duplicate handlers
# ---------------------------------------------------------------------------

_configured_loggers: set[str] = set()


def setup_rotating_logger(
    name: str,
    level: str = DEFAULT_LOG_LEVEL,
    log_dir: Optional[Path] = None,
) -> logging.Logger:
    """
    Configure and return a named ``logging.Logger`` with rotating file output.

    This function is idempotent for a given ``name`` — calling it again
    with the same name returns the existing logger without adding extra handlers.

    Args:
        name:    Logger name (e.g. ``"VoltGuard.Config"``).  Appears in every
                 log line so you can filter by module in the log file.
        level:   Logging level string: ``'DEBUG'``, ``'INFO'``, ``'WARNING'``,
                 ``'ERROR'``.  Defaults to ``DEFAULT_LOG_LEVEL``.
        log_dir: Directory for the log file.  Defaults to ``LOGS_DIR``
                 (``<project_root>/logs/``).

    Returns:
        A configured ``logging.Logger`` instance.
    """
    logger = logging.getLogger(name)

    # Idempotency guard — do not add handlers a second time.
    if name in _configured_loggers:
        return logger

    numeric_level: int = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(numeric_level)

    # Prevent log records from bubbling up to the root logger and causing
    # duplicate output when multiple VoltGuard loggers are active.
    logger.propagate = False

    target_dir: Path = log_dir or LOGS_DIR
    target_dir.mkdir(parents=True, exist_ok=True)

    log_path: Path = target_dir / LOG_FILE_NAME

    # ---- Rotating file handler -------------------------------------------
    file_handler = RotatingFileHandler(
        filename=str(log_path),
        maxBytes=LOG_MAX_BYTES,
        backupCount=LOG_BACKUP_COUNT,
        encoding="utf-8",
    )
    file_handler.setLevel(numeric_level)
    file_handler.setFormatter(
        logging.Formatter(fmt=LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    )
    logger.addHandler(file_handler)

    # ---- Console handler --------------------------------------------------
    is_tty: bool = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(numeric_level)
    console_handler.setFormatter(
        _ColourFormatter(fmt=LOG_FORMAT, datefmt=LOG_DATE_FORMAT, use_colour=is_tty)
    )
    logger.addHandler(console_handler)

    _configured_loggers.add(name)
    return logger


def get_logger(module_name: str) -> logging.Logger:
    """
    Convenience wrapper used by individual modules to acquire a logger.

    Translates a Python module ``__name__`` (e.g. ``src.config``) into a
    ``VoltGuard.*`` namespaced logger backed by the rotating file handler.

    Args:
        module_name: Typically the calling module's ``__name__``.

    Returns:
        A configured ``logging.Logger``.

    Example:
        # At the top of any src/*.py file:
        from src.logger import get_logger
        _log = get_logger(__name__)
    """
    # Strip the leading "src." prefix for cleaner log names.
    short_name = module_name.removeprefix("src.") if module_name.startswith("src.") else module_name
    logger_name = f"VoltGuard.{short_name}"
    return setup_rotating_logger(logger_name)
