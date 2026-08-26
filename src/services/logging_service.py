"""
VoltGuard — Logging Service
=============================
Singleton service that configures and exposes the application logger.

Features:
  - Writes structured log lines to ``logs/voltguard_YYYYMMDD.log``.
  - Also emits to stdout for development visibility.
  - Exposes convenience methods: debug(), info(), warning(), error().
  - The ``logs/`` directory is created automatically if absent.
  - Thread-safe via Python's built-in logging module lock.

Usage:
    from src.services.logging_service import logging_service
    logging_service.info("Application started", source="main")
"""

from __future__ import annotations

import logging
import os
import sys
import traceback
from datetime import datetime
from pathlib import Path
from typing import Optional


# Project root is two levels above this file: src/services/ → src/ → project/
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_LOGS_DIR = _PROJECT_ROOT / "logs"


class _LoggingService:
    """
    Centralised logging service for VoltGuard.

    Wraps Python's standard ``logging`` module.  All application code should
    use this service rather than calling ``print()`` or creating ad-hoc
    loggers so that every message is captured in the log file and can be
    forwarded to the database ``event_logs`` table in later milestones.
    """

    _LOGGER_NAME = "VoltGuard"

    def __init__(self) -> None:
        self._logger: Optional[logging.Logger] = None
        self._log_file: Optional[Path] = None
        self._initialized: bool = False

    # ------------------------------------------------------------------ #
    #  Initialisation                                                      #
    # ------------------------------------------------------------------ #

    def initialize(self, log_level: str = "INFO") -> None:
        """
        Set up file and console handlers for the application logger.

        This method is idempotent — calling it multiple times is safe.

        Args:
            log_level: One of 'DEBUG', 'INFO', 'WARNING', 'ERROR'.
                       Defaults to 'INFO'.
        """
        if self._initialized:
            return

        # Ensure the logs directory exists.
        _LOGS_DIR.mkdir(parents=True, exist_ok=True)

        date_str = datetime.now().strftime("%Y%m%d")
        self._log_file = _LOGS_DIR / f"voltguard_{date_str}.log"

        self._logger = logging.getLogger(self._LOGGER_NAME)
        numeric_level = getattr(logging, log_level.upper(), logging.INFO)
        self._logger.setLevel(numeric_level)

        # Prevent duplicate handlers if somehow called again.
        self._logger.handlers.clear()

        # ---- File handler -----------------------------------------------
        file_handler = logging.FileHandler(self._log_file, encoding="utf-8")
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(self._make_formatter())
        self._logger.addHandler(file_handler)

        # ---- Console (stdout) handler ------------------------------------
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(numeric_level)
        console_handler.setFormatter(self._make_formatter(color=True))
        self._logger.addHandler(console_handler)

        self._initialized = True
        self.info("Logging service initialised", source="LoggingService")

    @staticmethod
    def _make_formatter(color: bool = False) -> logging.Formatter:
        """
        Return a log formatter.

        Args:
            color: If True, wrap the level name in ANSI colour codes.
        """
        if color:
            fmt = (
                "\033[90m%(asctime)s\033[0m "
                "[\033[1m%(levelname)-8s\033[0m] "
                "%(message)s"
            )
        else:
            fmt = "%(asctime)s [%(levelname)-8s] %(message)s"
        return logging.Formatter(fmt, datefmt="%Y-%m-%d %H:%M:%S")

    # ------------------------------------------------------------------ #
    #  Public logging API                                                  #
    # ------------------------------------------------------------------ #

    def debug(self, message: str, source: str = "") -> None:
        """Log a DEBUG-level message."""
        self._emit(logging.DEBUG, message, source)

    def info(self, message: str, source: str = "") -> None:
        """Log an INFO-level message."""
        self._emit(logging.INFO, message, source)

    def warning(self, message: str, source: str = "") -> None:
        """Log a WARNING-level message."""
        self._emit(logging.WARNING, message, source)

    def error(self, message: str, source: str = "") -> None:
        """Log an ERROR-level message."""
        self._emit(logging.ERROR, message, source)

    def exception(self, message: str, source: str = "") -> None:
        """Log an ERROR-level message and append the current exception traceback."""
        if self._logger:
            prefix = f"[{source}] " if source else ""
            self._logger.error("%s%s", prefix, message, exc_info=True)

    def log_startup(self, version: str = "1.0.0") -> None:
        """Write a prominent application-start banner to the log file."""
        separator = "=" * 70
        self.info(separator, source="Startup")
        self.info(f"  VoltGuard v{version} — Application Starting", source="Startup")
        self.info(f"  Timestamp : {datetime.now().isoformat()}", source="Startup")
        self.info(f"  Log file  : {self._log_file}", source="Startup")
        self.info(separator, source="Startup")

    def log_exception_to_file(self, exc_type: type, exc_value: BaseException,
                               exc_tb: object) -> None:
        """
        Write a full formatted exception traceback to the log file.
        Called by the global exception handler in main.py.

        Args:
            exc_type:  Exception class.
            exc_value: Exception instance.
            exc_tb:    Traceback object.
        """
        tb_lines = traceback.format_exception(exc_type, exc_value, exc_tb)
        full_trace = "".join(tb_lines)
        self.error(f"UNHANDLED EXCEPTION:\n{full_trace}", source="ExceptionHandler")

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _emit(self, level: int, message: str, source: str) -> None:
        """Internal dispatch to the underlying logger."""
        if not self._initialized or self._logger is None:
            # Fallback: print to stderr before service is ready.
            print(f"[{logging.getLevelName(level)}] {message}", file=sys.stderr)
            return
        prefix = f"[{source}] " if source else ""
        self._logger.log(level, "%s%s", prefix, message)

    @property
    def log_file_path(self) -> Optional[Path]:
        """Return the path of the active log file, or None if not initialised."""
        return self._log_file


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
LoggingService = _LoggingService
logging_service: LoggingService = LoggingService()
