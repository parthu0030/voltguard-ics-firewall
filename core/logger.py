"""
VoltGuard Logging Module
------------------------
Provides structured, multi-stream logging for:
  - Application events
  - Packet capture logs
  - Error / exception logs
  - Security events / alerts
"""

import logging
import logging.handlers
import os
from datetime import datetime
from pathlib import Path
from typing import Optional


LOG_DIR = Path(__file__).resolve().parent.parent / "logs"


def _ensure_log_dir() -> None:
    """Create the logs directory if it does not already exist."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)


def _build_formatter(include_source: bool = True) -> logging.Formatter:
    """Return a consistent log formatter.

    Args:
        include_source: Whether to append the logger name / module to the format.
    """
    fmt = "%(asctime)s | %(levelname)-8s | %(name)s | %(message)s"
    if not include_source:
        fmt = "%(asctime)s | %(levelname)-8s | %(message)s"
    return logging.Formatter(fmt, datefmt="%Y-%m-%d %H:%M:%S")


def _create_rotating_handler(filename: str, level: int) -> logging.handlers.RotatingFileHandler:
    """Create a rotating file handler capped at 5 MB with 3 backups.

    Args:
        filename: Log file name (placed inside LOG_DIR).
        level:    Logging level for this handler.
    """
    path = LOG_DIR / filename
    handler = logging.handlers.RotatingFileHandler(
        path,
        maxBytes=5 * 1024 * 1024,  # 5 MB
        backupCount=3,
        encoding="utf-8",
    )
    handler.setLevel(level)
    handler.setFormatter(_build_formatter())
    return handler


def get_logger(name: str, level: Optional[int] = None) -> logging.Logger:
    """Return a named application logger.

    The logger writes to both the console and the rotating app log file.

    Args:
        name:  Logger name (typically the module ``__name__``).
        level: Override the default INFO level if provided.
    """
    _ensure_log_dir()
    log_level = level or logging.INFO
    logger = logging.getLogger(name)

    if logger.handlers:
        # Already configured — return existing logger to avoid duplicate handlers.
        return logger

    logger.setLevel(log_level)

    # Console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(log_level)
    console_handler.setFormatter(_build_formatter())
    logger.addHandler(console_handler)

    # Rotating file handler — app.log
    logger.addHandler(_create_rotating_handler("app.log", log_level))

    return logger


def get_packet_logger() -> logging.Logger:
    """Return a dedicated logger for packet capture events.

    Writes to ``logs/packets.log`` only (no console output to keep terminal clean).
    """
    _ensure_log_dir()
    name = "voltguard.packets"
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG)
    logger.propagate = False  # Don't bubble up to root
    logger.addHandler(_create_rotating_handler("packets.log", logging.DEBUG))
    return logger


def get_security_logger() -> logging.Logger:
    """Return a dedicated logger for security alert events.

    Writes to ``logs/security.log`` and also propagates to the root app logger.
    """
    _ensure_log_dir()
    name = "voltguard.security"
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(logging.WARNING)
    logger.propagate = True  # Let root logger also capture alerts

    handler = _create_rotating_handler("security.log", logging.WARNING)
    logger.addHandler(handler)
    return logger


def get_error_logger() -> logging.Logger:
    """Return a dedicated logger for unhandled errors and exceptions.

    Writes to ``logs/errors.log`` with full tracebacks.
    """
    _ensure_log_dir()
    name = "voltguard.errors"
    logger = logging.getLogger(name)

    if logger.handlers:
        return logger

    logger.setLevel(logging.ERROR)
    logger.propagate = True
    logger.addHandler(_create_rotating_handler("errors.log", logging.ERROR))
    return logger


def log_security_event(
    event_type: str,
    source_ip: str,
    destination_ip: str,
    description: str,
    severity: str = "HIGH",
) -> None:
    """Convenience function to record a structured security alert.

    Args:
        event_type:     Short event category (e.g. "MODBUS_VIOLATION").
        source_ip:      Originating IP address.
        destination_ip: Destination IP address.
        description:    Human-readable description of the event.
        severity:       Severity label — LOW, MEDIUM, HIGH, CRITICAL.
    """
    sec_logger = get_security_logger()
    msg = (
        f"[SECURITY] type={event_type} | severity={severity} | "
        f"src={source_ip} -> dst={destination_ip} | {description}"
    )
    sec_logger.warning(msg)


def setup_root_logging(level: int = logging.INFO) -> None:
    """Configure the root logger once at application startup.

    Args:
        level: Logging level to apply globally.
    """
    _ensure_log_dir()
    logging.basicConfig(
        level=level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    # Silence noisy third-party libraries
    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
    logging.getLogger("scapy.loading").setLevel(logging.ERROR)
