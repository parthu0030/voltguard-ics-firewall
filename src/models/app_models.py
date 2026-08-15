"""
VoltGuard — Application Data Models
====================================
Defines typed data-classes used throughout the application.
These are pure Python dataclasses with no dependency on Qt or any service.
They serve as the Model layer in the MVC architecture.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------

class PacketAction(str, Enum):
    """Possible decision outcomes for an inspected packet."""
    ALLOW = "ALLOW"
    BLOCK = "BLOCK"


class AlertSeverity(str, Enum):
    """Severity levels for security alerts."""
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class LogLevel(str, Enum):
    """Log severity levels mirroring Python's logging module."""
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


# ---------------------------------------------------------------------------
# Data Classes
# ---------------------------------------------------------------------------

@dataclass
class PacketLog:
    """
    Represents a single inspected network packet record.

    Attributes:
        id:         Auto-assigned database row ID (None before insertion).
        timestamp:  ISO-8601 datetime string of capture time.
        src_ip:     Source IP address string.
        dst_ip:     Destination IP address string.
        protocol:   Protocol name (e.g. 'Modbus TCP', 'TCP', 'UDP').
        port:       Destination port number.
        action:     Whether the packet was allowed or blocked.
        risk_score: Float in [0.0, 1.0]; 1.0 is maximum risk.
        raw_data:   Optional raw bytes of the packet payload.
    """
    timestamp: str
    src_ip: str
    dst_ip: str
    protocol: str
    port: int
    action: PacketAction
    risk_score: float = 0.0
    raw_data: Optional[bytes] = None
    id: Optional[int] = None

    @staticmethod
    def now_timestamp() -> str:
        """Return the current UTC time as an ISO-8601 string."""
        return datetime.utcnow().isoformat(timespec="seconds")


@dataclass
class Alert:
    """
    Represents a security alert raised by the detection engine.

    Attributes:
        id:           Auto-assigned database row ID.
        timestamp:    ISO-8601 datetime string.
        severity:     Alert severity level.
        message:      Human-readable alert description.
        acknowledged: True if an operator has dismissed/acknowledged it.
    """
    timestamp: str
    severity: AlertSeverity
    message: str
    acknowledged: bool = False
    id: Optional[int] = None

    @staticmethod
    def now_timestamp() -> str:
        """Return the current UTC time as an ISO-8601 string."""
        return datetime.utcnow().isoformat(timespec="seconds")


@dataclass
class ApplicationSetting:
    """
    Represents a single key-value application configuration entry.

    Attributes:
        key:        Unique setting identifier (e.g. 'theme').
        value:      String value stored for the key.
        updated_at: ISO-8601 datetime of last modification.
        id:         Auto-assigned database row ID.
    """
    key: str
    value: str
    updated_at: str
    id: Optional[int] = None

    @staticmethod
    def now_timestamp() -> str:
        """Return the current UTC time as an ISO-8601 string."""
        return datetime.utcnow().isoformat(timespec="seconds")


@dataclass
class EventLog:
    """
    Represents a structured application event stored in the database.

    Attributes:
        id:        Auto-assigned database row ID.
        timestamp: ISO-8601 datetime string.
        level:     Log severity level.
        source:    Module or component that generated the event.
        message:   Event description text.
    """
    timestamp: str
    level: LogLevel
    source: str
    message: str
    id: Optional[int] = None

    @staticmethod
    def now_timestamp() -> str:
        """Return the current UTC time as an ISO-8601 string."""
        return datetime.utcnow().isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# Application Configuration Defaults
# ---------------------------------------------------------------------------

APP_DEFAULT_SETTINGS: dict[str, str] = {
    "theme": "dark",
    "selected_interface": "lo0",
    "log_level": "INFO",
    "app_version": "1.0.0",
    "app_name": "VoltGuard",
}
