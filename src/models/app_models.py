"""
VoltGuard — Application Data Models
====================================
Defines typed data-classes used throughout the application.
These are pure Python dataclasses with no dependency on Qt or any service.
They serve as the Model layer in the MVC architecture.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


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
        return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")


@dataclass
class Alert:
    """
    Represents a security alert raised by the detection/policy engine.

    Attributes:
        id:             Auto-assigned database row ID.
        timestamp:      ISO-8601 datetime string.
        severity:       Alert severity level.
        message:        Human-readable alert description.
        acknowledged:   True if an operator has dismissed/acknowledged it.
        source_ip:      Source IP address if applicable.
        destination_ip: Destination IP address if applicable.
        protocol:       Protocol label.
        function_code:  Modbus function code integer if applicable.
        action:         Enforcement action string ('ALLOW', 'ALERT', 'BLOCK').
        risk_score:     Risk score (0-100).
        policy_id:      Matched policy identifier.
        event_id:       Associated SecurityEvent UUID string.
        repeat_count:   Deduplication occurrence counter.
    """
    timestamp: str
    severity: AlertSeverity
    message: str
    acknowledged: bool = False
    source_ip: str = ""
    destination_ip: str = ""
    protocol: str = ""
    function_code: Optional[int] = None
    action: str = ""
    risk_score: int = 0
    policy_id: Optional[str] = None
    event_id: Optional[str] = None
    repeat_count: int = 1
    id: Optional[int] = None

    @staticmethod
    def now_timestamp() -> str:
        """Return the current UTC time as an ISO-8601 string."""
        return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")

    def to_dict(self) -> dict[str, Any]:
        """Serialise to dictionary."""
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "severity": self.severity.value,
            "message": self.message,
            "acknowledged": self.acknowledged,
            "source_ip": self.source_ip,
            "destination_ip": self.destination_ip,
            "protocol": self.protocol,
            "function_code": self.function_code,
            "action": self.action,
            "risk_score": self.risk_score,
            "policy_id": self.policy_id,
            "event_id": self.event_id,
            "repeat_count": self.repeat_count,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Alert:
        """Construct from dictionary."""
        sev_val = data.get("severity", "LOW")
        try:
            severity = AlertSeverity(sev_val)
        except ValueError:
            severity = AlertSeverity.LOW
        return cls(
            id=data.get("id"),
            timestamp=str(data.get("timestamp", Alert.now_timestamp())),
            severity=severity,
            message=str(data.get("message", "")),
            acknowledged=bool(data.get("acknowledged", False)),
            source_ip=str(data.get("source_ip", "")),
            destination_ip=str(data.get("destination_ip", "")),
            protocol=str(data.get("protocol", "")),
            function_code=data.get("function_code"),
            action=str(data.get("action", "")),
            risk_score=int(data.get("risk_score", 0)),
            policy_id=data.get("policy_id"),
            event_id=data.get("event_id"),
            repeat_count=int(data.get("repeat_count", 1)),
        )


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
        return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")


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
        return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")


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
