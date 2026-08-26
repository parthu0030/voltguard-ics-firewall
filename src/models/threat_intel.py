"""
VoltGuard — Threat Intelligence Data Models (Day 8)
====================================================
Defines typed data models and enumerations for lightweight local threat
intelligence indicators and reputation scoring.

Design principles:
  - Pure Python dataclasses: No Qt or network dependencies.
  - Safe for thread-safe operations and serialization.
  - Supports IP, CIDR, and domain indicators with confidence scores.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


def _utc_now_iso() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")


class IndicatorType(str, Enum):
    """Supported indicator types."""
    IP = "IP"
    CIDR = "CIDR"
    DOMAIN = "DOMAIN"
    SUBNET = "SUBNET"


class ThreatReputation(str, Enum):
    """Reputation classification for an indicator."""
    MALICIOUS = "MALICIOUS"
    SUSPICIOUS = "SUSPICIOUS"
    TRUSTED = "TRUSTED"
    BENIGN = "BENIGN"
    UNKNOWN = "UNKNOWN"


@dataclass
class ThreatIndicator:
    """
    Represents a threat intelligence indicator (e.g. suspicious or trusted IP/subnet).

    Attributes:
        indicator:      The indicator string (e.g. '192.168.1.100', '10.0.0.0/8').
        indicator_type: Indicator type (IP, CIDR, DOMAIN).
        reputation:     Reputation classification (MALICIOUS, SUSPICIOUS, TRUSTED, etc.).
        confidence:     Confidence score in [0.0, 1.0].
        source:         Origin of indicator (e.g. 'local_config', 'operator', 'feed').
        description:    Human-readable explanation or context.
        created_at:     ISO-8601 creation timestamp.
        tags:           Optional list of contextual tags.
    """
    indicator: str
    indicator_type: IndicatorType = IndicatorType.IP
    reputation: ThreatReputation = ThreatReputation.SUSPICIOUS
    confidence: float = 0.8
    source: str = "local_config"
    description: str = ""
    created_at: str = field(default_factory=_utc_now_iso)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Serialize indicator to dictionary."""
        return {
            "indicator": self.indicator,
            "indicator_type": self.indicator_type.value,
            "reputation": self.reputation.value,
            "confidence": self.confidence,
            "source": self.source,
            "description": self.description,
            "created_at": self.created_at,
            "tags": list(self.tags),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> ThreatIndicator:
        """Instantiate ThreatIndicator from dictionary."""
        ind_type_str = data.get("indicator_type", "IP")
        try:
            ind_type = IndicatorType(ind_type_str)
        except ValueError:
            ind_type = IndicatorType.IP

        rep_str = data.get("reputation", "SUSPICIOUS")
        try:
            reputation = ThreatReputation(rep_str)
        except ValueError:
            reputation = ThreatReputation.SUSPICIOUS

        return cls(
            indicator=str(data.get("indicator", "")),
            indicator_type=ind_type,
            reputation=reputation,
            confidence=float(data.get("confidence", 0.8)),
            source=str(data.get("source", "local_config")),
            description=str(data.get("description", "")),
            created_at=str(data.get("created_at", _utc_now_iso())),
            tags=list(data.get("tags", [])),
        )
