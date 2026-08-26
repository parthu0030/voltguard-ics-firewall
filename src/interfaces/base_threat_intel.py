"""
VoltGuard — Threat Intelligence Provider Interface (Day 8)
===========================================================
Defines the abstract interface for threat intelligence providers in VoltGuard.
Enables pluggable threat intelligence implementations (e.g. local lookup,
rule-based feeds, or future external intelligence providers) without hard coupling.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from src.models.threat_intel import ThreatIndicator, ThreatReputation


class ThreatIntelProvider(ABC):
    """
    Abstract interface for Threat Intelligence providers.

    All methods are designed to be safe, fast, and thread-safe.
    """

    @abstractmethod
    def lookup_ip(self, ip_address: str) -> Optional[ThreatIndicator]:
        """
        Lookup threat intelligence for a given IP address.

        Args:
            ip_address: IPv4 or IPv6 address string.

        Returns:
            Matching ``ThreatIndicator`` if found, or None.
        """

    @abstractmethod
    def is_suspicious(self, ip_address: str) -> bool:
        """
        Check if an IP address is considered suspicious or malicious.

        Args:
            ip_address: IP address string.

        Returns:
            True if IP matches a SUSPICIOUS or MALICIOUS indicator with positive confidence.
        """

    @abstractmethod
    def is_trusted(self, ip_address: str) -> bool:
        """
        Check if an IP address is marked as explicitly trusted.

        Args:
            ip_address: IP address string.

        Returns:
            True if IP matches a TRUSTED indicator.
        """

    @abstractmethod
    def add_indicator(self, indicator: ThreatIndicator) -> None:
        """
        Add or update a threat intelligence indicator.

        Args:
            indicator: Populated ``ThreatIndicator`` instance.
        """

    @abstractmethod
    def remove_indicator(self, indicator_key: str) -> bool:
        """
        Remove an indicator by its indicator string.

        Args:
            indicator_key: Indicator string to remove.

        Returns:
            True if an indicator was removed, False otherwise.
        """

    @abstractmethod
    def get_indicators(
        self,
        reputation: Optional[ThreatReputation] = None,
    ) -> list[ThreatIndicator]:
        """
        Retrieve all registered indicators, optionally filtered by reputation.

        Args:
            reputation: Optional filter by ``ThreatReputation``.

        Returns:
            List of ``ThreatIndicator`` instances.
        """
