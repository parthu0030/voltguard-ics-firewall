"""
VoltGuard — Local Threat Intelligence Provider Service (Day 8)
===============================================================
Thread-safe, local threat intelligence provider implementation.
Evaluates IP addresses and subnets against local configurations and rules
without requiring external network/API dependencies.

Features:
  - Exact IPv4/IPv6 address lookups.
  - CIDR subnet containment lookups (e.g. 192.168.1.0/24, 10.0.0.0/8).
  - Configurable indicators (SUSPICIOUS, MALICIOUS, TRUSTED, BENIGN).
  - Confidence scoring and contextual metadata tagging.
  - Safe, fast in-memory lookups protected by reentrant lock.
"""

from __future__ import annotations

import ipaddress
import threading
from typing import Any, Optional

from src.interfaces.base_threat_intel import ThreatIntelProvider
from src.logger import get_logger
from src.models.threat_intel import (
    IndicatorType,
    ThreatIndicator,
    ThreatReputation,
)

_log = get_logger(__name__)


class LocalThreatIntelProvider(ThreatIntelProvider):
    """
    Local in-memory threat intelligence provider.

    Maintains exact IP indicators and CIDR network indicators.
    """

    def __init__(self, initial_indicators: Optional[list[ThreatIndicator]] = None) -> None:
        self._lock = threading.RLock()
        self._ip_indicators: dict[str, ThreatIndicator] = {}
        self._network_indicators: list[tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ThreatIndicator]] = []

        if initial_indicators:
            for ind in initial_indicators:
                self.add_indicator(ind)

    def add_indicator(self, indicator: ThreatIndicator) -> None:
        """
        Add or update an indicator in the local store.

        Supports single IPs and CIDR networks.
        """
        with self._lock:
            key = indicator.indicator.strip()
            # Check if it is a CIDR notation
            if "/" in key or indicator.indicator_type in (IndicatorType.CIDR, IndicatorType.SUBNET):
                try:
                    net = ipaddress.ip_network(key, strict=False)
                    # Remove existing if any
                    self._network_indicators = [
                        (n, ind) for (n, ind) in self._network_indicators if str(n) != str(net)
                    ]
                    self._network_indicators.append((net, indicator))
                    return
                except ValueError:
                    _log.warning("Invalid CIDR network indicator ignored: %s", key)

            # Otherwise treat as exact IP/string
            try:
                ip_obj = ipaddress.ip_address(key)
                self._ip_indicators[str(ip_obj)] = indicator
            except ValueError:
                # Store as literal string indicator (e.g. hostname / label)
                self._ip_indicators[key] = indicator

    def remove_indicator(self, indicator_key: str) -> bool:
        """Remove an indicator by key string."""
        with self._lock:
            key = indicator_key.strip()
            removed = False
            if key in self._ip_indicators:
                del self._ip_indicators[key]
                removed = True

            # Also check networks
            orig_len = len(self._network_indicators)
            self._network_indicators = [
                (n, ind) for (n, ind) in self._network_indicators
                if str(n) != key and ind.indicator != key
            ]
            if len(self._network_indicators) < orig_len:
                removed = True

            return removed

    def clear(self) -> None:
        """Clear all indicators."""
        with self._lock:
            self._ip_indicators.clear()
            self._network_indicators.clear()

    def lookup_ip(self, ip_address: str) -> Optional[ThreatIndicator]:
        """
        Look up threat intelligence for an IP address.

        Checks exact IP match first, then CIDR subnets.
        """
        if not ip_address or ip_address in ("unknown", "0.0.0.0", ""):
            return None

        ip_str = ip_address.strip()
        with self._lock:
            # 1. Exact match
            if ip_str in self._ip_indicators:
                return self._ip_indicators[ip_str]

            # 2. Try parsing IP and matching normalized IP or CIDR networks
            try:
                ip_obj = ipaddress.ip_address(ip_str)
                norm_str = str(ip_obj)
                if norm_str in self._ip_indicators:
                    return self._ip_indicators[norm_str]

                # Match against networks (most specific prefix first if multiple)
                matching_nets = [
                    (net, ind) for (net, ind) in self._network_indicators
                    if ip_obj in net
                ]
                if matching_nets:
                    # Sort by prefix length descending (longest prefix match)
                    matching_nets.sort(key=lambda x: x[0].prefixlen, reverse=True)
                    return matching_nets[0][1]

            except ValueError:
                # Not a valid IP object, try literal lookup
                return self._ip_indicators.get(ip_str)

        return None

    def is_suspicious(self, ip_address: str) -> bool:
        """Return True if IP matches a SUSPICIOUS or MALICIOUS indicator with positive confidence."""
        ind = self.lookup_ip(ip_address)
        if ind is None:
            return False
        return ind.reputation in (ThreatReputation.SUSPICIOUS, ThreatReputation.MALICIOUS) and ind.confidence > 0.0

    def is_trusted(self, ip_address: str) -> bool:
        """Return True if IP matches a TRUSTED or BENIGN indicator."""
        ind = self.lookup_ip(ip_address)
        if ind is None:
            return False
        return ind.reputation in (ThreatReputation.TRUSTED, ThreatReputation.BENIGN)

    def get_indicators(
        self,
        reputation: Optional[ThreatReputation] = None,
    ) -> list[ThreatIndicator]:
        """Retrieve list of indicators, optionally filtered by reputation."""
        with self._lock:
            all_inds: list[ThreatIndicator] = list(self._ip_indicators.values()) + [
                ind for (_, ind) in self._network_indicators
            ]
            if reputation is not None:
                return [ind for ind in all_inds if ind.reputation == reputation]
            return list(all_inds)

    def count(self) -> int:
        """Return total indicator count."""
        with self._lock:
            return len(self._ip_indicators) + len(self._network_indicators)


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
local_threat_intel_provider: LocalThreatIntelProvider = LocalThreatIntelProvider()
