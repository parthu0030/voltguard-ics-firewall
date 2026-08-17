"""
VoltGuard — Ethernet Frame Parser
====================================
Parses raw bytes into an ``EthernetFrame`` model, exposing the Ethernet II
header fields and returning the remaining payload bytes for the next layer.

Ethernet II Frame Layout (14-byte header):
  Bytes 0–5:   Destination MAC address
  Bytes 6–11:  Source MAC address
  Bytes 12–13: EtherType (0x0800 = IPv4, 0x0806 = ARP, …)
  Bytes 14+:   Payload (passed to the next parser)

Usage:
    from src.parser.ethernet_parser import EthernetParser

    parser = EthernetParser()
    frame, payload = parser.parse(raw_bytes)
"""

from __future__ import annotations

import struct
from typing import Tuple

from src.exceptions import ParserError
from src.parser.packet_models import EthernetFrame

# Ethernet II header is always exactly 14 bytes.
_ETHERNET_HEADER_SIZE: int = 14
# Struct format: 6B dst_mac + 6B src_mac + H ether_type
_ETHERNET_STRUCT: struct.Struct = struct.Struct("!6s6sH")


class EthernetParser:
    """
    Stateless parser for Ethernet II frame headers.

    Each call to ``parse()`` is fully independent — no instance state is
    modified, making this class safe for concurrent use.

    Raises:
        ParserError: If ``raw_bytes`` is shorter than the 14-byte Ethernet header.
    """

    def parse(self, raw_bytes: bytes) -> Tuple[EthernetFrame, bytes]:
        """
        Decode the Ethernet II header from ``raw_bytes``.

        Args:
            raw_bytes: Complete raw frame bytes starting at the Ethernet header.

        Returns:
            A tuple of ``(EthernetFrame, payload_bytes)`` where ``payload_bytes``
            is everything after the 14-byte Ethernet header.

        Raises:
            ParserError: If ``raw_bytes`` contains fewer than 14 bytes.
        """
        if len(raw_bytes) < _ETHERNET_HEADER_SIZE:
            raise ParserError(
                "Ethernet frame too short: expected at least "
                f"{_ETHERNET_HEADER_SIZE} bytes, got {len(raw_bytes)}.",
                detail=f"actual_length={len(raw_bytes)}",
            )

        dst_mac_bytes, src_mac_bytes, ether_type = _ETHERNET_STRUCT.unpack_from(raw_bytes)

        frame = EthernetFrame(
            dst_mac=self._format_mac(dst_mac_bytes),
            src_mac=self._format_mac(src_mac_bytes),
            ether_type=ether_type,
        )
        payload = raw_bytes[_ETHERNET_HEADER_SIZE:]
        return frame, payload

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _format_mac(mac_bytes: bytes) -> str:
        """
        Format a 6-byte MAC address as an upper-case colon-separated string.

        Args:
            mac_bytes: Exactly 6 bytes representing a MAC address.

        Returns:
            String in the form ``'AA:BB:CC:DD:EE:FF'``.
        """
        return ":".join(f"{b:02X}" for b in mac_bytes)
