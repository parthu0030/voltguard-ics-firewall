"""
VoltGuard — IPv4 Packet Parser
================================
Parses raw bytes (the payload of an Ethernet frame) into an ``IPv4Packet``
model, then returns the IP payload bytes for the next layer parser.

IPv4 Header Layout (variable length, minimum 20 bytes):
  Byte  0:      Version (4 bits) + IHL (4 bits)
  Byte  1:      DSCP + ECN (not decoded — not needed for ICS analysis)
  Bytes 2–3:    Total Length
  Bytes 4–5:    Identification (not decoded)
  Bytes 6–7:    Flags + Fragment Offset (not decoded)
  Byte  8:      TTL
  Byte  9:      Protocol (6=TCP, 17=UDP, …)
  Bytes 10–11:  Header Checksum (not verified here — hardware/OS responsibility)
  Bytes 12–15:  Source IP
  Bytes 16–19:  Destination IP
  Bytes 20+:    Options (if IHL > 5); then Payload

Usage:
    from src.parser.ipv4_parser import IPv4Parser

    parser = IPv4Parser()
    ipv4_pkt, tcp_payload = parser.parse(ethernet_payload_bytes)
"""

from __future__ import annotations

import socket
import struct
from typing import Tuple

from src.exceptions import ParserError
from src.parser.packet_models import IPv4Packet

# Minimum IPv4 header: 20 bytes (IHL=5, no options).
_IPV4_MIN_HEADER_SIZE: int = 20
# Fixed-position fields only — IHL tells us the actual header length.
# We unpack the first 20 bytes and handle options via slice.
_IPV4_FIXED_STRUCT: struct.Struct = struct.Struct("!BBHHHBBH4s4s")
# Field order: ver_ihl, dscp_ecn, total_len, ident, flags_frag, ttl, proto,
#              checksum, src_addr, dst_addr


class IPv4Parser:
    """
    Stateless parser for IPv4 packet headers.

    Each call to ``parse()`` is fully independent — no instance state is
    modified, making this class safe for concurrent use.

    Raises:
        ParserError: If the buffer is shorter than 20 bytes, the IP version
                     is not 4, or the IHL field is unreasonably small.
    """

    def parse(self, raw_bytes: bytes) -> Tuple[IPv4Packet, bytes]:
        """
        Decode the IPv4 header from ``raw_bytes``.

        Args:
            raw_bytes: Raw bytes starting at the beginning of the IP header
                       (i.e. the Ethernet payload after EtherType 0x0800).

        Returns:
            A tuple of ``(IPv4Packet, payload_bytes)`` where ``payload_bytes``
            is the IP payload (TCP/UDP data) with IP options stripped.

        Raises:
            ParserError: If the bytes are too short, the version is wrong,
                         or the IHL value is invalid.
        """
        if len(raw_bytes) < _IPV4_MIN_HEADER_SIZE:
            raise ParserError(
                "IPv4 packet too short: expected at least "
                f"{_IPV4_MIN_HEADER_SIZE} bytes, got {len(raw_bytes)}.",
                detail=f"actual_length={len(raw_bytes)}",
            )

        (
            ver_ihl, _dscp_ecn, total_length, _ident, _flags_frag,
            ttl, protocol, _checksum, src_bytes, dst_bytes,
        ) = _IPV4_FIXED_STRUCT.unpack_from(raw_bytes)

        version: int = (ver_ihl >> 4) & 0x0F
        ihl: int     = ver_ihl & 0x0F

        if version != 4:
            raise ParserError(
                f"Not an IPv4 packet: version field is {version}.",
                detail=f"version={version}",
            )

        if ihl < 5:
            raise ParserError(
                f"IPv4 IHL field {ihl} is invalid (minimum is 5).",
                detail=f"ihl={ihl}",
            )

        header_length: int = ihl * 4

        if len(raw_bytes) < header_length:
            raise ParserError(
                f"IPv4 packet truncated: IHL declares {header_length}-byte header "
                f"but only {len(raw_bytes)} bytes available.",
                detail=f"declared_header={header_length} actual={len(raw_bytes)}",
            )

        src_ip: str = socket.inet_ntoa(src_bytes)
        dst_ip: str = socket.inet_ntoa(dst_bytes)

        packet = IPv4Packet(
            version=version,
            ihl=ihl,
            total_length=total_length,
            ttl=ttl,
            protocol=protocol,
            src_ip=src_ip,
            dst_ip=dst_ip,
            raw_header=raw_bytes[:header_length],
        )
        payload = raw_bytes[header_length:]
        return packet, payload
