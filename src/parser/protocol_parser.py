"""
VoltGuard — Protocol Parser Orchestrator
==========================================
Top-level parser that coordinates all protocol-layer parsers into a single
pipeline:

    Raw bytes → EthernetParser → IPv4Parser → TCPParser → ModbusParser
                                                        ↓
                                                   FullPacket

``ProtocolParser`` is the single entry-point that downstream components
(physics engine, decision engine, dashboard) should interact with.

Two operating modes:
  1. ``parse_full_packet(raw_bytes)``  — complete Ethernet+IP+TCP+Modbus pipeline
  2. ``parse_modbus_only(raw_bytes)``  — Modbus MBAP+PDU bytes only (no network layers)

Both modes return a ``FullPacket`` regardless of success or failure — the
``parse_status`` field indicates the outcome, and ``error_message`` describes
the failure when relevant.

Parser Statistics (``ParserStatistics``) are updated after every call and can
be retrieved via ``get_statistics()``.

Every parsed packet is logged via the VoltGuard rotating logger.

Usage:
    from src.parser.protocol_parser import ProtocolParser

    parser = ProtocolParser()
    packet = parser.parse_modbus_only(raw_bytes)
    if packet.is_valid:
        print(packet.modbus.function_name)
    stats = parser.get_statistics()
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from src.exceptions import ParserError, UnsupportedProtocolError
from src.logger import get_logger
from src.parser.ethernet_parser import EthernetParser
from src.parser.ipv4_parser import IPv4Parser
from src.parser.modbus_parser import ModbusParser
from src.parser.packet_models import (
    EthernetFrame,
    FullPacket,
    IPv4Packet,
    ModbusTCPPacket,
    ParseStatus,
    TCPSegment,
)
from src.parser.tcp_parser import TCPParser

_log: logging.Logger = get_logger(__name__)


# ---------------------------------------------------------------------------
# Parser Statistics
# ---------------------------------------------------------------------------

@dataclass
class ParserStatistics:
    """
    Running counters maintained by ``ProtocolParser`` across all parse calls.

    Attributes:
        total_parsed:         Total number of parse attempts (success + failure).
        valid_count:          Number of packets that parsed successfully.
        invalid_count:        Number of packets that failed any validation step.
        function_code_counts: Map of FC name → count for successfully parsed packets.
        error_counts:         Map of ``ParseStatus`` name → count for failed packets.
    """
    total_parsed:         int                = 0
    valid_count:          int                = 0
    invalid_count:        int                = 0
    function_code_counts: dict[str, int]     = field(default_factory=dict)
    error_counts:         dict[str, int]     = field(default_factory=dict)

    def record_valid(self, function_name: str) -> None:
        """Record a successful parse and increment the per-FC counter."""
        self.total_parsed  += 1
        self.valid_count   += 1
        self.function_code_counts[function_name] = (
            self.function_code_counts.get(function_name, 0) + 1
        )

    def record_invalid(self, status: ParseStatus) -> None:
        """Record a failed parse and increment the per-status error counter."""
        self.total_parsed  += 1
        self.invalid_count += 1
        key = status.value
        self.error_counts[key] = self.error_counts.get(key, 0) + 1

    def reset(self) -> None:
        """Reset all counters to zero."""
        self.total_parsed         = 0
        self.valid_count          = 0
        self.invalid_count        = 0
        self.function_code_counts = {}
        self.error_counts         = {}

    def get_summary(self) -> dict:
        """
        Return a plain-dict summary of all statistics.

        Returns:
            Dict with keys: total, valid, invalid, by_function_code, by_error.
        """
        return {
            "total":            self.total_parsed,
            "valid":            self.valid_count,
            "invalid":          self.invalid_count,
            "by_function_code": dict(self.function_code_counts),
            "by_error":         dict(self.error_counts),
        }


# ---------------------------------------------------------------------------
# Protocol Parser Orchestrator
# ---------------------------------------------------------------------------

class ProtocolParser:
    """
    Orchestrates the full Ethernet → IPv4 → TCP → Modbus TCP parse pipeline.

    Maintains parser statistics across all calls.  Thread-safety note: the
    ``ParserStatistics`` update is not locked; use separate ``ProtocolParser``
    instances per thread if concurrent parsing is required.

    Attributes:
        _eth_parser:    Ethernet layer parser.
        _ipv4_parser:   IPv4 layer parser.
        _tcp_parser:    TCP layer parser.
        _modbus_parser: Modbus TCP layer parser.
        _stats:         Running parse statistics.
    """

    def __init__(self) -> None:
        self._eth_parser:    EthernetParser = EthernetParser()
        self._ipv4_parser:   IPv4Parser     = IPv4Parser()
        self._tcp_parser:    TCPParser      = TCPParser()
        self._modbus_parser: ModbusParser   = ModbusParser()
        self._stats:         ParserStatistics = ParserStatistics()

    # ------------------------------------------------------------------
    # Public Parse API
    # ------------------------------------------------------------------

    def parse_full_packet(self, raw_bytes: bytes) -> FullPacket:
        """
        Parse a complete Ethernet II / IPv4 / TCP / Modbus TCP frame.

        The parser runs each layer in sequence.  If any layer fails, a
        ``FullPacket`` is returned immediately with the appropriate
        ``ParseStatus`` and the layers decoded so far populated.

        Args:
            raw_bytes: Raw bytes of the full Ethernet frame.

        Returns:
            A ``FullPacket`` with all decoded layers and parse metadata.
            Never raises — all errors are captured in the returned object.
        """
        timestamp = self._utc_now()

        # ── Ethernet layer ─────────────────────────────────────────────────
        ethernet: Optional[EthernetFrame] = None
        ipv4:     Optional[IPv4Packet]    = None
        tcp:      Optional[TCPSegment]    = None
        modbus:   Optional[ModbusTCPPacket] = None

        try:
            ethernet, ip_payload = self._eth_parser.parse(raw_bytes)
        except ParserError as exc:
            return self._make_failed(
                raw_bytes, timestamp, ParseStatus.MALFORMED,
                str(exc), ethernet=None, ipv4=None, tcp=None, modbus=None,
            )

        # ── IPv4 layer ─────────────────────────────────────────────────────
        try:
            ipv4, tcp_payload = self._ipv4_parser.parse(ip_payload)
        except ParserError as exc:
            return self._make_failed(
                raw_bytes, timestamp, ParseStatus.MALFORMED,
                str(exc), ethernet=ethernet, ipv4=None, tcp=None, modbus=None,
            )

        # ── TCP layer ──────────────────────────────────────────────────────
        try:
            tcp, modbus_payload = self._tcp_parser.parse(tcp_payload)
        except ParserError as exc:
            return self._make_failed(
                raw_bytes, timestamp, ParseStatus.MALFORMED,
                str(exc), ethernet=ethernet, ipv4=ipv4, tcp=None, modbus=None,
            )

        # ── Modbus layer ───────────────────────────────────────────────────
        return self._parse_modbus_layer(
            raw_bytes, timestamp, modbus_payload,
            ethernet=ethernet, ipv4=ipv4, tcp=tcp,
        )

    def parse_modbus_only(self, raw_bytes: bytes) -> FullPacket:
        """
        Parse raw Modbus TCP MBAP+PDU bytes without any network layer headers.

        Use this when the bytes start directly at the Modbus Transaction ID —
        e.g. data received on a TCP stream, synthetic test data, or packets
        where the Ethernet/IP/TCP layers have already been stripped.

        Args:
            raw_bytes: Raw Modbus TCP bytes starting at the MBAP header.

        Returns:
            A ``FullPacket`` with only the Modbus layer populated.
            Never raises — all errors are captured in the returned object.
        """
        timestamp = self._utc_now()
        return self._parse_modbus_layer(
            raw_bytes, timestamp, raw_bytes,
            ethernet=None, ipv4=None, tcp=None,
        )

    def get_statistics(self) -> dict:
        """
        Return a plain-dict summary of all parse statistics.

        Returns:
            Dict with keys: total, valid, invalid, by_function_code, by_error.
        """
        return self._stats.get_summary()

    def reset_statistics(self) -> None:
        """Reset all parser statistics to zero."""
        self._stats.reset()

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _parse_modbus_layer(
        self,
        raw_bytes:  bytes,
        timestamp:  str,
        modbus_raw: bytes,
        *,
        ethernet: Optional[EthernetFrame],
        ipv4:     Optional[IPv4Packet],
        tcp:      Optional[TCPSegment],
    ) -> FullPacket:
        """
        Run the Modbus parser on ``modbus_raw`` and assemble a ``FullPacket``.

        Handles all Modbus-specific error cases and maps them to the correct
        ``ParseStatus`` before logging and returning.
        """
        modbus: Optional[ModbusTCPPacket] = None
        parse_status: ParseStatus
        error_message: str = ""

        try:
            modbus = self._modbus_parser.parse_modbus(modbus_raw)
            parse_status = ParseStatus.VALID

        except UnsupportedProtocolError as exc:
            parse_status  = ParseStatus.UNSUPPORTED_FC
            error_message = str(exc)

        except ParserError as exc:
            # Map the detail/message content to specific ParseStatus values.
            parse_status  = self._classify_parser_error(exc)
            error_message = str(exc)

        except Exception as exc:  # noqa: BLE001
            parse_status  = ParseStatus.MALFORMED
            error_message = f"Unexpected parse error: {exc}"

        # ── Log the outcome ────────────────────────────────────────────────
        src_ip = ipv4.src_ip if ipv4 else "unknown"
        dst_ip = ipv4.dst_ip if ipv4 else "unknown"
        self._log_packet(timestamp, src_ip, dst_ip, modbus, parse_status, error_message)

        # ── Update statistics ──────────────────────────────────────────────
        if parse_status == ParseStatus.VALID and modbus is not None:
            self._stats.record_valid(modbus.function_name)
        else:
            self._stats.record_invalid(parse_status)

        packet = FullPacket(
            parse_status=parse_status,
            raw_bytes=raw_bytes,
            timestamp=timestamp,
            ethernet=ethernet,
            ipv4=ipv4,
            tcp=tcp,
            modbus=modbus,
            error_message=error_message,
        )
        return packet

    def _make_failed(
        self,
        raw_bytes:     bytes,
        timestamp:     str,
        status:        ParseStatus,
        error_message: str,
        *,
        ethernet: Optional[EthernetFrame],
        ipv4:     Optional[IPv4Packet],
        tcp:      Optional[TCPSegment],
        modbus:   Optional[ModbusTCPPacket],
    ) -> FullPacket:
        """Build and return a failed ``FullPacket``, logging the error."""
        self._log_packet(timestamp, "unknown", "unknown", None, status, error_message)
        self._stats.record_invalid(status)
        return FullPacket(
            parse_status=status,
            raw_bytes=raw_bytes,
            timestamp=timestamp,
            ethernet=ethernet,
            ipv4=ipv4,
            tcp=tcp,
            modbus=modbus,
            error_message=error_message,
        )

    @staticmethod
    def _classify_parser_error(exc: ParserError) -> ParseStatus:
        """
        Map a ``ParserError`` to the most specific ``ParseStatus`` based on
        the error message content.

        Args:
            exc: The raised ``ParserError`` instance.

        Returns:
            The best matching ``ParseStatus`` enum value.
        """
        msg = str(exc).lower()
        if "too short" in msg or "length" in msg and "short" in msg:
            return ParseStatus.INVALID_LENGTH
        if "truncated" in msg or "declared" in msg and "bytes" in msg:
            return ParseStatus.TRUNCATED
        if "protocol id" in msg or "protocol_id" in msg:
            return ParseStatus.INVALID_PROTOCOL_ID
        return ParseStatus.MALFORMED

    @staticmethod
    def _log_packet(
        timestamp:     str,
        src_ip:        str,
        dst_ip:        str,
        modbus:        Optional[ModbusTCPPacket],
        parse_status:  ParseStatus,
        error_message: str,
    ) -> None:
        """
        Emit a structured log line for every parsed packet.

        Format:
          INFO  → valid packets (src → dst | FC | status)
          WARNING → invalid/unsupported packets
          ERROR → malformed/unexpected packets
        """
        fc_info = (
            f"FC=0x{modbus.function_code:02X} ({modbus.function_name})"
            if modbus else "FC=N/A"
        )
        log_line = (
            f"[{timestamp}] {src_ip} → {dst_ip} | {fc_info} | status={parse_status.value}"
        )
        if error_message:
            log_line += f" | error={error_message}"

        if parse_status == ParseStatus.VALID:
            _log.info(log_line)
        elif parse_status in (ParseStatus.UNSUPPORTED_FC, ParseStatus.INVALID_LENGTH,
                              ParseStatus.INVALID_PROTOCOL_ID, ParseStatus.TRUNCATED):
            _log.warning(log_line)
        else:
            _log.error(log_line)

    @staticmethod
    def _utc_now() -> str:
        """Return the current UTC time as an ISO-8601 string."""
        return datetime.now(timezone.utc).isoformat(timespec="seconds")
