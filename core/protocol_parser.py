"""
VoltGuard Protocol Parser
--------------------------
Parses captured Scapy packets and extracts structured metadata for:
  - Modbus TCP (port 502)
  - DNP3 (port 20000)
  - Generic / Unknown protocols
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Optional

from core.logger import get_logger

log = get_logger(__name__)

# Standard ICS protocol port mappings
MODBUS_PORT = 502
DNP3_PORT = 20000


@dataclass
class ParsedPacket:
    """Structured representation of a parsed network packet.

    Attributes:
        timestamp:      ISO-8601 capture time.
        src_ip:         Source IP address.
        dst_ip:         Destination IP address.
        src_port:       Source TCP/UDP port.
        dst_port:       Destination TCP/UDP port.
        protocol:       Identified protocol string (MODBUS, DNP3, TCP, UDP, UNKNOWN, …).
        function_code:  ICS function code (Modbus / DNP3) if applicable.
        payload_length: Raw payload size in bytes.
        raw_summary:    Brief human-readable packet summary.
        extra:          Protocol-specific metadata dictionary.
    """

    timestamp: str = ""
    src_ip: str = "0.0.0.0"
    dst_ip: str = "0.0.0.0"
    src_port: Optional[int] = None
    dst_port: Optional[int] = None
    protocol: str = "UNKNOWN"
    function_code: Optional[int] = None
    payload_length: int = 0
    raw_summary: str = ""
    extra: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        """Return a plain dictionary representation suitable for storage."""
        return {
            "timestamp": self.timestamp,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "src_port": self.src_port,
            "dst_port": self.dst_port,
            "protocol": self.protocol,
            "function_code": self.function_code,
            "payload_length": self.payload_length,
            "raw_summary": self.raw_summary,
        }


class ProtocolParser:
    """Stateless protocol parser that converts raw Scapy packets to :class:`ParsedPacket`.

    Usage::

        parser = ProtocolParser()
        parsed = parser.parse(scapy_packet)
    """

    def parse(self, pkt: Any) -> ParsedPacket:
        """Dispatch a Scapy packet to the appropriate protocol handler.

        Args:
            pkt: A Scapy packet object.

        Returns:
            A :class:`ParsedPacket` with fields populated to the extent possible.
        """
        # Lazy-import scapy layers to keep startup fast
        try:
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.layers.l2 import Ether
        except ImportError:
            log.error("Scapy not available — cannot parse packet.")
            return ParsedPacket()

        parsed = ParsedPacket(
            timestamp=datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S"),
            raw_summary=pkt.summary() if hasattr(pkt, "summary") else str(pkt),
        )

        # Extract IP layer
        if pkt.haslayer(IP):
            ip_layer = pkt[IP]
            parsed.src_ip = ip_layer.src
            parsed.dst_ip = ip_layer.dst

        # Extract transport layer
        if pkt.haslayer(TCP):
            tcp_layer = pkt[TCP]
            parsed.src_port = int(tcp_layer.sport)
            parsed.dst_port = int(tcp_layer.dport)
            payload = bytes(tcp_layer.payload)
            parsed.payload_length = len(payload)
            parsed = self._identify_tcp_protocol(parsed, tcp_layer, payload)

        elif pkt.haslayer(UDP):
            udp_layer = pkt[UDP]
            parsed.src_port = int(udp_layer.sport)
            parsed.dst_port = int(udp_layer.dport)
            payload = bytes(udp_layer.payload)
            parsed.payload_length = len(payload)
            parsed.protocol = "UDP"

        else:
            parsed.protocol = "NON-IP"

        log.debug(
            "Parsed packet: %s %s→%s proto=%s fc=%s",
            parsed.timestamp,
            parsed.src_ip,
            parsed.dst_ip,
            parsed.protocol,
            parsed.function_code,
        )
        return parsed

    # ------------------------------------------------------------------
    # Protocol-specific parsers
    # ------------------------------------------------------------------

    def _identify_tcp_protocol(
        self, parsed: ParsedPacket, tcp_layer: Any, payload: bytes
    ) -> ParsedPacket:
        """Route TCP packet to the correct ICS parser.

        Args:
            parsed:    Partially-populated :class:`ParsedPacket`.
            tcp_layer: Scapy TCP layer object.
            payload:   Raw TCP payload bytes.

        Returns:
            Updated :class:`ParsedPacket`.
        """
        sport = parsed.src_port or 0
        dport = parsed.dst_port or 0

        if MODBUS_PORT in (sport, dport):
            return self.parse_modbus(parsed, payload)
        elif DNP3_PORT in (sport, dport):
            return self.parse_dnp3(parsed, payload)
        else:
            parsed.protocol = "TCP"
            return parsed

    def parse_modbus(self, parsed: ParsedPacket, payload: bytes) -> ParsedPacket:
        """Extract Modbus TCP fields from raw payload bytes.

        Modbus TCP Application Data Unit (ADU) layout::

            [Transaction ID: 2 B][Protocol ID: 2 B][Length: 2 B]
            [Unit ID: 1 B][Function Code: 1 B][Data: N B]

        Args:
            parsed:  Partially-populated packet record.
            payload: Raw TCP payload bytes.

        Returns:
            Updated :class:`ParsedPacket` with Modbus metadata.
        """
        parsed.protocol = "MODBUS"

        if len(payload) < 8:
            # Payload too short to contain a valid Modbus ADU header
            parsed.extra["parse_error"] = "Modbus payload too short"
            return parsed

        transaction_id = int.from_bytes(payload[0:2], "big")
        protocol_id = int.from_bytes(payload[2:4], "big")
        length = int.from_bytes(payload[4:6], "big")
        unit_id = payload[6]
        function_code = payload[7]

        parsed.function_code = function_code
        parsed.extra.update(
            {
                "modbus_transaction_id": transaction_id,
                "modbus_protocol_id": protocol_id,
                "modbus_length": length,
                "modbus_unit_id": unit_id,
                "modbus_function_code": function_code,
                "modbus_function_name": _modbus_function_name(function_code),
            }
        )
        return parsed

    def parse_dnp3(self, parsed: ParsedPacket, payload: bytes) -> ParsedPacket:
        """Extract DNP3 fields from raw payload bytes.

        DNP3 Data Link Layer frame::

            [Start Bytes: 2 B (0x0564)][Length: 1 B][Control: 1 B]
            [Destination: 2 B][Source: 2 B][CRC: 2 B][Transport + App Data]

        Args:
            parsed:  Partially-populated packet record.
            payload: Raw TCP payload bytes.

        Returns:
            Updated :class:`ParsedPacket` with DNP3 metadata.
        """
        parsed.protocol = "DNP3"

        if len(payload) < 10:
            parsed.extra["parse_error"] = "DNP3 payload too short"
            return parsed

        # Verify start bytes
        if payload[0:2] != b"\x05\x64":
            parsed.extra["parse_warning"] = "DNP3 start bytes mismatch"

        length = payload[2]
        control = payload[3]
        destination = int.from_bytes(payload[4:6], "little")
        source = int.from_bytes(payload[6:8], "little")

        # Application function code is at offset 12 (after 2-byte CRC in link layer)
        function_code: Optional[int] = None
        if len(payload) >= 13:
            function_code = payload[12]
            parsed.function_code = function_code

        parsed.extra.update(
            {
                "dnp3_length": length,
                "dnp3_control": hex(control),
                "dnp3_destination": destination,
                "dnp3_source": source,
                "dnp3_function_code": function_code,
                "dnp3_function_name": _dnp3_function_name(function_code),
            }
        )
        return parsed

    def parse_unknown(self, parsed: ParsedPacket, payload: bytes) -> ParsedPacket:
        """Minimal fallback parser for unrecognised protocols.

        Args:
            parsed:  Partially-populated packet record.
            payload: Raw payload bytes.

        Returns:
            Updated :class:`ParsedPacket` tagged as UNKNOWN.
        """
        parsed.protocol = "UNKNOWN"
        parsed.extra["hex_preview"] = payload[:16].hex() if payload else ""
        return parsed


# ---------------------------------------------------------------------------
# ICS protocol function-code lookup tables
# ---------------------------------------------------------------------------

_MODBUS_FUNCTION_CODES: dict[int, str] = {
    1: "Read Coils",
    2: "Read Discrete Inputs",
    3: "Read Holding Registers",
    4: "Read Input Registers",
    5: "Write Single Coil",
    6: "Write Single Register",
    8: "Diagnostics",
    15: "Write Multiple Coils",
    16: "Write Multiple Registers",
    17: "Report Server ID",
    23: "Read/Write Multiple Registers",
    43: "Encapsulated Interface Transport",
}

_DNP3_FUNCTION_CODES: dict[int, str] = {
    0: "Confirm",
    1: "Read",
    2: "Write",
    3: "Select",
    4: "Operate",
    5: "Direct Operate",
    6: "Direct Operate No Ack",
    7: "Freeze",
    8: "Freeze No Ack",
    129: "Response",
    130: "Unsolicited Response",
    131: "Authentication Request",
}


def _modbus_function_name(code: int) -> str:
    """Translate a Modbus function code to its human-readable name."""
    return _MODBUS_FUNCTION_CODES.get(code, f"Unknown FC({code})")


def _dnp3_function_name(code: Optional[int]) -> str:
    """Translate a DNP3 function code to its human-readable name."""
    if code is None:
        return "N/A"
    return _DNP3_FUNCTION_CODES.get(code, f"Unknown FC({code})")
