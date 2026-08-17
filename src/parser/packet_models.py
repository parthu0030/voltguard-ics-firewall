"""
VoltGuard — Packet Data Models
================================
Pure Python dataclasses and enumerations that represent every protocol layer
the VoltGuard parser stack can decode.

Layer order (outer → inner):
  Ethernet Frame → IPv4 Packet → TCP Segment → Modbus TCP Packet

Design principles:
  - All models are immutable-friendly (frozen=False but treated as read-only
    after construction so the parser pipeline can freely pass them around).
  - No Qt, no database, no external library dependencies — safe to import
    from tests, the physics engine, or the decision engine.
  - Every field is fully type-annotated and documented.

Usage:
    from src.parser.packet_models import (
        EthernetFrame, IPv4Packet, TCPSegment,
        ModbusTCPPacket, FullPacket,
        ModbusFunctionCode, ParseStatus, TCPFlags,
    )
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntEnum, Enum
from typing import Optional


# ---------------------------------------------------------------------------
# Modbus Function Code Enumeration
# ---------------------------------------------------------------------------

class ModbusFunctionCode(IntEnum):
    """
    Supported Modbus function codes.

    Only function codes explicitly listed here are accepted as valid by the
    ModbusParser.  Any other code results in a ``ParseStatus.UNSUPPORTED_FC``
    error.
    """
    READ_COILS                = 0x01  # Read Coils
    READ_HOLDING_REGISTERS    = 0x03  # Read Holding Registers
    WRITE_SINGLE_COIL         = 0x05  # Write Single Coil
    WRITE_SINGLE_REGISTER     = 0x06  # Write Single Register
    WRITE_MULTIPLE_REGISTERS  = 0x10  # Write Multiple Registers

    @classmethod
    def from_byte(cls, value: int) -> "ModbusFunctionCode":
        """
        Convert a raw byte value to a ``ModbusFunctionCode``.

        Args:
            value: Raw function code byte.

        Returns:
            Matching ``ModbusFunctionCode`` member.

        Raises:
            ValueError: If the value is not a supported function code.
        """
        try:
            return cls(value)
        except ValueError:
            raise ValueError(
                f"Unsupported Modbus function code: 0x{value:02X}"
            )

    @property
    def description(self) -> str:
        """Return a human-readable description of this function code."""
        _descriptions: dict[int, str] = {
            0x01: "Read Coils",
            0x03: "Read Holding Registers",
            0x05: "Write Single Coil",
            0x06: "Write Single Register",
            0x10: "Write Multiple Registers",
        }
        return _descriptions.get(self.value, f"Unknown FC 0x{self.value:02X}")


# ---------------------------------------------------------------------------
# Parse Status Enumeration
# ---------------------------------------------------------------------------

class ParseStatus(Enum):
    """
    Result status of a packet parse attempt.

    Used to distinguish the specific reason a packet failed validation from
    a generic boolean pass/fail.
    """
    VALID                = "VALID"               # Successfully parsed
    INVALID_LENGTH       = "INVALID_LENGTH"      # Packet too short
    INVALID_PROTOCOL_ID  = "INVALID_PROTOCOL_ID" # Modbus protocol_id != 0x0000
    UNSUPPORTED_FC       = "UNSUPPORTED_FC"      # Function code not supported
    MALFORMED            = "MALFORMED"           # Structurally corrupt frame
    TRUNCATED            = "TRUNCATED"           # Declared length > actual bytes


# ---------------------------------------------------------------------------
# TCP Flags
# ---------------------------------------------------------------------------

@dataclass
class TCPFlags:
    """
    Individual TCP control flags extracted from the TCP header flags field.

    Attributes:
        fin: FIN — no more data from sender.
        syn: SYN — synchronise sequence numbers (connection initiation).
        rst: RST — reset the connection.
        psh: PSH — push buffered data to the application immediately.
        ack: ACK — acknowledgement field is significant.
        urg: URG — urgent pointer field is significant.
    """
    fin: bool = False
    syn: bool = False
    rst: bool = False
    psh: bool = False
    ack: bool = False
    urg: bool = False

    @classmethod
    def from_byte(cls, flags_byte: int) -> "TCPFlags":
        """
        Construct a ``TCPFlags`` instance from the raw flags byte in a TCP header.

        The lower 6 bits of the TCP data-offset + flags field are the control bits:
          Bit 0 = FIN, 1 = SYN, 2 = RST, 3 = PSH, 4 = ACK, 5 = URG.

        Args:
            flags_byte: The raw 8-bit flags value from the TCP header.

        Returns:
            A ``TCPFlags`` instance with the appropriate flags set.
        """
        return cls(
            fin=bool(flags_byte & 0x01),
            syn=bool(flags_byte & 0x02),
            rst=bool(flags_byte & 0x04),
            psh=bool(flags_byte & 0x08),
            ack=bool(flags_byte & 0x10),
            urg=bool(flags_byte & 0x20),
        )

    def to_string(self) -> str:
        """Return a compact string representation, e.g. ``'ACK PSH'``."""
        active = [
            name for name, active in [
                ("FIN", self.fin), ("SYN", self.syn), ("RST", self.rst),
                ("PSH", self.psh), ("ACK", self.ack), ("URG", self.urg),
            ] if active
        ]
        return " ".join(active) if active else "NONE"


# ---------------------------------------------------------------------------
# Ethernet Frame Model
# ---------------------------------------------------------------------------

@dataclass
class EthernetFrame:
    """
    Parsed representation of an Ethernet II frame header.

    Note: VoltGuard currently targets Ethernet II only (no 802.1Q VLAN tagging).

    Attributes:
        dst_mac:    Destination MAC address formatted as ``AA:BB:CC:DD:EE:FF``.
        src_mac:    Source MAC address formatted as ``AA:BB:CC:DD:EE:FF``.
        ether_type: 16-bit EtherType field (0x0800 = IPv4, 0x0806 = ARP, etc.).
    """
    dst_mac:    str
    src_mac:    str
    ether_type: int

    # Ethernet II header is exactly 14 bytes (6 dst + 6 src + 2 ethertype).
    HEADER_SIZE: int = field(default=14, init=False, repr=False)

    @property
    def ether_type_hex(self) -> str:
        """Return EtherType as a ``0x????`` hex string."""
        return f"0x{self.ether_type:04X}"

    @property
    def is_ipv4(self) -> bool:
        """Return True if this frame carries an IPv4 packet."""
        return self.ether_type == 0x0800


# ---------------------------------------------------------------------------
# IPv4 Packet Model
# ---------------------------------------------------------------------------

@dataclass
class IPv4Packet:
    """
    Parsed representation of an IPv4 packet header.

    Attributes:
        version:      IP version (should be 4).
        ihl:          Internet Header Length in 32-bit words (min 5 = 20 bytes).
        total_length: Total length of the IP packet including header and data.
        ttl:          Time To Live (hop count).
        protocol:     Encapsulated protocol number (6 = TCP, 17 = UDP).
        src_ip:       Source IP address as a dotted-decimal string.
        dst_ip:       Destination IP address as a dotted-decimal string.
        raw_header:   The raw IP header bytes (used for checksum verification if needed).
    """
    version:      int
    ihl:          int
    total_length: int
    ttl:          int
    protocol:     int
    src_ip:       str
    dst_ip:       str
    raw_header:   bytes = field(repr=False)

    @property
    def header_length_bytes(self) -> int:
        """Return the IP header length in bytes (ihl × 4)."""
        return self.ihl * 4

    @property
    def is_tcp(self) -> bool:
        """Return True if the encapsulated protocol is TCP."""
        return self.protocol == 6


# ---------------------------------------------------------------------------
# TCP Segment Model
# ---------------------------------------------------------------------------

@dataclass
class TCPSegment:
    """
    Parsed representation of a TCP segment header.

    Attributes:
        src_port:    Source port number (0–65535).
        dst_port:    Destination port number (0–65535).
        seq_num:     Sequence number (32-bit unsigned).
        ack_num:     Acknowledgement number (32-bit unsigned).
        data_offset: TCP header length in 32-bit words (min 5 = 20 bytes).
        flags:       Parsed TCP control flags.
        window_size: TCP receive window size in bytes.
    """
    src_port:    int
    dst_port:    int
    seq_num:     int
    ack_num:     int
    data_offset: int
    flags:       TCPFlags
    window_size: int

    @property
    def header_length_bytes(self) -> int:
        """Return the TCP header length in bytes (data_offset × 4)."""
        return self.data_offset * 4

    @property
    def is_modbus(self) -> bool:
        """Return True if either port matches the Modbus TCP well-known port 502."""
        return self.src_port == 502 or self.dst_port == 502


# ---------------------------------------------------------------------------
# Modbus TCP Packet Model
# ---------------------------------------------------------------------------

@dataclass
class ModbusTCPPacket:
    """
    Parsed representation of a Modbus TCP Application Data Unit (ADU).

    The Modbus TCP frame is structured as:
      - MBAP Header (7 bytes):
          - Transaction ID  (2 bytes) — echoed in response
          - Protocol ID     (2 bytes) — always 0x0000 for Modbus TCP
          - Length          (2 bytes) — number of bytes that follow
          - Unit ID         (1 byte)  — slave device identifier
      - PDU (variable):
          - Function Code   (1 byte)
          - Data            (variable)

    Attributes:
        transaction_id: 16-bit request/response correlation identifier.
        protocol_id:    Must be 0x0000 for a valid Modbus TCP frame.
        length:         Number of bytes from Unit ID to end of frame.
        unit_id:        Modbus slave device address (0–255).
        function_code:  Parsed ``ModbusFunctionCode`` member.
        payload:        Raw PDU data bytes (after the function code byte).
        function_name:  Human-readable function code description.
    """
    transaction_id: int
    protocol_id:    int
    length:         int
    unit_id:        int
    function_code:  ModbusFunctionCode
    payload:        bytes
    function_name:  str = ""

    # MBAP Header is 6 bytes; Unit ID + FC is 2 more = 8 total minimum.
    MBAP_HEADER_SIZE: int = field(default=6, init=False, repr=False)
    MIN_FRAME_SIZE:   int = field(default=8, init=False, repr=False)

    def __post_init__(self) -> None:
        if not self.function_name:
            self.function_name = self.function_code.description

    @property
    def register_address(self) -> Optional[int]:
        """
        Extract the register/coil starting address from the payload,
        if present (first 2 bytes of PDU data).
        Returns None if the payload is too short.
        """
        if len(self.payload) >= 2:
            return (self.payload[0] << 8) | self.payload[1]
        return None

    @property
    def register_value(self) -> Optional[int]:
        """
        Extract the register/coil output value from the payload,
        if present (bytes 2–3 of PDU data, i.e. second word).
        Returns None if payload is too short or function code doesn't use this field.
        """
        if len(self.payload) >= 4:
            return (self.payload[2] << 8) | self.payload[3]
        return None

    @property
    def quantity(self) -> Optional[int]:
        """
        Extract the quantity of registers or coils from the payload
        (bytes 2–3 for read requests).
        Returns None if the payload is too short.
        """
        if len(self.payload) >= 4:
            return (self.payload[2] << 8) | self.payload[3]
        return None


# ---------------------------------------------------------------------------
# Full Packet — Aggregation of All Layers
# ---------------------------------------------------------------------------

@dataclass
class FullPacket:
    """
    Aggregated parsed result containing all decoded protocol layers plus
    parser metadata.

    Produced by ``ProtocolParser`` after running a raw byte buffer through
    all layer parsers.  Downstream consumers (physics engine, decision engine,
    dashboard) receive a ``FullPacket`` and can inspect whichever layers they need.

    Attributes:
        ethernet:      Decoded Ethernet frame header (None if not available).
        ipv4:          Decoded IPv4 packet header (None if not available).
        tcp:           Decoded TCP segment header (None if not available).
        modbus:        Decoded Modbus TCP packet (None if parsing failed).
        parse_status:  Outcome of the parse attempt.
        error_message: Human-readable error description (empty string on success).
        raw_bytes:     Original undecoded bytes passed to the parser.
        timestamp:     ISO-8601 UTC timestamp set by the parser at parse time.
        src_ip:        Convenience accessor — mirrors ``ipv4.src_ip`` if available.
        dst_ip:        Convenience accessor — mirrors ``ipv4.dst_ip`` if available.
    """
    parse_status:  ParseStatus
    raw_bytes:     bytes
    timestamp:     str
    ethernet:      Optional[EthernetFrame]  = None
    ipv4:          Optional[IPv4Packet]     = None
    tcp:           Optional[TCPSegment]     = None
    modbus:        Optional[ModbusTCPPacket] = None
    error_message: str                      = ""

    @property
    def is_valid(self) -> bool:
        """Return True if and only if the parse completed successfully."""
        return self.parse_status == ParseStatus.VALID

    @property
    def src_ip(self) -> str:
        """Source IP if IPv4 layer was decoded, otherwise empty string."""
        return self.ipv4.src_ip if self.ipv4 else ""

    @property
    def dst_ip(self) -> str:
        """Destination IP if IPv4 layer was decoded, otherwise empty string."""
        return self.ipv4.dst_ip if self.ipv4 else ""

    @property
    def function_code(self) -> Optional[int]:
        """Modbus function code integer if the Modbus layer was decoded."""
        return self.modbus.function_code.value if self.modbus else None

    @property
    def function_name(self) -> str:
        """Modbus function code name if the Modbus layer was decoded."""
        return self.modbus.function_name if self.modbus else ""
