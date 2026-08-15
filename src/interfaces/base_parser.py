"""
VoltGuard — Base Parser Interface
=====================================
Defines the ``BaseParser`` Abstract Base Class that every protocol parser
must implement.

Architecture:
  - One concrete parser per industrial protocol (e.g. ``ModbusParser``,
    ``DNP3Parser``).
  - The decision engine calls parsers through this interface so new
    protocols can be added without modifying the engine.
  - All parsers are stateless between calls — each ``parse()`` invocation
    receives a complete, self-contained byte buffer.

Implementing a new parser:

    from src.interfaces.base_parser import BaseParser, ParsedPacket

    class ModbusParser(BaseParser):
        def parse(self, raw_bytes: bytes) -> ParsedPacket:
            ...
        def validate(self, raw_bytes: bytes) -> bool:
            ...
        def get_protocol(self) -> str:
            return "Modbus TCP"
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Data Transfer Object returned by all parsers
# ---------------------------------------------------------------------------

@dataclass
class ParsedPacket:
    """
    Canonical representation of a parsed industrial protocol packet.

    All parser implementations must map their protocol's fields onto
    this structure so the physics engine and decision engine receive
    a consistent interface regardless of the source protocol.

    Attributes:
        protocol:       Human-readable protocol name (e.g. "Modbus TCP").
        src_ip:         Source IP address as a string.
        dst_ip:         Destination IP address as a string.
        src_port:       Source TCP/UDP port.
        dst_port:       Destination TCP/UDP port.
        function_code:  Protocol function code (e.g. Modbus FC 0x03).
        register_addr:  Target register or coil address, if applicable.
        register_value: Value written or requested, if applicable.
        raw_bytes:      Original undecoded packet bytes (for logging).
        metadata:       Protocol-specific fields that don't fit above.
        timestamp:      ISO-8601 UTC capture time (set by caller).
    """
    protocol: str
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    function_code: Optional[int] = None
    register_addr: Optional[int] = None
    register_value: Optional[int] = None
    raw_bytes: Optional[bytes] = None
    metadata: dict[str, Any] = field(default_factory=dict)
    timestamp: str = ""


# ---------------------------------------------------------------------------
# Abstract Base Class
# ---------------------------------------------------------------------------

class BaseParser(ABC):
    """
    Abstract interface for all VoltGuard protocol parsers.

    Every concrete parser must implement all three abstract methods.
    The design deliberately keeps parsers stateless so they can be
    used concurrently without synchronisation overhead.
    """

    @abstractmethod
    def parse(self, raw_bytes: bytes) -> ParsedPacket:
        """
        Decode ``raw_bytes`` into a ``ParsedPacket``.

        Args:
            raw_bytes: Raw network packet payload (layer 4 and above).

        Returns:
            A fully populated ``ParsedPacket`` instance.

        Raises:
            ParserError: If the bytes cannot be decoded as the expected protocol.
        """

    @abstractmethod
    def validate(self, raw_bytes: bytes) -> bool:
        """
        Quickly check whether ``raw_bytes`` looks like a valid packet for
        this protocol **without** performing full decoding.

        Use this as a cheap pre-filter before calling the more expensive
        ``parse()`` method.

        Args:
            raw_bytes: Raw packet bytes to inspect.

        Returns:
            ``True`` if the bytes appear to be a valid frame for this protocol.
            ``False`` otherwise (do not raise on validation failure).
        """

    @abstractmethod
    def get_protocol(self) -> str:
        """
        Return the human-readable name of the protocol this parser handles.

        Examples: ``"Modbus TCP"``, ``"DNP3"``, ``"EtherNet/IP"``.

        Returns:
            Protocol name string.
        """

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} protocol={self.get_protocol()!r}>"
