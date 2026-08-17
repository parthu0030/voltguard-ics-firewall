"""
VoltGuard — Parser Package
============================
Provides all industrial protocol parsers for VoltGuard.

Day 2 Status: Modbus TCP full-stack parser implemented.

Implemented parsers:
  - ``ModbusParser``     — Modbus TCP (port 502) — implements BaseParser
  - ``ProtocolParser``   — Full Ethernet→IPv4→TCP→Modbus orchestrator

Layer parsers (used internally by ProtocolParser):
  - ``EthernetParser``   — Ethernet II frame header
  - ``IPv4Parser``       — IPv4 packet header
  - ``TCPParser``        — TCP segment header

Data models:
  - ``EthernetFrame``, ``IPv4Packet``, ``TCPSegment``, ``ModbusTCPPacket``
  - ``FullPacket``       — aggregated result from all layers
  - ``ModbusFunctionCode``, ``ParseStatus``, ``TCPFlags``

Sample data:
  - ``SamplePacketFactory`` — pre-built test frames for all 5 supported FCs

Statistics:
  - ``ParserStatistics`` — counters maintained by ``ProtocolParser``

All parsers implement ``src.interfaces.base_parser.BaseParser``.

Usage:
    from src.parser import ProtocolParser
    from src.parser import ModbusParser, SamplePacketFactory
    from src.parser.packet_models import FullPacket, ParseStatus
"""

from src.parser.ethernet_parser import EthernetParser
from src.parser.ipv4_parser import IPv4Parser
from src.parser.modbus_parser import ModbusParser
from src.parser.packet_models import (
    EthernetFrame,
    FullPacket,
    IPv4Packet,
    ModbusFunctionCode,
    ModbusTCPPacket,
    ParseStatus,
    TCPFlags,
    TCPSegment,
)
from src.parser.protocol_parser import ParserStatistics, ProtocolParser
from src.parser.sample_packets import SamplePacketFactory
from src.parser.tcp_parser import TCPParser

__all__ = [
    # Orchestrator
    "ProtocolParser",
    "ParserStatistics",
    # Layer parsers
    "EthernetParser",
    "IPv4Parser",
    "TCPParser",
    "ModbusParser",
    # Data models
    "EthernetFrame",
    "IPv4Packet",
    "TCPSegment",
    "ModbusTCPPacket",
    "FullPacket",
    "ModbusFunctionCode",
    "ParseStatus",
    "TCPFlags",
    # Sample data
    "SamplePacketFactory",
]
