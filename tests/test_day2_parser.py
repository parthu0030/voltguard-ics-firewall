"""
VoltGuard — Day 2 Unit Test Suite
====================================
Comprehensive tests for the Modbus TCP protocol parsing stack.

Coverage:
  - Data models (enumerations, dataclasses)
  - EthernetParser, IPv4Parser, TCPParser
  - ModbusParser: valid packets, invalid packets, boundary conditions,
    corrupted data
  - ProtocolParser: full-stack parse, Modbus-only parse, statistics
  - SamplePacketFactory: all samples parseable
  - Logging: log output is generated

Run with:
    python3 -m pytest tests/test_day2_parser.py -v
Or:
    python3 tests/test_day2_parser.py
"""

from __future__ import annotations

import logging
import struct
import sys
import unittest
from pathlib import Path

# ── Ensure project root is on sys.path ────────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.exceptions import ParserError, UnsupportedProtocolError
from src.parser.ethernet_parser import EthernetParser
from src.parser.ipv4_parser import IPv4Parser
from src.parser.modbus_parser import ModbusParser
from src.parser.packet_models import (
    EthernetFrame,
    FullPacket,
    ModbusFunctionCode,
    ModbusTCPPacket,
    ParseStatus,
    TCPFlags,
    TCPSegment,
)
from src.parser.protocol_parser import ParserStatistics, ProtocolParser
from src.parser.sample_packets import SamplePacketFactory
from src.parser.tcp_parser import TCPParser


# ===========================================================================
# TestModbusFunctionCodes
# ===========================================================================

class TestModbusFunctionCodes(unittest.TestCase):
    """Verify that ModbusFunctionCode enum holds correct values."""

    def test_read_coils_value(self) -> None:
        self.assertEqual(ModbusFunctionCode.READ_COILS, 0x01)

    def test_read_holding_registers_value(self) -> None:
        self.assertEqual(ModbusFunctionCode.READ_HOLDING_REGISTERS, 0x03)

    def test_write_single_coil_value(self) -> None:
        self.assertEqual(ModbusFunctionCode.WRITE_SINGLE_COIL, 0x05)

    def test_write_single_register_value(self) -> None:
        self.assertEqual(ModbusFunctionCode.WRITE_SINGLE_REGISTER, 0x06)

    def test_write_multiple_registers_value(self) -> None:
        self.assertEqual(ModbusFunctionCode.WRITE_MULTIPLE_REGISTERS, 0x10)

    def test_from_byte_valid(self) -> None:
        fc = ModbusFunctionCode.from_byte(0x03)
        self.assertEqual(fc, ModbusFunctionCode.READ_HOLDING_REGISTERS)

    def test_from_byte_invalid_raises(self) -> None:
        with self.assertRaises(ValueError):
            ModbusFunctionCode.from_byte(0xFF)

    def test_description_property(self) -> None:
        self.assertEqual(
            ModbusFunctionCode.READ_COILS.description, "Read Coils"
        )
        self.assertEqual(
            ModbusFunctionCode.WRITE_MULTIPLE_REGISTERS.description,
            "Write Multiple Registers",
        )

    def test_all_five_codes_are_int_enum(self) -> None:
        for fc in ModbusFunctionCode:
            self.assertIsInstance(fc, int)


# ===========================================================================
# TestParseStatus
# ===========================================================================

class TestParseStatus(unittest.TestCase):
    """Verify that ParseStatus enum contains all required statuses."""

    def test_valid_status_exists(self) -> None:
        self.assertIn("VALID", [s.value for s in ParseStatus])

    def test_invalid_length_exists(self) -> None:
        self.assertIn("INVALID_LENGTH", [s.value for s in ParseStatus])

    def test_invalid_protocol_id_exists(self) -> None:
        self.assertIn("INVALID_PROTOCOL_ID", [s.value for s in ParseStatus])

    def test_unsupported_fc_exists(self) -> None:
        self.assertIn("UNSUPPORTED_FC", [s.value for s in ParseStatus])

    def test_malformed_exists(self) -> None:
        self.assertIn("MALFORMED", [s.value for s in ParseStatus])

    def test_truncated_exists(self) -> None:
        self.assertIn("TRUNCATED", [s.value for s in ParseStatus])

    def test_exactly_six_statuses(self) -> None:
        self.assertEqual(len(ParseStatus), 6)


# ===========================================================================
# TestTCPFlags
# ===========================================================================

class TestTCPFlags(unittest.TestCase):
    """Verify correct TCP flag extraction from raw bytes."""

    def test_ack_flag(self) -> None:
        flags = TCPFlags.from_byte(0x10)
        self.assertTrue(flags.ack)
        self.assertFalse(flags.syn)

    def test_syn_flag(self) -> None:
        flags = TCPFlags.from_byte(0x02)
        self.assertTrue(flags.syn)
        self.assertFalse(flags.ack)

    def test_ack_psh_flags(self) -> None:
        flags = TCPFlags.from_byte(0x18)  # ACK + PSH
        self.assertTrue(flags.ack)
        self.assertTrue(flags.psh)
        self.assertFalse(flags.syn)
        self.assertFalse(flags.fin)

    def test_fin_flag(self) -> None:
        flags = TCPFlags.from_byte(0x01)
        self.assertTrue(flags.fin)

    def test_rst_flag(self) -> None:
        flags = TCPFlags.from_byte(0x04)
        self.assertTrue(flags.rst)

    def test_no_flags(self) -> None:
        flags = TCPFlags.from_byte(0x00)
        self.assertFalse(any([flags.fin, flags.syn, flags.rst,
                               flags.psh, flags.ack, flags.urg]))

    def test_to_string_ack_psh(self) -> None:
        flags = TCPFlags.from_byte(0x18)
        result = flags.to_string()
        self.assertIn("ACK", result)
        self.assertIn("PSH", result)

    def test_to_string_no_flags(self) -> None:
        flags = TCPFlags.from_byte(0x00)
        self.assertEqual(flags.to_string(), "NONE")


# ===========================================================================
# TestModbusTCPPacket
# ===========================================================================

class TestModbusTCPPacket(unittest.TestCase):
    """Test ModbusTCPPacket dataclass construction and computed properties."""

    def _make_packet(
        self,
        payload: bytes = bytes([0x00, 0x00, 0x00, 0x0A]),
    ) -> ModbusTCPPacket:
        return ModbusTCPPacket(
            transaction_id=1,
            protocol_id=0x0000,
            length=6,
            unit_id=1,
            function_code=ModbusFunctionCode.READ_HOLDING_REGISTERS,
            payload=payload,
        )

    def test_function_name_auto_populated(self) -> None:
        pkt = self._make_packet()
        self.assertEqual(pkt.function_name, "Read Holding Registers")

    def test_register_address(self) -> None:
        pkt = self._make_packet(bytes([0x00, 0x6B, 0x00, 0x0A]))
        self.assertEqual(pkt.register_address, 0x006B)

    def test_register_value(self) -> None:
        pkt = self._make_packet(bytes([0x00, 0x01, 0x00, 0x03]))
        self.assertEqual(pkt.register_value, 0x0003)

    def test_register_address_none_on_short_payload(self) -> None:
        pkt = self._make_packet(bytes([0x00]))
        self.assertIsNone(pkt.register_address)

    def test_register_value_none_on_short_payload(self) -> None:
        pkt = self._make_packet(bytes([0x00, 0x01]))
        self.assertIsNone(pkt.register_value)

    def test_quantity_property(self) -> None:
        pkt = self._make_packet(bytes([0x00, 0x6B, 0x00, 0x0A]))
        self.assertEqual(pkt.quantity, 0x000A)


# ===========================================================================
# TestEthernetParser
# ===========================================================================

class TestEthernetParser(unittest.TestCase):
    """Tests for EthernetParser."""

    def setUp(self) -> None:
        self._parser = EthernetParser()

    def test_parse_valid_frame(self) -> None:
        raw = SamplePacketFactory.full_ethernet_packet()
        frame, payload = self._parser.parse(raw)
        self.assertIsInstance(frame, EthernetFrame)
        self.assertGreater(len(payload), 0)

    def test_dst_mac_format(self) -> None:
        raw = SamplePacketFactory.full_ethernet_packet()
        frame, _ = self._parser.parse(raw)
        # Expected dst MAC from full_ethernet_packet: AA:BB:CC:DD:EE:FF
        self.assertEqual(frame.dst_mac, "AA:BB:CC:DD:EE:FF")

    def test_src_mac_format(self) -> None:
        raw = SamplePacketFactory.full_ethernet_packet()
        frame, _ = self._parser.parse(raw)
        self.assertEqual(frame.src_mac, "DE:AD:BE:EF:CA:FE")

    def test_ether_type_ipv4(self) -> None:
        raw = SamplePacketFactory.full_ethernet_packet()
        frame, _ = self._parser.parse(raw)
        self.assertEqual(frame.ether_type, 0x0800)
        self.assertTrue(frame.is_ipv4)

    def test_ether_type_hex_format(self) -> None:
        raw = SamplePacketFactory.full_ethernet_packet()
        frame, _ = self._parser.parse(raw)
        self.assertEqual(frame.ether_type_hex, "0x0800")

    def test_too_short_raises_parser_error(self) -> None:
        with self.assertRaises(ParserError):
            self._parser.parse(bytes(13))  # 1 byte short

    def test_exactly_14_bytes_succeeds(self) -> None:
        raw = bytes(14)  # All zeros — parses EtherType 0x0000
        frame, payload = self._parser.parse(raw)
        self.assertEqual(len(payload), 0)


# ===========================================================================
# TestIPv4Parser
# ===========================================================================

class TestIPv4Parser(unittest.TestCase):
    """Tests for IPv4Parser."""

    def setUp(self) -> None:
        self._eth_parser  = EthernetParser()
        self._ipv4_parser = IPv4Parser()

    def _get_ip_payload(self) -> bytes:
        raw = SamplePacketFactory.full_ethernet_packet()
        _, ip_payload = self._eth_parser.parse(raw)
        return ip_payload

    def test_parse_valid_ipv4(self) -> None:
        from src.parser.packet_models import IPv4Packet
        ipv4, payload = self._ipv4_parser.parse(self._get_ip_payload())
        self.assertIsInstance(ipv4, IPv4Packet)

    def test_version_is_4(self) -> None:
        ipv4, _ = self._ipv4_parser.parse(self._get_ip_payload())
        self.assertEqual(ipv4.version, 4)

    def test_ihl_is_5(self) -> None:
        ipv4, _ = self._ipv4_parser.parse(self._get_ip_payload())
        self.assertEqual(ipv4.ihl, 5)
        self.assertEqual(ipv4.header_length_bytes, 20)

    def test_protocol_is_tcp(self) -> None:
        ipv4, _ = self._ipv4_parser.parse(self._get_ip_payload())
        self.assertEqual(ipv4.protocol, 6)
        self.assertTrue(ipv4.is_tcp)

    def test_src_ip_format(self) -> None:
        ipv4, _ = self._ipv4_parser.parse(self._get_ip_payload())
        self.assertEqual(ipv4.src_ip, "192.168.1.100")

    def test_dst_ip_format(self) -> None:
        ipv4, _ = self._ipv4_parser.parse(self._get_ip_payload())
        self.assertEqual(ipv4.dst_ip, "192.168.1.1")

    def test_ttl_is_64(self) -> None:
        ipv4, _ = self._ipv4_parser.parse(self._get_ip_payload())
        self.assertEqual(ipv4.ttl, 64)

    def test_too_short_raises_parser_error(self) -> None:
        with self.assertRaises(ParserError):
            self._ipv4_parser.parse(bytes(19))

    def test_wrong_version_raises_parser_error(self) -> None:
        # Craft bytes with version 6 (IPv6)
        bad = bytearray(20)
        bad[0] = (6 << 4) | 5  # version=6, IHL=5
        with self.assertRaises(ParserError):
            self._ipv4_parser.parse(bytes(bad))


# ===========================================================================
# TestTCPParser
# ===========================================================================

class TestTCPParser(unittest.TestCase):
    """Tests for TCPParser."""

    def setUp(self) -> None:
        self._eth_parser  = EthernetParser()
        self._ipv4_parser = IPv4Parser()
        self._tcp_parser  = TCPParser()

    def _get_tcp_payload(self) -> bytes:
        raw = SamplePacketFactory.full_ethernet_packet()
        _, ip_payload = self._eth_parser.parse(raw)
        _, tcp_payload = self._ipv4_parser.parse(ip_payload)
        return tcp_payload

    def test_parse_valid_tcp(self) -> None:
        segment, _ = self._tcp_parser.parse(self._get_tcp_payload())
        self.assertIsInstance(segment, TCPSegment)

    def test_src_port(self) -> None:
        segment, _ = self._tcp_parser.parse(self._get_tcp_payload())
        self.assertEqual(segment.src_port, 49152)

    def test_dst_port_is_modbus(self) -> None:
        segment, _ = self._tcp_parser.parse(self._get_tcp_payload())
        self.assertEqual(segment.dst_port, 502)
        self.assertTrue(segment.is_modbus)

    def test_flags_ack_psh(self) -> None:
        segment, _ = self._tcp_parser.parse(self._get_tcp_payload())
        self.assertTrue(segment.flags.ack)
        self.assertTrue(segment.flags.psh)
        self.assertFalse(segment.flags.syn)

    def test_header_length_bytes(self) -> None:
        segment, _ = self._tcp_parser.parse(self._get_tcp_payload())
        self.assertEqual(segment.header_length_bytes, 20)

    def test_too_short_raises_parser_error(self) -> None:
        with self.assertRaises(ParserError):
            self._tcp_parser.parse(bytes(19))

    def test_window_size_nonzero(self) -> None:
        segment, _ = self._tcp_parser.parse(self._get_tcp_payload())
        self.assertGreater(segment.window_size, 0)


# ===========================================================================
# TestModbusParserValidPackets
# ===========================================================================

class TestModbusParserValidPackets(unittest.TestCase):
    """Verify that all 5 supported function codes parse without errors."""

    def setUp(self) -> None:
        self._parser = ModbusParser()

    def test_parse_read_coils(self) -> None:
        pkt = self._parser.parse_modbus(SamplePacketFactory.read_coils())
        self.assertEqual(pkt.function_code, ModbusFunctionCode.READ_COILS)
        self.assertEqual(pkt.transaction_id, 1)
        self.assertEqual(pkt.unit_id, 1)

    def test_parse_read_holding_registers(self) -> None:
        pkt = self._parser.parse_modbus(SamplePacketFactory.read_holding_registers())
        self.assertEqual(pkt.function_code, ModbusFunctionCode.READ_HOLDING_REGISTERS)
        self.assertEqual(pkt.register_address, 0x006B)
        self.assertEqual(pkt.quantity, 10)

    def test_parse_write_single_coil(self) -> None:
        pkt = self._parser.parse_modbus(SamplePacketFactory.write_single_coil())
        self.assertEqual(pkt.function_code, ModbusFunctionCode.WRITE_SINGLE_COIL)
        self.assertEqual(pkt.register_address, 0x00AC)
        self.assertEqual(pkt.register_value, 0xFF00)

    def test_parse_write_single_register(self) -> None:
        pkt = self._parser.parse_modbus(SamplePacketFactory.write_single_register())
        self.assertEqual(pkt.function_code, ModbusFunctionCode.WRITE_SINGLE_REGISTER)
        self.assertEqual(pkt.register_address, 0x0001)
        self.assertEqual(pkt.register_value, 0x0003)

    def test_parse_write_multiple_registers(self) -> None:
        pkt = self._parser.parse_modbus(SamplePacketFactory.write_multiple_registers())
        self.assertEqual(pkt.function_code, ModbusFunctionCode.WRITE_MULTIPLE_REGISTERS)
        self.assertEqual(pkt.register_address, 0x0001)

    def test_protocol_id_is_zero(self) -> None:
        for name, raw in SamplePacketFactory.all_valid_modbus().items():
            with self.subTest(name=name):
                pkt = self._parser.parse_modbus(raw)
                self.assertEqual(pkt.protocol_id, 0x0000)

    def test_base_parser_parse_method(self) -> None:
        """parse() (BaseParser contract) must return a ParsedPacket."""
        from src.interfaces.base_parser import ParsedPacket
        result = self._parser.parse(SamplePacketFactory.read_coils())
        self.assertIsInstance(result, ParsedPacket)
        self.assertEqual(result.function_code, 0x01)

    def test_get_protocol_returns_modbus_tcp(self) -> None:
        self.assertEqual(self._parser.get_protocol(), "Modbus TCP")

    def test_validate_returns_true_for_valid(self) -> None:
        for name, raw in SamplePacketFactory.all_valid_modbus().items():
            with self.subTest(name=name):
                self.assertTrue(self._parser.validate(raw))

    def test_all_five_samples_parseable(self) -> None:
        for name, raw in SamplePacketFactory.all_valid_modbus().items():
            with self.subTest(name=name):
                pkt = self._parser.parse_modbus(raw)
                self.assertIsInstance(pkt, ModbusTCPPacket)


# ===========================================================================
# TestModbusParserInvalidPackets
# ===========================================================================

class TestModbusParserInvalidPackets(unittest.TestCase):
    """Verify that all error conditions raise the correct exceptions."""

    def setUp(self) -> None:
        self._parser = ModbusParser()

    def test_too_short_raises_parser_error(self) -> None:
        with self.assertRaises(ParserError):
            self._parser.parse_modbus(SamplePacketFactory.invalid_short())

    def test_invalid_protocol_id_raises_parser_error(self) -> None:
        with self.assertRaises(ParserError):
            self._parser.parse_modbus(SamplePacketFactory.invalid_protocol_id())

    def test_unsupported_fc_raises_unsupported_protocol_error(self) -> None:
        with self.assertRaises(UnsupportedProtocolError):
            self._parser.parse_modbus(SamplePacketFactory.unsupported_function_code())

    def test_truncated_payload_raises_parser_error(self) -> None:
        with self.assertRaises(ParserError):
            self._parser.parse_modbus(SamplePacketFactory.truncated_payload())

    def test_random_garbage_raises(self) -> None:
        with self.assertRaises((ParserError, UnsupportedProtocolError)):
            self._parser.parse_modbus(SamplePacketFactory.random_garbage())

    def test_single_byte_raises_parser_error(self) -> None:
        with self.assertRaises(ParserError):
            self._parser.parse_modbus(SamplePacketFactory.single_byte())

    def test_validate_returns_false_for_invalid_short(self) -> None:
        self.assertFalse(self._parser.validate(SamplePacketFactory.invalid_short()))

    def test_validate_returns_false_for_wrong_protocol_id(self) -> None:
        self.assertFalse(self._parser.validate(SamplePacketFactory.invalid_protocol_id()))

    def test_validate_returns_false_for_unsupported_fc(self) -> None:
        self.assertFalse(self._parser.validate(SamplePacketFactory.unsupported_function_code()))

    def test_validate_returns_false_for_truncated(self) -> None:
        self.assertFalse(self._parser.validate(SamplePacketFactory.truncated_payload()))

    def test_validate_never_raises(self) -> None:
        """validate() must never raise, regardless of input."""
        for name, raw in SamplePacketFactory.all_invalid_modbus().items():
            with self.subTest(name=name):
                result = self._parser.validate(raw)
                self.assertIsInstance(result, bool)


# ===========================================================================
# TestModbusParserBoundaryConditions
# ===========================================================================

class TestModbusParserBoundaryConditions(unittest.TestCase):
    """Edge-case and boundary-condition tests."""

    def setUp(self) -> None:
        self._parser = ModbusParser()

    def test_minimum_valid_frame_8_bytes(self) -> None:
        """Smallest valid frame: 6 MBAP + Unit ID + FC, length field = 2."""
        raw = bytes([
            0x00, 0x01,   # Transaction ID
            0x00, 0x00,   # Protocol ID
            0x00, 0x02,   # Length = 2 (Unit ID + FC only)
            0x01,         # Unit ID
            0x05,         # FC: Write Single Coil — payload=0 bytes (response shape)
        ])
        # Write Single Coil with zero payload is technically a malformed request
        # but a valid response echo; the parser should raise for zero payload
        # on a code that requires data — so we verify the appropriate exception.
        with self.assertRaises(ParserError):
            self._parser.parse_modbus(raw)

    def test_maximum_transaction_id(self) -> None:
        """Transaction ID may be 0xFFFF (65535)."""
        raw = bytearray(SamplePacketFactory.read_coils())
        raw[0] = 0xFF
        raw[1] = 0xFF
        pkt = self._parser.parse_modbus(bytes(raw))
        self.assertEqual(pkt.transaction_id, 0xFFFF)

    def test_transaction_id_zero(self) -> None:
        """Transaction ID of 0 is valid."""
        raw = bytearray(SamplePacketFactory.read_coils())
        raw[0] = 0x00
        raw[1] = 0x00
        pkt = self._parser.parse_modbus(bytes(raw))
        self.assertEqual(pkt.transaction_id, 0x0000)

    def test_unit_id_zero(self) -> None:
        """Unit ID 0 (broadcast) is valid."""
        raw = bytearray(SamplePacketFactory.read_coils())
        raw[6] = 0x00
        pkt = self._parser.parse_modbus(bytes(raw))
        self.assertEqual(pkt.unit_id, 0)

    def test_unit_id_255(self) -> None:
        """Unit ID 255 is the broadcast address — valid field."""
        raw = bytearray(SamplePacketFactory.read_coils())
        raw[6] = 0xFF
        pkt = self._parser.parse_modbus(bytes(raw))
        self.assertEqual(pkt.unit_id, 0xFF)

    def test_empty_bytes_raises_parser_error(self) -> None:
        with self.assertRaises(ParserError):
            self._parser.parse_modbus(b"")

    def test_exactly_8_bytes_valid_write_single_coil_response(self) -> None:
        """8-byte Write Single Coil response (echo) — length=2 means 0 PDU bytes (raises)."""
        raw = bytes([
            0x00, 0x01,
            0x00, 0x00,
            0x00, 0x02,   # length = 2 → only unit_id + fc
            0x01,
            0x01,         # FC Read Coils — zero payload triggers error
        ])
        with self.assertRaises(ParserError):
            self._parser.parse_modbus(raw)

    def test_payload_bytes_captured(self) -> None:
        """Payload bytes must match the declared length."""
        raw = SamplePacketFactory.write_multiple_registers()
        pkt = self._parser.parse_modbus(raw)
        # Length field = 0x0B (11). Payload = length - 1 (unit_id) - 1 (fc) = 9 bytes.
        self.assertEqual(len(pkt.payload), 9)


# ===========================================================================
# TestModbusParserCorruptedPackets
# ===========================================================================

class TestModbusParserCorruptedPackets(unittest.TestCase):
    """Verify parser robustness against various forms of corrupt input."""

    def setUp(self) -> None:
        self._parser = ModbusParser()

    def test_random_garbage_does_not_crash(self) -> None:
        try:
            self._parser.parse_modbus(SamplePacketFactory.random_garbage())
        except (ParserError, UnsupportedProtocolError):
            pass  # Expected — should not raise any other exception

    def test_nul_bytes_does_not_crash(self) -> None:
        try:
            self._parser.parse_modbus(SamplePacketFactory.nul_bytes())
        except (ParserError, UnsupportedProtocolError):
            pass

    def test_all_0xff_bytes_does_not_crash(self) -> None:
        try:
            self._parser.parse_modbus(b"\xFF" * 20)
        except (ParserError, UnsupportedProtocolError):
            pass

    def test_valid_then_corrupted_byte_raises(self) -> None:
        raw = bytearray(SamplePacketFactory.read_coils())
        raw[2] = 0xFF   # Corrupt protocol_id high byte
        with self.assertRaises(ParserError):
            self._parser.parse_modbus(bytes(raw))

    def test_corrupted_length_field_raises(self) -> None:
        raw = bytearray(SamplePacketFactory.read_holding_registers())
        raw[4] = 0xFF   # Length = 0xFF__ — far more than actual bytes
        raw[5] = 0xFF
        with self.assertRaises(ParserError):
            self._parser.parse_modbus(bytes(raw))


# ===========================================================================
# TestSamplePackets
# ===========================================================================

class TestSamplePackets(unittest.TestCase):
    """Verify that all SamplePacketFactory methods produce parseable bytes."""

    def setUp(self) -> None:
        self._parser = ModbusParser()

    def test_read_coils_produces_bytes(self) -> None:
        raw = SamplePacketFactory.read_coils()
        self.assertIsInstance(raw, bytes)
        self.assertGreaterEqual(len(raw), 8)

    def test_read_holding_registers_produces_bytes(self) -> None:
        raw = SamplePacketFactory.read_holding_registers()
        self.assertIsInstance(raw, bytes)

    def test_write_single_coil_produces_bytes(self) -> None:
        raw = SamplePacketFactory.write_single_coil()
        self.assertIsInstance(raw, bytes)

    def test_write_single_register_produces_bytes(self) -> None:
        raw = SamplePacketFactory.write_single_register()
        self.assertIsInstance(raw, bytes)

    def test_write_multiple_registers_produces_bytes(self) -> None:
        raw = SamplePacketFactory.write_multiple_registers()
        self.assertIsInstance(raw, bytes)

    def test_all_valid_samples_parseable(self) -> None:
        for name, raw in SamplePacketFactory.all_valid_modbus().items():
            with self.subTest(name=name):
                pkt = self._parser.parse_modbus(raw)
                self.assertIsInstance(pkt, ModbusTCPPacket)

    def test_invalid_samples_dict_has_7_entries(self) -> None:
        invalid = SamplePacketFactory.all_invalid_modbus()
        self.assertEqual(len(invalid), 7)

    def test_valid_samples_dict_has_5_entries(self) -> None:
        valid = SamplePacketFactory.all_valid_modbus()
        self.assertEqual(len(valid), 5)

    def test_full_ethernet_packet_produces_bytes(self) -> None:
        raw = SamplePacketFactory.full_ethernet_packet()
        self.assertIsInstance(raw, bytes)
        # 14 (Eth) + 20 (IP) + 20 (TCP) + 12 (Modbus) = 66 bytes
        self.assertEqual(len(raw), 66)

    def test_invalid_short_is_too_short(self) -> None:
        raw = SamplePacketFactory.invalid_short()
        self.assertLess(len(raw), 8)

    def test_invalid_protocol_id_has_wrong_protocol(self) -> None:
        raw = SamplePacketFactory.invalid_protocol_id()
        protocol_id = (raw[2] << 8) | raw[3]
        self.assertNotEqual(protocol_id, 0x0000)


# ===========================================================================
# TestParserStatistics
# ===========================================================================

class TestParserStatistics(unittest.TestCase):
    """Verify ParserStatistics counter behaviour."""

    def test_initial_all_zero(self) -> None:
        stats = ParserStatistics()
        self.assertEqual(stats.total_parsed, 0)
        self.assertEqual(stats.valid_count, 0)
        self.assertEqual(stats.invalid_count, 0)
        self.assertEqual(stats.function_code_counts, {})
        self.assertEqual(stats.error_counts, {})

    def test_record_valid_increments_total_and_valid(self) -> None:
        stats = ParserStatistics()
        stats.record_valid("Read Coils")
        self.assertEqual(stats.total_parsed, 1)
        self.assertEqual(stats.valid_count, 1)
        self.assertEqual(stats.invalid_count, 0)

    def test_record_valid_increments_fc_counter(self) -> None:
        stats = ParserStatistics()
        stats.record_valid("Read Coils")
        stats.record_valid("Read Coils")
        self.assertEqual(stats.function_code_counts["Read Coils"], 2)

    def test_record_invalid_increments_total_and_invalid(self) -> None:
        stats = ParserStatistics()
        stats.record_invalid(ParseStatus.INVALID_LENGTH)
        self.assertEqual(stats.total_parsed, 1)
        self.assertEqual(stats.invalid_count, 1)
        self.assertEqual(stats.valid_count, 0)

    def test_record_invalid_increments_error_counter(self) -> None:
        stats = ParserStatistics()
        stats.record_invalid(ParseStatus.UNSUPPORTED_FC)
        stats.record_invalid(ParseStatus.UNSUPPORTED_FC)
        self.assertEqual(stats.error_counts["UNSUPPORTED_FC"], 2)

    def test_reset_clears_all(self) -> None:
        stats = ParserStatistics()
        stats.record_valid("Read Coils")
        stats.record_invalid(ParseStatus.MALFORMED)
        stats.reset()
        self.assertEqual(stats.total_parsed, 0)
        self.assertEqual(stats.function_code_counts, {})
        self.assertEqual(stats.error_counts, {})

    def test_get_summary_structure(self) -> None:
        stats = ParserStatistics()
        summary = stats.get_summary()
        self.assertIn("total", summary)
        self.assertIn("valid", summary)
        self.assertIn("invalid", summary)
        self.assertIn("by_function_code", summary)
        self.assertIn("by_error", summary)

    def test_multiple_fc_counts(self) -> None:
        stats = ParserStatistics()
        stats.record_valid("Read Coils")
        stats.record_valid("Write Single Register")
        stats.record_valid("Read Coils")
        self.assertEqual(stats.function_code_counts["Read Coils"], 2)
        self.assertEqual(stats.function_code_counts["Write Single Register"], 1)


# ===========================================================================
# TestProtocolParser
# ===========================================================================

class TestProtocolParser(unittest.TestCase):
    """End-to-end tests for ProtocolParser."""

    def setUp(self) -> None:
        self._parser = ProtocolParser()

    # ── parse_modbus_only ───────────────────────────────────────────────────

    def test_modbus_only_valid_read_coils(self) -> None:
        packet = self._parser.parse_modbus_only(SamplePacketFactory.read_coils())
        self.assertIsInstance(packet, FullPacket)
        self.assertTrue(packet.is_valid)
        self.assertEqual(packet.parse_status, ParseStatus.VALID)

    def test_modbus_only_all_valid_samples(self) -> None:
        for name, raw in SamplePacketFactory.all_valid_modbus().items():
            with self.subTest(name=name):
                packet = self._parser.parse_modbus_only(raw)
                self.assertTrue(packet.is_valid)
                self.assertIsNotNone(packet.modbus)

    def test_modbus_only_invalid_length_status(self) -> None:
        packet = self._parser.parse_modbus_only(SamplePacketFactory.invalid_short())
        self.assertFalse(packet.is_valid)
        self.assertEqual(packet.parse_status, ParseStatus.INVALID_LENGTH)

    def test_modbus_only_invalid_protocol_id_status(self) -> None:
        packet = self._parser.parse_modbus_only(SamplePacketFactory.invalid_protocol_id())
        self.assertFalse(packet.is_valid)
        self.assertEqual(packet.parse_status, ParseStatus.INVALID_PROTOCOL_ID)

    def test_modbus_only_unsupported_fc_status(self) -> None:
        packet = self._parser.parse_modbus_only(SamplePacketFactory.unsupported_function_code())
        self.assertFalse(packet.is_valid)
        self.assertEqual(packet.parse_status, ParseStatus.UNSUPPORTED_FC)

    def test_modbus_only_truncated_payload_status(self) -> None:
        packet = self._parser.parse_modbus_only(SamplePacketFactory.truncated_payload())
        self.assertFalse(packet.is_valid)
        self.assertIn(packet.parse_status, (ParseStatus.TRUNCATED, ParseStatus.MALFORMED))

    def test_modbus_only_error_message_on_failure(self) -> None:
        packet = self._parser.parse_modbus_only(SamplePacketFactory.invalid_short())
        self.assertNotEqual(packet.error_message, "")

    def test_modbus_only_never_raises(self) -> None:
        """parse_modbus_only must never raise for any input."""
        for name, raw in SamplePacketFactory.all_invalid_modbus().items():
            with self.subTest(name=name):
                result = self._parser.parse_modbus_only(raw)
                self.assertIsInstance(result, FullPacket)

    def test_modbus_only_function_code_accessible(self) -> None:
        packet = self._parser.parse_modbus_only(SamplePacketFactory.read_holding_registers())
        self.assertEqual(packet.function_code, 0x03)
        self.assertEqual(packet.function_name, "Read Holding Registers")

    def test_modbus_only_timestamp_set(self) -> None:
        packet = self._parser.parse_modbus_only(SamplePacketFactory.read_coils())
        self.assertNotEqual(packet.timestamp, "")

    # ── parse_full_packet ──────────────────────────────────────────────────

    def test_full_packet_valid(self) -> None:
        raw = SamplePacketFactory.full_ethernet_packet()
        packet = self._parser.parse_full_packet(raw)
        self.assertTrue(packet.is_valid)

    def test_full_packet_has_all_layers(self) -> None:
        raw = SamplePacketFactory.full_ethernet_packet()
        packet = self._parser.parse_full_packet(raw)
        self.assertIsNotNone(packet.ethernet)
        self.assertIsNotNone(packet.ipv4)
        self.assertIsNotNone(packet.tcp)
        self.assertIsNotNone(packet.modbus)

    def test_full_packet_src_ip(self) -> None:
        raw = SamplePacketFactory.full_ethernet_packet()
        packet = self._parser.parse_full_packet(raw)
        self.assertEqual(packet.src_ip, "192.168.1.100")

    def test_full_packet_dst_ip(self) -> None:
        raw = SamplePacketFactory.full_ethernet_packet()
        packet = self._parser.parse_full_packet(raw)
        self.assertEqual(packet.dst_ip, "192.168.1.1")

    def test_full_packet_too_short_for_ethernet(self) -> None:
        packet = self._parser.parse_full_packet(bytes(10))
        self.assertFalse(packet.is_valid)

    def test_full_packet_never_raises(self) -> None:
        """parse_full_packet must never raise for any input."""
        garbage_inputs = [b"", b"\x00" * 5, b"\xFF" * 100, b"INVALID"]
        for raw in garbage_inputs:
            result = self._parser.parse_full_packet(raw)
            self.assertIsInstance(result, FullPacket)

    # ── statistics integration ─────────────────────────────────────────────

    def test_statistics_after_valid_parses(self) -> None:
        parser = ProtocolParser()
        for raw in SamplePacketFactory.all_valid_modbus().values():
            parser.parse_modbus_only(raw)
        stats = parser.get_statistics()
        self.assertEqual(stats["total"], 5)
        self.assertEqual(stats["valid"], 5)
        self.assertEqual(stats["invalid"], 0)

    def test_statistics_after_invalid_parses(self) -> None:
        parser = ProtocolParser()
        for raw in SamplePacketFactory.all_invalid_modbus().values():
            parser.parse_modbus_only(raw)
        stats = parser.get_statistics()
        self.assertEqual(stats["total"], 7)
        self.assertEqual(stats["valid"], 0)
        self.assertEqual(stats["invalid"], 7)

    def test_reset_statistics(self) -> None:
        parser = ProtocolParser()
        parser.parse_modbus_only(SamplePacketFactory.read_coils())
        parser.reset_statistics()
        stats = parser.get_statistics()
        self.assertEqual(stats["total"], 0)

    def test_statistics_fc_breakdown(self) -> None:
        parser = ProtocolParser()
        parser.parse_modbus_only(SamplePacketFactory.read_coils())
        parser.parse_modbus_only(SamplePacketFactory.read_coils())
        parser.parse_modbus_only(SamplePacketFactory.write_single_register())
        stats = parser.get_statistics()
        self.assertEqual(stats["by_function_code"]["Read Coils"], 2)
        self.assertEqual(stats["by_function_code"]["Write Single Register"], 1)


# ===========================================================================
# TestLogging
# ===========================================================================

class TestLogging(unittest.TestCase):
    """
    Verify that the parser emits log records for every parse call.

    Note: VoltGuard loggers have ``propagate=False`` set by the logger factory
    so that each named logger handles its own records.  To capture records we
    attach the test handler *directly* to the concrete module logger
    (``VoltGuard.parser.protocol_parser``) rather than to the hierarchy root.
    """

    # The exact logger name used inside protocol_parser.py.
    _PARSER_LOGGER_NAME: str = "VoltGuard.parser.protocol_parser"

    def _attach_handler(
        self, logger_name: str
    ) -> tuple[logging.Logger, logging.Handler, list[logging.LogRecord]]:
        """Attach a capturing handler to the named logger and return all three."""
        log_records: list[logging.LogRecord] = []

        class CapturingHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:  # noqa: ANN001
                log_records.append(record)

        handler = CapturingHandler()
        handler.setLevel(logging.DEBUG)

        target = logging.getLogger(logger_name)
        old_level = target.level
        target.setLevel(logging.DEBUG)
        target.addHandler(handler)

        return target, handler, log_records, old_level  # type: ignore[return-value]

    def test_valid_parse_emits_info_log(self) -> None:
        target, handler, log_records, old_level = self._attach_handler(
            self._PARSER_LOGGER_NAME
        )
        try:
            parser = ProtocolParser()
            parser.parse_modbus_only(SamplePacketFactory.read_coils())
        finally:
            target.removeHandler(handler)
            target.setLevel(old_level)

        info_records = [r for r in log_records if r.levelno == logging.INFO]
        self.assertGreater(
            len(info_records), 0,
            "Expected at least one INFO log record from the parser.",
        )

    def test_invalid_parse_emits_warning_log(self) -> None:
        target, handler, log_records, old_level = self._attach_handler(
            self._PARSER_LOGGER_NAME
        )
        try:
            parser = ProtocolParser()
            parser.parse_modbus_only(SamplePacketFactory.invalid_short())
        finally:
            target.removeHandler(handler)
            target.setLevel(old_level)

        warning_or_error = [
            r for r in log_records if r.levelno >= logging.WARNING
        ]
        self.assertGreater(
            len(warning_or_error), 0,
            "Expected at least one WARNING/ERROR log for invalid packet.",
        )


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
