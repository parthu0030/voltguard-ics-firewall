"""
VoltGuard — Sample Modbus TCP Packet Factory
==============================================
Provides pre-built, byte-accurate Modbus TCP packet samples for testing,
simulation, and demonstration purposes.

All packets are crafted to match real-world Modbus TCP traffic:
  - Valid MBAP headers (Transaction ID, Protocol ID 0x0000, correct Length)
  - Correct unit IDs and function codes
  - Realistic register addresses and values

Usage:
    from src.parser.sample_packets import SamplePacketFactory

    # Single sample:
    raw = SamplePacketFactory.read_coils()

    # All valid samples at once:
    for name, data in SamplePacketFactory.all_valid_modbus().items():
        pkt = parser.parse_modbus_only(data)

    # Full Ethernet+IP+TCP+Modbus frame:
    full_frame = SamplePacketFactory.full_ethernet_packet()
"""

from __future__ import annotations

import struct


class SamplePacketFactory:
    """
    Factory for pre-built Modbus TCP byte sequences used in tests and demos.

    All methods are static — no instantiation needed.

    Modbus TCP samples contain only the raw MBAP+PDU bytes (starting at the
    Transaction ID), suitable for ``parser.parse_modbus_only()``.

    The ``full_ethernet_packet()`` method provides a complete Ethernet II /
    IPv4 / TCP / Modbus TCP frame suitable for ``parser.parse_full_packet()``.
    """

    # ------------------------------------------------------------------
    # Valid Modbus TCP Frames (MBAP + PDU only)
    # ------------------------------------------------------------------

    @staticmethod
    def read_coils() -> bytes:
        """
        FC 0x01 — Read Coils request.

        Reads 8 coils starting at address 0x0000 from slave unit 1.

        Frame breakdown:
          00 01  — Transaction ID = 1
          00 00  — Protocol ID    = 0x0000 (Modbus TCP)
          00 06  — Length         = 6 (Unit ID + FC + 4 data bytes)
          01     — Unit ID        = 1
          01     — FC             = 0x01 Read Coils
          00 00  — Start Address  = 0x0000
          00 08  — Quantity       = 8 coils
        """
        return bytes([
            0x00, 0x01,   # Transaction ID
            0x00, 0x00,   # Protocol ID
            0x00, 0x06,   # Length
            0x01,         # Unit ID
            0x01,         # FC: Read Coils
            0x00, 0x00,   # Start Address
            0x00, 0x08,   # Quantity of Coils
        ])

    @staticmethod
    def read_holding_registers() -> bytes:
        """
        FC 0x03 — Read Holding Registers request.

        Reads 10 holding registers starting at address 0x006B from slave unit 1.
        (Address 107, a common real-world Modbus data register.)

        Frame breakdown:
          00 02  — Transaction ID = 2
          00 00  — Protocol ID
          00 06  — Length
          01     — Unit ID
          03     — FC: Read Holding Registers
          00 6B  — Start Address = 107
          00 0A  — Quantity      = 10 registers
        """
        return bytes([
            0x00, 0x02,   # Transaction ID
            0x00, 0x00,   # Protocol ID
            0x00, 0x06,   # Length
            0x01,         # Unit ID
            0x03,         # FC: Read Holding Registers
            0x00, 0x6B,   # Start Address (107)
            0x00, 0x0A,   # Quantity of Registers (10)
        ])

    @staticmethod
    def write_single_coil() -> bytes:
        """
        FC 0x05 — Write Single Coil request.

        Turns ON the coil at output address 0x00AC (172) on slave unit 2.
        Value 0xFF00 = coil ON; 0x0000 = coil OFF.

        Frame breakdown:
          00 03  — Transaction ID = 3
          00 00  — Protocol ID
          00 06  — Length
          02     — Unit ID = 2
          05     — FC: Write Single Coil
          00 AC  — Output Address (172)
          FF 00  — Output Value   (0xFF00 = ON)
        """
        return bytes([
            0x00, 0x03,   # Transaction ID
            0x00, 0x00,   # Protocol ID
            0x00, 0x06,   # Length
            0x02,         # Unit ID
            0x05,         # FC: Write Single Coil
            0x00, 0xAC,   # Output Address (172)
            0xFF, 0x00,   # Output Value (ON)
        ])

    @staticmethod
    def write_single_register() -> bytes:
        """
        FC 0x06 — Write Single Register request.

        Writes value 3 to holding register at address 0x0001 on slave unit 1.

        Frame breakdown:
          00 04  — Transaction ID = 4
          00 00  — Protocol ID
          00 06  — Length
          01     — Unit ID
          06     — FC: Write Single Register
          00 01  — Register Address (1)
          00 03  — Register Value   (3)
        """
        return bytes([
            0x00, 0x04,   # Transaction ID
            0x00, 0x00,   # Protocol ID
            0x00, 0x06,   # Length
            0x01,         # Unit ID
            0x06,         # FC: Write Single Register
            0x00, 0x01,   # Register Address
            0x00, 0x03,   # Register Value
        ])

    @staticmethod
    def write_multiple_registers() -> bytes:
        """
        FC 0x10 (16) — Write Multiple Registers request.

        Writes 2 registers starting at address 0x0001 on slave unit 1.
        Values: register 1 = 0x000A (10), register 2 = 0x0102 (258).

        Frame breakdown:
          00 05  — Transaction ID = 5
          00 00  — Protocol ID
          00 0B  — Length = 11 (Unit ID + FC + 4 + byte_count + 4 data bytes)
          01     — Unit ID
          10     — FC: Write Multiple Registers
          00 01  — Starting Address (1)
          00 02  — Quantity of Registers (2)
          04     — Byte Count (2 registers × 2 bytes each)
          00 0A  — Register 1 value (10)
          01 02  — Register 2 value (258)
        """
        return bytes([
            0x00, 0x05,   # Transaction ID
            0x00, 0x00,   # Protocol ID
            0x00, 0x0B,   # Length = 11
            0x01,         # Unit ID
            0x10,         # FC: Write Multiple Registers
            0x00, 0x01,   # Starting Address
            0x00, 0x02,   # Quantity of Registers
            0x04,         # Byte Count
            0x00, 0x0A,   # Register 1 value
            0x01, 0x02,   # Register 2 value
        ])

    # ------------------------------------------------------------------
    # Invalid / Error Condition Frames
    # ------------------------------------------------------------------

    @staticmethod
    def invalid_short() -> bytes:
        """
        Packet shorter than the minimum 8-byte Modbus TCP frame.

        Used to test ``ParseStatus.INVALID_LENGTH`` handling.
        """
        return bytes([0x00, 0x01, 0x00, 0x00])   # Only 4 bytes — too short

    @staticmethod
    def invalid_protocol_id() -> bytes:
        """
        Packet with Protocol ID = 0x0001 instead of the required 0x0000.

        Used to test ``ParseStatus.INVALID_PROTOCOL_ID`` handling.
        """
        return bytes([
            0x00, 0x06,   # Transaction ID
            0x00, 0x01,   # Protocol ID = 0x0001 (INVALID)
            0x00, 0x06,   # Length
            0x01,         # Unit ID
            0x03,         # FC: Read Holding Registers
            0x00, 0x00,   # Start Address
            0x00, 0x01,   # Quantity
        ])

    @staticmethod
    def unsupported_function_code() -> bytes:
        """
        Packet with Function Code 0xFF which is not in the supported set.

        Used to test ``ParseStatus.UNSUPPORTED_FC`` handling.
        """
        return bytes([
            0x00, 0x07,   # Transaction ID
            0x00, 0x00,   # Protocol ID
            0x00, 0x06,   # Length
            0x01,         # Unit ID
            0xFF,         # FC: 0xFF — unsupported
            0x00, 0x00,
            0x00, 0x01,
        ])

    @staticmethod
    def truncated_payload() -> bytes:
        """
        Packet where the Length field declares more bytes than are present.

        Used to test ``ParseStatus.TRUNCATED`` handling.

        The Length field says 10 (meaning 10 bytes from Unit ID onwards) but
        the actual frame only has 8 bytes total (6 MBAP + 2), so only 2 bytes
        follow the MBAP header.
        """
        return bytes([
            0x00, 0x08,   # Transaction ID
            0x00, 0x00,   # Protocol ID
            0x00, 0x0A,   # Length = 10  (declares 10 bytes after MBAP)
            0x01,         # Unit ID
            0x03,         # FC: Read Holding Registers
            # MISSING: 8 more bytes declared by Length field
        ])

    @staticmethod
    def random_garbage() -> bytes:
        """
        Completely random bytes with no valid Modbus TCP structure.

        Used to test parser robustness against corrupt input.
        """
        return bytes([
            0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
            0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        ])

    @staticmethod
    def nul_bytes() -> bytes:
        """
        16 NUL bytes — tests parser handling of zero-filled input.
        """
        return b"\x00" * 16

    @staticmethod
    def single_byte() -> bytes:
        """
        A single byte — extreme truncation test case.
        """
        return bytes([0x01])

    # ------------------------------------------------------------------
    # Full Ethernet + IP + TCP + Modbus Frame
    # ------------------------------------------------------------------

    @staticmethod
    def full_ethernet_packet() -> bytes:
        """
        A complete, byte-accurate Ethernet II / IPv4 / TCP / Modbus TCP frame.

        The frame encodes a Modbus FC 0x03 (Read Holding Registers) request:
          - Ethernet: src=DE:AD:BE:EF:CA:FE → dst=AA:BB:CC:DD:EE:FF (EtherType=0x0800)
          - IPv4:     src=192.168.1.100 → dst=192.168.1.1 (proto=TCP, TTL=64)
          - TCP:      src_port=49152 → dst_port=502 (Modbus), ACK+PSH set
          - Modbus:   FC 0x03, read 10 registers from address 0x006B

        This is suitable for testing the full ``parse_full_packet()`` pipeline.

        Returns:
            Raw bytes of the complete Ethernet frame.
        """
        # ── Modbus PDU ─────────────────────────────────────────────────────
        modbus_payload = bytes([
            0x00, 0x01,   # Transaction ID
            0x00, 0x00,   # Protocol ID
            0x00, 0x06,   # Length
            0x01,         # Unit ID
            0x03,         # FC: Read Holding Registers
            0x00, 0x6B,   # Start Address
            0x00, 0x0A,   # Quantity
        ])

        # ── TCP Header (20 bytes, no options) ──────────────────────────────
        src_port    = 49152
        dst_port    = 502
        seq_num     = 1000
        ack_num     = 2000
        # Data offset = 5 (20 bytes); flags = ACK(0x10) | PSH(0x08) = 0x18
        data_offset_flags = (5 << 4) | 0x00   # high nibble = data offset
        flags_byte        = 0x18              # ACK + PSH
        window_size       = 65535
        checksum    = 0x0000
        urgent_ptr  = 0x0000

        tcp_header = struct.pack(
            "!HHIIBBHHH",
            src_port, dst_port, seq_num, ack_num,
            data_offset_flags, flags_byte, window_size, checksum, urgent_ptr,
        )

        tcp_segment = tcp_header + modbus_payload

        # ── IPv4 Header (20 bytes, no options) ────────────────────────────
        version_ihl  = (4 << 4) | 5          # IPv4, IHL=5
        dscp_ecn     = 0x00
        total_length = 20 + len(tcp_segment)  # IP header + TCP segment
        ident        = 0x1234
        flags_frag   = 0x4000                 # Don't Fragment
        ttl          = 64
        protocol     = 6                      # TCP
        ip_checksum  = 0x0000
        src_ip       = bytes([192, 168, 1, 100])
        dst_ip       = bytes([192, 168, 1,   1])

        ipv4_header = struct.pack(
            "!BBHHHBBH4s4s",
            version_ihl, dscp_ecn, total_length, ident, flags_frag,
            ttl, protocol, ip_checksum, src_ip, dst_ip,
        )

        ip_packet = ipv4_header + tcp_segment

        # ── Ethernet II Header (14 bytes) ──────────────────────────────────
        dst_mac    = bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])
        src_mac    = bytes([0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE])
        ether_type = 0x0800                   # IPv4

        eth_header = dst_mac + src_mac + struct.pack("!H", ether_type)

        return eth_header + ip_packet

    # ------------------------------------------------------------------
    # Convenience aggregators
    # ------------------------------------------------------------------

    @staticmethod
    def all_valid_modbus() -> dict[str, bytes]:
        """
        Return a dict mapping sample name → raw bytes for every valid Modbus
        TCP sample.  Suitable for parameterised test loops.

        Returns:
            ``{'read_coils': <bytes>, 'read_holding_registers': <bytes>, ...}``
        """
        return {
            "read_coils":               SamplePacketFactory.read_coils(),
            "read_holding_registers":   SamplePacketFactory.read_holding_registers(),
            "write_single_coil":        SamplePacketFactory.write_single_coil(),
            "write_single_register":    SamplePacketFactory.write_single_register(),
            "write_multiple_registers": SamplePacketFactory.write_multiple_registers(),
        }

    @staticmethod
    def all_invalid_modbus() -> dict[str, bytes]:
        """
        Return a dict mapping sample name → raw bytes for every invalid Modbus
        TCP sample.  Suitable for parameterised error-condition tests.

        Returns:
            ``{'invalid_short': <bytes>, 'invalid_protocol_id': <bytes>, ...}``
        """
        return {
            "invalid_short":            SamplePacketFactory.invalid_short(),
            "invalid_protocol_id":      SamplePacketFactory.invalid_protocol_id(),
            "unsupported_function_code": SamplePacketFactory.unsupported_function_code(),
            "truncated_payload":        SamplePacketFactory.truncated_payload(),
            "random_garbage":           SamplePacketFactory.random_garbage(),
            "nul_bytes":                SamplePacketFactory.nul_bytes(),
            "single_byte":              SamplePacketFactory.single_byte(),
        }
