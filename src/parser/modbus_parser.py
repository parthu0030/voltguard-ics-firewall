"""
VoltGuard — Modbus TCP Parser
================================
Implements the core Modbus TCP Application Data Unit (ADU) parser.

Modbus TCP ADU Structure:
  MBAP Header (7 bytes):
    Bytes 0–1:  Transaction Identifier
    Bytes 2–3:  Protocol Identifier  (must be 0x0000 for Modbus TCP)
    Bytes 4–5:  Length               (number of bytes following, including Unit ID)
    Byte  6:    Unit Identifier      (slave device address)
  PDU (variable):
    Byte  7:    Function Code
    Bytes 8+:   PDU data (function-code specific)

Minimum valid frame: 8 bytes (6 MBAP header + Unit ID + Function Code).

Supported Function Codes:
  0x01 — Read Coils
  0x03 — Read Holding Registers
  0x05 — Write Single Coil
  0x06 — Write Single Register
  0x10 — Write Multiple Registers

This parser implements ``BaseParser`` from ``src.interfaces.base_parser``
so it integrates cleanly with the future Decision Engine.

Usage:
    from src.parser.modbus_parser import ModbusParser

    parser = ModbusParser()
    # Full BaseParser interface:
    parsed_packet = parser.parse(raw_modbus_bytes)
    # Rich Modbus model:
    modbus_pkt = parser.parse_modbus(raw_modbus_bytes)
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone
from typing import Optional

from src.exceptions import ParserError, UnsupportedProtocolError
from src.interfaces.base_parser import BaseParser, ParsedPacket
from src.parser.packet_models import (
    ModbusTCPPacket,
    ModbusFunctionCode,
    ParseStatus,
)

# ── Modbus TCP constants ──────────────────────────────────────────────────
_MODBUS_PROTOCOL_ID: int = 0x0000
_MBAP_HEADER_SIZE:   int = 6        # Transaction ID + Protocol ID + Length
_MBAP_FULL_HEADER:   int = 7        # MBAP (6) + Unit ID (1)
_MIN_FRAME_SIZE:     int = 8        # MBAP (6) + Unit ID + Function Code

# MBAP header struct: transaction_id(H), protocol_id(H), length(H)
_MBAP_STRUCT: struct.Struct = struct.Struct("!HHH")

# Protocol name published to the rest of the system.
_PROTOCOL_NAME: str = "Modbus TCP"


class ModbusParser(BaseParser):
    """
    Full-featured Modbus TCP parser implementing the ``BaseParser`` interface.

    The parser is stateless per-call:
      - ``parse()``        → returns a ``ParsedPacket`` (BaseParser contract).
      - ``parse_modbus()`` → returns the richer ``ModbusTCPPacket`` model.
      - ``validate()``     → cheap pre-check without full decoding.
      - ``get_protocol()`` → returns ``"Modbus TCP"``.

    Error policy:
      - ``parse()`` raises ``ParserError`` / ``UnsupportedProtocolError`` on failure.
      - ``validate()`` never raises — returns False on any structural problem.
      - ``parse_modbus()`` raises on failure (same as ``parse()``).
    """

    # ------------------------------------------------------------------
    # BaseParser contract
    # ------------------------------------------------------------------

    def get_protocol(self) -> str:
        """Return the human-readable protocol name."""
        return _PROTOCOL_NAME

    def validate(self, raw_bytes: bytes) -> bool:
        """
        Quickly check whether ``raw_bytes`` looks like a valid Modbus TCP frame.

        Checks:
          - Length ≥ 8 bytes
          - Protocol ID == 0x0000
          - Function code is in the supported set
          - Declared length is consistent with actual bytes

        Args:
            raw_bytes: Raw bytes to inspect.

        Returns:
            True if the frame passes all lightweight checks; False otherwise.
        """
        try:
            if len(raw_bytes) < _MIN_FRAME_SIZE:
                return False
            _txn_id, protocol_id, length = _MBAP_STRUCT.unpack_from(raw_bytes)
            if protocol_id != _MODBUS_PROTOCOL_ID:
                return False
            function_code_byte: int = raw_bytes[7]
            try:
                ModbusFunctionCode.from_byte(function_code_byte)
            except ValueError:
                return False
            # Length field includes Unit ID (1 byte), so PDU bytes = length - 1.
            # Total frame must be MBAP header (6) + length bytes.
            expected_total = _MBAP_HEADER_SIZE + length
            if len(raw_bytes) < expected_total:
                return False
            return True
        except Exception:  # noqa: BLE001
            return False

    def parse(self, raw_bytes: bytes) -> ParsedPacket:
        """
        Decode ``raw_bytes`` as a Modbus TCP frame and return a ``ParsedPacket``.

        This method satisfies the ``BaseParser`` contract and is the primary
        integration point for the Decision Engine.

        Args:
            raw_bytes: Raw Modbus TCP bytes starting at the MBAP header.

        Returns:
            A ``ParsedPacket`` populated with Modbus fields.

        Raises:
            ParserError:             If the frame is malformed or truncated.
            UnsupportedProtocolError: If the function code is not supported.
        """
        modbus_pkt = self.parse_modbus(raw_bytes)
        return ParsedPacket(
            protocol=_PROTOCOL_NAME,
            src_ip="",            # Not available at Modbus layer alone
            dst_ip="",            # Populated by ProtocolParser when full stack is used
            src_port=0,
            dst_port=502,
            function_code=modbus_pkt.function_code.value,
            register_addr=modbus_pkt.register_address,
            register_value=modbus_pkt.register_value,
            raw_bytes=raw_bytes,
            metadata={
                "transaction_id": modbus_pkt.transaction_id,
                "unit_id":        modbus_pkt.unit_id,
                "function_name":  modbus_pkt.function_name,
                "length":         modbus_pkt.length,
                "payload_hex":    modbus_pkt.payload.hex(),
            },
            timestamp=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        )

    # ------------------------------------------------------------------
    # Extended API — rich model
    # ------------------------------------------------------------------

    def parse_modbus(self, raw_bytes: bytes) -> ModbusTCPPacket:
        """
        Decode ``raw_bytes`` as a Modbus TCP frame and return a ``ModbusTCPPacket``.

        This is the richest form of the decode result and is used by the
        ``ProtocolParser`` to build a ``FullPacket``.

        Args:
            raw_bytes: Raw Modbus TCP bytes starting at the MBAP header.

        Returns:
            A fully populated ``ModbusTCPPacket``.

        Raises:
            ParserError:             On length, protocol-ID, or structural errors.
            UnsupportedProtocolError: If the function code is not in the supported set.
        """
        # ── 1. Minimum length check ────────────────────────────────────────
        if len(raw_bytes) < _MIN_FRAME_SIZE:
            raise ParserError(
                f"Modbus TCP frame too short: minimum is {_MIN_FRAME_SIZE} bytes, "
                f"got {len(raw_bytes)}.",
                detail=f"actual_length={len(raw_bytes)}",
            )

        # ── 2. Unpack MBAP header ──────────────────────────────────────────
        transaction_id: int
        protocol_id:    int
        length:         int
        transaction_id, protocol_id, length = _MBAP_STRUCT.unpack_from(raw_bytes)

        # ── 3. Protocol ID validation ──────────────────────────────────────
        if protocol_id != _MODBUS_PROTOCOL_ID:
            raise ParserError(
                f"Invalid Modbus protocol ID: expected 0x{_MODBUS_PROTOCOL_ID:04X}, "
                f"got 0x{protocol_id:04X}.",
                detail=f"protocol_id=0x{protocol_id:04X}",
            )

        # ── 4. Length field sanity check ───────────────────────────────────
        # The Length field counts bytes from Unit ID to end of frame.
        # Minimum: 2 (Unit ID + FC); payload may be 0 bytes.
        if length < 2:
            raise ParserError(
                f"Modbus Length field {length} is invalid (minimum is 2).",
                detail=f"length={length}",
            )

        expected_total: int = _MBAP_HEADER_SIZE + length
        if len(raw_bytes) < expected_total:
            raise ParserError(
                f"Modbus frame truncated: Length field declares {length} bytes "
                f"after MBAP header (expected {expected_total} total), "
                f"but only {len(raw_bytes)} bytes available.",
                detail=f"expected={expected_total} actual={len(raw_bytes)}",
            )

        # ── 5. Unit ID and Function Code ───────────────────────────────────
        unit_id:           int = raw_bytes[6]
        function_code_byte: int = raw_bytes[7]

        try:
            function_code = ModbusFunctionCode.from_byte(function_code_byte)
        except ValueError as exc:
            raise UnsupportedProtocolError(
                f"Unsupported Modbus function code: 0x{function_code_byte:02X}.",
                detail=f"function_code=0x{function_code_byte:02X}",
            ) from exc

        # ── 6. Extract PDU payload ─────────────────────────────────────────
        # PDU bytes = everything after byte 7 (the FC byte) up to declared length.
        # payload starts at byte 8 (after FC).
        pdu_end:  int = _MBAP_HEADER_SIZE + length   # exclusive
        payload: bytes = raw_bytes[8:pdu_end]

        # ── 7. Function-code-specific validation ───────────────────────────
        self._validate_pdu_payload(function_code, payload, raw_bytes)

        return ModbusTCPPacket(
            transaction_id=transaction_id,
            protocol_id=protocol_id,
            length=length,
            unit_id=unit_id,
            function_code=function_code,
            payload=payload,
        )

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _validate_pdu_payload(
        function_code: ModbusFunctionCode,
        payload: bytes,
        raw_bytes: bytes,
    ) -> None:
        """
        Perform function-code-specific payload length validation.

        Checks that the PDU data portion contains the minimum expected bytes
        for the given function code.  Raises ``ParserError`` on failure.

        Minimum PDU data sizes (bytes after the FC byte, in a request frame):
          FC 0x01 — Read Coils:                 4 (start addr 2 + quantity 2)
          FC 0x03 — Read Holding Registers:     4 (start addr 2 + quantity 2)
          FC 0x05 — Write Single Coil:          4 (output addr 2 + value 2)
          FC 0x06 — Write Single Register:      4 (reg addr 2 + value 2)
          FC 0x10 — Write Multiple Registers:   5 (addr 2 + qty 2 + byte_count 1)

        Response frames carry different data but are never validated here;
        the parser accepts both request and response shapes and lets the
        decision engine distinguish them via the transaction_id.

        Args:
            function_code: Parsed function code.
            payload:       PDU data bytes (after the FC byte).
            raw_bytes:     Original raw bytes (for error context only).
        """
        _min_payload_sizes: dict[ModbusFunctionCode, int] = {
            ModbusFunctionCode.READ_COILS:               4,
            ModbusFunctionCode.READ_HOLDING_REGISTERS:   4,
            ModbusFunctionCode.WRITE_SINGLE_COIL:        4,
            ModbusFunctionCode.WRITE_SINGLE_REGISTER:    4,
            ModbusFunctionCode.WRITE_MULTIPLE_REGISTERS: 5,
        }

        min_size: int = _min_payload_sizes.get(function_code, 0)
        # For response frames the payload may be shorter; only enforce for
        # request-sized payloads.
        # Strategy: only raise if payload is 0 bytes for FCs that require data
        # (completely empty PDU is always malformed for these codes).
        if min_size > 0 and len(payload) == 0:
            raise ParserError(
                f"Modbus FC 0x{function_code:02X} ({function_code.description}) "
                f"PDU data is empty — expected at least {min_size} bytes.",
                detail=(
                    f"function_code=0x{function_code:02X} "
                    f"payload_len=0 min_expected={min_size}"
                ),
            )
