"""
VoltGuard — TCP Segment Parser
================================
Parses raw bytes (the payload of an IPv4 packet with protocol=6) into a
``TCPSegment`` model, then returns the TCP payload bytes for the next layer.

TCP Header Layout (variable, minimum 20 bytes):
  Bytes 0–1:   Source Port
  Bytes 2–3:   Destination Port
  Bytes 4–7:   Sequence Number
  Bytes 8–11:  Acknowledgement Number
  Byte  12:    Data Offset (4 bits, high) + Reserved (3 bits) + NS flag (1 bit)
  Byte  13:    Control Flags: CWR ECE URG ACK PSH RST SYN FIN
  Bytes 14–15: Window Size
  Bytes 16–17: Checksum (not verified here)
  Bytes 18–19: Urgent Pointer
  Bytes 20+:   Options (if data_offset > 5); then Payload (Modbus data)

Usage:
    from src.parser.tcp_parser import TCPParser

    parser = TCPParser()
    segment, modbus_payload = parser.parse(ip_payload_bytes)
"""

from __future__ import annotations

import struct
from typing import Tuple

from src.exceptions import ParserError
from src.parser.packet_models import TCPSegment, TCPFlags

# Minimum TCP header: 20 bytes (data offset = 5, no options).
_TCP_MIN_HEADER_SIZE: int = 20
# Fixed first 20 bytes of the TCP header.
_TCP_STRUCT: struct.Struct = struct.Struct("!HHIIBBHHH")
# Fields: src_port, dst_port, seq_num, ack_num,
#         data_offset_byte, flags_byte, window_size, checksum, urgent_ptr


class TCPParser:
    """
    Stateless parser for TCP segment headers.

    Each call to ``parse()`` is fully independent — no instance state is
    modified, making this class safe for concurrent use.

    Raises:
        ParserError: If ``raw_bytes`` is shorter than 20 bytes or the
                     data offset field encodes a value that exceeds the
                     available buffer.
    """

    def parse(self, raw_bytes: bytes) -> Tuple[TCPSegment, bytes]:
        """
        Decode the TCP header from ``raw_bytes``.

        Args:
            raw_bytes: Raw bytes starting at the beginning of the TCP header
                       (i.e. the IPv4 payload for protocol=6 packets).

        Returns:
            A tuple of ``(TCPSegment, payload_bytes)`` where ``payload_bytes``
            is the TCP payload (application data, e.g. Modbus frames).

        Raises:
            ParserError: If the bytes are too short or the data-offset field
                         is out of range.
        """
        if len(raw_bytes) < _TCP_MIN_HEADER_SIZE:
            raise ParserError(
                "TCP segment too short: expected at least "
                f"{_TCP_MIN_HEADER_SIZE} bytes, got {len(raw_bytes)}.",
                detail=f"actual_length={len(raw_bytes)}",
            )

        (
            src_port, dst_port, seq_num, ack_num,
            data_offset_byte, flags_byte, window_size,
            _checksum, _urgent_ptr,
        ) = _TCP_STRUCT.unpack_from(raw_bytes)

        # Data offset occupies the upper 4 bits of byte 12.
        data_offset: int = (data_offset_byte >> 4) & 0x0F
        header_length: int = data_offset * 4

        if header_length < _TCP_MIN_HEADER_SIZE:
            raise ParserError(
                f"TCP data offset {data_offset} encodes a header length of "
                f"{header_length} bytes, which is below the minimum of 20.",
                detail=f"data_offset={data_offset}",
            )

        if len(raw_bytes) < header_length:
            raise ParserError(
                f"TCP segment truncated: data offset declares {header_length}-byte "
                f"header but only {len(raw_bytes)} bytes available.",
                detail=f"declared_header={header_length} actual={len(raw_bytes)}",
            )

        flags = TCPFlags.from_byte(flags_byte)

        segment = TCPSegment(
            src_port=src_port,
            dst_port=dst_port,
            seq_num=seq_num,
            ack_num=ack_num,
            data_offset=data_offset,
            flags=flags,
            window_size=window_size,
        )
        payload = raw_bytes[header_length:]
        return segment, payload
