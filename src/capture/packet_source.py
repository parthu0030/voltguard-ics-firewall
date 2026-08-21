"""
VoltGuard — Abstract Packet Source
=====================================
Defines ``PacketSource``, the abstract base class that every packet capture
backend must implement.

Design
------
- All methods are intentionally simple and side-effect-free except ``start``
  and ``stop``.
- ``get_packet()`` is non-blocking: it returns ``None`` immediately if no
  packet is available rather than blocking the caller.
- The processing pipeline is responsible for deciding how long to sleep
  between ``get_packet()`` calls.
- Implementations must be thread-safe.

Usage::

    from src.capture.packet_source import PacketSource

    class MySource(PacketSource):
        def start(self) -> None: ...
        def stop(self) -> None: ...
        def get_packet(self) -> Optional[bytes]: ...
        def get_mode(self) -> CaptureMode: ...
        def is_running(self) -> bool: ...
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Optional

from src.capture.capture_mode import CaptureMode


class PacketSource(ABC):
    """
    Abstract base class for all VoltGuard packet capture backends.

    Concrete implementations:
      - ``SimulationPacketSource`` — deterministic replay of sample frames.
      - ``LivePacketSource``       — Scapy-based live network capture.
    """

    @abstractmethod
    def start(self) -> None:
        """
        Activate the packet source.

        Should be called once before the first ``get_packet()`` call.
        Implementations must be idempotent (safe to call twice).
        """

    @abstractmethod
    def stop(self) -> None:
        """
        Deactivate the packet source and release all resources.

        After ``stop()``, ``get_packet()`` must return ``None``.
        Implementations must be idempotent (safe to call twice).
        """

    @abstractmethod
    def get_packet(self) -> Optional[bytes]:
        """
        Return the next available packet as raw bytes, or ``None``.

        This method must be **non-blocking**.  If no packet is available,
        return ``None`` immediately so the caller can sleep or do other work.

        Returns:
            Raw packet bytes (full Ethernet frame for live mode; Modbus-only
            bytes for simulation mode), or ``None`` if nothing is available.
        """

    @abstractmethod
    def get_mode(self) -> CaptureMode:
        """Return the ``CaptureMode`` this source operates in."""

    @abstractmethod
    def is_running(self) -> bool:
        """Return ``True`` if the source is currently active."""

    def __repr__(self) -> str:
        return (
            f"<{self.__class__.__name__} "
            f"mode={self.get_mode().value} "
            f"running={self.is_running()}>"
        )
