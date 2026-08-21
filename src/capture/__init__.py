"""
VoltGuard — Packet Capture Package
=====================================
Provides a clean packet-capture abstraction supporting both live network
capture and deterministic simulation mode for development/testing.

Day 5: Packet Capture / Input Layer

Modes
-----
``SIMULATION`` — Uses ``SamplePacketFactory`` to replay a deterministic
    sequence of ICS packets through the full pipeline without any network
    access.  Safe on all development machines.

``LIVE`` — Attempts to use Scapy for live capture on port 502.  Falls back
    to simulation mode if Scapy is unavailable or permission is denied.

Usage::

    from src.capture import CaptureMode, SimulationPacketSource, LivePacketSource

    source = SimulationPacketSource()
    source.start()
    raw = source.get_packet()   # bytes or None
    source.stop()
"""

from src.capture.capture_mode import CaptureMode
from src.capture.live_source import LivePacketSource
from src.capture.packet_source import PacketSource
from src.capture.simulation_source import SimulationPacketSource

__all__ = [
    "CaptureMode",
    "PacketSource",
    "SimulationPacketSource",
    "LivePacketSource",
]
