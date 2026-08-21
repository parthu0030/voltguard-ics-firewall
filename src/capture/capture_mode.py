"""
VoltGuard — Capture Mode Enum
================================
Defines the two operating modes for the packet capture layer.
"""

from __future__ import annotations

from enum import Enum


class CaptureMode(str, Enum):
    """
    Operating mode for the VoltGuard packet capture system.

    Attributes:
        SIMULATION: Replay a deterministic sequence of sample packets through
                    the full pipeline.  No network access required.  Safe on
                    all development machines and CI environments.
        LIVE:       Capture real network packets from the configured interface.
                    Requires Scapy and appropriate system permissions.  Falls
                    back to SIMULATION if either is unavailable.
    """

    SIMULATION = "SIMULATION"
    LIVE = "LIVE"
