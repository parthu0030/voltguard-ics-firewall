"""
VoltGuard — Security Pipeline Package
========================================
Implements the Day 5 real-time ICS packet security pipeline.

Pipeline
--------
    PacketSource (Simulation or Live)
          ↓
    ProtocolParser          (Day 2 — Ethernet→IPv4→TCP→Modbus)
          ↓
    WaterSystemEngine       (Day 3 — current physics state)
          ↓
    PhysicsAwareDecisionEngine (Day 4 — ALLOW / ALERT / BLOCK)
          ↓
    PipelineEvent           (canonical security event for the UI)

Components
----------
- ``PacketPipeline``  — main orchestrator (runs on a background thread)
- ``PipelineEvent``   — canonical security event data structure
- ``PipelineStats``   — live packet/decision counters

Usage::

    from src.pipeline import PacketPipeline, CaptureMode

    pipeline = PacketPipeline(mode=CaptureMode.SIMULATION)
    pipeline.on_event(lambda evt: print(evt))
    pipeline.start()
    ...
    pipeline.stop()
"""

from src.capture.capture_mode import CaptureMode
from src.pipeline.packet_pipeline import PacketPipeline, PipelineStats
from src.pipeline.pipeline_event import PipelineEvent

__all__ = [
    "PacketPipeline",
    "PipelineEvent",
    "PipelineStats",
    "CaptureMode",
]
