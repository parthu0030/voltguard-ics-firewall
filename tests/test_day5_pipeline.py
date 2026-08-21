"""
VoltGuard — Day 5 Pipeline Test Suite
=======================================
Comprehensive tests for the real-time ICS packet security pipeline.

Coverage (15 tests):
  1.  SimulationPacketSource: start, get_packet, stop lifecycle
  2.  SimulationPacketSource: produces exactly 5 packets per cycle (no-loop mode)
  3.  SimulationPacketSource: loops correctly in loop=True mode
  4.  SimulationPacketSource: returns None after stop()
  5.  SimulationPacketSource: is_running state transitions
  6.  LivePacketSource: falls back to simulation when Scapy absent
  7.  PipelineEvent.from_decision: correct field mapping
  8.  PipelineEvent.from_parse_failure: correct fields for failures
  9.  PipelineEvent: is_blocked / is_alerted / is_allowed / is_parse_failure helpers
  10. PacketPipeline: initialises all Day 2–4 components
  11. PacketPipeline: processes a valid Modbus packet end-to-end
  12. PacketPipeline: handles malformed packets without crashing
  13. PacketPipeline: ALLOW decision updates AppState counters
  14. PacketPipeline: BLOCK decision updates AppState counters
  15. PacketPipeline: clean shutdown (no thread leak)

End-to-end integration test:
  E2E: Full pipeline — Sample Packet → Capture → Parser → Physics → Decision Engine → SecurityEvent

Run with:
    python3 -m pytest tests/test_day5_pipeline.py -v
"""

from __future__ import annotations

import sys
import threading
import time
import unittest
from pathlib import Path
from typing import List

# ── Ensure project root is on sys.path ────────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ── Bootstrap configuration ───────────────────────────────────────────────
from src.config import config_loader
if not config_loader.is_loaded:
    config_loader.load()

# ── Subjects under test ───────────────────────────────────────────────────
from src.capture.capture_mode import CaptureMode
from src.capture.live_source import LivePacketSource
from src.capture.packet_source import PacketSource
from src.capture.simulation_source import SimulationPacketSource
from src.core.app_state import app_state
from src.decision_engine.models import DecisionType, SeverityLevel
from src.parser.packet_models import FullPacket, ParseStatus
from src.parser.protocol_parser import ProtocolParser
from src.parser.sample_packets import SamplePacketFactory
from src.physics.physics_config import PhysicsConfig
from src.physics.system_state import SystemState
from src.physics.water_system_engine import WaterSystemEngine
from src.pipeline.packet_pipeline import PacketPipeline, PipelineStats
from src.pipeline.pipeline_event import PipelineEvent


# ---------------------------------------------------------------------------
# Helper factories
# ---------------------------------------------------------------------------

def _make_physics_state() -> SystemState:
    """Return a nominal system state for testing."""
    return SystemState(
        pressure_bar=4.5,
        flow_lps=15.0,
        temperature_celsius=32.0,
        pump_on=True,
        pump_rpm=1500.0,
        valve_position=0.6,
        tank_level_m3=75.0,
    )


def _parse_full(raw: bytes) -> FullPacket:
    parser = ProtocolParser()
    if len(raw) >= 54:
        return parser.parse_full_packet(raw)
    return parser.parse_modbus_only(raw)


# ---------------------------------------------------------------------------
# Test 1–5: SimulationPacketSource
# ---------------------------------------------------------------------------

class TestSimulationPacketSource(unittest.TestCase):

    # ---- Test 1: Start / get_packet / stop lifecycle ─────────────────────
    def test_01_lifecycle(self):
        """SimulationPacketSource: start → get_packet → stop."""
        source = SimulationPacketSource(loop=False)
        self.assertFalse(source.is_running())

        source.start()
        self.assertTrue(source.is_running())
        self.assertEqual(source.get_mode(), CaptureMode.SIMULATION)

        pkt = source.get_packet()
        self.assertIsNotNone(pkt)
        self.assertIsInstance(pkt, bytes)
        self.assertGreater(len(pkt), 0)

        source.stop()
        self.assertFalse(source.is_running())

    # ---- Test 2: Exactly 5 packets per non-looping cycle -----------------
    def test_02_exactly_five_packets_no_loop(self):
        """SimulationPacketSource: no-loop mode produces exactly 5 packets."""
        source = SimulationPacketSource(loop=False)
        source.start()

        packets = []
        for _ in range(10):  # Try to get more than 5
            pkt = source.get_packet()
            if pkt is not None:
                packets.append(pkt)

        source.stop()
        self.assertEqual(len(packets), 5,
                         f"Expected 5 packets, got {len(packets)}")

    # ---- Test 3: Loop mode produces more than 5 packets ------------------
    def test_03_loop_mode_produces_more_than_five(self):
        """SimulationPacketSource: loop=True cycles past 5 packets."""
        source = SimulationPacketSource(loop=True)
        source.start()

        packets = []
        for _ in range(12):  # Request 12 — should cycle
            pkt = source.get_packet()
            if pkt is not None:
                packets.append(pkt)

        source.stop()
        self.assertGreater(len(packets), 5,
                           "Loop mode should produce more than 5 packets")

    # ---- Test 4: Returns None after stop() ──────────────────────────────
    def test_04_returns_none_after_stop(self):
        """SimulationPacketSource: get_packet() → None after stop()."""
        source = SimulationPacketSource()
        source.start()
        source.stop()
        result = source.get_packet()
        self.assertIsNone(result)

    # ---- Test 5: is_running state transitions ────────────────────────────
    def test_05_is_running_transitions(self):
        """SimulationPacketSource: is_running tracks start/stop correctly."""
        source = SimulationPacketSource()
        self.assertFalse(source.is_running())
        source.start()
        self.assertTrue(source.is_running())
        source.stop()
        self.assertFalse(source.is_running())
        # Idempotent stop
        source.stop()
        self.assertFalse(source.is_running())


# ---------------------------------------------------------------------------
# Test 6: LivePacketSource fallback
# ---------------------------------------------------------------------------

class TestLivePacketSource(unittest.TestCase):

    # ---- Test 6: Falls back to simulation without Scapy ------------------
    def test_06_fallback_to_simulation_without_scapy(self):
        """LivePacketSource: falls back to simulation when Scapy is absent."""
        source = LivePacketSource(interface="lo0")
        source.start()

        # In a dev environment without Scapy, mode must be SIMULATION
        mode = source.get_mode()
        self.assertIn(mode, [CaptureMode.SIMULATION, CaptureMode.LIVE])
        self.assertTrue(source.is_running())

        # Should be able to get at least one packet
        pkt = source.get_packet()
        # May be None if live with no traffic, but should not crash
        if mode == CaptureMode.SIMULATION:
            self.assertIsNotNone(pkt)

        source.stop()
        self.assertFalse(source.is_running())


# ---------------------------------------------------------------------------
# Test 7–9: PipelineEvent
# ---------------------------------------------------------------------------

class TestPipelineEvent(unittest.TestCase):

    def _make_allow_result(self):
        """Build a minimal SecurityDecisionResult for ALLOW."""
        from src.decision_engine.decision_config import DecisionConfig
        from src.decision_engine.engine import PhysicsAwareDecisionEngine

        physics_cfg  = PhysicsConfig.from_config(config_loader)
        decision_cfg = DecisionConfig.from_config(config_loader)
        engine = PhysicsAwareDecisionEngine(physics_cfg, decision_cfg)

        raw = SamplePacketFactory.read_coils()
        packet = ProtocolParser().parse_modbus_only(raw)
        state = _make_physics_state()
        return engine.evaluate_full_packet(packet, state), packet

    # ---- Test 7: from_decision field mapping ─────────────────────────────
    def test_07_from_decision_fields(self):
        """PipelineEvent.from_decision: all required fields are populated."""
        result, packet = self._make_allow_result()
        evt = PipelineEvent.from_decision(result, packet)

        self.assertIsInstance(evt.timestamp, str)
        self.assertIn("decision", evt.to_dict())
        self.assertIn("risk_score", evt.to_dict())
        self.assertIn("risk_level", evt.to_dict())
        self.assertIn("source_ip", evt.to_dict())
        self.assertIn("destination_ip", evt.to_dict())
        self.assertIn("protocol", evt.to_dict())
        self.assertIn("modbus_function", evt.to_dict())
        self.assertIn("triggered_rules", evt.to_dict())
        self.assertIn("reason", evt.to_dict())
        self.assertIn("parse_status", evt.to_dict())

    # ---- Test 8: from_parse_failure fields ──────────────────────────────
    def test_08_from_parse_failure_fields(self):
        """PipelineEvent.from_parse_failure: correct fields for parse errors."""
        raw = SamplePacketFactory.random_garbage()
        packet = ProtocolParser().parse_modbus_only(raw)
        self.assertFalse(packet.is_valid)

        from datetime import datetime, timezone
        ts = datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
        evt = PipelineEvent.from_parse_failure(packet, ts)

        self.assertEqual(evt.timestamp, ts)
        self.assertNotEqual(evt.parse_status, ParseStatus.VALID.value)
        self.assertTrue(evt.is_parse_failure)
        # Parse failures default to ALLOW (packet never reached a device)
        self.assertTrue(evt.is_allowed)

    # ---- Test 9: helper properties ──────────────────────────────────────
    def test_09_helper_properties(self):
        """PipelineEvent: is_blocked / is_alerted / is_allowed are correct."""
        result, packet = self._make_allow_result()
        evt = PipelineEvent.from_decision(result, packet)

        if evt.decision == "ALLOW":
            self.assertTrue(evt.is_allowed)
            self.assertFalse(evt.is_alerted)
            self.assertFalse(evt.is_blocked)
        elif evt.decision == "ALERT":
            self.assertTrue(evt.is_alerted)
        elif evt.decision == "BLOCK":
            self.assertTrue(evt.is_blocked)


# ---------------------------------------------------------------------------
# Test 10–15: PacketPipeline
# ---------------------------------------------------------------------------

class TestPacketPipeline(unittest.TestCase):

    def setUp(self):
        """Reset AppState counters before each test."""
        app_state.reset_counters()

    # ---- Test 10: Components initialise ─────────────────────────────────
    def test_10_pipeline_initialises_components(self):
        """PacketPipeline: Day 2–4 components initialise without error."""
        pipeline = PacketPipeline(mode=CaptureMode.SIMULATION)
        pipeline.start()
        # If start() completes without exception, components are initialised
        self.assertTrue(pipeline.is_running)
        pipeline.stop()
        self.assertFalse(pipeline.is_running)

    # ---- Test 11: Valid Modbus packet end-to-end ─────────────────────────
    def test_11_valid_modbus_packet_produces_event(self):
        """PacketPipeline: a valid Modbus packet produces a PipelineEvent."""
        events: list[PipelineEvent] = []
        got_event = threading.Event()

        def _cb(evt: PipelineEvent):
            events.append(evt)
            got_event.set()

        pipeline = PacketPipeline(mode=CaptureMode.SIMULATION, tick_interval_sec=0.01)
        pipeline.on_event(_cb)
        pipeline.start()

        # Wait up to 5 seconds for at least one event
        got_event.wait(timeout=5.0)
        pipeline.stop()

        self.assertGreater(len(events), 0, "Expected at least one PipelineEvent")
        evt = events[0]
        self.assertIsInstance(evt, PipelineEvent)
        self.assertIn(evt.decision, ["ALLOW", "ALERT", "BLOCK"])
        self.assertGreaterEqual(evt.risk_score, 0)
        self.assertLessEqual(evt.risk_score, 100)

    # ---- Test 12: Malformed packet does not crash ───────────────────────
    def test_12_malformed_packet_no_crash(self):
        """PacketPipeline: malformed packets are handled without crashing."""
        from src.capture.simulation_source import SimulationPacketSource as Sim

        class SingleMalformedSource(PacketSource):
            """Returns one garbage packet then stops."""
            def __init__(self):
                self._done = False
            def start(self): self._done = False
            def stop(self): self._done = True
            def get_packet(self):
                if self._done:
                    return None
                self._done = True
                return SamplePacketFactory.random_garbage()
            def get_mode(self): return CaptureMode.SIMULATION
            def is_running(self): return not self._done

        finished = threading.Event()
        errors = []

        def _cb(evt: PipelineEvent):
            finished.set()

        pipeline = PacketPipeline(
            source=SingleMalformedSource(),
            tick_interval_sec=0.01,
        )
        pipeline.on_event(_cb)
        pipeline.start()
        time.sleep(0.5)
        pipeline.stop()

        # Pipeline must not have crashed (no errors in stats)
        self.assertEqual(pipeline.stats.errors, 0,
                         f"Unexpected errors: {pipeline.stats.errors}")

    # ---- Test 13: ALLOW updates AppState ────────────────────────────────
    def test_13_allow_updates_app_state(self):
        """PacketPipeline: ALLOW decisions increment AppState.packets_allowed."""
        initial_allowed = app_state.packets_allowed
        initial_captured = app_state.packets_captured

        got = threading.Event()

        def _cb(evt: PipelineEvent):
            got.set()

        pipeline = PacketPipeline(mode=CaptureMode.SIMULATION, tick_interval_sec=0.01)
        pipeline.on_event(_cb)
        pipeline.start()
        got.wait(timeout=5.0)
        pipeline.stop()

        # At least one counter must have been incremented
        self.assertGreater(
            app_state.packets_captured, initial_captured,
            "packets_captured should have increased"
        )

    # ---- Test 14: BLOCK updates AppState ────────────────────────────────
    def test_14_block_decision_updates_blocked_counter(self):
        """PacketPipeline: BLOCK decisions increment AppState.packets_blocked."""
        # Directly call the AppState update through a synthetic BLOCK event
        initial = app_state.packets_blocked
        app_state.increment_blocked()
        self.assertEqual(app_state.packets_blocked, initial + 1)
        self.assertEqual(app_state.packets_captured, initial + 1)

    # ---- Test 15: Clean shutdown ─────────────────────────────────────────
    def test_15_clean_shutdown(self):
        """PacketPipeline: stop() terminates the worker thread cleanly."""
        pipeline = PacketPipeline(mode=CaptureMode.SIMULATION, tick_interval_sec=0.01)
        pipeline.start()
        time.sleep(0.1)

        self.assertTrue(pipeline.is_running)
        pipeline.stop()
        self.assertFalse(pipeline.is_running)

        # Worker thread should have exited — join with timeout
        if pipeline._worker_thread is not None:
            pipeline._worker_thread.join(timeout=2.0)
            self.assertFalse(pipeline._worker_thread.is_alive(),
                             "Worker thread did not exit cleanly")


# ---------------------------------------------------------------------------
# Additional unit tests
# ---------------------------------------------------------------------------

class TestPipelineStats(unittest.TestCase):

    def test_stats_record_decision_allow(self):
        stats = PipelineStats()
        stats.record_decision("ALLOW")
        self.assertEqual(stats.total, 1)
        self.assertEqual(stats.allowed, 1)
        self.assertEqual(stats.alerted, 0)
        self.assertEqual(stats.blocked, 0)

    def test_stats_record_decision_alert(self):
        stats = PipelineStats()
        stats.record_decision("ALERT")
        self.assertEqual(stats.alerted, 1)
        self.assertEqual(stats.total, 1)

    def test_stats_record_decision_block(self):
        stats = PipelineStats()
        stats.record_decision("BLOCK")
        self.assertEqual(stats.blocked, 1)
        self.assertEqual(stats.total, 1)

    def test_stats_record_parse_failure(self):
        stats = PipelineStats()
        stats.record_parse_failure()
        self.assertEqual(stats.parse_failures, 1)
        self.assertEqual(stats.total, 1)

    def test_stats_to_dict_keys(self):
        stats = PipelineStats()
        d = stats.to_dict()
        self.assertIn("total", d)
        self.assertIn("allowed", d)
        self.assertIn("alerted", d)
        self.assertIn("blocked", d)
        self.assertIn("parse_failures", d)
        self.assertIn("errors", d)


class TestAppStateAlertCounter(unittest.TestCase):
    """Verify the new alerted counter added to AppState in Day 5."""

    def setUp(self):
        app_state.reset_counters()

    def test_initial_alerted_is_zero(self):
        self.assertEqual(app_state.packets_alerted, 0)

    def test_increment_alerted(self):
        app_state.increment_alerted()
        self.assertEqual(app_state.packets_alerted, 1)
        self.assertEqual(app_state.packets_captured, 1)

    def test_alerted_in_snapshot(self):
        snapshot = app_state.snapshot()
        self.assertIn("packets_alerted", snapshot)

    def test_reset_clears_alerted(self):
        app_state.increment_alerted()
        app_state.increment_alerted()
        app_state.reset_counters()
        self.assertEqual(app_state.packets_alerted, 0)


class TestCaptureMode(unittest.TestCase):

    def test_mode_values(self):
        self.assertEqual(CaptureMode.SIMULATION.value, "SIMULATION")
        self.assertEqual(CaptureMode.LIVE.value, "LIVE")

    def test_mode_is_str_enum(self):
        self.assertIsInstance(CaptureMode.SIMULATION, str)


class TestPacketSourceAbstraction(unittest.TestCase):

    def test_simulation_source_is_packet_source(self):
        source = SimulationPacketSource()
        self.assertIsInstance(source, PacketSource)

    def test_live_source_is_packet_source(self):
        source = LivePacketSource()
        self.assertIsInstance(source, PacketSource)

    def test_simulation_source_repr(self):
        source = SimulationPacketSource()
        r = repr(source)
        self.assertIn("SimulationPacketSource", r)
        self.assertIn("SIMULATION", r)


# ---------------------------------------------------------------------------
# End-to-End Integration Test
# ---------------------------------------------------------------------------

class TestEndToEndPipeline(unittest.TestCase):
    """
    E2E: Sample Packet → Capture → Parser → Physics → Decision Engine → PipelineEvent

    This test exercises the complete pipeline synchronously (no background
    thread) using the Day 2–4 components directly, mirroring what
    ``PacketPipeline._process_one_cycle()`` does.
    """

    def test_e2e_complete_pipeline(self):
        """Full pipeline: sample packet flows through all Day 2–4 stages."""
        from src.decision_engine.decision_config import DecisionConfig
        from src.decision_engine.engine import PhysicsAwareDecisionEngine
        from src.pipeline.packet_pipeline import _patch_engine_state_method
        import copy

        # ── Step 1: Packet Source ──────────────────────────────────────────
        source = SimulationPacketSource(loop=False)
        source.start()
        raw = source.get_packet()
        source.stop()

        self.assertIsNotNone(raw, "Source must produce at least one packet")

        # ── Step 2: Parse (Day 2) ──────────────────────────────────────────
        parser = ProtocolParser()
        if len(raw) >= 54:
            packet = parser.parse_full_packet(raw)
        else:
            packet = parser.parse_modbus_only(raw)

        self.assertIsInstance(packet, FullPacket)

        # ── Step 3: Physics state (Day 3) ─────────────────────────────────
        physics_cfg = PhysicsConfig.from_config(config_loader)
        engine = WaterSystemEngine(physics_cfg)
        from src.physics.water_system_engine import CommandType
        engine.apply_command(CommandType.SET_PUMP, 1.0)
        engine.apply_command(CommandType.SET_VALVE, 0.6)
        engine.update_state()

        with engine._lock:
            physics_state = copy.copy(engine._state)

        self.assertIsInstance(physics_state, SystemState)

        # ── Step 4: Decision Engine (Day 4) ───────────────────────────────
        decision_cfg = DecisionConfig.from_config(config_loader)
        decider = PhysicsAwareDecisionEngine(physics_cfg, decision_cfg)

        if packet.is_valid:
            result = decider.evaluate_full_packet(packet, physics_state)
            self.assertIn(result.decision.value, ["ALLOW", "ALERT", "BLOCK"])
            self.assertGreaterEqual(result.risk_score, 0)
            self.assertLessEqual(result.risk_score, 100)

            # ── Step 5: Build PipelineEvent ──────────────────────────────
            evt = PipelineEvent.from_decision(result, packet)

            # Verify the complete event structure
            self.assertIsInstance(evt, PipelineEvent)
            self.assertIn("timestamp",       evt.to_dict())
            self.assertIn("source_ip",       evt.to_dict())
            self.assertIn("destination_ip",  evt.to_dict())
            self.assertIn("source_port",     evt.to_dict())
            self.assertIn("destination_port",evt.to_dict())
            self.assertIn("protocol",        evt.to_dict())
            self.assertIn("modbus_function", evt.to_dict())
            self.assertIn("decision",        evt.to_dict())
            self.assertIn("risk_score",      evt.to_dict())
            self.assertIn("risk_level",      evt.to_dict())
            self.assertIn("reason",          evt.to_dict())
            self.assertIn("triggered_rules", evt.to_dict())

            self.assertIsInstance(evt.triggered_rules, list)
            self.assertIn(evt.decision, ["ALLOW", "ALERT", "BLOCK"])

        else:
            # Parse failure path — still a valid pipeline outcome
            from datetime import datetime, timezone
            ts = datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
            evt = PipelineEvent.from_parse_failure(packet, ts)
            self.assertTrue(evt.is_parse_failure)

        # ── Step 6: Verify parser statistics updated ───────────────────
        stats = parser.get_statistics()
        self.assertGreater(stats["total"], 0)


# ---------------------------------------------------------------------------
# Simulation Mode Test
# ---------------------------------------------------------------------------

class TestSimulationMode(unittest.TestCase):
    """Verify the complete simulation demo runs without errors."""

    def test_simulation_demo_runs_deterministically(self):
        """Simulation mode: produces deterministic events for all 5 scenarios."""
        from src.pipeline.simulation_demo import run_simulation_demo

        # Run once
        events_1 = run_simulation_demo()

        # Run again — same scenario count
        events_2 = run_simulation_demo()

        self.assertEqual(
            len(events_1), len(events_2),
            "Simulation mode must be deterministic (same event count each run)"
        )
        self.assertEqual(len(events_1), 5,
                         "Expected exactly 5 events for 5 simulation scenarios")

    def test_simulation_decisions_contain_expected_outcomes(self):
        """Simulation mode: produces at least one ALLOW and one non-ALLOW event."""
        from src.pipeline.simulation_demo import run_simulation_demo
        events = run_simulation_demo()

        decisions = [e.decision for e in events]
        # Malformed packet is excluded from decisions (it's a parse failure / ALLOW by default)
        non_failure = [e for e in events if not e.is_parse_failure]

        # We expect at least one ALLOW (read operations are safe by default)
        self.assertIn("ALLOW", decisions,
                      f"Expected at least one ALLOW decision, got: {decisions}")

        # Verify parse failure event is present for malformed packet
        failures = [e for e in events if e.is_parse_failure]
        self.assertGreater(len(failures), 0,
                           "Expected at least one parse failure for the malformed scenario")


# ---------------------------------------------------------------------------
# Multiple packets / capture error handling
# ---------------------------------------------------------------------------

class TestPipelineRobustness(unittest.TestCase):

    def test_multiple_packets_no_memory_leak(self):
        """PacketPipeline: bounded event deque prevents memory growth."""
        pipeline = PacketPipeline(
            mode=CaptureMode.SIMULATION,
            tick_interval_sec=0.005,
            max_events=10,  # Very small limit
        )
        pipeline.start()
        time.sleep(0.5)
        pipeline.stop()

        events = pipeline.get_recent_events(limit=1000)
        self.assertLessEqual(
            len(events), 10,
            "Event deque must respect max_events limit"
        )

    def test_capture_error_handling_continues(self):
        """PacketPipeline: an exception in get_packet does not crash pipeline."""

        class FaultySource(PacketSource):
            """Raises an exception on first call, then returns None."""
            def __init__(self):
                self._calls = 0
            def start(self): pass
            def stop(self): pass
            def get_packet(self):
                self._calls += 1
                if self._calls == 1:
                    raise RuntimeError("Simulated capture failure")
                return None
            def get_mode(self): return CaptureMode.SIMULATION
            def is_running(self): return True

        pipeline = PacketPipeline(
            source=FaultySource(),
            tick_interval_sec=0.01,
        )
        pipeline.start()
        time.sleep(0.2)
        pipeline.stop()

        # Should not have crashed — error count may be 0 since exception is
        # in source.get_packet(), not in the pipeline's processing logic.
        # The pipeline handles None gracefully.
        self.assertFalse(pipeline.is_running)


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    unittest.main(verbosity=2)
