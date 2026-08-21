"""
VoltGuard — Packet Security Pipeline
======================================
Implements ``PacketPipeline``, the central orchestrator that wires together
all Day 2–4 components into a complete, real-time ICS packet security pipeline.

Pipeline (11-step end-to-end flow)
------------------------------------
  1.  ``PacketSource.get_packet()``       — raw bytes from simulation or network
  2.  Protocol filter                     — skip None / empty payloads
  3.  ``ProtocolParser.parse_full_packet()``  — Ethernet→IPv4→TCP→Modbus (Day 2)
       └── if parse failed → log failure event, continue
  4.  Retrieve current physics state      — ``WaterSystemEngine.get_current_system_state()``
  5.  ``PhysicsAwareDecisionEngine.evaluate_full_packet()`` — ALLOW/ALERT/BLOCK (Day 4)
  6.  Build ``PipelineEvent``             — canonical security event
  7.  Firewall decision layer             — BLOCK → mark + record, NOT OS-level blocking
  8.  Update ``AppState`` counters        — packets_captured / allowed / alerted / blocked
  9.  Append to event deque              — bounded (max ``MAX_EVENTS``)
  10. Fire registered callbacks          — e.g. UI refresh
  11. Log structured event               — via rotating logger

Design
------
- The pipeline runs on a **background thread** (`threading.Thread`).
  The UI thread never blocks on packet processing.
- `threading.Event` drives clean shutdown — no infinite busy-loop.
- `collections.deque(maxlen=MAX_EVENTS)` prevents unbounded memory growth.
- Per-packet exceptions are caught and logged — the pipeline never crashes.
- BLOCK decisions are recorded and logged but do NOT modify the host firewall.
  The architecture is ready for a future enforcement layer.

Usage::

    from src.pipeline import PacketPipeline, CaptureMode

    pipeline = PacketPipeline(mode=CaptureMode.SIMULATION)
    pipeline.on_event(lambda evt: print(evt.decision, evt.risk_score))
    pipeline.start()
    time.sleep(5)
    pipeline.stop()

    stats = pipeline.stats
    print(stats.total, stats.allowed, stats.blocked)
"""

from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Callable, Optional

from src.capture.capture_mode import CaptureMode
from src.capture.live_source import LivePacketSource
from src.capture.packet_source import PacketSource
from src.capture.simulation_source import SimulationPacketSource
from src.config import config_loader
from src.core.app_state import app_state
from src.decision_engine.decision_config import DecisionConfig
from src.decision_engine.engine import PhysicsAwareDecisionEngine
from src.decision_engine.models import DecisionType
from src.logger import get_logger
from src.parser.packet_models import FullPacket, ParseStatus
from src.parser.protocol_parser import ProtocolParser
from src.physics.physics_config import PhysicsConfig
from src.physics.system_state import SystemState
from src.physics.water_system_engine import WaterSystemEngine
from src.pipeline.pipeline_event import PipelineEvent

_log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Pipeline Statistics
# ---------------------------------------------------------------------------

@dataclass
class PipelineStats:
    """
    Counters maintained by ``PacketPipeline`` across all processed packets.

    Attributes:
        total:           Total packets processed (success + failure).
        allowed:         Packets with ALLOW decision.
        alerted:         Packets with ALERT decision.
        blocked:         Packets with BLOCK decision.
        parse_failures:  Packets that failed parsing (not sent to decision engine).
        errors:          Unhandled exceptions during processing.
    """
    total:          int = 0
    allowed:        int = 0
    alerted:        int = 0
    blocked:        int = 0
    parse_failures: int = 0
    errors:         int = 0

    def record_decision(self, decision: str) -> None:
        """Increment the appropriate counter for a decision."""
        self.total += 1
        if decision == DecisionType.ALLOW.value:
            self.allowed += 1
        elif decision == DecisionType.ALERT.value:
            self.alerted += 1
        elif decision == DecisionType.BLOCK.value:
            self.blocked += 1

    def record_parse_failure(self) -> None:
        """Record one parse failure (packet not sent to decision engine)."""
        self.total += 1
        self.parse_failures += 1

    def record_error(self) -> None:
        """Record one unhandled processing exception."""
        self.errors += 1

    def to_dict(self) -> dict:
        """Serialise to plain dict."""
        return {
            "total":          self.total,
            "allowed":        self.allowed,
            "alerted":        self.alerted,
            "blocked":        self.blocked,
            "parse_failures": self.parse_failures,
            "errors":         self.errors,
        }


# ---------------------------------------------------------------------------
# Packet Pipeline Orchestrator
# ---------------------------------------------------------------------------

class PacketPipeline:
    """
    Central orchestrator for the VoltGuard ICS packet security pipeline.

    Connects ``PacketSource`` → ``ProtocolParser`` → ``WaterSystemEngine``
    → ``PhysicsAwareDecisionEngine`` and emits ``PipelineEvent`` objects to
    registered callbacks.

    Parameters
    ----------
    mode : CaptureMode
        SIMULATION (default) or LIVE.
    interface : str, optional
        Network interface for LIVE mode (passed to ``LivePacketSource``).
    tick_interval_sec : float
        Sleep interval between processing cycles when no packet is available.
        Default 0.05 s (50 ms) — keeps CPU usage low without adding latency.
    max_events : int
        Maximum number of events to retain in the internal history deque.
        Default 500.
    source : PacketSource, optional
        Inject a custom packet source (for testing). Overrides ``mode``.
    """

    MAX_EVENTS: int = 500
    DEFAULT_TICK_SEC: float = 0.05

    def __init__(
        self,
        mode: CaptureMode = CaptureMode.SIMULATION,
        interface: Optional[str] = None,
        tick_interval_sec: float = DEFAULT_TICK_SEC,
        max_events: int = MAX_EVENTS,
        source: Optional[PacketSource] = None,
    ) -> None:
        self._mode: CaptureMode = mode
        self._interface: Optional[str] = interface
        self._tick_sec: float = tick_interval_sec
        self._max_events: int = max_events

        # ── Core components (lazily initialised in start()) ──────────────
        self._source: Optional[PacketSource] = source
        self._parser: Optional[ProtocolParser] = None
        self._physics_engine: Optional[WaterSystemEngine] = None
        self._decision_engine: Optional[PhysicsAwareDecisionEngine] = None

        # ── Runtime state ────────────────────────────────────────────────
        self._running: bool = False
        self._stop_event: threading.Event = threading.Event()
        self._worker_thread: Optional[threading.Thread] = None

        # ── Event storage ─────────────────────────────────────────────────
        self._events: deque[PipelineEvent] = deque(maxlen=max_events)
        self._events_lock: threading.Lock = threading.Lock()
        self._stats: PipelineStats = PipelineStats()
        self._stats_lock: threading.Lock = threading.Lock()

        # ── Callbacks ─────────────────────────────────────────────────────
        self._event_callbacks: list[Callable[[PipelineEvent], None]] = []
        self._callbacks_lock: threading.Lock = threading.Lock()

        _log.info(
            "PacketPipeline created. mode=%s interface=%r tick=%.3fs",
            mode.value, interface, tick_interval_sec,
        )

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------

    def start(self) -> None:
        """
        Start the pipeline on a background thread.

        Initialises all Day 2–4 components and the packet source.
        Idempotent — safe to call when already running.
        """
        if self._running:
            _log.warning("PacketPipeline.start() called while already running.")
            return

        _log.info("PacketPipeline starting...")
        self._stop_event.clear()

        # ── Initialise Day 2–4 components ───────────────────────────────
        self._init_components()

        # ── Start packet source ──────────────────────────────────────────
        if self._source is None:
            self._source = self._create_source()
        self._source.start()

        # ── Launch worker thread ─────────────────────────────────────────
        self._running = True
        self._worker_thread = threading.Thread(
            target=self._processing_loop,
            daemon=True,
            name="VoltGuard-Pipeline",
        )
        self._worker_thread.start()

        _log.info(
            "PacketPipeline started. source=%r",
            self._source,
        )

    def stop(self) -> None:
        """
        Stop the pipeline and release all resources.

        Blocks until the worker thread exits (max 5 s timeout).
        Idempotent — safe to call when already stopped.
        """
        if not self._running:
            return

        _log.info("PacketPipeline stopping...")
        self._running = False
        self._stop_event.set()

        if self._source is not None:
            self._source.stop()

        if self._worker_thread is not None:
            self._worker_thread.join(timeout=5.0)
            self._worker_thread = None

        _log.info(
            "PacketPipeline stopped. stats=%s",
            self._stats.to_dict(),
        )

    def restart(self) -> None:
        """Stop and immediately restart the pipeline."""
        self.stop()
        self._stats = PipelineStats()
        with self._events_lock:
            self._events.clear()
        self.start()

    # ------------------------------------------------------------------
    # Callback registration
    # ------------------------------------------------------------------

    def on_event(self, callback: Callable[[PipelineEvent], None]) -> None:
        """
        Register a callback that fires every time a new ``PipelineEvent``
        is produced.

        The callback is invoked from the pipeline's **worker thread**.
        If you're updating a Qt UI, use a thread-safe mechanism such as
        ``QMetaObject.invokeMethod()`` or post to a queue and poll via
        ``QTimer``.

        Args:
            callback: A callable that accepts a single ``PipelineEvent``.
        """
        with self._callbacks_lock:
            self._event_callbacks.append(callback)

    def remove_event_callback(self, callback: Callable[[PipelineEvent], None]) -> None:
        """Remove a previously registered callback."""
        with self._callbacks_lock:
            try:
                self._event_callbacks.remove(callback)
            except ValueError:
                pass

    # ------------------------------------------------------------------
    # Read-only accessors
    # ------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        """``True`` if the pipeline is currently active."""
        return self._running

    @property
    def stats(self) -> PipelineStats:
        """Current pipeline statistics (snapshot — not locked)."""
        return self._stats

    @property
    def mode(self) -> CaptureMode:
        """The configured capture mode."""
        return self._mode

    def get_recent_events(self, limit: int = 50) -> list[PipelineEvent]:
        """
        Return the most recent pipeline events (newest first).

        Args:
            limit: Maximum number of events to return.

        Returns:
            List of ``PipelineEvent`` objects (newest first).
        """
        with self._events_lock:
            events = list(self._events)
        events.reverse()
        return events[:limit]

    def clear_events(self) -> None:
        """Clear all stored events from the history deque."""
        with self._events_lock:
            self._events.clear()

    # ------------------------------------------------------------------
    # Processing loop (runs on worker thread)
    # ------------------------------------------------------------------

    def _processing_loop(self) -> None:
        """
        Main packet processing loop on the worker thread.

        Runs until ``_stop_event`` is set or ``_running`` becomes ``False``.
        """
        _log.info("PacketPipeline: worker thread started.")

        while not self._stop_event.is_set() and self._running:
            try:
                self._process_one_cycle()
            except Exception as exc:  # noqa: BLE001
                with self._stats_lock:
                    self._stats.record_error()
                _log.error(
                    "PacketPipeline: unhandled error in processing loop: %s",
                    exc,
                    exc_info=True,
                )
            # Brief sleep to avoid a busy loop when no packets are available
            time.sleep(self._tick_sec)

        _log.info("PacketPipeline: worker thread exiting.")

    def _process_one_cycle(self) -> None:
        """
        Process one packet through the complete pipeline.

        This is the core pipeline logic:
          raw_bytes → parse → physics → decide → record → notify

        Never raises — all exceptions are caught and recorded.
        """
        # ── Step 1: Get packet ─────────────────────────────────────────
        if self._source is None:
            return

        raw = self._source.get_packet()
        if raw is None or len(raw) == 0:
            return

        # ── Step 2: Parse ──────────────────────────────────────────────
        packet = self._parse_packet(raw)
        if packet is None:
            return

        # ── Step 3: Check parse status ─────────────────────────────────
        if not packet.is_valid:
            self._handle_parse_failure(packet)
            return

        # ── Step 4: Physics state ──────────────────────────────────────
        physics_state = self._get_physics_state()

        # ── Step 5: Decision engine ────────────────────────────────────
        result = self._evaluate(packet, physics_state)
        if result is None:
            return

        # ── Step 6: Build pipeline event ───────────────────────────────
        event = PipelineEvent.from_decision(result, packet)

        # ── Step 7: Firewall decision layer (safe simulation only) ─────
        if event.is_blocked:
            _log.warning(
                "PacketPipeline [BLOCK] %s→%s FC=%s risk=%d — "
                "packet marked blocked (no OS firewall change in simulation).",
                event.source_ip, event.destination_ip,
                event.modbus_function, event.risk_score,
            )

        # ── Steps 8–11: Record, notify ────────────────────────────────
        self._record_event(event)

    # ------------------------------------------------------------------
    # Private helpers — parse / evaluate / record
    # ------------------------------------------------------------------

    def _parse_packet(self, raw: bytes) -> Optional[FullPacket]:
        """
        Parse raw bytes through the Day 2 protocol parser.

        Automatically selects ``parse_full_packet`` (Ethernet frame) or
        ``parse_modbus_only`` (raw Modbus bytes) based on length heuristic:
        frames longer than 34 bytes (min Eth+IP+TCP header) are assumed to
        be full frames.

        Args:
            raw: Raw bytes from the packet source.

        Returns:
            ``FullPacket`` (may have non-VALID status), or ``None`` on exception.
        """
        if self._parser is None:
            return None
        try:
            # Heuristic: full Ethernet frames are at least 54 bytes
            # (14 Eth + 20 IP + 20 TCP), Modbus-only frames start with MBAP.
            if len(raw) >= 54:
                return self._parser.parse_full_packet(raw)
            else:
                return self._parser.parse_modbus_only(raw)
        except Exception as exc:  # noqa: BLE001
            _log.error("PacketPipeline: parser exception: %s", exc)
            with self._stats_lock:
                self._stats.record_error()
            return None

    def _get_physics_state(self) -> Optional[SystemState]:
        """
        Retrieve the current physics state from the Day 3 engine.

        Returns ``None`` if the engine is unavailable — the decision engine
        will skip physics rules in that case.
        """
        if self._physics_engine is None:
            return None
        try:
            return self._physics_engine.get_current_system_state()
        except Exception as exc:  # noqa: BLE001
            _log.warning("PacketPipeline: physics state error: %s", exc)
            return None

    def _evaluate(self, packet: FullPacket, physics_state: Optional[SystemState]):
        """
        Run the Day 4 decision engine on the parsed packet.

        Returns:
            ``SecurityDecisionResult`` or ``None`` on failure.
        """
        if self._decision_engine is None:
            return None
        try:
            return self._decision_engine.evaluate_full_packet(packet, physics_state)
        except Exception as exc:  # noqa: BLE001
            _log.error("PacketPipeline: decision engine exception: %s", exc)
            with self._stats_lock:
                self._stats.record_error()
            return None

    def _handle_parse_failure(self, packet: FullPacket) -> None:
        """
        Record a parse failure without sending the packet through the decision
        engine.  Logs the failure and updates statistics.

        Args:
            packet: ``FullPacket`` with a non-VALID ``parse_status``.
        """
        _log.warning(
            "PacketPipeline: parse failure status=%s error=%r",
            packet.parse_status.value,
            packet.error_message,
        )
        with self._stats_lock:
            self._stats.record_parse_failure()

        timestamp = datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
        event = PipelineEvent.from_parse_failure(packet, timestamp)
        self._record_event(event)

    def _record_event(self, event: PipelineEvent) -> None:
        """
        Store the event, update AppState counters, and fire all callbacks.

        Args:
            event: The ``PipelineEvent`` to record.
        """
        # ── Store in history ──────────────────────────────────────────
        with self._events_lock:
            self._events.append(event)

        # ── Update pipeline stats ──────────────────────────────────────
        with self._stats_lock:
            self._stats.record_decision(event.decision)

        # ── Update AppState (for dashboard display) ────────────────────
        self._update_app_state(event)

        # ── Log the event ─────────────────────────────────────────────
        _log.info(
            "PipelineEvent: %s→%s FC=%r decision=%s risk=%d level=%s",
            event.source_ip,
            event.destination_ip,
            event.modbus_function,
            event.decision,
            event.risk_score,
            event.risk_level,
        )

        # ── Fire callbacks ─────────────────────────────────────────────
        with self._callbacks_lock:
            callbacks = list(self._event_callbacks)

        for cb in callbacks:
            try:
                cb(event)
            except Exception as exc:  # noqa: BLE001
                _log.warning(
                    "PacketPipeline: callback raised an exception: %s", exc
                )

    @staticmethod
    def _update_app_state(event: PipelineEvent) -> None:
        """
        Update the global ``AppState`` counters based on the event decision.

        Args:
            event: The processed ``PipelineEvent``.
        """
        try:
            if event.decision == DecisionType.BLOCK.value:
                app_state.increment_blocked()
            elif event.decision == DecisionType.ALERT.value:
                app_state.increment_alerted()
            else:
                app_state.increment_allowed()
        except Exception as exc:  # noqa: BLE001
            _log.warning("PacketPipeline: app_state update error: %s", exc)

    # ------------------------------------------------------------------
    # Component initialisation
    # ------------------------------------------------------------------

    def _init_components(self) -> None:
        """
        Initialise (or re-use) the Day 2–4 components.

        Uses ``config_loader`` to build ``PhysicsConfig`` and ``DecisionConfig``.
        """
        # Ensure config is loaded
        if not config_loader.is_loaded:
            config_loader.load()

        # Day 2: Protocol Parser
        if self._parser is None:
            self._parser = ProtocolParser()
            _log.debug("PacketPipeline: ProtocolParser initialised.")

        # Day 3: Physics Engine
        if self._physics_engine is None:
            physics_cfg = PhysicsConfig.from_config(config_loader)
            self._physics_engine = WaterSystemEngine(physics_cfg)
            # Give the engine a running-state for more realistic physics
            from src.physics.water_system_engine import CommandType
            self._physics_engine.apply_command(CommandType.SET_PUMP, 1.0)
            self._physics_engine.apply_command(CommandType.SET_VALVE, 0.6)
            self._physics_engine.update_state()
            _log.debug("PacketPipeline: WaterSystemEngine initialised.")

        # Day 4: Decision Engine
        if self._decision_engine is None:
            physics_cfg = PhysicsConfig.from_config(config_loader)
            decision_cfg = DecisionConfig.from_config(config_loader)
            self._decision_engine = PhysicsAwareDecisionEngine(
                physics_cfg, decision_cfg
            )
            _log.debug("PacketPipeline: PhysicsAwareDecisionEngine initialised.")

    def _create_source(self) -> PacketSource:
        """
        Build the appropriate ``PacketSource`` based on ``self._mode``.

        Returns:
            A new, not-yet-started ``PacketSource`` instance.
        """
        if self._mode == CaptureMode.LIVE:
            return LivePacketSource(interface=self._interface)
        return SimulationPacketSource(loop=True)

    # ------------------------------------------------------------------
    # Representation
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"<PacketPipeline "
            f"mode={self._mode.value} "
            f"running={self._running} "
            f"total={self._stats.total}>"
        )


# ---------------------------------------------------------------------------
# WaterSystemEngine helper — expose get_current_system_state
# ---------------------------------------------------------------------------

def _patch_engine_state_method() -> None:
    """
    Monkey-patch ``WaterSystemEngine`` with ``get_current_system_state()``
    if it does not already exist.

    Day 3 exposes ``get_state()`` (returns base PhysicsState DTO) and
    ``_state`` (internal attribute).  The pipeline needs a clean public
    method that returns the rich ``SystemState`` directly.
    """
    import copy as _copy

    def get_current_system_state(self) -> "SystemState":
        """Return a snapshot of the current ``SystemState``."""
        with self._lock:
            return _copy.copy(self._state)

    if not hasattr(WaterSystemEngine, "get_current_system_state"):
        WaterSystemEngine.get_current_system_state = get_current_system_state
        _log.debug(
            "PacketPipeline: patched WaterSystemEngine.get_current_system_state()"
        )


_patch_engine_state_method()
