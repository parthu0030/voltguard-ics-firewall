"""
VoltGuard — Simulation Packet Source
=======================================
Implements ``SimulationPacketSource``, a deterministic packet source that
replays a fixed sequence of pre-built Modbus TCP frames through the full
pipeline without any network access.

Simulation Scenario Sequence
-----------------------------
The source cycles through 5 scenarios in order, each representing a distinct
security-relevant ICS event:

  1. Safe read       — FC 0x01 Read Coils (expected: ALLOW)
  2. Safe write      — FC 0x06 Write Single Register, low value (expected: ALLOW)
  3. Suspicious write— FC 0x05 Write Single Coil at high address (expected: ALERT)
  4. Unsafe command  — FC 0x10 Write Multiple Registers with extreme values (expected: BLOCK)
  5. Malformed packet— Truncated / garbage bytes (expected: parse failure → logged)

This sequence produces deterministic, reproducible results for every test run.

Full Ethernet frames (for ``parse_full_packet()``) are used for scenarios 1–4.
Raw Modbus bytes are used for scenario 5 to exercise the malformed path.

Usage::

    from src.capture.simulation_source import SimulationPacketSource

    source = SimulationPacketSource()
    source.start()
    for _ in range(10):
        raw = source.get_packet()   # cycles through 5 scenarios
        if raw:
            process(raw)
    source.stop()
"""

from __future__ import annotations

import threading
from collections import deque
from typing import Optional

from src.capture.capture_mode import CaptureMode
from src.capture.packet_source import PacketSource
from src.logger import get_logger
from src.parser.sample_packets import SamplePacketFactory

_log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Simulation scenario descriptors
# ---------------------------------------------------------------------------

_SCENARIOS: list[dict] = [
    {
        "name": "safe_read",
        "description": "Safe read — FC 0x01 Read Coils (expect ALLOW)",
        "full_frame": True,   # True → use full Ethernet packet
    },
    {
        "name": "safe_write",
        "description": "Safe write — FC 0x06 Write Single Register (expect ALLOW)",
        "full_frame": False,  # False → raw Modbus bytes only
    },
    {
        "name": "suspicious_write",
        "description": "Suspicious write — FC 0x05 Write Single Coil at address 0xAC (expect ALERT)",
        "full_frame": False,
    },
    {
        "name": "unsafe_command",
        "description": "Physically unsafe — FC 0x10 Write Multiple Registers (expect BLOCK/ALERT)",
        "full_frame": False,
    },
    {
        "name": "malformed",
        "description": "Malformed / garbage packet (expect parse failure)",
        "full_frame": False,
    },
]


class SimulationPacketSource(PacketSource):
    """
    Deterministic packet source that replays a fixed 5-scenario sequence.

    Thread-safe: ``get_packet()`` may be called from the pipeline thread while
    ``start()`` / ``stop()`` are called from the main thread.

    Attributes:
        _running:         Whether the source is currently active.
        _packet_queue:    Bounded deque of pre-generated raw bytes.
        _scenario_index:  Current position in the scenario cycle (0–4).
        _lock:            Mutex protecting the running flag and queue.
        _loop:            Whether to loop continuously (default True).
        _packet_count:    Total packets produced since ``start()``.
    """

    QUEUE_MAX = 50  # Bounded to prevent unbounded memory growth

    def __init__(self, loop: bool = True) -> None:
        """
        Args:
            loop: If ``True`` (default), cycle through scenarios indefinitely.
                  If ``False``, stop after completing one full cycle (5 packets).
        """
        self._running: bool = False
        self._loop: bool = loop
        self._scenario_index: int = 0
        self._packet_queue: deque[bytes] = deque(maxlen=self.QUEUE_MAX)
        self._lock: threading.Lock = threading.Lock()
        self._packet_count: int = 0

    # ------------------------------------------------------------------
    # PacketSource contract
    # ------------------------------------------------------------------

    def start(self) -> None:
        """Activate the simulation source and pre-load the first packet."""
        with self._lock:
            if self._running:
                return  # Idempotent
            self._running = True
            self._scenario_index = 0
            self._packet_count = 0
            self._packet_queue.clear()
            # Pre-load all 5 scenarios so the first call to get_packet()
            # is always available immediately.
            self._enqueue_all_scenarios()
        _log.info(
            "SimulationPacketSource started. %d scenarios loaded.",
            len(self._packet_queue),
        )

    def stop(self) -> None:
        """Deactivate the simulation source."""
        with self._lock:
            if not self._running:
                return  # Idempotent
            self._running = False
            self._packet_queue.clear()
        _log.info(
            "SimulationPacketSource stopped. Total packets produced: %d",
            self._packet_count,
        )

    def get_packet(self) -> Optional[bytes]:
        """
        Return the next simulation packet, or ``None`` if not running or empty.

        When the queue is drained and ``loop=True``, the next full cycle is
        automatically enqueued.
        """
        with self._lock:
            if not self._running:
                return None

            if not self._packet_queue:
                if self._loop:
                    self._enqueue_all_scenarios()
                else:
                    return None

            if not self._packet_queue:
                return None

            raw = self._packet_queue.popleft()
            self._packet_count += 1
            return raw

    def get_mode(self) -> CaptureMode:
        """Return SIMULATION mode."""
        return CaptureMode.SIMULATION

    def is_running(self) -> bool:
        """Return ``True`` if the source is active."""
        return self._running

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def packet_count(self) -> int:
        """Total packets produced since the last ``start()``."""
        return self._packet_count

    @property
    def scenario_count(self) -> int:
        """Total number of scenarios in one cycle."""
        return len(_SCENARIOS)

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _enqueue_all_scenarios(self) -> None:
        """
        Build and enqueue one complete cycle of all 5 simulation scenarios.

        Must be called while holding ``self._lock``.
        """
        for scenario in _SCENARIOS:
            raw = self._build_scenario_bytes(scenario["name"])
            if raw is not None:
                self._packet_queue.append(raw)
                _log.debug(
                    "SimulationSource: enqueued scenario=%s (%d bytes)",
                    scenario["name"],
                    len(raw),
                )

    @staticmethod
    def _build_scenario_bytes(name: str) -> Optional[bytes]:
        """
        Produce the raw bytes for a named simulation scenario.

        Args:
            name: Scenario name string (matches ``_SCENARIOS[i]['name']``).

        Returns:
            Raw packet bytes, or ``None`` if the name is unknown.
        """
        if name == "safe_read":
            # Full Ethernet frame: Modbus FC 0x03 Read Holding Registers
            return SamplePacketFactory.full_ethernet_packet()

        if name == "safe_write":
            # Raw Modbus: FC 0x06 Write Single Register with value 3
            return SamplePacketFactory.write_single_register()

        if name == "suspicious_write":
            # Raw Modbus: FC 0x05 Write Single Coil at address 0xAC
            return SamplePacketFactory.write_single_coil()

        if name == "unsafe_command":
            # Raw Modbus: FC 0x10 Write Multiple Registers (many registers)
            return SamplePacketFactory.write_multiple_registers()

        if name == "malformed":
            # Garbage bytes — parser must fail gracefully
            return SamplePacketFactory.random_garbage()

        _log.warning("SimulationSource: unknown scenario name=%r", name)
        return None

    def get_scenario_descriptions(self) -> list[str]:
        """Return a list of human-readable scenario descriptions."""
        return [s["description"] for s in _SCENARIOS]
