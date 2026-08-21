"""
VoltGuard — Live Packet Source
==================================
Implements ``LivePacketSource``, a packet capture backend that uses Scapy
to capture real network traffic from a configured network interface.

Safety / Graceful Degradation
------------------------------
Live capture is OPTIONAL in VoltGuard.  If any of the following conditions
are true, the source falls back transparently to ``SimulationPacketSource``
with a warning log:

  - Scapy is not installed (``ImportError``).
  - The process lacks network capture privileges (``PermissionError``).
  - The specified interface does not exist.
  - Any other capture initialisation failure.

This ensures the application remains fully usable on all macOS / Linux
development machines without requiring root or installing extra packages.

IMPORTANT — Packet Filtering
------------------------------
When Scapy IS available, capture is filtered to Modbus TCP traffic only:
  - Berkeley Packet Filter (BPF): ``tcp port 502``
  - All other traffic is silently dropped before reaching the parser.

This is safe and focused on ICS traffic only.

Blocking Behaviour
------------------
BLOCK decisions from the decision engine do NOT cause this class to send
RST packets or modify any firewall rule.  The pipeline marks the packet
as BLOCKED in the event log only.  The enforcement layer is reserved for
a future milestone.

Usage::

    from src.capture.live_source import LivePacketSource

    source = LivePacketSource(interface="eth0")
    source.start()
    raw = source.get_packet()   # bytes or None
    source.stop()
"""

from __future__ import annotations

import queue
import threading
from typing import Optional

from src.capture.capture_mode import CaptureMode
from src.capture.packet_source import PacketSource
from src.capture.simulation_source import SimulationPacketSource
from src.logger import get_logger

_log = get_logger(__name__)

# BPF filter: Modbus TCP traffic only (port 502)
_MODBUS_BPF_FILTER: str = "tcp port 502"

# Maximum packets in the internal buffer before dropping
_QUEUE_MAX: int = 200


class LivePacketSource(PacketSource):
    """
    Live network packet source backed by Scapy.

    If Scapy is unavailable or capture permissions are denied, this class
    automatically delegates to ``SimulationPacketSource`` so the pipeline
    continues functioning.

    Attributes:
        _interface:   Network interface name (e.g. ``"en0"``, ``"eth0"``).
        _running:     Whether the source is currently capturing.
        _fallback:    ``SimulationPacketSource`` used when Scapy is unavailable.
        _using_scapy: ``True`` if Scapy capture is active; ``False`` for fallback.
        _pkt_queue:   Thread-safe buffer for packets from the sniffer thread.
        _sniffer_thread: Background thread running the Scapy sniffer loop.
    """

    def __init__(self, interface: Optional[str] = None) -> None:
        """
        Args:
            interface: Network interface to capture from.
                       Defaults to ``None`` (Scapy picks the first available).
        """
        self._interface: Optional[str] = interface
        self._running: bool = False
        self._using_scapy: bool = False
        self._fallback: Optional[SimulationPacketSource] = None
        self._pkt_queue: queue.Queue[bytes] = queue.Queue(maxsize=_QUEUE_MAX)
        self._sniffer_thread: Optional[threading.Thread] = None
        self._stop_event: threading.Event = threading.Event()

    # ------------------------------------------------------------------
    # PacketSource contract
    # ------------------------------------------------------------------

    def start(self) -> None:
        """
        Activate the source.

        Attempts to start live Scapy capture.  If that fails for any reason,
        falls back to ``SimulationPacketSource`` transparently.
        """
        if self._running:
            return  # Idempotent

        self._stop_event.clear()

        if self._try_start_scapy():
            self._running = True
            self._using_scapy = True
            _log.info(
                "LivePacketSource: Scapy capture started on interface=%r "
                "filter=%r",
                self._interface or "auto",
                _MODBUS_BPF_FILTER,
            )
        else:
            # Fall back to simulation mode
            self._fallback = SimulationPacketSource(loop=True)
            self._fallback.start()
            self._running = True
            self._using_scapy = False
            _log.warning(
                "LivePacketSource: Scapy unavailable or permission denied. "
                "Falling back to SimulationPacketSource."
            )

    def stop(self) -> None:
        """Deactivate the source and release resources."""
        if not self._running:
            return  # Idempotent

        self._running = False
        self._stop_event.set()

        if self._using_scapy and self._sniffer_thread is not None:
            self._sniffer_thread.join(timeout=3.0)
            self._sniffer_thread = None
            _log.info("LivePacketSource: Scapy sniffer stopped.")

        if self._fallback is not None:
            self._fallback.stop()
            self._fallback = None

        self._using_scapy = False
        # Drain the queue
        while not self._pkt_queue.empty():
            try:
                self._pkt_queue.get_nowait()
            except queue.Empty:
                break

    def get_packet(self) -> Optional[bytes]:
        """
        Return the next captured packet, or ``None`` if none is available.

        Non-blocking: returns immediately.
        """
        if not self._running:
            return None

        if not self._using_scapy and self._fallback is not None:
            return self._fallback.get_packet()

        # Live mode — pull from the thread-safe queue
        try:
            return self._pkt_queue.get_nowait()
        except queue.Empty:
            return None

    def get_mode(self) -> CaptureMode:
        """Return LIVE if Scapy is active, SIMULATION if using fallback."""
        if self._using_scapy:
            return CaptureMode.LIVE
        return CaptureMode.SIMULATION

    def is_running(self) -> bool:
        """Return ``True`` if the source is active."""
        return self._running

    # ------------------------------------------------------------------
    # Properties
    # ------------------------------------------------------------------

    @property
    def is_using_scapy(self) -> bool:
        """``True`` if live Scapy capture is active."""
        return self._using_scapy

    @property
    def interface(self) -> Optional[str]:
        """Configured network interface name."""
        return self._interface

    # ------------------------------------------------------------------
    # Private helpers
    # ------------------------------------------------------------------

    def _try_start_scapy(self) -> bool:
        """
        Attempt to import Scapy and start the sniffer thread.

        Returns:
            ``True`` if the sniffer started successfully.
            ``False`` if Scapy is unavailable or capture failed to initialise.
        """
        try:
            # Lazy import — Scapy is optional
            from scapy.all import sniff  # type: ignore[import]
        except ImportError:
            _log.debug(
                "LivePacketSource: Scapy not installed. "
                "Install with: pip install scapy>=2.5.0"
            )
            return False

        try:
            # Quick capability probe — try to bind a BPF socket.
            # This will raise PermissionError if the process lacks privileges.
            import socket
            _probe = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
            _probe.close()
        except PermissionError:
            _log.warning(
                "LivePacketSource: Insufficient privileges for raw socket capture. "
                "Run with sudo or use SIMULATION mode for development."
            )
            return False
        except OSError:
            # Some systems may raise OSError (e.g. unsupported AF_INET+RAW).
            pass

        # Start the sniffer on a daemon thread.
        self._sniffer_thread = threading.Thread(
            target=self._scapy_sniffer_loop,
            args=(sniff,),
            daemon=True,
            name="VoltGuard-Sniffer",
        )
        self._sniffer_thread.start()
        return True

    def _scapy_sniffer_loop(self, sniff_fn) -> None:
        """
        Run the Scapy sniffer on the worker thread.

        Continuously captures packets and pushes raw bytes to the queue.
        Runs until ``_stop_event`` is set.

        Args:
            sniff_fn: The ``scapy.all.sniff`` callable (injected to avoid
                      re-importing inside the thread).
        """
        def _store_packet(pkt) -> None:
            """Callback invoked by Scapy for every captured packet."""
            try:
                raw: bytes = bytes(pkt)
                self._pkt_queue.put_nowait(raw)
            except queue.Full:
                _log.debug(
                    "LivePacketSource: packet queue full — dropping packet."
                )
            except Exception as exc:  # noqa: BLE001
                _log.warning(
                    "LivePacketSource: error storing packet: %s", exc
                )

        def _stop_filter(_pkt) -> bool:
            """Tell Scapy to stop sniffing when stop is requested."""
            return self._stop_event.is_set()

        _log.debug("LivePacketSource: sniffer thread started.")
        try:
            sniff_fn(
                iface=self._interface,
                filter=_MODBUS_BPF_FILTER,
                prn=_store_packet,
                stop_filter=_stop_filter,
                store=False,   # Do not buffer packets in Scapy — we handle that
                timeout=None,  # Run until stop_filter returns True
            )
        except Exception as exc:  # noqa: BLE001
            _log.error(
                "LivePacketSource: sniffer loop error: %s. "
                "Capture stopped.",
                exc,
            )
        finally:
            _log.debug("LivePacketSource: sniffer thread exiting.")
