"""
VoltGuard Packet Capture Module
---------------------------------
Provides a thread-safe, start/stop packet capture engine built on Scapy.
Emits parsed packet records via a callback mechanism so the GUI can update
without coupling to Scapy internals.
"""

from __future__ import annotations

import threading
import uuid
from typing import Callable, List, Optional

from core.logger import get_logger, get_packet_logger
from core.protocol_parser import ParsedPacket, ProtocolParser
from database.database import get_db

log = get_logger(__name__)
pkt_log = get_packet_logger()

# Scapy is imported lazily to avoid startup delay
try:
    import scapy.all as scapy
    from scapy.arch import get_if_list

    SCAPY_AVAILABLE = True
except Exception as _e:  # broad catch — scapy can raise on import on some platforms
    SCAPY_AVAILABLE = False
    log.warning("Scapy not fully available: %s", _e)


PacketCallback = Callable[[ParsedPacket], None]


class PacketCapture:
    """Non-blocking packet capture engine.

    Capture runs in a background daemon thread so the GUI thread is never
    blocked.  Register callbacks via :meth:`add_callback` to receive parsed
    packets in real-time.

    Example::

        capture = PacketCapture()
        capture.add_callback(my_handler)
        capture.start(interface="eth0")
        # ... later ...
        capture.stop()
    """

    def __init__(self) -> None:
        self._parser = ProtocolParser()
        self._db = get_db()
        self._callbacks: List[PacketCallback] = []
        self._thread: Optional[threading.Thread] = None
        self._stop_event = threading.Event()

        # Runtime counters
        self._total_packets: int = 0
        self._blocked_packets: int = 0
        self._allowed_packets: int = 0
        self._session_id: Optional[str] = None
        self._interface: str = "auto"
        self._is_running: bool = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def is_running(self) -> bool:
        """``True`` while packet capture is active."""
        return self._is_running

    @property
    def total_packets(self) -> int:
        """Total packets captured in the current session."""
        return self._total_packets

    @property
    def blocked_packets(self) -> int:
        """Blocked packets in the current session."""
        return self._blocked_packets

    @property
    def allowed_packets(self) -> int:
        """Allowed packets in the current session."""
        return self._allowed_packets

    @property
    def current_interface(self) -> str:
        """Network interface currently in use."""
        return self._interface

    def add_callback(self, cb: PacketCallback) -> None:
        """Register a callback to receive :class:`ParsedPacket` objects.

        Args:
            cb: Callable that accepts a single :class:`ParsedPacket` argument.
        """
        if cb not in self._callbacks:
            self._callbacks.append(cb)

    def remove_callback(self, cb: PacketCallback) -> None:
        """Unregister a previously added callback.

        Args:
            cb: The callback to remove.
        """
        try:
            self._callbacks.remove(cb)
        except ValueError:
            pass

    def get_available_interfaces(self) -> List[str]:
        """Return a list of network interfaces detected by Scapy.

        Returns:
            List of interface name strings, or an empty list if Scapy is
            unavailable.
        """
        if not SCAPY_AVAILABLE:
            log.warning("Scapy unavailable — cannot enumerate interfaces.")
            return []
        try:
            return sorted(get_if_list())
        except Exception as exc:
            log.error("Failed to enumerate interfaces: %s", exc)
            return []

    def start(self, interface: Optional[str] = None) -> bool:
        """Begin packet capture on the given interface.

        If *interface* is ``None`` or ``"auto"``, Scapy's default interface is
        used.  The capture runs in a background daemon thread; this method
        returns immediately.

        Args:
            interface: Interface name or ``None`` / ``"auto"`` for default.

        Returns:
            ``True`` if capture started successfully, ``False`` otherwise.
        """
        if self._is_running:
            log.warning("Capture already running — call stop() first.")
            return False

        if not SCAPY_AVAILABLE:
            log.error("Cannot start capture: Scapy is not available.")
            return False

        self._interface = interface or "auto"
        self._session_id = str(uuid.uuid4())
        self._stop_event.clear()
        self._reset_counters()

        # Record session in database
        db_interface = self._interface if self._interface != "auto" else "default"
        self._db.start_scan_session(self._session_id, db_interface)

        self._thread = threading.Thread(
            target=self._capture_loop,
            name="VoltGuard-Capture",
            daemon=True,
        )
        self._thread.start()
        self._is_running = True
        log.info("Packet capture STARTED on interface: %s", self._interface)
        return True

    def stop(self) -> None:
        """Gracefully stop packet capture.

        Signals the capture loop to exit and waits up to 3 seconds for the
        background thread to finish.
        """
        if not self._is_running:
            return

        log.info("Stopping packet capture...")
        self._stop_event.set()
        self._is_running = False

        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=3.0)

        # Finalise the session record
        if self._session_id:
            self._db.end_scan_session(
                self._session_id,
                self._total_packets,
                self._blocked_packets,
                self._allowed_packets,
            )
        log.info(
            "Packet capture STOPPED. Total=%d Blocked=%d Allowed=%d",
            self._total_packets,
            self._blocked_packets,
            self._allowed_packets,
        )

    def get_stats(self) -> dict:
        """Return current session counters as a plain dictionary."""
        return {
            "total": self._total_packets,
            "blocked": self._blocked_packets,
            "allowed": self._allowed_packets,
            "interface": self._interface,
            "running": self._is_running,
        }

    # ------------------------------------------------------------------
    # Internal capture loop
    # ------------------------------------------------------------------

    def _capture_loop(self) -> None:
        """Background thread body: run Scapy sniff with stop-event support."""
        iface = None if self._interface == "auto" else self._interface
        try:
            scapy.sniff(
                iface=iface,
                prn=self._process_packet,
                store=False,
                stop_filter=lambda _: self._stop_event.is_set(),
            )
        except PermissionError:
            log.error(
                "Permission denied: run VoltGuard with sudo/administrator privileges "
                "to capture packets."
            )
        except Exception as exc:
            log.exception("Unexpected error in capture loop: %s", exc)
        finally:
            self._is_running = False

    def _process_packet(self, pkt: object) -> None:
        """Callback invoked by Scapy for each captured packet.

        Parses the packet, increments counters, persists to the database, and
        notifies all registered GUI callbacks.

        Args:
            pkt: Raw Scapy packet object.
        """
        try:
            parsed = self._parser.parse(pkt)  # type: ignore[arg-type]

            # Naive allow/block decision (decision engine not yet wired in Week 1)
            action = "ALLOWED"
            parsed.extra["action"] = action

            # Update counters
            self._total_packets += 1
            if action == "BLOCKED":
                self._blocked_packets += 1
            else:
                self._allowed_packets += 1

            # Persist to database
            self._db.insert_packet_log(
                src_ip=parsed.src_ip,
                dst_ip=parsed.dst_ip,
                src_port=parsed.src_port,
                dst_port=parsed.dst_port,
                protocol=parsed.protocol,
                function_code=parsed.function_code,
                payload_length=parsed.payload_length,
                action=action,
                raw_summary=parsed.raw_summary,
            )

            # Log to packet log file
            pkt_log.debug(
                "%s | %s→%s | proto=%s | fc=%s | len=%d | %s",
                parsed.timestamp,
                parsed.src_ip,
                parsed.dst_ip,
                parsed.protocol,
                parsed.function_code,
                parsed.payload_length,
                action,
            )

            # Notify GUI callbacks (must be thread-safe — PySide6 signals handle this)
            for cb in self._callbacks:
                try:
                    cb(parsed)
                except Exception as exc:
                    log.error("Callback error: %s", exc)

        except Exception as exc:
            log.exception("Failed to process packet: %s", exc)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    def _reset_counters(self) -> None:
        """Reset per-session counters to zero."""
        self._total_packets = 0
        self._blocked_packets = 0
        self._allowed_packets = 0
