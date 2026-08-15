"""
VoltGuard — Application State (Core)
======================================
Provides the global, in-memory application state as a singleton.
This is the single source of truth for live runtime counters and
status flags that the UI reads to render the dashboard.

Design:
  - Singleton via module-level instance ``app_state``.
  - No Qt dependency; pure Python so unit tests run headlessly.
  - Qt components connect to the state and poll or receive signals
    through the service layer — business logic stays here, not in UI.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from threading import Lock
from typing import Callable, Optional


@dataclass
class _AppState:
    """
    Mutable singleton holding live application metrics and status.

    All public attributes are safe to read from the UI thread.
    Mutations must use the provided setter methods which acquire
    the internal lock to prevent race conditions.
    """

    # ------------------------------------------------------------------ #
    #  Packet counters                                                     #
    # ------------------------------------------------------------------ #
    _packets_captured: int = field(default=0, init=False, repr=False)
    _packets_allowed: int = field(default=0, init=False, repr=False)
    _packets_blocked: int = field(default=0, init=False, repr=False)

    # ------------------------------------------------------------------ #
    #  Status strings                                                      #
    # ------------------------------------------------------------------ #
    _app_status: str = field(default="Idle", init=False, repr=False)
    _db_status: str = field(default="Disconnected", init=False, repr=False)
    _selected_interface: str = field(default="—", init=False, repr=False)

    # ------------------------------------------------------------------ #
    #  Internal                                                            #
    # ------------------------------------------------------------------ #
    _lock: Lock = field(default_factory=Lock, init=False, repr=False)
    _change_callbacks: list[Callable[[], None]] = field(
        default_factory=list, init=False, repr=False
    )

    # ------------------------------------------------------------------ #
    #  Subscription API                                                    #
    # ------------------------------------------------------------------ #

    def subscribe(self, callback: Callable[[], None]) -> None:
        """
        Register a callback that fires whenever any state value changes.

        Args:
            callback: Zero-argument callable (e.g. a slot or lambda).
        """
        with self._lock:
            self._change_callbacks.append(callback)

    def _notify(self) -> None:
        """Invoke all registered change callbacks. Must be called under lock."""
        for cb in self._change_callbacks:
            try:
                cb()
            except Exception:
                pass  # Never crash the state manager due to a bad callback.

    # ------------------------------------------------------------------ #
    #  Packet counter accessors                                            #
    # ------------------------------------------------------------------ #

    @property
    def packets_captured(self) -> int:
        """Total packets seen since application start."""
        return self._packets_captured

    @property
    def packets_allowed(self) -> int:
        """Total packets forwarded (action = ALLOW)."""
        return self._packets_allowed

    @property
    def packets_blocked(self) -> int:
        """Total packets dropped (action = BLOCK)."""
        return self._packets_blocked

    def increment_allowed(self) -> None:
        """Record one allowed packet and update captured counter."""
        with self._lock:
            self._packets_allowed += 1
            self._packets_captured += 1
            self._notify()

    def increment_blocked(self) -> None:
        """Record one blocked packet and update captured counter."""
        with self._lock:
            self._packets_blocked += 1
            self._packets_captured += 1
            self._notify()

    def reset_counters(self) -> None:
        """Reset all packet counters to zero."""
        with self._lock:
            self._packets_captured = 0
            self._packets_allowed = 0
            self._packets_blocked = 0
            self._notify()

    # ------------------------------------------------------------------ #
    #  Status accessors                                                    #
    # ------------------------------------------------------------------ #

    @property
    def app_status(self) -> str:
        """Human-readable application operational status."""
        return self._app_status

    @app_status.setter
    def app_status(self, value: str) -> None:
        with self._lock:
            self._app_status = value
            self._notify()

    @property
    def db_status(self) -> str:
        """Database connection status string."""
        return self._db_status

    @db_status.setter
    def db_status(self, value: str) -> None:
        with self._lock:
            self._db_status = value
            self._notify()

    @property
    def selected_interface(self) -> str:
        """Currently configured network interface name."""
        return self._selected_interface

    @selected_interface.setter
    def selected_interface(self, value: str) -> None:
        with self._lock:
            self._selected_interface = value
            self._notify()

    # ------------------------------------------------------------------ #
    #  Utility                                                             #
    # ------------------------------------------------------------------ #

    def system_time(self) -> str:
        """Return current local time formatted as HH:MM:SS."""
        return datetime.now().strftime("%H:%M:%S")

    def snapshot(self) -> dict:
        """
        Return an immutable snapshot of all state values as a plain dict.
        Useful for passing to UI render functions without exposing the lock.
        """
        return {
            "packets_captured": self._packets_captured,
            "packets_allowed": self._packets_allowed,
            "packets_blocked": self._packets_blocked,
            "app_status": self._app_status,
            "db_status": self._db_status,
            "selected_interface": self._selected_interface,
            "system_time": self.system_time(),
        }


# ---------------------------------------------------------------------------
# Module-level singleton — import and use directly:
#   from src.core.app_state import app_state
# ---------------------------------------------------------------------------
app_state: _AppState = _AppState()
