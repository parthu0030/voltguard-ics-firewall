"""
VoltGuard — Physics Simulation Runner
=======================================
Provides ``SimulationRunner``, a Qt-compatible background-thread wrapper
around ``WaterSystemEngine``.

The runner executes on a ``QThread`` and emits a ``state_updated`` signal
each time the engine completes a simulation tick.  UI components connect
to this signal to receive live state updates without polling.

Architecture
----------------------------------------------------------------------
  QThread
  └── SimulationRunner._worker (SimulationWorker)
        └── WaterSystemEngine
              └── SystemState (emitted as signal each tick)

The ``SimulationRunner`` itself lives on the Qt main thread and acts
as the public API.  The ``SimulationWorker`` lives on the worker thread
and must not be accessed directly by UI code.

Usage::

    from src.physics.simulation_runner import SimulationRunner

    runner = SimulationRunner()
    runner.state_updated.connect(my_slot)
    runner.start_simulation()
    ...
    runner.stop_simulation()
"""

from __future__ import annotations

import copy
from typing import Optional

from PyQt6.QtCore import QObject, QThread, QTimer, pyqtSignal, pyqtSlot

from src.config import config_loader
from src.logger import get_logger
from src.physics.physics_config import PhysicsConfig
from src.physics.safety_monitor import PhysicsSafetyMonitor, PhysicsViolation
from src.physics.system_state import SystemState
from src.physics.water_system_engine import WaterSystemEngine

_log = get_logger(__name__)


# ---------------------------------------------------------------------------
# SimulationWorker (lives on QThread)
# ---------------------------------------------------------------------------

class _SimulationWorker(QObject):
    """
    Inner QObject that runs the physics engine loop on a worker thread.

    This class must NOT be used directly from the UI thread.  All
    interaction goes through ``SimulationRunner``.

    Signals:
        tick_done (SystemState): Emitted after every simulation tick
                                  with the new state snapshot.
        error_occurred (str):    Emitted if the engine raises an exception.
    """

    tick_done: pyqtSignal = pyqtSignal(object)   # carries SystemState
    error_occurred: pyqtSignal = pyqtSignal(str)

    def __init__(self, engine: WaterSystemEngine, interval_ms: int) -> None:
        """
        Args:
            engine:      Configured ``WaterSystemEngine`` instance.
            interval_ms: Tick interval in milliseconds.
        """
        super().__init__()
        self._engine = engine
        self._interval_ms = interval_ms
        self._timer: Optional[QTimer] = None
        self._running: bool = False

    # ------------------------------------------------------------------ #
    #  Slots (called from the worker thread's event loop)                 #
    # ------------------------------------------------------------------ #

    @pyqtSlot()
    def start(self) -> None:
        """Start the simulation timer on the worker thread."""
        self._running = True
        self._timer = QTimer()
        self._timer.setInterval(self._interval_ms)
        self._timer.timeout.connect(self._tick)
        self._timer.start()
        _log.info(
            "SimulationWorker started (interval=%d ms).", self._interval_ms
        )

    @pyqtSlot()
    def stop(self) -> None:
        """Stop the simulation timer."""
        self._running = False
        if self._timer is not None:
            self._timer.stop()
            self._timer = None
        # Quit only after stopping the timer in its owning thread.
        thread = self.thread()
        if thread is not None:
            thread.quit()
        _log.info("SimulationWorker stopped.")

    @pyqtSlot(str, float)
    def apply_command(self, cmd_type: str, value: float) -> None:
        """
        Forward a command to the underlying engine.

        Safe to call from the worker thread via a Qt queued connection.
        """
        self._engine.apply_command(cmd_type, value)

    @pyqtSlot()
    def reset_engine(self) -> None:
        """Reset the underlying engine to initial state."""
        self._engine.reset()
        _log.info("SimulationWorker engine reset.")

    @pyqtSlot(str)
    def inject_anomaly(self, scenario: str) -> None:
        """Queue a safe in-memory training anomaly on the worker thread."""
        self._engine.inject_anomaly(scenario)

    # ------------------------------------------------------------------ #
    #  Private                                                             #
    # ------------------------------------------------------------------ #

    def _tick(self) -> None:
        """Execute one simulation tick and emit the result."""
        if not self._running:
            return
        try:
            new_state = self._engine.update_state()
            self.tick_done.emit(copy.copy(new_state))
        except Exception as exc:  # noqa: BLE001
            _log.error("SimulationWorker tick error: %s", exc, exc_info=True)
            self.error_occurred.emit(str(exc))


# ---------------------------------------------------------------------------
# SimulationRunner (public API, lives on main thread)
# ---------------------------------------------------------------------------

class SimulationRunner(QObject):
    """
    Qt-compatible simulation runner that drives ``WaterSystemEngine``
    on a background ``QThread``.

    Connect to ``state_updated`` to receive live ``SystemState`` objects
    after every simulation tick.  Use the command methods to control
    the industrial process.

    Signals:
        state_updated (SystemState):  Emitted on every simulation tick.
        simulation_error (str):       Emitted if the engine raises an error.
        simulation_started ():        Emitted when the simulation begins.
        simulation_stopped ():        Emitted when the simulation stops.

    Example::

        runner = SimulationRunner()
        runner.state_updated.connect(my_ui_slot)
        runner.start_simulation()
    """

    state_updated: pyqtSignal = pyqtSignal(object)    # SystemState
    simulation_error: pyqtSignal = pyqtSignal(str)
    simulation_started: pyqtSignal = pyqtSignal()
    simulation_stopped: pyqtSignal = pyqtSignal()
    physics_violation: pyqtSignal = pyqtSignal(object)

    def __init__(self, parent: Optional[QObject] = None) -> None:
        """
        Initialise the runner.

        The config loader must have been called before instantiating
        this class.  If it has not been loaded yet, it will be loaded
        automatically.
        """
        super().__init__(parent)

        # Ensure config is loaded.
        if not config_loader.is_loaded:
            config_loader.load()

        self._config = PhysicsConfig.from_config(config_loader)
        self._engine = WaterSystemEngine(self._config)

        interval_ms = max(
            100, int(self._config.simulation_interval_sec * 1000)
        )

        # Worker + thread setup.
        self._thread = QThread(self)
        self._worker = _SimulationWorker(self._engine, interval_ms)
        self._worker.moveToThread(self._thread)

        # Wire internal signals.
        self._thread.started.connect(self._worker.start)
        self._worker.tick_done.connect(self._on_tick)
        self._worker.error_occurred.connect(self._on_error)
        self._safety_monitor = PhysicsSafetyMonitor(self._config)

        self._is_running: bool = False
        _log.info(
            "SimulationRunner ready (engine=%r, interval=%d ms).",
            self._engine,
            interval_ms,
        )

    # ------------------------------------------------------------------ #
    #  Lifecycle                                                           #
    # ------------------------------------------------------------------ #

    def start_simulation(self) -> None:
        """
        Start the background simulation thread.

        Safe to call from the UI thread.  Idempotent — calling when
        already running has no effect.
        """
        if self._is_running:
            _log.debug("start_simulation() called but already running.")
            return
        self._is_running = True
        self._thread.start()
        self.simulation_started.emit()
        _log.info("SimulationRunner: simulation started.")

    def stop_simulation(self) -> None:
        """
        Stop the background simulation thread gracefully.

        Blocks until the thread finishes (up to 3 000 ms).
        """
        if not self._is_running:
            return
        self._is_running = False
        # Ask the worker to stop via a queued connection.
        from PyQt6.QtCore import QMetaObject, Qt
        QMetaObject.invokeMethod(self._worker, "stop", Qt.ConnectionType.QueuedConnection)
        self._thread.wait(3000)
        self.simulation_stopped.emit()
        _log.info("SimulationRunner: simulation stopped.")

    def is_running(self) -> bool:
        """Return ``True`` if the simulation is currently running."""
        return self._is_running

    # ------------------------------------------------------------------ #
    #  Command API (thread-safe — uses queued connections)                #
    # ------------------------------------------------------------------ #

    def send_command(self, cmd_type: str, value: float) -> bool:
        """
        Send a control command to the physics engine.

        Thread-safe: the command is delivered to the worker thread via
        Qt's queued connection mechanism.

        Args:
            cmd_type: Command type string (``CommandType.*``).
            value:    Command argument.
        """
        if not self._is_running or not self._thread.isRunning():
            _log.warning("Ignoring %s command: simulation is not running.", cmd_type)
            return False

        from PyQt6.QtCore import QMetaObject, Q_ARG, Qt
        QMetaObject.invokeMethod(
            self._worker,
            "apply_command",
            Qt.ConnectionType.QueuedConnection,
            Q_ARG(str, cmd_type),
            Q_ARG(float, float(value)),
        )
        return True

    def set_pump(self, on: bool) -> bool:
        """
        Turn the pump ON or OFF.

        Args:
            on: ``True`` to start the pump, ``False`` to stop it.
        """
        from src.physics.water_system_engine import CommandType
        sent = self.send_command(CommandType.SET_PUMP, 1.0 if on else 0.0)
        _log.debug("set_pump(%s)", on)
        return sent

    def set_valve(self, position: float) -> bool:
        """
        Set the valve opening position.

        Args:
            position: Fraction 0.0 (fully closed) to 1.0 (fully open).
        """
        from src.physics.water_system_engine import CommandType
        position = max(0.0, min(1.0, position))
        sent = self.send_command(CommandType.SET_VALVE, position)
        _log.debug("set_valve(%.3f)", position)
        return sent

    def trigger_anomaly(self, scenario: str) -> bool:
        """Queue a safe physics-training scenario while the simulation runs."""
        if not self._is_running or not self._thread.isRunning():
            _log.warning("Ignoring anomaly scenario while simulation is stopped: %s", scenario)
            return False
        from PyQt6.QtCore import QMetaObject, Q_ARG, Qt
        QMetaObject.invokeMethod(
            self._worker,
            "inject_anomaly",
            Qt.ConnectionType.QueuedConnection,
            Q_ARG(str, scenario),
        )
        return True

    def reset_simulation(self) -> None:
        """
        Reset the physics engine to its initial state.

        Thread-safe: delivered as a queued call to the worker thread.
        """
        self._safety_monitor.reset()
        if not self._is_running:
            self._engine.reset()
            _log.info("SimulationRunner: reset while stopped.")
            return

        from PyQt6.QtCore import QMetaObject, Qt
        QMetaObject.invokeMethod(
            self._worker,
            "reset_engine",
            Qt.ConnectionType.QueuedConnection,
        )
        _log.info("SimulationRunner: reset requested.")

    # ------------------------------------------------------------------ #
    #  Direct Engine Access (for testing or non-threaded use)             #
    # ------------------------------------------------------------------ #

    @property
    def engine(self) -> WaterSystemEngine:
        """
        Direct access to the underlying ``WaterSystemEngine``.

        **Warning**: Only use this when not running in threaded mode
        (e.g. in unit tests).  From the UI, use the command API instead.
        """
        return self._engine

    @property
    def current_state(self) -> SystemState:
        """Return the current engine state (snapshot)."""
        return self._engine.get_system_state()

    # ------------------------------------------------------------------ #
    #  Private Slots                                                       #
    # ------------------------------------------------------------------ #

    def _on_tick(self, state: SystemState) -> None:
        """Relay the worker's tick result to external listeners."""
        try:
            from src.services.database_service import database_service
            if not database_service.is_ready:
                database_service.initialize()
            if database_service.is_ready:
                database_service.save_physics_reading(state)
        except Exception as exc:
            _log.error("Failed to persist physics reading: %s", exc)
        self.state_updated.emit(state)
        for violation in self._safety_monitor.evaluate(state):
            self.physics_violation.emit(violation)
            self._record_physics_violation(violation)

    @staticmethod
    def _record_physics_violation(violation: PhysicsViolation) -> None:
        """Bridge a physics violation into VoltGuard's existing alert flow."""
        try:
            from src.models.app_models import AlertSeverity
            from src.models.security_event import SecurityEvent
            from src.services.alert_manager import alert_manager

            severity = AlertSeverity(violation.severity.value)
            action = "BLOCK" if violation.severity.value == "CRITICAL" else "ALERT"
            event = SecurityEvent(
                timestamp=violation.timestamp,
                source_ip="physics-monitor",
                destination_ip="water-system",
                protocol="Physics Simulation",
                risk_score=violation.risk_score,
                risk_level=violation.severity.value,
                original_decision=action,
                matched_policy_id=violation.rule_id,
                matched_policy_name="Physics Safety Monitor",
                final_action=action,
                reason=(f"{violation.description} Current {violation.parameter}="
                        f"{violation.current_value:.3f}; safe range {violation.safe_range}."),
                event_type="PHYSICS_VIOLATION",
                severity=severity,
            )
            alert_manager.process_security_event(event)
        except Exception as exc:  # Persistence must not stop the simulator.
            _log.error("Failed to persist physics violation %s: %s", violation.rule_id, exc)

    def _on_error(self, message: str) -> None:
        """Relay engine errors to external listeners and log them."""
        _log.error("SimulationRunner engine error: %s", message)
        self.simulation_error.emit(message)

    # ------------------------------------------------------------------ #
    #  Cleanup                                                             #
    # ------------------------------------------------------------------ #

    def cleanup(self) -> None:
        """
        Stop the simulation and release all Qt resources.

        Call this before the application exits or before discarding
        a ``SimulationRunner`` instance.
        """
        self.stop_simulation()
        _log.info("SimulationRunner cleaned up.")
