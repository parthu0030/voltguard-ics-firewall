"""
VoltGuard Physics Engine
--------------------------
Provides a reusable simulation interface for industrial control-system (ICS)
physical process variables.  Week-1 implementation establishes the class
hierarchy and method signatures; numerical models will be added in later weeks.

Supported variables:
  - Pressure    (bar / PSI)
  - Flow rate   (m³/h or L/min)
  - Temperature (°C)
  - Rotational speed / RPM
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass
class PhysicsState:
    """Snapshot of all simulated physical variables at a point in time.

    Attributes:
        timestamp:   Unix epoch time of the snapshot.
        pressure:    Simulated pressure value.
        flow:        Simulated flow rate.
        temperature: Simulated temperature.
        rpm:         Simulated rotational speed.
        anomaly:     ``True`` if any value is outside safe thresholds.
        details:     Per-variable detail dictionary for extended inspection.
    """

    timestamp: float = field(default_factory=time.time)
    pressure: float = 0.0
    flow: float = 0.0
    temperature: float = 20.0
    rpm: float = 0.0
    anomaly: bool = False
    details: Dict[str, object] = field(default_factory=dict)


@dataclass
class PhysicsThresholds:
    """Safe operating bounds for all physical variables."""

    pressure_min: float = 0.0
    pressure_max: float = 100.0
    flow_min: float = 0.0
    flow_max: float = 50.0
    temperature_min: float = -20.0
    temperature_max: float = 150.0
    rpm_min: float = 0.0
    rpm_max: float = 3600.0


class PhysicsEngine:
    """Core simulation engine for ICS physical process variables.

    The engine maintains an internal state vector and exposes individual
    ``simulate_*`` methods that update one variable at a time.  Each method
    returns the updated value so callers can react immediately.

    Example::

        engine = PhysicsEngine()
        pressure = engine.simulate_pressure(current_value=45.0, delta_t=1.0)
        state = engine.get_current_state()
    """

    def __init__(self, thresholds: Optional[PhysicsThresholds] = None) -> None:
        self._thresholds = thresholds or PhysicsThresholds()
        self._state = PhysicsState()
        self._history: List[PhysicsState] = []

    # ------------------------------------------------------------------
    # Simulation methods
    # ------------------------------------------------------------------

    def simulate_pressure(
        self,
        current_value: float,
        delta_t: float = 1.0,
        pump_setpoint: float = 50.0,
    ) -> float:
        """Simulate one time-step of pressure dynamics.

        In Week 1 this is a direct pass-through that validates the value
        against safe thresholds.  Week 2+ will add PID / physics equations.

        Args:
            current_value: Current pressure reading (bar or PSI).
            delta_t:       Time-step duration in seconds.
            pump_setpoint: Target pump setpoint (unused in Week 1).

        Returns:
            Updated pressure value after simulation step.
        """
        self._state.pressure = current_value
        self._state.details["pressure_in_range"] = self._in_range(
            current_value, self._thresholds.pressure_min, self._thresholds.pressure_max
        )
        self._update_anomaly_flag()
        return current_value

    def simulate_flow(
        self,
        current_value: float,
        delta_t: float = 1.0,
        valve_position: float = 1.0,
    ) -> float:
        """Simulate one time-step of flow-rate dynamics.

        Args:
            current_value:  Current flow-rate reading (m³/h or L/min).
            delta_t:        Time-step duration in seconds.
            valve_position: Valve open fraction 0.0–1.0 (unused in Week 1).

        Returns:
            Updated flow-rate value.
        """
        self._state.flow = current_value
        self._state.details["flow_in_range"] = self._in_range(
            current_value, self._thresholds.flow_min, self._thresholds.flow_max
        )
        self._update_anomaly_flag()
        return current_value

    def simulate_temperature(
        self,
        current_value: float,
        delta_t: float = 1.0,
        ambient: float = 25.0,
    ) -> float:
        """Simulate one time-step of temperature dynamics.

        Args:
            current_value: Current temperature reading (°C).
            delta_t:       Time-step duration in seconds.
            ambient:       Ambient temperature for heat-transfer model (unused Week 1).

        Returns:
            Updated temperature value.
        """
        self._state.temperature = current_value
        self._state.details["temperature_in_range"] = self._in_range(
            current_value,
            self._thresholds.temperature_min,
            self._thresholds.temperature_max,
        )
        self._update_anomaly_flag()
        return current_value

    def simulate_rpm(
        self,
        current_value: float,
        delta_t: float = 1.0,
        load_torque: float = 0.0,
    ) -> float:
        """Simulate one time-step of rotational speed dynamics.

        Args:
            current_value: Current RPM reading.
            delta_t:       Time-step duration in seconds.
            load_torque:   Applied load torque (unused in Week 1).

        Returns:
            Updated RPM value.
        """
        self._state.rpm = current_value
        self._state.details["rpm_in_range"] = self._in_range(
            current_value, self._thresholds.rpm_min, self._thresholds.rpm_max
        )
        self._update_anomaly_flag()
        return current_value

    # ------------------------------------------------------------------
    # State inspection
    # ------------------------------------------------------------------

    def get_current_state(self) -> PhysicsState:
        """Return a *copy* of the current simulation state.

        Returns:
            :class:`PhysicsState` snapshot.
        """
        import copy
        snapshot = copy.copy(self._state)
        snapshot.timestamp = time.time()
        self._history.append(snapshot)
        return snapshot

    def get_history(self, last_n: int = 100) -> List[PhysicsState]:
        """Return the last *n* state snapshots.

        Args:
            last_n: Maximum number of historical records to return.

        Returns:
            List of :class:`PhysicsState` objects, oldest first.
        """
        return self._history[-last_n:]

    def reset(self) -> None:
        """Reset the simulation state to default values."""
        self._state = PhysicsState()
        self._history.clear()

    def update_thresholds(self, thresholds: PhysicsThresholds) -> None:
        """Replace the active threshold configuration.

        Args:
            thresholds: New :class:`PhysicsThresholds` to apply.
        """
        self._thresholds = thresholds
        # Re-evaluate anomaly status with new bounds
        self._update_anomaly_flag()

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _in_range(value: float, low: float, high: float) -> bool:
        """Return ``True`` if *value* is within [*low*, *high*]."""
        return low <= value <= high

    def _update_anomaly_flag(self) -> None:
        """Set ``self._state.anomaly`` based on current thresholds."""
        s = self._state
        t = self._thresholds
        self._state.anomaly = not all(
            [
                self._in_range(s.pressure, t.pressure_min, t.pressure_max),
                self._in_range(s.flow, t.flow_min, t.flow_max),
                self._in_range(s.temperature, t.temperature_min, t.temperature_max),
                self._in_range(s.rpm, t.rpm_min, t.rpm_max),
            ]
        )

    def is_anomaly(self) -> bool:
        """Return ``True`` if the current state contains any anomaly."""
        return self._state.anomaly

    def __repr__(self) -> str:
        return (
            f"<PhysicsEngine pressure={self._state.pressure:.2f} "
            f"flow={self._state.flow:.2f} "
            f"temp={self._state.temperature:.2f} "
            f"rpm={self._state.rpm:.2f} "
            f"anomaly={self._state.anomaly}>"
        )
