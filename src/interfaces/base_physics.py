"""
VoltGuard — Base Physics Engine Interface
==========================================
Defines the ``BasePhysicsEngine`` Abstract Base Class that every physics
simulation model must implement.

Architecture:
  - The physics engine is the core differentiator of VoltGuard: it predicts
    whether executing a given industrial command would produce an unsafe
    physical state (over-pressure, over-temperature, runaway RPM, etc.).
  - Each engine is stateful — it maintains the current simulated process
    variables across calls and advances the simulation on each ``simulate()``
    invocation.
  - The decision engine calls ``check_constraints()`` after ``simulate()``
    to determine whether to ALLOW or BLOCK the pending command.

Implementing a new physics model:

    from src.interfaces.base_physics import BasePhysicsEngine, PhysicsState

    class PumpStationEngine(BasePhysicsEngine):
        def simulate(self, command_value: float, delta_t: float) -> PhysicsState:
            ...
        def get_state(self) -> PhysicsState:
            ...
        def check_constraints(self, state: PhysicsState) -> bool:
            ...
        def reset(self) -> None:
            ...
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# Physics State DTO
# ---------------------------------------------------------------------------

@dataclass
class PhysicsState:
    """
    Snapshot of the simulated physical process variables at a single instant.

    All fields are optional so that engines can populate only the
    variables they model; uninitialised variables remain ``None``.

    Attributes:
        pressure_bar:       Current simulated pressure (bar).
        flow_lps:           Current simulated flow rate (litres/second).
        temperature_celsius:Current simulated temperature (°C).
        rpm:                Current simulated rotational speed (RPM).
        timestamp:          ISO-8601 UTC time of this state snapshot.
        is_safe:            Whether the current state is within safe limits.
        violations:         List of constraint violation descriptions (empty if safe).
        metadata:           Engine-specific fields not covered by standard attributes.
    """
    pressure_bar: Optional[float] = None
    flow_lps: Optional[float] = None
    temperature_celsius: Optional[float] = None
    rpm: Optional[float] = None
    timestamp: str = ""
    is_safe: bool = True
    violations: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)

    def mark_violation(self, description: str) -> None:
        """
        Record a safety constraint violation and set ``is_safe`` to False.

        Args:
            description: Human-readable description of the violated constraint,
                         e.g. ``"pressure 12.4 bar > limit 10.0 bar"``.
        """
        self.violations.append(description)
        self.is_safe = False


# ---------------------------------------------------------------------------
# Abstract Base Class
# ---------------------------------------------------------------------------

class BasePhysicsEngine(ABC):
    """
    Abstract interface for all VoltGuard physics simulation engines.

    Each engine encapsulates the equations governing a particular type
    of industrial process (pump station, heat exchanger, valve manifold, …).
    Engines are stateful: they accumulate process state between calls.

    Thread safety: engines are NOT thread-safe by default.  If used from
    multiple threads, the caller must synchronise access.
    """

    @abstractmethod
    def simulate(self, command_value: float, delta_t: float) -> PhysicsState:
        """
        Advance the simulation by ``delta_t`` seconds given a control input.

        Args:
            command_value: The commanded setpoint or delta applied to the process
                           (e.g. valve opening percentage 0.0–1.0, or a register
                           value decoded by the parser).
            delta_t:       Time step in seconds since the previous simulation step.

        Returns:
            The predicted ``PhysicsState`` after applying the command.

        Raises:
            PhysicsError: If the simulation state diverges or NaN/Inf values
                          are produced.
        """

    @abstractmethod
    def get_state(self) -> PhysicsState:
        """
        Return the current (last simulated) process state without advancing
        the simulation.

        Returns:
            The most recent ``PhysicsState``.
        """

    @abstractmethod
    def check_constraints(self, state: PhysicsState) -> bool:
        """
        Evaluate whether ``state`` violates any configured safety constraints.

        This method should populate ``state.violations`` for each violated
        constraint and set ``state.is_safe = False``.

        Args:
            state: The ``PhysicsState`` to validate (mutated in-place).

        Returns:
            ``True`` if the state is safe, ``False`` if any constraint is violated.
        """

    @abstractmethod
    def reset(self) -> None:
        """
        Reset the engine to its initial / nominal operating state.

        Use this to clear accumulated simulation state between test scenarios
        or when the monitored process is restarted.
        """

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}>"
