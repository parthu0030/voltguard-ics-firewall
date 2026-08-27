"""
VoltGuard — Physics Engine Package
=====================================
Exports the complete industrial physics simulation stack for VoltGuard.

Day 3 Status: Fully implemented — Water System Simulation Engine.

Components
----------
- ``WaterSystemEngine``   Core physics engine (pump, valve, pressure, flow, temp, tank)
- ``SystemState``         Typed snapshot DTO for all process variables
- ``PhysicsConfig``       Immutable configuration container (loaded from config.json)
- ``SimulationRunner``    Qt QThread wrapper; emits ``state_updated`` signals per tick
- ``CommandType``         String constants for engine commands

Architecture
------------
All engines implement ``src.interfaces.base_physics.BasePhysicsEngine``.
The ``SimulationRunner`` is the entry point for UI integration; the
engine and state model can also be used standalone in tests and scripts.

Quick Start::

    from src.physics import SimulationRunner

    runner = SimulationRunner()
    runner.state_updated.connect(my_slot)
    runner.start_simulation()
    runner.set_pump(True)
    runner.set_valve(0.75)
"""

from src.physics.physics_config import PhysicsConfig
from src.physics.simulation_runner import SimulationRunner
from src.physics.safety_monitor import PhysicsSafetyMonitor, PhysicsViolation
from src.physics.system_state import SystemState
from src.physics.water_system_engine import CommandType, WaterSystemEngine

__all__ = [
    "PhysicsConfig",
    "SimulationRunner",
    "PhysicsSafetyMonitor",
    "PhysicsViolation",
    "SystemState",
    "CommandType",
    "WaterSystemEngine",
]
