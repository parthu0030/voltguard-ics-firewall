"""
VoltGuard — System State Model
================================
Defines ``SystemState``, the canonical data-transfer object (DTO) that
carries a complete snapshot of all simulated physical process variables
for the industrial water system.

This module is deliberately Qt-free and dependency-free so it can be
imported by tests, the physics engine, and any UI component without
side effects.

Usage::

    from src.physics.system_state import SystemState

    state = SystemState()
    print(state.pressure_bar)   # 0.0
    d = state.to_dict()
    delta = new_state.diff(old_state)
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string (seconds precision)."""
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")


# ---------------------------------------------------------------------------
# SystemState DTO
# ---------------------------------------------------------------------------

@dataclass
class SystemState:
    """
    Complete snapshot of the simulated industrial water-system state.

    All fields represent the physical process variables at a single
    simulation tick.  ``timestamp`` is set automatically on construction
    but can be overridden for testing.

    Attributes:
        pressure_bar:       Current pipeline pressure in bar.
        flow_lps:           Current volumetric flow rate in litres/second.
        temperature_celsius:Current fluid/ambient temperature in °C.
        pump_on:            Whether the main pump is currently running.
        pump_rpm:           Current pump rotational speed in RPM.
        valve_position:     Valve opening fraction 0.0 (closed) – 1.0 (fully open).
        tank_level_m3:      Current water volume in the storage tank (m³).
        timestamp:          ISO-8601 UTC timestamp of this snapshot.
    """

    pressure_bar: float = 0.0
    flow_lps: float = 0.0
    temperature_celsius: float = 22.0
    pump_on: bool = False
    pump_rpm: float = 0.0
    valve_position: float = 0.0
    tank_level_m3: float = 75.0
    timestamp: str = field(default_factory=_utc_now)

    # ------------------------------------------------------------------ #
    #  Serialisation                                                       #
    # ------------------------------------------------------------------ #

    def to_dict(self) -> dict[str, Any]:
        """
        Serialise the state to a plain Python dictionary.

        All floats are rounded to 4 decimal places for readability
        in log output.

        Returns:
            Ordered dict with all state fields.
        """
        raw = asdict(self)
        # Round floats for cleaner log output.
        for key, value in raw.items():
            if isinstance(value, float):
                raw[key] = round(value, 4)
        return raw

    # ------------------------------------------------------------------ #
    #  Diff / Comparison                                                   #
    # ------------------------------------------------------------------ #

    def diff(self, other: "SystemState") -> dict[str, dict[str, Any]]:
        """
        Compute the set of fields that changed between ``self`` and ``other``.

        Returns a dict mapping changed field names to
        ``{"prev": old_value, "new": new_value}`` pairs.
        Ignores the ``timestamp`` field since it always changes.

        Args:
            other: The previous ``SystemState`` to compare against.

        Returns:
            Dict of changed fields.  Empty if states are identical
            (ignoring timestamp).

        Example::

            delta = new_state.diff(old_state)
            # {'pressure_bar': {'prev': 3.2, 'new': 4.1}, ...}
        """
        IGNORED_FIELDS = {"timestamp"}
        changed: dict[str, dict[str, Any]] = {}

        self_dict = asdict(self)
        other_dict = asdict(other)

        for key in self_dict:
            if key in IGNORED_FIELDS:
                continue
            new_val = self_dict[key]
            old_val = other_dict.get(key)
            if isinstance(new_val, float) and isinstance(old_val, float):
                # Use a small epsilon for float comparison.
                if abs(new_val - old_val) > 1e-6:
                    changed[key] = {"prev": round(old_val, 4), "new": round(new_val, 4)}
            elif new_val != old_val:
                changed[key] = {"prev": old_val, "new": new_val}

        return changed

    # ------------------------------------------------------------------ #
    #  Warning / Constraint Helpers                                        #
    # ------------------------------------------------------------------ #

    def has_warnings(self, config: "PhysicsConfig") -> list[str]:  # type: ignore[name-defined]
        """
        Return a list of human-readable warning strings for any value
        that is approaching or exceeding configured safety thresholds.

        A warning is generated when a value reaches 90 % of its
        maximum (or 110 % of its minimum) without yet being a hard
        violation.  Hard violations (≥ max / ≤ min) are also included.

        Args:
            config: The ``PhysicsConfig`` instance with all thresholds.

        Returns:
            List of warning strings.  Empty list if all values are safe.
        """
        warnings: list[str] = []

        # --- Pressure ---
        # CRITICAL only when the value genuinely exceeds the safety limit
        # (the engine clamps to max, so > catches pre-clamp violations).
        # WARNING when approaching 90 % of the limit.
        if self.pressure_bar > config.pressure_max_bar:
            warnings.append(
                f"CRITICAL: Pressure {self.pressure_bar:.2f} bar > max "
                f"{config.pressure_max_bar:.2f} bar"
            )
        elif self.pressure_bar >= config.pressure_max_bar * 0.9:
            warnings.append(
                f"WARNING: Pressure {self.pressure_bar:.2f} bar approaching max "
                f"{config.pressure_max_bar:.2f} bar"
            )

        # --- Flow ---
        if self.flow_lps > config.flow_max_lps:
            warnings.append(
                f"CRITICAL: Flow {self.flow_lps:.2f} L/s > max "
                f"{config.flow_max_lps:.2f} L/s"
            )
        elif self.flow_lps < 0.0:
            warnings.append(f"ERROR: Flow {self.flow_lps:.2f} L/s is negative (invalid)")

        # --- Temperature ---
        if self.temperature_celsius > config.temp_max_celsius:
            warnings.append(
                f"CRITICAL: Temperature {self.temperature_celsius:.2f} °C > max "
                f"{config.temp_max_celsius:.2f} °C"
            )
        elif self.temperature_celsius >= config.temp_max_celsius * 0.9:
            warnings.append(
                f"WARNING: Temperature {self.temperature_celsius:.2f} °C approaching max "
                f"{config.temp_max_celsius:.2f} °C"
            )
        elif self.temperature_celsius < config.temp_min_celsius:
            warnings.append(
                f"WARNING: Temperature {self.temperature_celsius:.2f} °C < min "
                f"{config.temp_min_celsius:.2f} °C"
            )

        # --- Pump RPM ---
        # pump_rpm_max is the *rated* maximum (normal full-speed operation).
        # Only warn when RPM genuinely exceeds the rated limit.
        if self.pump_rpm > config.pump_rpm_max:
            warnings.append(
                f"CRITICAL: Pump RPM {self.pump_rpm:.0f} > rated max {config.pump_rpm_max:.0f}"
            )
        elif self.pump_rpm >= config.pump_rpm_max * 0.95:
            warnings.append(
                f"INFO: Pump running at {self.pump_rpm:.0f} RPM (near rated max "
                f"{config.pump_rpm_max:.0f} RPM)"
            )

        # --- Tank level ---
        if self.tank_level_m3 < config.tank_min_m3:
            warnings.append(
                f"CRITICAL: Tank level {self.tank_level_m3:.2f} m³ < min "
                f"{config.tank_min_m3:.2f} m³ (empty)"
            )
        elif self.tank_level_m3 <= config.tank_min_m3 + (config.tank_max_m3 * 0.1):
            warnings.append(
                f"WARNING: Tank level {self.tank_level_m3:.2f} m³ is critically low"
            )
        if self.tank_level_m3 > config.tank_max_m3:
            warnings.append(
                f"CRITICAL: Tank level {self.tank_level_m3:.2f} m³ > max "
                f"{config.tank_max_m3:.2f} m³ (overflow)"
            )

        return warnings

    # ------------------------------------------------------------------ #
    #  Representation                                                      #
    # ------------------------------------------------------------------ #

    def __repr__(self) -> str:
        return (
            f"SystemState("
            f"P={self.pressure_bar:.2f}bar, "
            f"F={self.flow_lps:.2f}L/s, "
            f"T={self.temperature_celsius:.1f}°C, "
            f"pump={'ON' if self.pump_on else 'OFF'}, "
            f"RPM={self.pump_rpm:.0f}, "
            f"valve={self.valve_position:.2f}, "
            f"tank={self.tank_level_m3:.1f}m³)"
        )
