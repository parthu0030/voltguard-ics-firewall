"""
VoltGuard — Physics Simulation Configuration
==============================================
Defines ``PhysicsConfig``, a typed dataclass that holds every threshold
and rate parameter used by the physics simulation engine.

All values are loaded from ``config.json`` via the project's
``ConfigLoader`` singleton.  Hard-coded fallback defaults ensure the
engine can operate even if a key is absent from the config file.

Design decisions:
  - Immutable after construction (``frozen=True``).
  - Validates that limits are logically consistent (e.g. min < max).
  - Single source of truth — the engine imports this and never accesses
    ``config_loader`` directly.

Usage::

    from src.physics.physics_config import PhysicsConfig
    from src.config import config_loader

    config_loader.load()
    cfg = PhysicsConfig.from_config(config_loader)
    print(cfg.pressure_max_bar)
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from src.exceptions import ConfigurationError

if TYPE_CHECKING:
    from src.config import ConfigLoader


# ---------------------------------------------------------------------------
# PhysicsConfig Dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PhysicsConfig:
    """
    Immutable configuration container for all physics simulation parameters.

    Every threshold is read from ``config.json`` under the ``physics.*``
    namespace.  All values carry safe fallback defaults so the engine
    never fails due to a missing key.

    Pressure / Flow / Temperature
    -----------------------------------------------------------------------
    Attributes:
        pressure_max_bar:           Maximum safe pipeline pressure (bar).
        pressure_min_bar:           Minimum expected pipeline pressure (bar).
        flow_max_lps:               Maximum safe flow rate (litres/second).
        temp_max_celsius:           Maximum safe fluid temperature (°C).
        temp_min_celsius:           Minimum safe fluid temperature (°C).
        temp_ambient_celsius:       Ambient environment temperature (°C).

    Pump
    -----------------------------------------------------------------------
    Attributes:
        pump_rpm_max:               Maximum safe pump rotational speed (RPM).
        pump_ramp_rate_rpm_per_sec: Rate at which RPM increases when pump ON.
        pump_decay_rate_rpm_per_sec:Rate at which RPM decreases when pump OFF.
        pressure_ramp_bar_per_rpm:  Pressure gain per unit of RPM (bar/RPM).
        pressure_decay_rate_bar_per_sec: Pressure loss rate when pump is OFF.

    Flow Coefficients
    -----------------------------------------------------------------------
    Attributes:
        flow_coefficient:           Flow (L/s) = pressure (bar) × valve × this.

    Temperature Rates
    -----------------------------------------------------------------------
    Attributes:
        temp_rise_rate_celsius_per_sec: Temperature increase rate (pump ON).
        temp_cool_rate_celsius_per_sec: Temperature cooling rate (pump OFF).

    Tank
    -----------------------------------------------------------------------
    Attributes:
        tank_max_m3:                Maximum tank capacity (m³).
        tank_min_m3:                Minimum safe tank volume (m³, typically 0).
        tank_initial_m3:            Initial tank volume at simulation start.
        tank_drain_factor:          Multiplier applied to flow when draining tank.
        tank_fill_rate_m3_per_sec:  Rate at which tank auto-refills.
        tank_fill_threshold_m3:     Tank volume at which auto-fill triggers.

    Valve
    -----------------------------------------------------------------------
    Attributes:
        valve_speed_per_sec:        Max rate of valve position change per second.

    Simulation
    -----------------------------------------------------------------------
    Attributes:
        simulation_interval_sec:    Simulation tick duration (seconds).
    """

    # Pressure
    pressure_max_bar: float = 10.0
    pressure_min_bar: float = 0.5

    # Flow
    flow_max_lps: float = 50.0

    # Temperature
    temp_max_celsius: float = 150.0
    temp_min_celsius: float = 5.0
    temp_ambient_celsius: float = 22.0

    # Pump
    pump_rpm_max: float = 3600.0
    pump_ramp_rate_rpm_per_sec: float = 300.0
    pump_decay_rate_rpm_per_sec: float = 150.0
    pressure_ramp_bar_per_rpm: float = 0.0025
    pressure_decay_rate_bar_per_sec: float = 0.4

    # Flow coefficient
    flow_coefficient: float = 0.015

    # Temperature rates
    temp_rise_rate_celsius_per_sec: float = 0.08
    temp_cool_rate_celsius_per_sec: float = 0.05

    # Tank
    tank_max_m3: float = 100.0
    tank_min_m3: float = 0.0
    tank_initial_m3: float = 75.0
    tank_drain_factor: float = 1.0
    tank_fill_rate_m3_per_sec: float = 2.0
    tank_fill_threshold_m3: float = 20.0

    # Valve
    valve_speed_per_sec: float = 0.05

    # Simulation tick
    simulation_interval_sec: float = 1.0

    # ------------------------------------------------------------------ #
    #  Factory                                                             #
    # ------------------------------------------------------------------ #

    @classmethod
    def from_config(cls, config_loader: "ConfigLoader") -> "PhysicsConfig":
        """
        Construct a ``PhysicsConfig`` from the loaded ``ConfigLoader``.

        Reads every value from the ``physics.*`` namespace in config.json.
        Missing keys silently fall back to the field defaults defined above.

        Args:
            config_loader: A fully loaded ``ConfigLoader`` instance.

        Returns:
            A populated, frozen ``PhysicsConfig``.

        Raises:
            ConfigurationError: If any value has an invalid type or a
                                 logically inconsistent relationship
                                 (e.g. min > max).
        """
        def _f(key: str, default: float) -> float:
            """Helper: read a float from physics.* namespace."""
            return config_loader.get_float(f"physics.{key}", default)

        cfg = cls(
            pressure_max_bar                = _f("pressure_max_bar",                10.0),
            pressure_min_bar                = _f("pressure_min_bar",                0.5),
            flow_max_lps                    = _f("flow_max_lps",                    50.0),
            temp_max_celsius                = _f("temp_max_celsius",                150.0),
            temp_min_celsius                = _f("temp_min_celsius",                5.0),
            temp_ambient_celsius            = _f("temp_ambient_celsius",            22.0),
            pump_rpm_max                    = _f("rpm_max",                         3600.0),
            pump_ramp_rate_rpm_per_sec      = _f("pump_ramp_rate_rpm_per_sec",      300.0),
            pump_decay_rate_rpm_per_sec     = _f("pump_decay_rate_rpm_per_sec",     150.0),
            pressure_ramp_bar_per_rpm       = _f("pressure_ramp_bar_per_rpm",       0.0025),
            pressure_decay_rate_bar_per_sec = _f("pressure_decay_rate_bar_per_sec", 0.4),
            flow_coefficient                = _f("flow_coefficient",                0.015),
            temp_rise_rate_celsius_per_sec  = _f("temp_rise_rate_celsius_per_sec",  0.08),
            temp_cool_rate_celsius_per_sec  = _f("temp_cool_rate_celsius_per_sec",  0.05),
            tank_max_m3                     = _f("tank_max_m3",                     100.0),
            tank_min_m3                     = _f("tank_min_m3",                     0.0),
            tank_initial_m3                 = _f("tank_initial_m3",                 75.0),
            tank_drain_factor               = _f("tank_drain_factor",               1.0),
            tank_fill_rate_m3_per_sec       = _f("tank_fill_rate_m3_per_sec",       2.0),
            tank_fill_threshold_m3          = _f("tank_fill_threshold_m3",          20.0),
            valve_speed_per_sec             = _f("valve_speed_per_sec",             0.05),
            simulation_interval_sec         = _f("simulation_interval_sec",         1.0),
        )

        cfg._validate()
        return cfg

    # ------------------------------------------------------------------ #
    #  Validation                                                          #
    # ------------------------------------------------------------------ #

    def _validate(self) -> None:
        """
        Verify that all configuration values are logically consistent.

        Raises:
            ConfigurationError: On any constraint violation.
        """
        errors: list[str] = []

        if self.pressure_min_bar >= self.pressure_max_bar:
            errors.append(
                f"pressure_min_bar ({self.pressure_min_bar}) must be "
                f"< pressure_max_bar ({self.pressure_max_bar})"
            )
        if self.temp_min_celsius >= self.temp_max_celsius:
            errors.append(
                f"temp_min_celsius ({self.temp_min_celsius}) must be "
                f"< temp_max_celsius ({self.temp_max_celsius})"
            )
        if self.tank_min_m3 >= self.tank_max_m3:
            errors.append(
                f"tank_min_m3 ({self.tank_min_m3}) must be "
                f"< tank_max_m3 ({self.tank_max_m3})"
            )
        if not (self.tank_min_m3 <= self.tank_initial_m3 <= self.tank_max_m3):
            errors.append(
                f"tank_initial_m3 ({self.tank_initial_m3}) must be within "
                f"[{self.tank_min_m3}, {self.tank_max_m3}]"
            )
        if self.simulation_interval_sec <= 0:
            errors.append(
                f"simulation_interval_sec ({self.simulation_interval_sec}) must be > 0"
            )
        if self.pump_rpm_max <= 0:
            errors.append(
                f"pump_rpm_max ({self.pump_rpm_max}) must be > 0"
            )
        if self.flow_max_lps <= 0:
            errors.append(
                f"flow_max_lps ({self.flow_max_lps}) must be > 0"
            )

        if errors:
            raise ConfigurationError(
                "Physics configuration is invalid:\n" + "\n".join(f"  • {e}" for e in errors),
                detail="source=physics_config",
            )

    # ------------------------------------------------------------------ #
    #  Representation                                                      #
    # ------------------------------------------------------------------ #

    def __str__(self) -> str:
        return (
            f"PhysicsConfig("
            f"P={self.pressure_min_bar}–{self.pressure_max_bar} bar, "
            f"F≤{self.flow_max_lps} L/s, "
            f"T={self.temp_min_celsius}–{self.temp_max_celsius} °C, "
            f"RPM≤{self.pump_rpm_max}, "
            f"tank={self.tank_min_m3}–{self.tank_max_m3} m³, "
            f"dt={self.simulation_interval_sec}s)"
        )
