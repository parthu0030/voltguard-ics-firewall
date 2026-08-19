"""
VoltGuard — Decision Engine Configuration
==========================================
Defines ``DecisionConfig``, an immutable dataclass that holds every
threshold and parameter used by the decision engine's rule evaluation
and risk-scoring logic.

All values are loaded from ``config.json`` under the ``decision.*``
namespace via the project's ``ConfigLoader`` singleton.  Hard-coded
defaults ensure the engine operates even when keys are absent.

Design decisions:
  - ``frozen=True`` — immutable after construction.
  - Validates that thresholds are logically ordered.
  - Reuses ``ConfigLoader`` — does NOT duplicate configuration logic.

Usage::

    from src.decision_engine.decision_config import DecisionConfig
    from src.config import config_loader

    config_loader.load()
    cfg = DecisionConfig.from_config(config_loader)
    print(cfg.risk_block_threshold)   # 70
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from src.exceptions import ConfigurationError

if TYPE_CHECKING:
    from src.config import ConfigLoader


# ---------------------------------------------------------------------------
# DecisionConfig Dataclass
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class DecisionConfig:
    """
    Immutable configuration for the physics-aware decision engine.

    Risk Thresholds
    -----------------------------------------------------------------------
    Attributes:
        risk_alert_threshold:  Risk score ≥ this value triggers ALERT (default 40).
        risk_block_threshold:  Risk score ≥ this value triggers BLOCK (default 70).

    Physics Warning Fractions (fraction of the physics config max)
    -----------------------------------------------------------------------
    Attributes:
        pressure_warning_fraction:  Fraction of pressure_max_bar that triggers
                                    a warning-level rule (default 0.80 = 80%).
        pressure_critical_fraction: Fraction of pressure_max_bar that triggers
                                    a critical-level rule (default 0.95 = 95%).
        flow_warning_fraction:      Fraction of flow_max_lps that triggers
                                    a warning-level rule (default 0.80).
        temp_warning_fraction:      Fraction of temp_max_celsius that triggers
                                    a warning-level rule (default 0.85).

    Modbus Write Limits
    -----------------------------------------------------------------------
    Attributes:
        max_registers_per_write:    Maximum quantity of registers a single
                                    Write Multiple Registers command may write
                                    before being flagged (default 125).
        suspicious_register_min:    Low end of the ``suspicious register`` range
                                    (inclusive, default 0).
        suspicious_register_max:    High end of the ``suspicious register`` range
                                    (inclusive, default 9999).
    """

    # Risk score thresholds
    risk_alert_threshold: int   = 40
    risk_block_threshold: int   = 70

    # Physics fraction thresholds
    pressure_warning_fraction:  float = 0.80
    pressure_critical_fraction: float = 0.95
    flow_warning_fraction:      float = 0.80
    temp_warning_fraction:      float = 0.85

    # Modbus write limits
    max_registers_per_write: int = 125
    suspicious_register_min: int = 0
    suspicious_register_max: int = 9999

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_config(cls, config_loader: "ConfigLoader") -> "DecisionConfig":
        """
        Construct a ``DecisionConfig`` from the loaded ``ConfigLoader``.

        Reads all values from the ``decision.*`` namespace in config.json.
        Missing keys fall back to the field defaults defined above.

        Args:
            config_loader: A fully loaded ``ConfigLoader`` instance.

        Returns:
            A populated, frozen ``DecisionConfig``.

        Raises:
            ConfigurationError: If any value fails logical consistency checks.
        """
        def _i(key: str, default: int) -> int:
            return config_loader.get_int(f"decision.{key}", default)

        def _f(key: str, default: float) -> float:
            return config_loader.get_float(f"decision.{key}", default)

        cfg = cls(
            risk_alert_threshold        = _i("risk_alert_threshold",        40),
            risk_block_threshold        = _i("risk_block_threshold",        70),
            pressure_warning_fraction   = _f("pressure_warning_fraction",   0.80),
            pressure_critical_fraction  = _f("pressure_critical_fraction",  0.95),
            flow_warning_fraction       = _f("flow_warning_fraction",       0.80),
            temp_warning_fraction       = _f("temp_warning_fraction",       0.85),
            max_registers_per_write     = _i("max_registers_per_write",     125),
            suspicious_register_min     = _i("suspicious_register_min",     0),
            suspicious_register_max     = _i("suspicious_register_max",     9999),
        )
        cfg._validate()
        return cfg

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def _validate(self) -> None:
        """
        Verify that all configuration values are logically consistent.

        Raises:
            ConfigurationError: On any constraint violation.
        """
        errors: list[str] = []

        if not (0 < self.risk_alert_threshold < self.risk_block_threshold <= 100):
            errors.append(
                f"risk thresholds must satisfy: 0 < alert ({self.risk_alert_threshold}) "
                f"< block ({self.risk_block_threshold}) ≤ 100"
            )
        for fname, fval in [
            ("pressure_warning_fraction",  self.pressure_warning_fraction),
            ("pressure_critical_fraction", self.pressure_critical_fraction),
            ("flow_warning_fraction",      self.flow_warning_fraction),
            ("temp_warning_fraction",      self.temp_warning_fraction),
        ]:
            if not (0.0 < fval <= 1.0):
                errors.append(f"{fname} must be in (0, 1]; got {fval}")

        if self.pressure_warning_fraction >= self.pressure_critical_fraction:
            errors.append(
                f"pressure_warning_fraction ({self.pressure_warning_fraction}) "
                f"must be < pressure_critical_fraction ({self.pressure_critical_fraction})"
            )
        if self.max_registers_per_write < 1:
            errors.append(
                f"max_registers_per_write must be ≥ 1; got {self.max_registers_per_write}"
            )
        if self.suspicious_register_min > self.suspicious_register_max:
            errors.append(
                f"suspicious_register_min ({self.suspicious_register_min}) "
                f"must be ≤ suspicious_register_max ({self.suspicious_register_max})"
            )

        if errors:
            raise ConfigurationError(
                "Decision configuration is invalid:\n"
                + "\n".join(f"  • {e}" for e in errors),
                detail="source=decision_config",
            )

    # ------------------------------------------------------------------
    # Representation
    # ------------------------------------------------------------------

    def __str__(self) -> str:
        return (
            f"DecisionConfig("
            f"alert≥{self.risk_alert_threshold}, "
            f"block≥{self.risk_block_threshold}, "
            f"P_warn={self.pressure_warning_fraction:.0%}, "
            f"P_crit={self.pressure_critical_fraction:.0%})"
        )
