"""
VoltGuard — Custom Exception Hierarchy
========================================
Defines all domain-specific exceptions used throughout VoltGuard.

Design:
  - Every exception derives from ``VoltGuardError`` so callers can catch
    the entire family with a single ``except VoltGuardError`` clause.
  - Each sub-exception maps to exactly one module boundary, making it
    immediately clear which layer raised an error.
  - All exceptions accept an optional ``detail`` string for machine-readable
    context (useful for logging and alert generation).

Usage:
    from src.exceptions import ConfigurationError, ParserError

    raise ConfigurationError(
        "Missing required key 'log_level' in config.json",
        detail="key=log_level",
    )
"""

from __future__ import annotations

from typing import Optional


# ---------------------------------------------------------------------------
# Base Exception
# ---------------------------------------------------------------------------

class VoltGuardError(Exception):
    """
    Root exception for all VoltGuard domain errors.

    All custom exceptions inherit from this class so that callers can
    choose to catch the entire VoltGuard error family or be specific.

    Attributes:
        message: Human-readable error description.
        detail:  Optional machine-readable context string (key=value pairs,
                 file paths, etc.) for log enrichment.
    """

    def __init__(self, message: str, detail: Optional[str] = None) -> None:
        super().__init__(message)
        self.message: str = message
        self.detail: Optional[str] = detail

    def __str__(self) -> str:
        if self.detail:
            return f"{self.message} | detail: {self.detail}"
        return self.message

    def __repr__(self) -> str:
        return (
            f"{self.__class__.__name__}("
            f"message={self.message!r}, detail={self.detail!r})"
        )


# ---------------------------------------------------------------------------
# Configuration Layer
# ---------------------------------------------------------------------------

class ConfigurationError(VoltGuardError):
    """
    Raised when the configuration system encounters an unrecoverable error.

    Examples:
      - Required key missing from config.json.
      - Value type mismatch (expected int, got string).
      - config.json is malformed JSON.
      - File permission error prevents reading the config file.
    """


# ---------------------------------------------------------------------------
# Parser Layer (src/parser/)
# ---------------------------------------------------------------------------

class ParserError(VoltGuardError):
    """
    Raised when the packet parser cannot process a network packet.

    Examples:
      - Malformed Modbus TCP frame.
      - Unsupported function code.
      - Packet too short to be a valid industrial protocol frame.
      - Checksum / CRC validation failure.
    """


class UnsupportedProtocolError(ParserError):
    """
    Raised when a packet uses a protocol the parser does not handle.

    This is a sub-class of ``ParserError`` so callers that catch ``ParserError``
    will also catch this without changes.
    """


# ---------------------------------------------------------------------------
# Physics Engine Layer (src/physics/)
# ---------------------------------------------------------------------------

class PhysicsError(VoltGuardError):
    """
    Raised when the physics simulation encounters an unrecoverable state.

    Examples:
      - Simulation state diverges (NaN / Inf values).
      - Required process variable is outside the configured safe range.
      - Physics model is missing required initial conditions.
    """


class SafetyConstraintViolation(PhysicsError):
    """
    Raised specifically when a predicted physical state violates a
    configured safety limit (e.g. pressure exceeds max bar).

    The ``detail`` field should contain the variable name and values:
        "variable=pressure actual=12.4 limit=10.0 unit=bar"
    """


# ---------------------------------------------------------------------------
# Decision Engine Layer (src/decision_engine/)
# ---------------------------------------------------------------------------

class DecisionEngineError(VoltGuardError):
    """
    Raised when the decision engine cannot evaluate a packet or rule.

    Examples:
      - Rule set is empty or corrupt.
      - Packet context is incomplete for evaluation.
      - Engine is called before physics simulation has run.
    """


class RuleViolationError(DecisionEngineError):
    """
    Raised when a packet explicitly violates a configured firewall rule.
    The ``detail`` field should identify the rule that triggered.
    """


# ---------------------------------------------------------------------------
# Dashboard / UI Layer (src/dashboard/)
# ---------------------------------------------------------------------------

class DashboardError(VoltGuardError):
    """
    Raised when the dashboard or UI layer encounters an error that
    cannot be handled gracefully within the view.

    Examples:
      - Chart rendering failure.
      - Export to PDF/CSV fails due to a permissions issue.
      - Required data is missing when a widget tries to render.
    """


# ---------------------------------------------------------------------------
# Health Check Layer (src/healthcheck.py)
# ---------------------------------------------------------------------------

class HealthCheckError(VoltGuardError):
    """
    Raised when a health check detects a critical system fault that
    prevents the application from starting safely.

    Examples:
      - Logs directory is not writable.
      - Reports directory does not exist and cannot be created.
    """
