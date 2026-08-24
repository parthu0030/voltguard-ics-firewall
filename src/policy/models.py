"""
VoltGuard — Firewall Policy Data Models (Day 6)
================================================
Defines all strongly-typed dataclasses and enumerations used by the
Day 6 Firewall Policy & Enforcement layer.

Design principles:
  - No Qt, no database dependency — safe to import from tests and the pipeline.
  - Fully type-annotated and documented.
  - Reuses ``DecisionType`` and ``SeverityLevel`` from Day 4 where appropriate.
  - Policies are data-driven (JSON config) — no rules hard-coded in Python logic.

Key types:
  - ``PolicyAction``     — ALLOW / ALERT / BLOCK (what the policy says to do)
  - ``FirewallPolicy``   — A single configurable ICS firewall policy
  - ``EnforcementResult``— Outcome of running the Policy Engine on a decision

Usage::

    from src.policy.models import (
        PolicyAction,
        FirewallPolicy,
        EnforcementResult,
    )
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional


# ---------------------------------------------------------------------------
# Policy Action Enum
# ---------------------------------------------------------------------------

class PolicyAction(str, Enum):
    """
    The three possible actions a firewall policy can prescribe.

    Values are uppercase strings so they can be stored directly in logs
    and databases without further conversion.

    Note: This is intentionally separate from ``DecisionType`` (Day 4).
    The Decision Engine determines *risk*; the Policy Engine determines *action*.
    """
    ALLOW = "ALLOW"   # Forward the packet — no further intervention.
    ALERT = "ALERT"   # Forward the packet but generate a security alert.
    BLOCK = "BLOCK"   # Drop the packet immediately.


# ---------------------------------------------------------------------------
# FirewallPolicy — A Single Configurable ICS Security Policy
# ---------------------------------------------------------------------------

@dataclass
class FirewallPolicy:
    """
    A single, fully configurable firewall policy for ICS traffic.

    Policies are loaded from ``config.json`` under the ``policies`` key
    and evaluated by the ``PolicyEngine`` in ascending ``priority`` order.

    **Match criteria** — all fields are optional (``None`` = wildcard).
    A packet matches a policy only if ALL specified criteria match.

    Attributes:
        policy_id:        Unique, stable identifier (e.g. ``"POL-001"``).
        name:             Human-readable policy name.
        description:      Explanation of what the policy enforces.
        enabled:          If ``False``, the policy is completely skipped.
        priority:         Evaluation order — lower number = higher priority.
                          Tie-break: lexicographic order of ``policy_id``.
        action:           ``PolicyAction`` to apply when the policy matches.

    Match criteria (``None`` = wildcard):
        src_ip:           Source IP or CIDR network (e.g. ``"192.168.1.0/24"``).
        dst_ip:           Destination IP or CIDR network.
        src_port:         Source TCP/UDP port (exact integer match).
        dst_port:         Destination TCP/UDP port (e.g. 502 for Modbus TCP).
        protocol:         Protocol label string (e.g. ``"Modbus TCP"``).
        modbus_function:  Modbus function code integer to match exactly.
        modbus_functions: List of Modbus function codes to match (OR logic).
        risk_min:         Minimum risk score (inclusive) to match.
        risk_max:         Maximum risk score (inclusive) to match.
        risk_level:       Exact ``SeverityLevel`` string to match (e.g. ``"CRITICAL"``).
        risk_levels:      List of ``SeverityLevel`` strings (OR logic).
        decision:         Day 4 Decision Engine recommendation to match
                          (e.g. ``"BLOCK"`` only fires this policy when D4 says BLOCK).
    """
    policy_id:         str
    name:              str
    action:            PolicyAction
    priority:          int
    description:       str = ""
    enabled:           bool = True

    # ── Match criteria — all optional (None = wildcard) ─────────────────────
    src_ip:            Optional[str]       = None
    dst_ip:            Optional[str]       = None
    src_port:          Optional[int]       = None
    dst_port:          Optional[int]       = None
    protocol:          Optional[str]       = None
    modbus_function:   Optional[int]       = None   # single FC match
    modbus_functions:  list[int]           = field(default_factory=list)  # OR list
    risk_min:          Optional[int]       = None   # risk_score >= risk_min
    risk_max:          Optional[int]       = None   # risk_score <= risk_max
    risk_level:        Optional[str]       = None   # exact SeverityLevel string
    risk_levels:       list[str]           = field(default_factory=list)  # OR list
    decision:          Optional[str]       = None   # matches Day 4 decision value

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    @property
    def is_wildcard(self) -> bool:
        """True if no match criteria are set — this policy matches everything."""
        return all(v is None or v == [] for v in [
            self.src_ip, self.dst_ip, self.src_port, self.dst_port,
            self.protocol, self.modbus_function, self.modbus_functions,
            self.risk_min, self.risk_max, self.risk_level,
            self.risk_levels, self.decision,
        ])

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "FirewallPolicy":
        """
        Construct a ``FirewallPolicy`` from a plain dictionary (e.g. parsed JSON).

        Args:
            data: Dictionary with policy fields.  Unknown keys are ignored.

        Returns:
            A populated ``FirewallPolicy``.

        Raises:
            ValueError: If required fields (``policy_id``, ``name``, ``action``,
                        ``priority``) are missing or invalid.
        """
        required = ["policy_id", "name", "action", "priority"]
        for key in required:
            if key not in data:
                raise ValueError(
                    f"FirewallPolicy: missing required field '{key}' "
                    f"in policy data: {data}"
                )

        try:
            action = PolicyAction(str(data["action"]).upper())
        except ValueError:
            raise ValueError(
                f"FirewallPolicy '{data['policy_id']}': invalid action "
                f"'{data['action']}' — must be ALLOW, ALERT, or BLOCK."
            )

        try:
            priority = int(data["priority"])
        except (ValueError, TypeError):
            raise ValueError(
                f"FirewallPolicy '{data['policy_id']}': priority must be an "
                f"integer; got {data['priority']!r}."
            )

        return cls(
            policy_id        = str(data["policy_id"]),
            name             = str(data["name"]),
            action           = action,
            priority         = priority,
            description      = str(data.get("description", "")),
            enabled          = bool(data.get("enabled", True)),
            src_ip           = data.get("src_ip"),
            dst_ip           = data.get("dst_ip"),
            src_port         = _opt_int(data.get("src_port")),
            dst_port         = _opt_int(data.get("dst_port")),
            protocol         = data.get("protocol"),
            modbus_function  = _opt_int(data.get("modbus_function")),
            modbus_functions = [int(f) for f in data.get("modbus_functions", [])],
            risk_min         = _opt_int(data.get("risk_min")),
            risk_max         = _opt_int(data.get("risk_max")),
            risk_level       = data.get("risk_level"),
            risk_levels      = [str(r) for r in data.get("risk_levels", [])],
            decision         = data.get("decision"),
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dictionary (for logging/storage)."""
        return {
            "policy_id":        self.policy_id,
            "name":             self.name,
            "action":           self.action.value,
            "priority":         self.priority,
            "description":      self.description,
            "enabled":          self.enabled,
            "src_ip":           self.src_ip,
            "dst_ip":           self.dst_ip,
            "src_port":         self.src_port,
            "dst_port":         self.dst_port,
            "protocol":         self.protocol,
            "modbus_function":  self.modbus_function,
            "modbus_functions": self.modbus_functions,
            "risk_min":         self.risk_min,
            "risk_max":         self.risk_max,
            "risk_level":       self.risk_level,
            "risk_levels":      self.risk_levels,
            "decision":         self.decision,
        }

    def __repr__(self) -> str:
        return (
            f"<FirewallPolicy id={self.policy_id!r} "
            f"priority={self.priority} action={self.action.value} "
            f"enabled={self.enabled}>"
        )


# ---------------------------------------------------------------------------
# EnforcementResult — Output of the Policy Engine
# ---------------------------------------------------------------------------

@dataclass
class EnforcementResult:
    """
    Complete output of the Policy Engine for a single evaluated packet.

    Produced by ``PolicyEngine.evaluate()`` and consumed by:
      - ``SimulationEnforcementAdapter`` (executes the action safely)
      - The pipeline (updates ``PipelineEvent``)
      - The audit logger

    Attributes:
        final_action:         The enforcement action decided by the matching policy.
        matched_policy_id:    ID of the policy that matched (None = no match → fallback).
        matched_policy_name:  Human-readable name of the matched policy.
        priority:             Priority of the matched policy.
        reason:               Explanation of why this action was selected.
        original_risk_score:  Risk score from the Day 4 Decision Engine.
        original_risk_level:  Severity string from Day 4 (SAFE/LOW/MEDIUM/HIGH/CRITICAL).
        original_decision:    Day 4's own recommendation (ALLOW/ALERT/BLOCK).
        timestamp:            ISO-8601 UTC time the enforcement decision was made.
        src_ip:               Source IP of the evaluated packet.
        dst_ip:               Destination IP of the evaluated packet.
        function_code:        Modbus function code integer (None if not Modbus).
        function_name:        Modbus function code name string.
        all_policies_checked: Total number of enabled policies evaluated.
    """
    final_action:          PolicyAction
    reason:                str
    original_risk_score:   int
    original_risk_level:   str
    original_decision:     str
    timestamp:             str
    src_ip:                str
    dst_ip:                str
    matched_policy_id:     Optional[str]  = None
    matched_policy_name:   Optional[str]  = None
    priority:              Optional[int]  = None
    function_code:         Optional[int]  = None
    function_name:         str            = ""
    all_policies_checked:  int            = 0

    # ------------------------------------------------------------------
    # Convenience properties
    # ------------------------------------------------------------------

    @property
    def is_blocked(self) -> bool:
        """True if the final action is BLOCK."""
        return self.final_action == PolicyAction.BLOCK

    @property
    def is_alerted(self) -> bool:
        """True if the final action is ALERT."""
        return self.final_action == PolicyAction.ALERT

    @property
    def is_allowed(self) -> bool:
        """True if the final action is ALLOW."""
        return self.final_action == PolicyAction.ALLOW

    @property
    def has_matched_policy(self) -> bool:
        """True if a policy was matched (as opposed to using a fallback)."""
        return self.matched_policy_id is not None

    def to_dict(self) -> dict[str, Any]:
        """Serialise to a plain dictionary for logging and storage."""
        return {
            "final_action":          self.final_action.value,
            "matched_policy_id":     self.matched_policy_id,
            "matched_policy_name":   self.matched_policy_name,
            "priority":              self.priority,
            "reason":                self.reason,
            "original_risk_score":   self.original_risk_score,
            "original_risk_level":   self.original_risk_level,
            "original_decision":     self.original_decision,
            "timestamp":             self.timestamp,
            "src_ip":                self.src_ip,
            "dst_ip":                self.dst_ip,
            "function_code":         self.function_code,
            "function_name":         self.function_name,
            "all_policies_checked":  self.all_policies_checked,
        }

    def __repr__(self) -> str:
        return (
            f"<EnforcementResult "
            f"action={self.final_action.value} "
            f"policy={self.matched_policy_id!r} "
            f"risk={self.original_risk_score}>"
        )


# ---------------------------------------------------------------------------
# Internal helper
# ---------------------------------------------------------------------------

def _opt_int(value: Any) -> Optional[int]:
    """Convert a value to int, or return None if it is None/empty."""
    if value is None:
        return None
    try:
        return int(value)
    except (ValueError, TypeError):
        return None
