"""
VoltGuard — Policy Configuration (Day 6)
==========================================
Defines ``PolicyConfig``, which loads the ``policies`` array from
``config.json`` (via the existing ``ConfigLoader`` singleton) and
validates each policy at startup.

Design decisions:
  - Reuses the existing ``config_loader`` — does NOT duplicate the config system.
  - All policies are loaded as ``FirewallPolicy`` instances.
  - Invalid policies produce clear ``ConfigurationError`` with the offending
    ``policy_id`` so operators can fix config issues without reading source code.
  - An empty ``policies`` array is allowed (logged as a warning); the engine
    will fall back to Day 4 decisions in that case.

Usage::

    from src.policy.policy_config import PolicyConfig
    from src.config import config_loader

    config_loader.load()
    policy_cfg = PolicyConfig.from_config(config_loader)
    print(len(policy_cfg.policies), "policies loaded")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from src.exceptions import ConfigurationError
from src.policy.models import FirewallPolicy, PolicyAction

if TYPE_CHECKING:
    from src.config import ConfigLoader

_log = logging.getLogger("VoltGuard.policy.policy_config")


# ---------------------------------------------------------------------------
# Default policies — applied when config.json has no "policies" key
# ---------------------------------------------------------------------------

_DEFAULT_POLICIES: list[dict[str, Any]] = [
    {
        "policy_id":   "POL-001",
        "name":        "Allow Modbus Read Operations",
        "description": "Permit legitimate Modbus read commands (FC 0x01, 0x03) to port 502 when risk is low.",
        "enabled":     True,
        "priority":    10,
        "action":      "ALLOW",
        "dst_port":    502,
        "modbus_functions": [1, 3],
        "risk_max":    39,
    },
    {
        "policy_id":   "POL-002",
        "name":        "Allow Safe Single-Register Writes",
        "description": "Permit Write Single Register (FC 0x06) commands when risk score is low.",
        "enabled":     True,
        "priority":    20,
        "action":      "ALLOW",
        "dst_port":    502,
        "modbus_function": 6,
        "risk_max":    39,
    },
    {
        "policy_id":   "POL-003",
        "name":        "Allow Safe Single-Coil Writes",
        "description": "Permit Write Single Coil (FC 0x05) commands when risk score is low.",
        "enabled":     True,
        "priority":    25,
        "action":      "ALLOW",
        "dst_port":    502,
        "modbus_function": 5,
        "risk_max":    39,
    },
    {
        "policy_id":   "POL-004",
        "name":        "Alert on Write Multiple Registers",
        "description": "Generate an alert for Write Multiple Registers (FC 0x10) — may affect multiple process variables simultaneously.",
        "enabled":     True,
        "priority":    30,
        "action":      "ALERT",
        "dst_port":    502,
        "modbus_function": 16,
        "risk_min":    40,
    },
    {
        "policy_id":   "POL-005",
        "name":        "Alert on Medium Risk Traffic",
        "description": "Alert on any traffic with MEDIUM or HIGH risk level that has not been matched by a more specific policy.",
        "enabled":     True,
        "priority":    40,
        "action":      "ALERT",
        "risk_levels": ["MEDIUM", "HIGH"],
    },
    {
        "policy_id":   "POL-006",
        "name":        "Block Critical Safety Violations",
        "description": "Block any command that triggers a CRITICAL risk level — indicates a physical safety limit violation.",
        "enabled":     True,
        "priority":    50,
        "action":      "BLOCK",
        "risk_levels": ["CRITICAL"],
    },
    {
        "policy_id":   "POL-007",
        "name":        "Block High-Score Unmatched Traffic",
        "description": "Block traffic with risk score ≥ 70 that has not been matched by a more specific policy.",
        "enabled":     True,
        "priority":    60,
        "action":      "BLOCK",
        "risk_min":    70,
    },
    {
        "policy_id":   "POL-DEFAULT",
        "name":        "Default Allow Low Risk",
        "description": "Permit any traffic with risk score below the alert threshold — catch-all safe traffic pass-through.",
        "enabled":     True,
        "priority":    100,
        "action":      "ALLOW",
        "risk_max":    39,
    },
    {
        "policy_id":   "POL-FALLBACK",
        "name":        "Fallback Block Unknown High Risk",
        "description": "Final safety net — block anything not matched by a higher-priority policy with an elevated risk score.",
        "enabled":     True,
        "priority":    200,
        "action":      "BLOCK",
        "risk_min":    40,
    },
]


# ---------------------------------------------------------------------------
# PolicyConfig Dataclass
# ---------------------------------------------------------------------------

@dataclass
class PolicyConfig:
    """
    Validated collection of ``FirewallPolicy`` objects loaded from config.

    Produced by ``PolicyConfig.from_config(config_loader)`` and consumed
    by ``PolicyEngine``.

    Attributes:
        policies:         List of validated ``FirewallPolicy`` instances,
                          sorted ascending by (priority, policy_id).
        fail_safe_action: Action to use if no policy matches AND no fallback
                          policy exists.  Defaults to ``PolicyAction.BLOCK``
                          (fail-safe).
    """
    policies: list[FirewallPolicy] = field(default_factory=list)
    fail_safe_action: PolicyAction = PolicyAction.BLOCK

    # ------------------------------------------------------------------
    # Factory
    # ------------------------------------------------------------------

    @classmethod
    def from_config(cls, config_loader: "ConfigLoader") -> "PolicyConfig":
        """
        Load and validate all policies from ``config.json``.

        Reads the ``policies`` key (list of policy dictionaries).
        If the key is absent, the built-in defaults are used.
        Each policy dict is validated; any error raises ``ConfigurationError``
        with the offending ``policy_id`` clearly identified.

        Args:
            config_loader: A fully loaded ``ConfigLoader`` instance.

        Returns:
            A ``PolicyConfig`` with all policies sorted by priority.

        Raises:
            ConfigurationError: If any policy dict is invalid.
        """
        raw_policies: Any = config_loader.get("policies", None)

        if raw_policies is None:
            _log.warning(
                "PolicyConfig: 'policies' key not found in config.json — "
                "using built-in defaults."
            )
            raw_policies = _DEFAULT_POLICIES

        if not isinstance(raw_policies, list):
            raise ConfigurationError(
                "PolicyConfig: 'policies' in config.json must be a JSON array.",
                detail=f"got type={type(raw_policies).__name__}",
            )

        if len(raw_policies) == 0:
            _log.warning(
                "PolicyConfig: 'policies' array is empty — the policy engine "
                "will fall back to the Day 4 decision engine verdict for all packets."
            )

        policies: list[FirewallPolicy] = []
        errors: list[str] = []

        for i, raw in enumerate(raw_policies):
            if not isinstance(raw, dict):
                errors.append(f"  • policies[{i}]: expected a JSON object, got {type(raw).__name__!r}")
                continue
            try:
                policy = FirewallPolicy.from_dict(raw)
                policies.append(policy)
            except ValueError as exc:
                errors.append(f"  • policies[{i}]: {exc}")

        if errors:
            raise ConfigurationError(
                "Policy configuration contains invalid entries:\n" + "\n".join(errors),
                detail="source=config.json key=policies",
            )

        # Sort ascending by (priority, policy_id) for deterministic evaluation
        policies.sort(key=lambda p: (p.priority, p.policy_id))

        _log.info(
            "PolicyConfig: loaded %d policies (%d enabled).",
            len(policies),
            sum(1 for p in policies if p.enabled),
        )
        for p in policies:
            _log.debug(
                "  [%3d] %s — %s — %s",
                p.priority, p.policy_id, p.name, p.action.value,
            )

        # Load fail_safe_action from config (default BLOCK)
        fail_safe_raw = str(config_loader.get("policy_fail_safe", "BLOCK")).upper()
        try:
            fail_safe = PolicyAction(fail_safe_raw)
        except ValueError:
            _log.warning(
                "PolicyConfig: invalid policy_fail_safe=%r; defaulting to BLOCK.",
                fail_safe_raw,
            )
            fail_safe = PolicyAction.BLOCK

        return cls(policies=policies, fail_safe_action=fail_safe)

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @property
    def enabled_policies(self) -> list[FirewallPolicy]:
        """Return only enabled policies, sorted by (priority, policy_id)."""
        return [p for p in self.policies if p.enabled]

    def get_policy(self, policy_id: str) -> "FirewallPolicy | None":
        """Return the policy with the given ID, or None if not found."""
        for p in self.policies:
            if p.policy_id == policy_id:
                return p
        return None

    def __repr__(self) -> str:
        return (
            f"<PolicyConfig total={len(self.policies)} "
            f"enabled={len(self.enabled_policies)} "
            f"fail_safe={self.fail_safe_action.value}>"
        )
