"""
VoltGuard — Firewall Policy Engine (Day 6)
===========================================
Implements ``PolicyEngine``, the policy evaluation layer that sits
**between** the Day 4 Decision Engine and the Enforcement Adapter.

Responsibilities:
  - Accept a ``SecurityDecisionResult`` (from Day 4) and packet metadata.
  - Match the result against loaded ``FirewallPolicy`` objects in priority order.
  - Return an ``EnforcementResult`` explaining *exactly* which policy matched
    and why the action was chosen.

Priority evaluation:
  1. Policies are sorted ascending by ``(priority, policy_id)``.
  2. The first fully matching **enabled** policy wins.
  3. If no policy matches, the Day 4 decision is honoured as a fallback
     and clearly labelled as such in the ``EnforcementResult``.
  4. Tie-breaking by ``policy_id`` (lexicographic) is deterministic and documented.

Separation of concerns:
  - The Decision Engine (Day 4) determines **risk**.
  - The Policy Engine (Day 6) determines **action** given risk and policy.
  - These two layers are deliberately separate and independently testable.

Usage::

    from src.policy.policy_engine import PolicyEngine
    from src.policy.policy_config import PolicyConfig
    from src.config import config_loader

    config_loader.load()
    policy_cfg = PolicyConfig.from_config(config_loader)
    engine = PolicyEngine(policy_cfg)

    result = engine.evaluate(decision_result, src_ip, dst_ip, src_port, dst_port, protocol)
    print(result.final_action, result.matched_policy_id, result.reason)
"""

from __future__ import annotations

import ipaddress
from datetime import datetime, timezone
from typing import Optional

from src.decision_engine.models import SecurityDecisionResult
from src.logger import get_logger
from src.policy.models import EnforcementResult, FirewallPolicy, PolicyAction
from src.policy.policy_config import PolicyConfig

_log = get_logger(__name__)


# ---------------------------------------------------------------------------
# PolicyEngine
# ---------------------------------------------------------------------------

class PolicyEngine:
    """
    Deterministic, explainable, configurable Firewall Policy Engine.

    Evaluates a ``SecurityDecisionResult`` (from Day 4) against all configured
    ``FirewallPolicy`` objects and returns an ``EnforcementResult`` that
    identifies the winning policy and the chosen action.

    Parameters
    ----------
    policy_cfg : PolicyConfig
        The loaded, validated policy configuration.
    """

    def __init__(self, policy_cfg: PolicyConfig) -> None:
        """
        Initialise the engine with a validated ``PolicyConfig``.

        Args:
            policy_cfg: Validated ``PolicyConfig`` from ``PolicyConfig.from_config()``.
        """
        self._cfg = policy_cfg
        _log.info(
            "PolicyEngine initialised. Policies loaded: %d (%d enabled). "
            "Fail-safe: %s.",
            len(self._cfg.policies),
            len(self._cfg.enabled_policies),
            self._cfg.fail_safe_action.value,
        )

    # ------------------------------------------------------------------
    # Primary API
    # ------------------------------------------------------------------

    def evaluate(
        self,
        decision_result: SecurityDecisionResult,
        src_port: int = 0,
        dst_port: int = 0,
        protocol: str = "",
    ) -> EnforcementResult:
        """
        Evaluate a Day 4 ``SecurityDecisionResult`` against all policies.

        Match criteria are extracted from ``decision_result`` (IP addresses,
        function codes, risk) plus the optional port/protocol fields passed
        from the pipeline.

        **Policy matching algorithm**:
        1. Iterate over enabled policies sorted by ``(priority, policy_id)``.
        2. For each policy, check every non-None match criterion.
        3. First policy where all criteria match → return its action.
        4. If no policy matches → honour Day 4's own decision as fallback
           (logged as WARNING so the operator knows to add a policy).

        Args:
            decision_result: ``SecurityDecisionResult`` from
                             ``PhysicsAwareDecisionEngine.evaluate_full_packet()``.
            src_port:        Source TCP/UDP port (from the pipeline).
            dst_port:        Destination TCP/UDP port (from the pipeline).
            protocol:        Protocol label string (from ``PipelineEvent``).

        Returns:
            An ``EnforcementResult`` with the final action and full provenance.
        """
        timestamp = _utc_now()
        enabled = self._cfg.enabled_policies

        # Evaluate each policy in priority order
        for policy in enabled:
            if self._matches(policy, decision_result, src_port, dst_port, protocol):
                reason = self._build_reason(policy, decision_result)
                _log.debug(
                    "PolicyEngine: matched policy=%r priority=%d action=%s",
                    policy.policy_id, policy.priority, policy.action.value,
                )
                return EnforcementResult(
                    final_action          = policy.action,
                    matched_policy_id     = policy.policy_id,
                    matched_policy_name   = policy.name,
                    priority              = policy.priority,
                    reason                = reason,
                    original_risk_score   = decision_result.risk_score,
                    original_risk_level   = decision_result.severity.value,
                    original_decision     = decision_result.decision.value,
                    timestamp             = timestamp,
                    src_ip                = decision_result.src_ip,
                    dst_ip                = decision_result.dst_ip,
                    function_code         = decision_result.function_code,
                    function_name         = decision_result.function_name,
                    all_policies_checked  = len(enabled),
                )

        # ── No policy matched — fall back to Day 4 decision ──────────────
        return self._fallback(decision_result, len(enabled), timestamp)

    # ------------------------------------------------------------------
    # Policy matching logic
    # ------------------------------------------------------------------

    def _matches(
        self,
        policy: FirewallPolicy,
        result: SecurityDecisionResult,
        src_port: int,
        dst_port: int,
        protocol: str,
    ) -> bool:
        """
        Check whether a single policy matches the given packet context.

        All specified criteria (non-None fields) must match — logical AND.
        Unset (None) fields are wildcards.

        Args:
            policy:   Policy to test.
            result:   Day 4 decision result carrying IP, FC, risk data.
            src_port: Source port from the pipeline.
            dst_port: Destination port from the pipeline.
            protocol: Protocol label string.

        Returns:
            True if ALL criteria match; False otherwise.
        """
        # ── Source IP ──────────────────────────────────────────────────
        if policy.src_ip is not None:
            if not _ip_matches(result.src_ip, policy.src_ip):
                return False

        # ── Destination IP ─────────────────────────────────────────────
        if policy.dst_ip is not None:
            if not _ip_matches(result.dst_ip, policy.dst_ip):
                return False

        # ── Source port ────────────────────────────────────────────────
        if policy.src_port is not None:
            if src_port != policy.src_port:
                return False

        # ── Destination port ───────────────────────────────────────────
        if policy.dst_port is not None:
            if dst_port != policy.dst_port:
                return False

        # ── Protocol ───────────────────────────────────────────────────
        if policy.protocol is not None:
            if protocol.lower() != policy.protocol.lower():
                return False

        # ── Modbus function (single) ───────────────────────────────────
        if policy.modbus_function is not None:
            if result.function_code != policy.modbus_function:
                return False

        # ── Modbus function (list — OR logic) ─────────────────────────
        if policy.modbus_functions:
            if result.function_code not in policy.modbus_functions:
                return False

        # ── Risk score minimum ─────────────────────────────────────────
        if policy.risk_min is not None:
            if result.risk_score < policy.risk_min:
                return False

        # ── Risk score maximum ─────────────────────────────────────────
        if policy.risk_max is not None:
            if result.risk_score > policy.risk_max:
                return False

        # ── Risk level (single exact match) ───────────────────────────
        if policy.risk_level is not None:
            if result.severity.value != policy.risk_level.upper():
                return False

        # ── Risk levels (list — OR logic) ─────────────────────────────
        if policy.risk_levels:
            if result.severity.value not in [r.upper() for r in policy.risk_levels]:
                return False

        # ── Day 4 decision ─────────────────────────────────────────────
        if policy.decision is not None:
            if result.decision.value != policy.decision.upper():
                return False

        return True

    # ------------------------------------------------------------------
    # Reason builder
    # ------------------------------------------------------------------

    @staticmethod
    def _build_reason(
        policy: FirewallPolicy,
        result: SecurityDecisionResult,
    ) -> str:
        """
        Generate a human-readable explanation of why this policy was selected.

        Args:
            policy: The winning policy.
            result: The Day 4 decision result.

        Returns:
            Multi-sentence explanation string.
        """
        lines = [
            f"Policy '{policy.name}' (ID: {policy.policy_id}, "
            f"priority {policy.priority}) matched.",
        ]
        if policy.description:
            lines.append(policy.description)
        lines.append(
            f"Day 4 risk score: {result.risk_score} "
            f"(severity: {result.severity.value}, "
            f"Day 4 recommendation: {result.decision.value})."
        )
        lines.append(f"Enforcement action: {policy.action.value}.")
        return " ".join(lines)

    # ------------------------------------------------------------------
    # Fallback
    # ------------------------------------------------------------------

    def _fallback(
        self,
        result: SecurityDecisionResult,
        policies_checked: int,
        timestamp: str,
    ) -> EnforcementResult:
        """
        Build a fallback ``EnforcementResult`` when no policy matched.

        The fallback honours the Day 4 Decision Engine's own verdict.
        This is logged as a WARNING so operators know they should add
        a matching policy to their configuration.

        Args:
            result:           The Day 4 decision result.
            policies_checked: Number of enabled policies that were evaluated.
            timestamp:        ISO-8601 UTC timestamp.

        Returns:
            ``EnforcementResult`` using Day 4's decision as the action.
        """
        # Map Day 4 DecisionType → PolicyAction (they are parallel enums)
        fallback_map = {"ALLOW": PolicyAction.ALLOW,
                        "ALERT": PolicyAction.ALERT,
                        "BLOCK": PolicyAction.BLOCK}
        fallback_action = fallback_map.get(result.decision.value, PolicyAction.BLOCK)

        reason = (
            f"No configured policy matched this packet "
            f"({policies_checked} policies evaluated). "
            f"Falling back to Day 4 Decision Engine recommendation: "
            f"{result.decision.value} (risk={result.risk_score}, "
            f"severity={result.severity.value})."
        )

        _log.warning(
            "PolicyEngine: no policy matched — falling back to Day 4 decision=%s "
            "risk=%d src=%s dst=%s FC=%s. "
            "Consider adding a policy to cover this traffic pattern.",
            result.decision.value, result.risk_score,
            result.src_ip, result.dst_ip, result.function_name or "N/A",
        )

        return EnforcementResult(
            final_action          = fallback_action,
            matched_policy_id     = None,
            matched_policy_name   = None,
            priority              = None,
            reason                = reason,
            original_risk_score   = result.risk_score,
            original_risk_level   = result.severity.value,
            original_decision     = result.decision.value,
            timestamp             = timestamp,
            src_ip                = result.src_ip,
            dst_ip                = result.dst_ip,
            function_code         = result.function_code,
            function_name         = result.function_name,
            all_policies_checked  = policies_checked,
        )

    # ------------------------------------------------------------------
    # Representation
    # ------------------------------------------------------------------

    def reload(self, policy_cfg: PolicyConfig) -> None:
        """
        Hot-reload the policy configuration without restarting the engine.

        Args:
            policy_cfg: New validated ``PolicyConfig``.
        """
        self._cfg = policy_cfg
        _log.info(
            "PolicyEngine: reloaded %d policies (%d enabled).",
            len(policy_cfg.policies), len(policy_cfg.enabled_policies),
        )

    @property
    def policy_count(self) -> int:
        """Total number of configured policies (enabled + disabled)."""
        return len(self._cfg.policies)

    @property
    def enabled_policy_count(self) -> int:
        """Number of enabled policies."""
        return len(self._cfg.enabled_policies)

    def __repr__(self) -> str:
        return (
            f"<PolicyEngine policies={self.policy_count} "
            f"enabled={self.enabled_policy_count}>"
        )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _ip_matches(packet_ip: str, policy_ip: str) -> bool:
    """
    Check if ``packet_ip`` matches the ``policy_ip`` criterion.

    Supports:
      - Exact IP match: ``"192.168.1.100"``
      - CIDR network:   ``"192.168.1.0/24"``
      - Wildcard:       ``"*"`` or ``""`` (always matches)

    Args:
        packet_ip: The IP address from the packet (dotted-decimal string).
        policy_ip: The IP pattern from the policy.

    Returns:
        True if the packet IP satisfies the policy criterion.
    """
    if not policy_ip or policy_ip == "*":
        return True
    try:
        if "/" in policy_ip:
            network = ipaddress.ip_network(policy_ip, strict=False)
            return ipaddress.ip_address(packet_ip) in network
        return packet_ip == policy_ip
    except ValueError:
        # Malformed IP in policy — log and treat as no-match
        _log.warning("PolicyEngine: malformed IP criterion %r — treating as no-match.", policy_ip)
        return False


def _utc_now() -> str:
    """Return the current UTC time as an ISO-8601 string."""
    return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
