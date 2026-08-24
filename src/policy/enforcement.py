"""
VoltGuard — Enforcement Adapter Layer (Day 6)
==============================================
Defines the enforcement abstraction and the simulation-safe concrete
implementation used in Day 6.

Architecture:
  ``EnforcementAdapter`` (ABC)
        ↑
  ``SimulationEnforcementAdapter`` (concrete — safe, no OS changes)

Design constraints:
  - ``SimulationEnforcementAdapter`` NEVER executes OS-level commands.
  - It does NOT call ``iptables``, ``pfctl``, ``nftables``, ``subprocess``,
    or any route/interface manipulation commands.
  - ALLOW → log INFO  + mark result allowed.
  - ALERT → log WARN  + mark result allowed + generate audit entry.
  - BLOCK → log ERROR + mark result blocked.  Packet goes no further
    through the simulated pipeline.
  - The ABC makes it straightforward to add a ``RealFirewallAdapter`` in
    the future without changing the rest of the pipeline.

Audit logging:
  - Every enforcement decision is logged via the existing rotating logger.
  - Structured audit entries contain all fields required for a security audit.

Usage::

    from src.policy.enforcement import SimulationEnforcementAdapter
    from src.policy.models import EnforcementResult

    adapter = SimulationEnforcementAdapter()
    adapter.enforce(enforcement_result)
    print(adapter.stats)
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Optional

from src.logger import get_logger
from src.policy.models import EnforcementResult, PolicyAction

_log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Enforcement Statistics
# ---------------------------------------------------------------------------

@dataclass
class EnforcementStats:
    """
    Running counters maintained by the ``SimulationEnforcementAdapter``.

    Attributes:
        allowed:  Total packets marked ALLOW.
        alerted:  Total packets marked ALERT (allowed with alert generated).
        blocked:  Total packets marked BLOCK.
    """
    allowed: int = 0
    alerted: int = 0
    blocked: int = 0

    @property
    def total(self) -> int:
        """Total enforcement decisions made."""
        return self.allowed + self.alerted + self.blocked

    def to_dict(self) -> dict:
        """Serialise to plain dict."""
        return {
            "allowed": self.allowed,
            "alerted": self.alerted,
            "blocked": self.blocked,
            "total":   self.total,
        }


# ---------------------------------------------------------------------------
# EnforcementAdapter — Abstract Base Class
# ---------------------------------------------------------------------------

class EnforcementAdapter(ABC):
    """
    Abstract base class for all VoltGuard enforcement adapters.

    Implementations must handle the three possible enforcement actions
    without duplicating policy logic — actions are determined by the
    ``PolicyEngine`` and simply *executed* by the adapter.

    This abstraction means a real firewall adapter (e.g. ``PfctlAdapter``)
    can be added in the future without touching the pipeline or policy engine.
    """

    @abstractmethod
    def enforce(self, result: EnforcementResult) -> None:
        """
        Execute the enforcement action specified in ``result``.

        Args:
            result: The ``EnforcementResult`` produced by the ``PolicyEngine``.
        """

    @abstractmethod
    def allow(self, result: EnforcementResult) -> None:
        """Mark the packet as allowed and log accordingly."""

    @abstractmethod
    def alert(self, result: EnforcementResult) -> None:
        """Mark the packet as allowed but generate a security alert."""

    @abstractmethod
    def block(self, result: EnforcementResult) -> None:
        """Mark the packet as blocked and stop further processing."""

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__}>"


# ---------------------------------------------------------------------------
# SimulationEnforcementAdapter — Safe Concrete Implementation
# ---------------------------------------------------------------------------

class SimulationEnforcementAdapter(EnforcementAdapter):
    """
    A simulation-safe enforcement adapter that never modifies the host firewall.

    Behaviour by action:
      - **ALLOW**: Logs an INFO-level message.  Packet continues normally.
      - **ALERT**: Logs a WARNING-level message.  Packet continues normally
                   (allowed but flagged) and a structured alert entry is logged.
      - **BLOCK**: Logs an ERROR-level message.  Packet is conceptually dropped
                   and should not continue through the pipeline.

    **Safety guarantee**: This class never calls ``subprocess``, ``os.system``,
    or any OS-level command.  It is safe to run in a test environment, CI,
    or on a production host without risk of modifying real firewall rules.

    The future ``RealFirewallAdapter`` would subclass ``EnforcementAdapter``
    independently and could use ``subprocess`` under explicit operator consent.
    """

    # Sentinel used to verify in tests that no OS commands are ever called.
    SAFE_MODE: bool = True
    """Always True — guards against accidental OS-level enforcement."""

    def __init__(self) -> None:
        self._stats = EnforcementStats()

    # ------------------------------------------------------------------
    # Primary API
    # ------------------------------------------------------------------

    def enforce(self, result: EnforcementResult) -> None:
        """
        Dispatch to the appropriate handler based on ``result.final_action``.

        Args:
            result: ``EnforcementResult`` from the ``PolicyEngine``.
        """
        if result.final_action == PolicyAction.ALLOW:
            self.allow(result)
        elif result.final_action == PolicyAction.ALERT:
            self.alert(result)
        elif result.final_action == PolicyAction.BLOCK:
            self.block(result)
        else:
            # Should never happen — defensive fallback
            _log.error(
                "SimulationEnforcementAdapter: unknown action %r — defaulting to BLOCK.",
                result.final_action,
            )
            self.block(result)

    # ------------------------------------------------------------------
    # Action handlers
    # ------------------------------------------------------------------

    def allow(self, result: EnforcementResult) -> None:
        """
        Mark the packet as allowed.

        Logs a structured INFO entry.  No OS-level command is executed.

        Args:
            result: The enforcement result to act upon.
        """
        self._stats.allowed += 1
        _log.info(
            "[ENFORCEMENT] ALLOW | %s→%s | FC=%s | "
            "risk=%d (%s) | policy=%s | %s",
            result.src_ip,
            result.dst_ip,
            result.function_name or "N/A",
            result.original_risk_score,
            result.original_risk_level,
            result.matched_policy_id or "fallback",
            result.matched_policy_name or "no policy",
        )
        self._audit_log(result)

    def alert(self, result: EnforcementResult) -> None:
        """
        Mark the packet as allowed but generate a security alert.

        Logs a structured WARNING entry with full audit context.
        The packet is *not* blocked — it continues through the pipeline.

        Args:
            result: The enforcement result to act upon.
        """
        self._stats.alerted += 1
        _log.warning(
            "[ENFORCEMENT] ALERT | %s→%s | FC=%s | "
            "risk=%d (%s) | policy=%s | %s",
            result.src_ip,
            result.dst_ip,
            result.function_name or "N/A",
            result.original_risk_score,
            result.original_risk_level,
            result.matched_policy_id or "fallback",
            result.matched_policy_name or "no policy",
        )
        _log.warning(
            "[SECURITY ALERT] Reason: %s",
            result.reason,
        )
        self._audit_log(result)

    def block(self, result: EnforcementResult) -> None:
        """
        Mark the packet as blocked.

        Logs a structured ERROR entry.  The packet must not continue through
        the simulated pipeline after this call returns.

        **This method NEVER executes OS-level firewall commands.**
        The block is enforced only within the simulated pipeline.

        Args:
            result: The enforcement result to act upon.
        """
        self._stats.blocked += 1
        _log.error(
            "[ENFORCEMENT] BLOCK | %s→%s | FC=%s | "
            "risk=%d (%s) | policy=%s | %s",
            result.src_ip,
            result.dst_ip,
            result.function_name or "N/A",
            result.original_risk_score,
            result.original_risk_level,
            result.matched_policy_id or "fallback",
            result.matched_policy_name or "no policy",
        )
        _log.error(
            "[BLOCK REASON] %s",
            result.reason,
        )
        self._audit_log(result)

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    @property
    def stats(self) -> EnforcementStats:
        """Live enforcement statistics snapshot."""
        return self._stats

    def reset_stats(self) -> None:
        """Reset all enforcement counters to zero."""
        self._stats = EnforcementStats()

    # ------------------------------------------------------------------
    # Audit logging
    # ------------------------------------------------------------------

    def _audit_log(self, result: EnforcementResult) -> None:
        """
        Emit a DEBUG-level structured JSON audit entry for the enforcement decision.

        The audit entry contains all fields needed for a compliance audit:
        timestamp, packet info, risk, matched policy, priority, final action,
        and the human-readable reason.

        Args:
            result: The enforcement result to audit-log.
        """
        audit_entry = {
            "audit":              "ENFORCEMENT",
            "timestamp":          result.timestamp,
            "src_ip":             result.src_ip,
            "dst_ip":             result.dst_ip,
            "function_code":      result.function_code,
            "function_name":      result.function_name,
            "original_risk_score": result.original_risk_score,
            "original_risk_level": result.original_risk_level,
            "original_decision":  result.original_decision,
            "matched_policy_id":  result.matched_policy_id,
            "matched_policy_name": result.matched_policy_name,
            "policy_priority":    result.priority,
            "final_action":       result.final_action.value,
            "reason":             result.reason,
            "policies_checked":   result.all_policies_checked,
        }
        _log.debug(
            "[ENFORCEMENT-AUDIT] %s",
            json.dumps(audit_entry, default=str),
        )

    def __repr__(self) -> str:
        return (
            f"<SimulationEnforcementAdapter "
            f"allowed={self._stats.allowed} "
            f"alerted={self._stats.alerted} "
            f"blocked={self._stats.blocked}>"
        )
