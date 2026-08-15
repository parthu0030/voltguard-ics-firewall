"""
VoltGuard — Base Decision Engine Interface
===========================================
Defines the ``BaseDecisionEngine`` Abstract Base Class that the intrusion
prevention decision engine must implement.

Architecture:
  - The decision engine is the final arbiter: it receives a ``ParsedPacket``
    and a ``PhysicsState`` and decides whether to ALLOW or BLOCK the packet.
  - Rule sets are loaded at startup and evaluated in priority order.
  - Each engine implementation may use a different evaluation strategy
    (rule chain, ML model, threshold-based, …) without changing the interface.

Implementing a new engine:

    from src.interfaces.base_engine import BaseDecisionEngine, DecisionResult, FirewallRule

    class PriorityRuleEngine(BaseDecisionEngine):
        def evaluate(self, packet, physics_state) -> DecisionResult:
            ...
        def get_rules(self) -> list[FirewallRule]:
            ...
        def add_rule(self, rule) -> None:
            ...
        def clear_rules(self) -> None:
            ...
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from src.interfaces.base_parser import ParsedPacket
from src.interfaces.base_physics import PhysicsState


# ---------------------------------------------------------------------------
# Decision Action Enum
# ---------------------------------------------------------------------------

class DecisionAction(str, Enum):
    """Possible outcomes of a decision engine evaluation."""
    ALLOW = "ALLOW"    # Packet is safe — forward to the industrial device.
    BLOCK = "BLOCK"    # Packet is dangerous — drop immediately.
    ALERT = "ALERT"    # Packet is suspicious — allow but raise an alert.


# ---------------------------------------------------------------------------
# Firewall Rule DTO
# ---------------------------------------------------------------------------

@dataclass
class FirewallRule:
    """
    Represents a single firewall rule evaluated by the decision engine.

    Rules are evaluated in ascending ``priority`` order (lower number = higher
    priority).  The first matching rule wins.

    Attributes:
        rule_id:     Unique identifier string (e.g. ``"ICS-001"``).
        description: Human-readable description of what the rule guards against.
        priority:    Evaluation order — lower numbers run first.
        action:      ``DecisionAction`` to apply when the rule matches.
        enabled:     If ``False``, the rule is skipped during evaluation.
        metadata:    Additional rule attributes (source IP filters, FC codes, …).
    """
    rule_id: str
    description: str
    priority: int
    action: DecisionAction
    enabled: bool = True
    metadata: dict = field(default_factory=dict)

    def __repr__(self) -> str:
        return (
            f"<FirewallRule id={self.rule_id!r} "
            f"priority={self.priority} action={self.action.value}>"
        )


# ---------------------------------------------------------------------------
# Decision Result DTO
# ---------------------------------------------------------------------------

@dataclass
class DecisionResult:
    """
    The outcome of evaluating a single packet through the decision engine.

    Attributes:
        action:      The final allow/block/alert decision.
        risk_score:  Float in [0.0, 1.0]; 1.0 is maximum risk.
        rule_id:     ID of the rule that triggered the decision, if any.
        reason:      Human-readable explanation for the decision.
        timestamp:   ISO-8601 UTC time the decision was made.
        packet:      Reference to the parsed packet that was evaluated.
        physics_state: Reference to the physics state used for evaluation.
    """
    action: DecisionAction
    risk_score: float
    reason: str
    timestamp: str = ""
    rule_id: Optional[str] = None
    packet: Optional[ParsedPacket] = None
    physics_state: Optional[PhysicsState] = None

    @property
    def is_blocked(self) -> bool:
        """True if the decision is to block the packet."""
        return self.action == DecisionAction.BLOCK

    @property
    def is_allowed(self) -> bool:
        """True if the decision is to allow the packet."""
        return self.action == DecisionAction.ALLOW


# ---------------------------------------------------------------------------
# Abstract Base Class
# ---------------------------------------------------------------------------

class BaseDecisionEngine(ABC):
    """
    Abstract interface for all VoltGuard decision engines.

    The decision engine is responsible for combining network-layer analysis
    (``ParsedPacket``) and physics-layer analysis (``PhysicsState``) into a
    single allow/block/alert verdict.

    Implementations may use:
      - Static rule chains (simple, auditable, fast)
      - Threshold-based scoring
      - Machine-learning anomaly detection (future)
    """

    @abstractmethod
    def evaluate(
        self,
        packet: ParsedPacket,
        physics_state: Optional[PhysicsState] = None,
    ) -> DecisionResult:
        """
        Evaluate a parsed packet (and optional physics state) and return a verdict.

        Args:
            packet:        The packet to evaluate, as decoded by a ``BaseParser``.
            physics_state: The physics engine's predicted state after the command,
                           or ``None`` if physics evaluation was skipped.

        Returns:
            A ``DecisionResult`` containing the action, risk score, and reasoning.

        Raises:
            DecisionEngineError: If the rule set is empty or evaluation fails
                                  in an unrecoverable way.
        """

    @abstractmethod
    def get_rules(self) -> list[FirewallRule]:
        """
        Return the currently loaded rule set.

        Returns:
            List of ``FirewallRule`` instances ordered by priority (ascending).
        """

    @abstractmethod
    def add_rule(self, rule: FirewallRule) -> None:
        """
        Add a rule to the engine's rule set.

        Args:
            rule: The ``FirewallRule`` to add.

        Raises:
            ValueError: If a rule with the same ``rule_id`` already exists.
        """

    @abstractmethod
    def clear_rules(self) -> None:
        """
        Remove all rules from the engine's rule set.

        Use with caution: an engine with no rules cannot make decisions.
        """

    def __repr__(self) -> str:
        return f"<{self.__class__.__name__} rules={len(self.get_rules())}>"
