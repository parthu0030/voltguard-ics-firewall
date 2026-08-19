"""
VoltGuard — Rule Engine
========================
Orchestrates the three rule evaluation layers into a single, reusable
evaluation pipeline:

    1. evaluate_protocol_rules()  — structural/protocol validity
    2. evaluate_modbus_rules()    — Modbus command-level security
    3. evaluate_physics_rules()   — physics-state–aware safety

``RuleEngine`` aggregates the results from all three layers and returns
a flat list of triggered ``DecisionReason`` objects for the ``RiskScorer``.

Design:
  - Each layer is independently callable for targeted testing.
  - The engine holds no mutable state between evaluations.
  - Physics evaluation is skipped gracefully when no state is provided.

Usage::

    from src.decision_engine.rule_engine import RuleEngine
    from src.decision_engine.decision_config import DecisionConfig
    from src.physics.physics_config import PhysicsConfig

    engine = RuleEngine(physics_cfg, decision_cfg)
    reasons = engine.evaluate_packet(packet, state)
"""

from __future__ import annotations

from typing import Optional

from src.decision_engine.decision_config import DecisionConfig
from src.decision_engine.models import DecisionReason
from src.decision_engine.rules.modbus_rules import evaluate_modbus_rules
from src.decision_engine.rules.physics_rules import evaluate_physics_rules
from src.decision_engine.rules.protocol_rules import evaluate_protocol_rules
from src.parser.packet_models import FullPacket
from src.physics.physics_config import PhysicsConfig
from src.physics.system_state import SystemState


class RuleEngine:
    """
    Orchestrates all security rule layers for the VoltGuard decision pipeline.

    The engine applies rules in three ordered passes:

    1. **Protocol rules** — checks parse validity, protocol ID, function code.
       If the packet is malformed, subsequent passes still run but produce
       no false negatives (physics rules require a valid Modbus layer).

    2. **Modbus rules** — checks command type, register address, quantity,
       and control-target for write operations.

    3. **Physics rules** — checks the current physical state against safety
       thresholds and flags write commands that are dangerous given the
       current conditions.

    Parameters
    ----------
    physics_cfg : PhysicsConfig
        All physical system thresholds (pressure max, flow max, etc.).
    decision_cfg : DecisionConfig
        Decision-engine–specific thresholds (alert/block levels, fractions).
    """

    def __init__(
        self,
        physics_cfg: PhysicsConfig,
        decision_cfg: DecisionConfig,
    ) -> None:
        """
        Initialise the rule engine with both configuration objects.

        Args:
            physics_cfg:  Validated ``PhysicsConfig`` from the physics module.
            decision_cfg: Validated ``DecisionConfig`` from the decision module.
        """
        self._physics_cfg  = physics_cfg
        self._decision_cfg = decision_cfg

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate_packet(
        self,
        packet: FullPacket,
        physics_state: Optional[SystemState] = None,
    ) -> list[DecisionReason]:
        """
        Run all three rule layers and return the combined list of triggered
        ``DecisionReason`` objects.

        This is the primary entry point for the decision engine.  The
        ``RiskScorer`` then converts the returned list into a
        ``RiskAssessment``.

        Args:
            packet:        The ``FullPacket`` produced by ``ProtocolParser``.
            physics_state: Current ``SystemState`` snapshot from the physics
                           engine.  If ``None``, physics rules are skipped.

        Returns:
            Flat list of all triggered reasons from all rule layers.
            Empty list means the packet passed every rule without triggering.
        """
        reasons: list[DecisionReason] = []

        # Layer 1: Protocol rules — always run
        reasons.extend(self.evaluate_protocol_rules(packet))

        # Layer 2: Modbus rules — only meaningful with a valid Modbus layer
        reasons.extend(self.evaluate_modbus_rules(packet))

        # Layer 3: Physics rules — only when state is provided
        if physics_state is not None:
            reasons.extend(self.evaluate_physics_rules(packet, physics_state))

        return reasons

    def evaluate_protocol_rules(self, packet: FullPacket) -> list[DecisionReason]:
        """
        Run only the protocol-level rules (Layer 1).

        Useful for targeted testing of the protocol validation layer.

        Args:
            packet: The ``FullPacket`` to evaluate.

        Returns:
            List of triggered ``DecisionReason`` objects from protocol rules.
        """
        return evaluate_protocol_rules(packet)

    def evaluate_modbus_rules(self, packet: FullPacket) -> list[DecisionReason]:
        """
        Run only the Modbus command-level rules (Layer 2).

        Useful for targeted testing of the Modbus security layer.

        Args:
            packet: The ``FullPacket`` to evaluate (must have a Modbus layer).

        Returns:
            List of triggered ``DecisionReason`` objects from Modbus rules.
        """
        return evaluate_modbus_rules(packet, self._decision_cfg)

    def evaluate_physics_rules(
        self,
        packet: FullPacket,
        state: SystemState,
    ) -> list[DecisionReason]:
        """
        Run only the physics-aware safety rules (Layer 3).

        Useful for targeted testing of the physics integration layer.

        Args:
            packet: The ``FullPacket`` (needed for write-command rules).
            state:  Current ``SystemState`` snapshot from the physics engine.

        Returns:
            List of triggered ``DecisionReason`` objects from physics rules.
        """
        return evaluate_physics_rules(
            packet, state, self._physics_cfg, self._decision_cfg
        )

    def evaluate_safety_rules(
        self,
        state: SystemState,
    ) -> list[str]:
        """
        Return raw warning strings from ``SystemState.has_warnings()``.

        This is a convenience wrapper that exposes the physics engine's
        built-in safety check in a form consumable by the rule engine.

        Args:
            state: Current ``SystemState`` to evaluate.

        Returns:
            List of human-readable warning strings (empty if all safe).
        """
        return state.has_warnings(self._physics_cfg)

    # ------------------------------------------------------------------
    # Representation
    # ------------------------------------------------------------------

    def __repr__(self) -> str:
        return (
            f"<RuleEngine "
            f"alert≥{self._decision_cfg.risk_alert_threshold} "
            f"block≥{self._decision_cfg.risk_block_threshold}>"
        )
