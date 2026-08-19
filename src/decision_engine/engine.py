"""
VoltGuard — Physics-Aware Decision Engine
==========================================
Implements the Day 4 security decision pipeline as ``PhysicsAwareDecisionEngine``,
a concrete implementation of ``BaseDecisionEngine`` from
``src/interfaces/base_engine.py``.

Decision pipeline (11 steps)
------------------------------
1.  Validate the packet (parse status check).
2.  Extract protocol information (IP, FC, timestamps).
3.  Identify the Modbus operation type.
4.  Capture the current physics state snapshot.
5.  Evaluate protocol security rules (Layer 1).
6.  Evaluate Modbus command rules (Layer 2).
7.  Evaluate physics-aware safety rules (Layer 3).
8.  Calculate the deterministic risk score via ``RiskScorer``.
9.  Determine severity (from the ``RiskAssessment``).
10. Determine ALLOW / ALERT / BLOCK from score vs. thresholds.
11. Build explanation, create ``SecurityEvent``, log the decision.

Integration:
  - Consumes ``FullPacket`` from the Day 2 ``ProtocolParser``.
  - Consumes ``SystemState`` from the Day 3 ``WaterSystemEngine``.
  - Produces a ``SecurityDecisionResult`` with full provenance.

Usage::

    from src.decision_engine.engine import PhysicsAwareDecisionEngine
    from src.decision_engine.decision_config import DecisionConfig
    from src.physics.physics_config import PhysicsConfig

    engine = PhysicsAwareDecisionEngine(physics_cfg, decision_cfg)
    result = engine.evaluate(packet, physics_state)
    print(result.decision, result.risk_score, result.reason)
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional

from src.decision_engine.decision_config import DecisionConfig
from src.decision_engine.models import (
    DecisionReason,
    DecisionType,
    RiskAssessment,
    SecurityDecisionResult,
    SecurityEvent,
    SeverityLevel,
)
from src.decision_engine.risk_scorer import RiskScorer
from src.decision_engine.rule_engine import RuleEngine
from src.exceptions import DecisionEngineError
from src.interfaces.base_engine import (
    BaseDecisionEngine,
    DecisionAction,
    DecisionResult,
    FirewallRule,
)
from src.interfaces.base_parser import ParsedPacket
from src.interfaces.base_physics import PhysicsState
from src.logger import get_logger
from src.parser.packet_models import FullPacket
from src.physics.physics_config import PhysicsConfig
from src.physics.system_state import SystemState

_log = get_logger(__name__)


# ---------------------------------------------------------------------------
# Helper: convert DecisionType → DecisionAction (base interface)
# ---------------------------------------------------------------------------

_TYPE_TO_ACTION: dict[DecisionType, DecisionAction] = {
    DecisionType.ALLOW: DecisionAction.ALLOW,
    DecisionType.ALERT: DecisionAction.ALERT,
    DecisionType.BLOCK: DecisionAction.BLOCK,
}


# ---------------------------------------------------------------------------
# PhysicsAwareDecisionEngine
# ---------------------------------------------------------------------------

class PhysicsAwareDecisionEngine(BaseDecisionEngine):
    """
    The primary VoltGuard security decision engine for Day 4.

    Combines the Day 2 Modbus parser output and the Day 3 physics engine
    state to produce a deterministic, explainable ALLOW / ALERT / BLOCK
    verdict for every industrial packet.

    Parameters
    ----------
    physics_cfg : PhysicsConfig
        All physical system thresholds.  Reuses the Day 3 configuration.
    decision_cfg : DecisionConfig
        Decision-engine–specific thresholds loaded from config.json.
    """

    def __init__(
        self,
        physics_cfg: PhysicsConfig,
        decision_cfg: DecisionConfig,
    ) -> None:
        """
        Initialise the engine with both configuration objects.

        Args:
            physics_cfg:  Validated ``PhysicsConfig`` from the physics module.
            decision_cfg: Validated ``DecisionConfig`` from the decision module.
        """
        self._physics_cfg  = physics_cfg
        self._decision_cfg = decision_cfg
        self._rule_engine  = RuleEngine(physics_cfg, decision_cfg)
        self._scorer       = RiskScorer(decision_cfg)
        self._rules: list[FirewallRule] = []  # custom rules (BaseDecisionEngine API)
        self._event_counter: int = 0

        _log.info(
            "PhysicsAwareDecisionEngine initialised. Config: %s | %s",
            physics_cfg,
            decision_cfg,
        )

    # ------------------------------------------------------------------
    # Primary API — full FullPacket evaluation
    # ------------------------------------------------------------------

    def evaluate_full_packet(
        self,
        packet: FullPacket,
        physics_state: Optional[SystemState] = None,
    ) -> SecurityDecisionResult:
        """
        Evaluate a ``FullPacket`` (from the Day 2 parser) and an optional
        ``SystemState`` (from the Day 3 engine) through the 11-step pipeline.

        This is the main entry point for Day 4 integration.

        Args:
            packet:        ``FullPacket`` produced by ``ProtocolParser``.
            physics_state: Current ``SystemState``.  If ``None``, physics
                           rules are skipped.

        Returns:
            ``SecurityDecisionResult`` with the full decision provenance.
        """
        timestamp = self._utc_now()

        # ── Step 1–3: Extract metadata ─────────────────────────────────────
        src_ip       = packet.src_ip or "unknown"
        dst_ip       = packet.dst_ip or "unknown"
        function_code = packet.function_code
        function_name = packet.function_name or ""

        # ── Step 4: Capture physics state snapshot ─────────────────────────
        physics_snapshot = (
            physics_state.to_dict() if physics_state is not None else {}
        )

        # ── Steps 5–7: Evaluate all rule layers ────────────────────────────
        reasons: list[DecisionReason] = self._rule_engine.evaluate_packet(
            packet, physics_state
        )

        # ── Step 8: Deterministic risk score ───────────────────────────────
        assessment: RiskAssessment = self._scorer.calculate(reasons)

        # ── Steps 9–10: Determine decision ────────────────────────────────
        decision = self._score_to_decision(assessment.risk_score)

        # ── Step 10: Generate explanation ─────────────────────────────────
        reason_text = self._build_reason(decision, assessment)

        # ── Step 11: Build result, create event, log ──────────────────────
        result = SecurityDecisionResult(
            decision=decision,
            risk_score=assessment.risk_score,
            severity=assessment.severity,
            reason=reason_text,
            triggered_rules=assessment.triggered_rules,
            timestamp=timestamp,
            src_ip=src_ip,
            dst_ip=dst_ip,
            function_code=function_code,
            function_name=function_name,
            relevant_physics_state=physics_snapshot,
            all_reasons=assessment.reasons,
        )

        self._emit_event(result)
        self._log_decision(result)

        return result

    # ------------------------------------------------------------------
    # BaseDecisionEngine contract — uses ParsedPacket / PhysicsState DTOs
    # ------------------------------------------------------------------

    def evaluate(
        self,
        packet: ParsedPacket,
        physics_state: Optional[PhysicsState] = None,
    ) -> DecisionResult:
        """
        Satisfy the ``BaseDecisionEngine`` interface contract.

        This adapter method accepts the base-interface types and returns
        the base-interface ``DecisionResult``.  For richer output, call
        ``evaluate_full_packet()`` directly with ``FullPacket`` and
        ``SystemState``.

        Args:
            packet:        A ``ParsedPacket`` from the base parser interface.
            physics_state: Optional base ``PhysicsState`` DTO.

        Returns:
            Base ``DecisionResult`` (action, risk_score, reason, timestamp).

        Raises:
            DecisionEngineError: If the packet object is completely invalid.
        """
        # The base interface uses generic types; we need FullPacket for real
        # evaluation.  If the caller passes a FullPacket (which IS a valid
        # ParsedPacket-compatible object), use it directly.
        if isinstance(packet, FullPacket):
            sys_state: Optional[SystemState] = None
            if physics_state is not None:
                # Wrap the base PhysicsState into a minimal SystemState for
                # compatibility.  Use only the fields present in PhysicsState.
                sys_state = SystemState(
                    pressure_bar=physics_state.pressure_bar or 0.0,
                    flow_lps=physics_state.flow_lps or 0.0,
                    temperature_celsius=physics_state.temperature_celsius or 22.0,
                    pump_on=False,
                    pump_rpm=physics_state.rpm or 0.0,
                    valve_position=0.0,
                    tank_level_m3=75.0,
                )
            rich_result = self.evaluate_full_packet(packet, sys_state)
            return DecisionResult(
                action=_TYPE_TO_ACTION[rich_result.decision],
                risk_score=rich_result.risk_score / 100.0,  # base uses 0.0–1.0
                reason=rich_result.reason,
                timestamp=rich_result.timestamp,
                rule_id=rich_result.triggered_rules[0] if rich_result.triggered_rules else None,
                packet=packet,
                physics_state=physics_state,
            )

        raise DecisionEngineError(
            "evaluate() requires a FullPacket object. "
            "Use evaluate_full_packet() for direct FullPacket evaluation.",
            detail=f"received type={type(packet).__name__}",
        )

    def get_rules(self) -> list[FirewallRule]:
        """Return the currently loaded custom ``FirewallRule`` list."""
        return list(self._rules)

    def add_rule(self, rule: FirewallRule) -> None:
        """
        Add a custom ``FirewallRule`` to the engine.

        Args:
            rule: The ``FirewallRule`` to add.

        Raises:
            ValueError: If a rule with the same ``rule_id`` already exists.
        """
        existing_ids = {r.rule_id for r in self._rules}
        if rule.rule_id in existing_ids:
            raise ValueError(
                f"Rule with id={rule.rule_id!r} already exists. "
                f"Remove it first before adding."
            )
        self._rules.append(rule)
        _log.info("Custom rule added: %r", rule)

    def clear_rules(self) -> None:
        """Remove all custom ``FirewallRule`` objects from the engine."""
        self._rules.clear()
        _log.info("All custom rules cleared.")

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _score_to_decision(self, score: int) -> DecisionType:
        """
        Map an integer risk score to a ``DecisionType``.

        Uses ``DecisionConfig`` thresholds (not hard-coded values):
          - score < alert_threshold  → ALLOW
          - alert_threshold ≤ score < block_threshold → ALERT
          - score ≥ block_threshold  → BLOCK

        Args:
            score: Integer risk score in [0, 100].

        Returns:
            The corresponding ``DecisionType``.
        """
        if score >= self._decision_cfg.risk_block_threshold:
            return DecisionType.BLOCK
        if score >= self._decision_cfg.risk_alert_threshold:
            return DecisionType.ALERT
        return DecisionType.ALLOW

    def _build_reason(
        self, decision: DecisionType, assessment: RiskAssessment
    ) -> str:
        """
        Generate a human-readable explanation of the decision from
        the actual rule results.

        For ALLOW decisions: a brief confirmation of safety.
        For ALERT/BLOCK: lists every triggered rule with its description.

        Args:
            decision:   The final decision type.
            assessment: The ``RiskAssessment`` with all triggered reasons.

        Returns:
            Multi-line human-readable explanation string.
        """
        if decision == DecisionType.ALLOW:
            if not assessment.triggered_rules:
                return (
                    "Packet evaluated against all security rules. "
                    "No violations detected. Physical state is within safe limits."
                )
            # ALLOW despite some low-risk rules firing
            rules_str = ", ".join(assessment.triggered_rules)
            return (
                f"Packet allowed. Risk score {assessment.risk_score} is below the "
                f"alert threshold ({self._decision_cfg.risk_alert_threshold}). "
                f"Low-risk rules observed: [{rules_str}]."
            )

        # ALERT or BLOCK — explain every triggered rule
        lines = [
            f"Decision: {decision.value} | Risk Score: {assessment.risk_score} | "
            f"Severity: {assessment.severity.value}",
            "",
            "Triggered Rules:",
        ]
        for reason in assessment.reasons:
            lines.append(
                f"  • [{reason.rule_id}] ({reason.severity.value}, "
                f"+{reason.risk_contribution} pts): {reason.description}"
            )

        return "\n".join(lines)

    def _emit_event(self, result: SecurityDecisionResult) -> None:
        """
        Create a ``SecurityEvent`` audit record from the result.

        Currently stores in-memory (increments the counter).
        Future Day 5 work can persist this to the database.

        Args:
            result: The completed ``SecurityDecisionResult``.
        """
        self._event_counter += 1
        event = SecurityEvent.from_result(result)
        event.event_id = self._event_counter

    def _log_decision(self, result: SecurityDecisionResult) -> None:
        """
        Emit a structured log entry for every evaluated packet.

        Format: one INFO/WARNING/ERROR line per decision, followed by
        a DEBUG JSON dump for diagnostic purposes.

        Sensitive fields (raw packet bytes) are NOT logged.

        Args:
            result: The completed ``SecurityDecisionResult``.
        """
        fc_str = (
            f"FC=0x{result.function_code:02X} ({result.function_name})"
            if result.function_code is not None
            else "FC=N/A"
        )
        triggered_str = (
            "[" + ", ".join(result.triggered_rules) + "]"
            if result.triggered_rules
            else "[]"
        )

        log_line = (
            f"[DECISION] {result.timestamp} | "
            f"{result.src_ip} → {result.dst_ip} | "
            f"{fc_str} | "
            f"Decision={result.decision.value} | "
            f"Risk={result.risk_score} | "
            f"Severity={result.severity.value} | "
            f"Rules={triggered_str}"
        )

        if result.decision == DecisionType.ALLOW:
            _log.info(log_line)
        elif result.decision == DecisionType.ALERT:
            _log.warning(log_line)
        else:  # BLOCK
            _log.error(log_line)

        # Debug-level JSON dump for deep diagnostics (not exposed in prod logs)
        _log.debug(
            "[DECISION-DETAIL] %s",
            json.dumps(result.to_dict(), default=str, indent=None),
        )

    @staticmethod
    def _utc_now() -> str:
        """Return the current UTC time as an ISO-8601 string."""
        return datetime.now(tz=timezone.utc).isoformat(timespec="seconds")

    @property
    def event_count(self) -> int:
        """Number of security events generated since initialisation."""
        return self._event_counter

    def __repr__(self) -> str:
        return (
            f"<PhysicsAwareDecisionEngine "
            f"events={self._event_counter} "
            f"custom_rules={len(self._rules)}>"
        )
