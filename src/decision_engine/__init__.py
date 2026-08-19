"""
VoltGuard — Decision Engine Package
======================================
Implements the Day 4 physics-aware security decision pipeline.

Pipeline
--------
    FullPacket (Day 2)  +  SystemState (Day 3)
                ↓
    PhysicsAwareDecisionEngine
                ↓
    SecurityDecisionResult  →  ALLOW / ALERT / BLOCK

Components
----------
- ``PhysicsAwareDecisionEngine`` — 11-step evaluation pipeline
- ``RuleEngine``                 — Three-layer rule orchestrator
- ``RiskScorer``                 — Deterministic score aggregator
- ``DecisionConfig``             — Configuration (from config.json)
- ``DecisionType``               — ALLOW / ALERT / BLOCK enum
- ``SeverityLevel``              — SAFE / LOW / MEDIUM / HIGH / CRITICAL enum
- ``DecisionReason``             — Single triggered rule + contribution
- ``RiskAssessment``             — Aggregated score from all reasons
- ``SecurityDecisionResult``     — Full decision output DTO
- ``SecurityEvent``              — Audit record

Quick Start::

    from src.decision_engine import PhysicsAwareDecisionEngine, DecisionConfig
    from src.physics.physics_config import PhysicsConfig
    from src.config import config_loader

    config_loader.load()
    physics_cfg  = PhysicsConfig.from_config(config_loader)
    decision_cfg = DecisionConfig.from_config(config_loader)
    engine = PhysicsAwareDecisionEngine(physics_cfg, decision_cfg)

    result = engine.evaluate_full_packet(packet, system_state)
    print(result.decision, result.risk_score)
"""

from src.decision_engine.decision_config import DecisionConfig
from src.decision_engine.engine import PhysicsAwareDecisionEngine
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

__all__ = [
    # Engine
    "PhysicsAwareDecisionEngine",
    # Configuration
    "DecisionConfig",
    # Rule orchestrator
    "RuleEngine",
    # Risk scorer
    "RiskScorer",
    # Models / enums
    "DecisionType",
    "SeverityLevel",
    "DecisionReason",
    "RiskAssessment",
    "SecurityDecisionResult",
    "SecurityEvent",
]
