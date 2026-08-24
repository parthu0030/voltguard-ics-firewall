"""
VoltGuard — Firewall Policy Package (Day 6)
============================================
Implements the Policy & Enforcement layer that sits between the Day 4
Decision Engine and the final packet disposition.

Pipeline position:
    SecurityDecisionResult (Day 4)
              ↓
        PolicyEngine          ← this package
              ↓
        EnforcementResult
              ↓
    SimulationEnforcementAdapter
              ↓
        ALLOW / ALERT / BLOCK (simulation-safe, no OS changes)

Key components:
  - ``PolicyAction``                 — ALLOW / ALERT / BLOCK enum
  - ``FirewallPolicy``               — Configurable ICS security policy
  - ``EnforcementResult``            — Full output of the Policy Engine
  - ``PolicyConfig``                 — Loads policies from config.json
  - ``PolicyEngine``                 — Deterministic policy evaluator
  - ``EnforcementAdapter``           — Abstract enforcement interface
  - ``SimulationEnforcementAdapter`` — Safe simulation-only implementation

Quick start::

    from src.policy import PolicyEngine, PolicyConfig, SimulationEnforcementAdapter
    from src.config import config_loader

    config_loader.load()
    policy_cfg = PolicyConfig.from_config(config_loader)
    engine     = PolicyEngine(policy_cfg)
    adapter    = SimulationEnforcementAdapter()

    result = engine.evaluate(decision_result, dst_port=502, protocol="Modbus TCP")
    adapter.enforce(result)
    print(result.final_action, result.matched_policy_id)
"""

from src.policy.enforcement import EnforcementAdapter, EnforcementStats, SimulationEnforcementAdapter
from src.policy.models import EnforcementResult, FirewallPolicy, PolicyAction
from src.policy.policy_config import PolicyConfig
from src.policy.policy_engine import PolicyEngine

__all__ = [
    # Enums / models
    "PolicyAction",
    "FirewallPolicy",
    "EnforcementResult",
    # Configuration
    "PolicyConfig",
    # Engine
    "PolicyEngine",
    # Enforcement
    "EnforcementAdapter",
    "SimulationEnforcementAdapter",
    "EnforcementStats",
]
