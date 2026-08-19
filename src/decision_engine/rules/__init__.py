"""
VoltGuard — Decision Engine Rules Package
==========================================
Exports all modular security rule evaluators.

Three modules, each covering a distinct evaluation layer:

  - ``protocol_rules``  — Modbus TCP protocol validity rules
  - ``modbus_rules``    — Modbus command-level security rules
  - ``physics_rules``   — Physics-state–aware safety rules

Each module exposes a ``evaluate_*`` function that accepts the parsed
packet and/or physics state and returns a list of triggered
``DecisionReason`` objects.  An empty list means no rules fired.

Usage::

    from src.decision_engine.rules.protocol_rules import evaluate_protocol_rules
    from src.decision_engine.rules.modbus_rules import evaluate_modbus_rules
    from src.decision_engine.rules.physics_rules import evaluate_physics_rules
"""

from src.decision_engine.rules.modbus_rules import evaluate_modbus_rules
from src.decision_engine.rules.physics_rules import evaluate_physics_rules
from src.decision_engine.rules.protocol_rules import evaluate_protocol_rules

__all__ = [
    "evaluate_protocol_rules",
    "evaluate_modbus_rules",
    "evaluate_physics_rules",
]
