"""
VoltGuard — Interfaces Package
================================
Contains Abstract Base Classes (ABCs) that define the contracts for
each major sub-system of VoltGuard.

Sub-modules:
  - ``base_parser``  — Contract for all protocol parsers (Modbus, DNP3, …)
  - ``base_physics`` — Contract for all physics simulation engines
  - ``base_engine``  — Contract for the decision / firewall engine

Usage:
    from src.interfaces.base_parser import BaseParser
    from src.interfaces.base_physics import BasePhysicsEngine
    from src.interfaces.base_engine import BaseDecisionEngine
"""
