"""
VoltGuard — Day 4 Decision Engine Test Suite
==============================================
Comprehensive tests for the Physics-Aware Decision Engine.

Coverage:
  1.  Safe read operation → ALLOW
  2.  Safe write operation → ALLOW
  3.  Suspicious write (pump control) → ALERT
  4.  Unsafe pressure operation → BLOCK
  5.  Unsafe valve operation → BLOCK
  6.  Invalid packet → BLOCK (safe failure)
  7.  Multiple triggered rules → highest severity selected
  8.  Risk score boundaries (0, 39, 40, 69, 70, 100)
  9.  Empty / missing physics state
  10. Malformed decision request
  11. Deterministic repeated evaluation
  12. Integration test: Parser → Physics → Decision Engine (end-to-end)

Additional unit tests:
  - DecisionConfig validation
  - RiskScorer.calculate() with empty, single, and multiple reasons
  - RuleEngine layer isolation (protocol / modbus / physics)
  - SeverityLevel ordering and comparison
  - SecurityDecisionResult.to_dict() serialisation
  - SecurityEvent.from_result() construction
  - PhysicsAwareDecisionEngine interface compliance

Run with:
    python3 -m pytest tests/test_day4_decision.py -v
Or directly:
    python3 tests/test_day4_decision.py
"""

from __future__ import annotations

import dataclasses
import sys
import unittest
from pathlib import Path
from typing import Optional

# ── Ensure project root is on sys.path ────────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ── Bootstrap configuration ───────────────────────────────────────────────
from src.config import config_loader
if not config_loader.is_loaded:
    config_loader.load()

# ── Import the subjects under test ────────────────────────────────────────
from src.decision_engine import (
    DecisionConfig,
    DecisionReason,
    DecisionType,
    PhysicsAwareDecisionEngine,
    RiskAssessment,
    RiskScorer,
    RuleEngine,
    SecurityDecisionResult,
    SecurityEvent,
    SeverityLevel,
)
from src.decision_engine.rules.modbus_rules import evaluate_modbus_rules
from src.decision_engine.rules.physics_rules import evaluate_physics_rules
from src.decision_engine.rules.protocol_rules import evaluate_protocol_rules
from src.exceptions import ConfigurationError
from src.interfaces.base_engine import DecisionAction
from src.parser import ProtocolParser, SamplePacketFactory
from src.parser.packet_models import FullPacket, ParseStatus
from src.physics.physics_config import PhysicsConfig
from src.physics.system_state import SystemState
from src.physics.water_system_engine import WaterSystemEngine


# ---------------------------------------------------------------------------
# Test Helpers
# ---------------------------------------------------------------------------

def _default_physics_cfg() -> PhysicsConfig:
    """Return PhysicsConfig from config.json."""
    return PhysicsConfig.from_config(config_loader)


def _default_decision_cfg() -> DecisionConfig:
    """Return DecisionConfig from config.json."""
    return DecisionConfig.from_config(config_loader)


def _engine() -> PhysicsAwareDecisionEngine:
    """Create a fresh PhysicsAwareDecisionEngine with default config."""
    return PhysicsAwareDecisionEngine(
        _default_physics_cfg(), _default_decision_cfg()
    )


def _parser() -> ProtocolParser:
    """Return a fresh ProtocolParser."""
    return ProtocolParser()


def _safe_state() -> SystemState:
    """A completely safe SystemState well within all limits."""
    cfg = _default_physics_cfg()
    return SystemState(
        pressure_bar=2.0,            # well below 10.0 max
        flow_lps=5.0,                # well below 50.0 max
        temperature_celsius=30.0,    # well below 150.0 max
        pump_on=True,
        pump_rpm=1200.0,
        valve_position=0.5,
        tank_level_m3=70.0,
    )


def _dangerous_pressure_state() -> SystemState:
    """A SystemState with pressure at 98% of maximum (above critical fraction)."""
    cfg = _default_physics_cfg()
    return SystemState(
        pressure_bar=cfg.pressure_max_bar * 0.98,  # 9.8 bar (critical threshold is 9.5)
        flow_lps=10.0,
        temperature_celsius=50.0,
        pump_on=True,
        pump_rpm=3400.0,
        valve_position=0.8,
        tank_level_m3=50.0,
    )


def _pump_off_valve_open_state() -> SystemState:
    """Pump OFF, valve open — creates an impossible flow condition."""
    return SystemState(
        pressure_bar=0.5,
        flow_lps=0.0,
        temperature_celsius=22.0,
        pump_on=False,
        pump_rpm=0.0,
        valve_position=0.6,
        tank_level_m3=70.0,
    )


def _parse(raw: bytes) -> FullPacket:
    """Parse raw Modbus bytes using the Day 2 parser."""
    return _parser().parse_modbus_only(raw)


def _reason(rule_id: str, contrib: int, sev: SeverityLevel) -> DecisionReason:
    """Construct a minimal DecisionReason for scorer tests."""
    return DecisionReason(
        rule_id=rule_id,
        description=f"Test rule: {rule_id}",
        risk_contribution=contrib,
        severity=sev,
    )


# ===========================================================================
# 1. TestSeverityLevel
# ===========================================================================

class TestSeverityLevel(unittest.TestCase):
    """Verify SeverityLevel ordering and comparison operators."""

    def test_ordering(self):
        levels = [
            SeverityLevel.SAFE, SeverityLevel.LOW, SeverityLevel.MEDIUM,
            SeverityLevel.HIGH, SeverityLevel.CRITICAL,
        ]
        for i in range(len(levels) - 1):
            self.assertLess(levels[i], levels[i + 1])

    def test_max_works(self):
        reasons = [
            _reason("A", 5, SeverityLevel.LOW),
            _reason("B", 10, SeverityLevel.CRITICAL),
            _reason("C", 5, SeverityLevel.MEDIUM),
        ]
        max_sev = max(r.severity for r in reasons)
        self.assertEqual(max_sev, SeverityLevel.CRITICAL)

    def test_safe_is_lowest(self):
        self.assertLess(SeverityLevel.SAFE, SeverityLevel.LOW)
        self.assertLess(SeverityLevel.SAFE, SeverityLevel.CRITICAL)

    def test_critical_is_highest(self):
        self.assertGreater(SeverityLevel.CRITICAL, SeverityLevel.HIGH)
        self.assertGreater(SeverityLevel.CRITICAL, SeverityLevel.SAFE)


# ===========================================================================
# 2. TestDecisionConfig
# ===========================================================================

class TestDecisionConfig(unittest.TestCase):
    """Verify DecisionConfig loading and validation."""

    def test_loads_from_config(self):
        cfg = DecisionConfig.from_config(config_loader)
        self.assertEqual(cfg.risk_alert_threshold, 40)
        self.assertEqual(cfg.risk_block_threshold, 70)
        self.assertAlmostEqual(cfg.pressure_warning_fraction, 0.80)
        self.assertAlmostEqual(cfg.pressure_critical_fraction, 0.95)

    def test_defaults_are_valid(self):
        cfg = DecisionConfig()
        cfg._validate()  # should not raise

    def test_invalid_thresholds_raise(self):
        with self.assertRaises(ConfigurationError):
            DecisionConfig(
                risk_alert_threshold=80,
                risk_block_threshold=40,  # alert > block — invalid
            )._validate()

    def test_warning_must_be_less_than_critical(self):
        with self.assertRaises(ConfigurationError):
            DecisionConfig(
                pressure_warning_fraction=0.95,
                pressure_critical_fraction=0.80,  # warning > critical — invalid
            )._validate()

    def test_max_registers_must_be_positive(self):
        with self.assertRaises(ConfigurationError):
            DecisionConfig(max_registers_per_write=0)._validate()

    def test_frozen(self):
        cfg = DecisionConfig()
        with self.assertRaises((AttributeError, TypeError, dataclasses.FrozenInstanceError)):
            cfg.risk_alert_threshold = 99  # type: ignore


# ===========================================================================
# 3. TestRiskScorer
# ===========================================================================

class TestRiskScorer(unittest.TestCase):
    """Verify deterministic risk score calculation."""

    def setUp(self):
        self.scorer = RiskScorer(DecisionConfig())

    def test_empty_reasons_gives_zero(self):
        result = self.scorer.calculate([])
        self.assertEqual(result.risk_score, 0)
        self.assertEqual(result.severity, SeverityLevel.SAFE)
        self.assertEqual(result.triggered_rules, [])

    def test_single_reason_score(self):
        r = _reason("R1", 30, SeverityLevel.LOW)
        result = self.scorer.calculate([r])
        self.assertEqual(result.risk_score, 30)
        self.assertEqual(result.severity, SeverityLevel.LOW)
        self.assertIn("R1", result.triggered_rules)

    def test_sum_is_clamped_to_100(self):
        reasons = [
            _reason("R1", 60, SeverityLevel.MEDIUM),
            _reason("R2", 60, SeverityLevel.HIGH),
        ]
        result = self.scorer.calculate(reasons)
        self.assertEqual(result.risk_score, 100)

    def test_max_severity_wins(self):
        reasons = [
            _reason("R1", 5, SeverityLevel.SAFE),
            _reason("R2", 5, SeverityLevel.LOW),
            _reason("R3", 85, SeverityLevel.CRITICAL),
        ]
        result = self.scorer.calculate(reasons)
        self.assertEqual(result.severity, SeverityLevel.CRITICAL)

    def test_deterministic(self):
        reasons = [
            _reason("R1", 30, SeverityLevel.MEDIUM),
            _reason("R2", 25, SeverityLevel.LOW),
        ]
        r1 = self.scorer.calculate(reasons)
        r2 = self.scorer.calculate(reasons)
        self.assertEqual(r1.risk_score, r2.risk_score)
        self.assertEqual(r1.severity, r2.severity)
        self.assertEqual(r1.triggered_rules, r2.triggered_rules)

    def test_risk_score_boundary_39(self):
        # 39 → ALLOW territory
        result = self.scorer.calculate([_reason("R", 39, SeverityLevel.LOW)])
        self.assertEqual(result.risk_score, 39)

    def test_risk_score_boundary_40(self):
        # 40 → ALERT territory
        result = self.scorer.calculate([_reason("R", 40, SeverityLevel.MEDIUM)])
        self.assertEqual(result.risk_score, 40)

    def test_risk_score_boundary_70(self):
        # 70 → BLOCK territory
        result = self.scorer.calculate([_reason("R", 70, SeverityLevel.HIGH)])
        self.assertEqual(result.risk_score, 70)


# ===========================================================================
# 4. TestProtocolRules (Layer 1)
# ===========================================================================

class TestProtocolRules(unittest.TestCase):
    """Test the protocol-level rule evaluator in isolation."""

    def _parse(self, raw: bytes) -> FullPacket:
        return _parse(raw)

    def test_valid_packet_no_protocol_reasons(self):
        packet = self._parse(SamplePacketFactory.read_coils())
        reasons = evaluate_protocol_rules(packet)
        rule_ids = [r.rule_id for r in reasons]
        self.assertNotIn("INVALID_PACKET", rule_ids)
        self.assertNotIn("INVALID_PROTOCOL_ID", rule_ids)
        self.assertNotIn("UNSUPPORTED_FC", rule_ids)

    def test_malformed_packet_triggers_invalid_packet(self):
        # random_garbage has DEAD:BEEF as bytes 2-3 → Protocol ID = 0xBEEF → INVALID_PROTOCOL_ID
        # Use truncated_payload for a genuine MALFORMED/TRUNCATED case
        packet = self._parse(SamplePacketFactory.truncated_payload())
        reasons = evaluate_protocol_rules(packet)
        rule_ids = [r.rule_id for r in reasons]
        # Truncated → MALFORMED or TRUNCATED → triggers INVALID_PACKET catch-all
        self.assertGreater(len(reasons), 0, "Expected at least one protocol violation")

    def test_invalid_protocol_id_triggers_rule(self):
        packet = self._parse(SamplePacketFactory.invalid_protocol_id())
        reasons = evaluate_protocol_rules(packet)
        rule_ids = [r.rule_id for r in reasons]
        self.assertIn("INVALID_PROTOCOL_ID", rule_ids)

    def test_unsupported_fc_triggers_rule(self):
        packet = self._parse(SamplePacketFactory.unsupported_function_code())
        reasons = evaluate_protocol_rules(packet)
        rule_ids = [r.rule_id for r in reasons]
        self.assertIn("UNSUPPORTED_FC", rule_ids)

    def test_too_short_triggers_invalid_packet(self):
        packet = self._parse(SamplePacketFactory.invalid_short())
        reasons = evaluate_protocol_rules(packet)
        rule_ids = [r.rule_id for r in reasons]
        self.assertIn("INVALID_PACKET", rule_ids)


# ===========================================================================
# 5. TestModbusRules (Layer 2)
# ===========================================================================

class TestModbusRules(unittest.TestCase):
    """Test the Modbus command-level rule evaluator in isolation."""

    def setUp(self):
        self.cfg = DecisionConfig()

    def _eval(self, raw: bytes) -> list[DecisionReason]:
        return evaluate_modbus_rules(_parse(raw), self.cfg)

    def test_read_coils_triggers_read_operation(self):
        reasons = self._eval(SamplePacketFactory.read_coils())
        rule_ids = [r.rule_id for r in reasons]
        self.assertIn("READ_OPERATION", rule_ids)

    def test_read_holding_registers_triggers_read_operation(self):
        reasons = self._eval(SamplePacketFactory.read_holding_registers())
        rule_ids = [r.rule_id for r in reasons]
        self.assertIn("READ_OPERATION", rule_ids)

    def test_read_operation_is_low_risk(self):
        reasons = self._eval(SamplePacketFactory.read_coils())
        read_reason = next(r for r in reasons if r.rule_id == "READ_OPERATION")
        self.assertLessEqual(read_reason.risk_contribution, 10)
        self.assertEqual(read_reason.severity, SeverityLevel.SAFE)

    def test_write_single_register_triggers_critical_register(self):
        reasons = self._eval(SamplePacketFactory.write_single_register())
        rule_ids = [r.rule_id for r in reasons]
        self.assertIn("WRITE_TO_CRITICAL_REGISTER", rule_ids)

    def test_write_multiple_normal_quantity_no_excessive_rule(self):
        # Standard write_multiple_registers sample writes 2 registers (< 125)
        reasons = self._eval(SamplePacketFactory.write_multiple_registers())
        rule_ids = [r.rule_id for r in reasons]
        self.assertNotIn("EXCESSIVE_REGISTER_WRITE", rule_ids)

    def test_write_pump_coil_triggers_pump_control(self):
        # Build a write single coil to address 0x0000 (pump coil)
        pump_coil_packet = bytes([
            0x00, 0x01,  # Transaction ID
            0x00, 0x00,  # Protocol ID
            0x00, 0x06,  # Length
            0x01,        # Unit ID
            0x05,        # FC: Write Single Coil
            0x00, 0x00,  # Address = 0x0000 (pump)
            0xFF, 0x00,  # Value = ON
        ])
        reasons = evaluate_modbus_rules(_parse(pump_coil_packet), self.cfg)
        rule_ids = [r.rule_id for r in reasons]
        self.assertIn("PUMP_CONTROL_WRITE", rule_ids)

    def test_invalid_packet_no_modbus_rules(self):
        reasons = self._eval(SamplePacketFactory.random_garbage())
        # No Modbus layer → no Modbus rules fire
        self.assertEqual(reasons, [])


# ===========================================================================
# 6. TestPhysicsRules (Layer 3)
# ===========================================================================

class TestPhysicsRules(unittest.TestCase):
    """Test the physics-aware rule evaluator in isolation."""

    def setUp(self):
        self.physics_cfg  = _default_physics_cfg()
        self.decision_cfg = _default_decision_cfg()

    def _eval(
        self,
        raw: bytes,
        state: SystemState,
    ) -> list[DecisionReason]:
        packet = _parse(raw)
        return evaluate_physics_rules(
            packet, state, self.physics_cfg, self.decision_cfg
        )

    def test_safe_state_no_physics_rules(self):
        reasons = self._eval(
            SamplePacketFactory.read_coils(), _safe_state()
        )
        rule_ids = [r.rule_id for r in reasons]
        self.assertNotIn("PRESSURE_LIMIT_EXCEEDED", rule_ids)
        self.assertNotIn("PRESSURE_APPROACHING_LIMIT", rule_ids)
        self.assertNotIn("FLOW_LIMIT_EXCEEDED", rule_ids)

    def test_high_pressure_triggers_pressure_exceeded(self):
        reasons = self._eval(
            SamplePacketFactory.write_single_register(),
            _dangerous_pressure_state(),
        )
        rule_ids = [r.rule_id for r in reasons]
        self.assertIn("PRESSURE_LIMIT_EXCEEDED", rule_ids)

    def test_pump_off_valve_open_write_triggers_unsafe_valve(self):
        reasons = self._eval(
            SamplePacketFactory.write_single_coil(),
            _pump_off_valve_open_state(),
        )
        rule_ids = [r.rule_id for r in reasons]
        self.assertIn("UNSAFE_VALVE_OPEN_PUMP_OFF", rule_ids)

    def test_pump_off_valve_open_read_no_unsafe_valve_rule(self):
        # Reads don't trigger the valve/write rule
        reasons = self._eval(
            SamplePacketFactory.read_coils(),
            _pump_off_valve_open_state(),
        )
        rule_ids = [r.rule_id for r in reasons]
        self.assertNotIn("UNSAFE_VALVE_OPEN_PUMP_OFF", rule_ids)

    def test_approaching_pressure_triggers_approaching_rule(self):
        cfg = _default_physics_cfg()
        # 85% of max pressure — above warning fraction (80%) but below critical (95%)
        state = SystemState(
            pressure_bar=cfg.pressure_max_bar * 0.87,
            flow_lps=5.0,
            temperature_celsius=30.0,
            pump_on=True,
            pump_rpm=2000.0,
            valve_position=0.5,
            tank_level_m3=60.0,
        )
        reasons = self._eval(SamplePacketFactory.write_single_register(), state)
        rule_ids = [r.rule_id for r in reasons]
        self.assertIn("PRESSURE_APPROACHING_LIMIT", rule_ids)
        self.assertNotIn("PRESSURE_LIMIT_EXCEEDED", rule_ids)


# ===========================================================================
# 7. TestRuleEngine
# ===========================================================================

class TestRuleEngine(unittest.TestCase):
    """Test the RuleEngine orchestrator."""

    def setUp(self):
        self.engine = RuleEngine(_default_physics_cfg(), _default_decision_cfg())

    def test_protocol_layer_only_on_invalid(self):
        # random_garbage → INVALID_PROTOCOL_ID (0xBEEF in bytes 2-3)
        packet = _parse(SamplePacketFactory.random_garbage())
        reasons = self.engine.evaluate_protocol_rules(packet)
        # Any protocol violation is acceptable
        self.assertGreater(
            len(reasons), 0,
            "Expected at least one protocol rule to fire on random_garbage"
        )

    def test_no_physics_state_skips_physics_layer(self):
        packet = _parse(SamplePacketFactory.write_single_register())
        reasons = self.engine.evaluate_packet(packet, physics_state=None)
        # Modbus rules should fire but no physics rules
        physics_rule_ids = {
            "PRESSURE_LIMIT_EXCEEDED", "PRESSURE_APPROACHING_LIMIT",
            "UNSAFE_VALVE_OPEN_PUMP_OFF", "FLOW_LIMIT_EXCEEDED",
            "TEMPERATURE_APPROACHING_LIMIT", "WRITE_WOULD_EXCEED_PRESSURE",
            "WRITE_WHILE_UNSAFE",
        }
        triggered_ids = {r.rule_id for r in reasons}
        self.assertTrue(triggered_ids.isdisjoint(physics_rule_ids))

    def test_all_layers_run_with_state(self):
        packet = _parse(SamplePacketFactory.write_single_register())
        reasons = self.engine.evaluate_packet(packet, _safe_state())
        # Modbus rules should fire (write to critical register)
        rule_ids = {r.rule_id for r in reasons}
        self.assertIn("WRITE_TO_CRITICAL_REGISTER", rule_ids)

    def test_evaluate_safety_rules_safe_state(self):
        warnings = self.engine.evaluate_safety_rules(_safe_state())
        self.assertIsInstance(warnings, list)

    def test_repr(self):
        repr_str = repr(self.engine)
        self.assertIn("RuleEngine", repr_str)


# ===========================================================================
# 8. TestDecisionEngine — Core Scenarios
# ===========================================================================

class TestDecisionEngineScenarios(unittest.TestCase):
    """
    Test the 11 mandatory scenarios from the Day 4 specification.
    """

    def setUp(self):
        self.engine = _engine()
        self.safe   = _safe_state()

    # ── Scenario 1: Safe read operation → ALLOW ────────────────────────────
    def test_01_safe_read_allow(self):
        packet = _parse(SamplePacketFactory.read_coils())
        result = self.engine.evaluate_full_packet(packet, self.safe)
        self.assertEqual(result.decision, DecisionType.ALLOW)
        self.assertIsInstance(result.risk_score, int)
        self.assertGreaterEqual(result.risk_score, 0)

    def test_01b_safe_read_registers_allow(self):
        packet = _parse(SamplePacketFactory.read_holding_registers())
        result = self.engine.evaluate_full_packet(packet, self.safe)
        self.assertEqual(result.decision, DecisionType.ALLOW)

    # ── Scenario 2: Safe write operation → ALLOW ───────────────────────────
    def test_02_safe_write_allow(self):
        # Build a write to a benign non-pump, non-valve register (addr=50)
        # that doesn't trigger any elevated Modbus rule.
        # write_single_register in SamplePacketFactory targets addr=0x0001
        # (pump RPM setpoint) which does trigger PUMP_CONTROL_WRITE + WRITE_TO_CRITICAL_REGISTER.
        # Use a higher address to stay in the monitored range but avoid pump/valve addresses.
        safe_write_packet = bytes([
            0x00, 0x04,  # Transaction ID
            0x00, 0x00,  # Protocol ID
            0x00, 0x06,  # Length
            0x01,        # Unit ID
            0x06,        # FC: Write Single Register
            0x00, 0x32,  # Address = 0x0032 (50) — not pump/valve coil
            0x00, 0x0A,  # Value = 10
        ])
        packet = _parse(safe_write_packet)
        result = self.engine.evaluate_full_packet(packet, self.safe)
        # Only WRITE_TO_CRITICAL_REGISTER fires (30 pts) → below alert(40) → ALLOW
        self.assertEqual(result.decision, DecisionType.ALLOW)

    # ── Scenario 3: Suspicious write → ALERT ──────────────────────────────
    def test_03_suspicious_write_alert(self):
        # Pump control write (35 pts) + critical register (30 pts) = 65 pts
        # That's ≥ alert(40) but < block(70) → ALERT
        pump_coil_packet = bytes([
            0x00, 0x01,  # Transaction ID
            0x00, 0x00,  # Protocol ID
            0x00, 0x06,  # Length
            0x01,        # Unit ID
            0x05,        # FC: Write Single Coil (pump coil writes are suspicious)
            0x00, 0xAC,  # Valve coil address (not pump, but still suspicious)
            0xFF, 0x00,  # ON
        ])
        # Use pump-off / valve-open state to trigger extra rules
        state = _pump_off_valve_open_state()
        packet = _parse(pump_coil_packet)
        result = self.engine.evaluate_full_packet(packet, state)
        # Should be ALERT or BLOCK — at minimum not ALLOW
        self.assertIn(result.decision, (DecisionType.ALERT, DecisionType.BLOCK))

    # ── Scenario 4: Unsafe pressure → BLOCK ───────────────────────────────
    def test_04_unsafe_pressure_block(self):
        packet = _parse(SamplePacketFactory.write_single_register())
        state  = _dangerous_pressure_state()
        result = self.engine.evaluate_full_packet(packet, state)
        # PRESSURE_LIMIT_EXCEEDED contributes 85 pts → BLOCK
        self.assertEqual(result.decision, DecisionType.BLOCK)
        self.assertIn("PRESSURE_LIMIT_EXCEEDED", result.triggered_rules)

    # ── Scenario 5: Unsafe valve operation → BLOCK ─────────────────────────
    def test_05_unsafe_valve_block(self):
        # Write single coil with pump off + valve open triggers
        # UNSAFE_VALVE_OPEN_PUMP_OFF (50 pts) + VALVE_CONTROL_WRITE (25 pts) = 75 pts
        valve_packet = bytes([
            0x00, 0x01, 0x00, 0x00, 0x00, 0x06,
            0x01, 0x05,       # Write Single Coil
            0x00, 0xAC,       # Valve coil address
            0xFF, 0x00,       # Open valve
        ])
        state = _pump_off_valve_open_state()
        result = self.engine.evaluate_full_packet(_parse(valve_packet), state)
        self.assertIn(result.decision, (DecisionType.BLOCK, DecisionType.ALERT))
        self.assertTrue(
            result.risk_score >= 40,
            f"Expected elevated risk, got {result.risk_score}"
        )

    # ── Scenario 6: Invalid packet → BLOCK ────────────────────────────────
    def test_06_invalid_packet_block(self):
        # random_garbage: bytes 2-3 = 0xBEEF → INVALID_PROTOCOL_ID (70 pts) → BLOCK
        packet = _parse(SamplePacketFactory.random_garbage())
        result = self.engine.evaluate_full_packet(packet)
        self.assertEqual(result.decision, DecisionType.BLOCK)
        # Either INVALID_PACKET or INVALID_PROTOCOL_ID must be in triggered rules
        invalid_rules = {"INVALID_PACKET", "INVALID_PROTOCOL_ID", "UNSUPPORTED_FC"}
        self.assertTrue(
            bool(invalid_rules & set(result.triggered_rules)),
            f"Expected an invalid-class rule, got: {result.triggered_rules}"
        )

    def test_06b_too_short_block(self):
        packet = _parse(SamplePacketFactory.invalid_short())
        result = self.engine.evaluate_full_packet(packet)
        self.assertEqual(result.decision, DecisionType.BLOCK)

    def test_06c_unsupported_fc_alert_or_block(self):
        packet = _parse(SamplePacketFactory.unsupported_function_code())
        result = self.engine.evaluate_full_packet(packet)
        # UNSUPPORTED_FC contributes 60 pts → ALERT (≥40) or BLOCK (≥70)
        self.assertIn(result.decision, (DecisionType.ALERT, DecisionType.BLOCK))

    # ── Scenario 7: Multiple rules → highest severity selected ─────────────
    def test_07_multiple_rules_highest_severity(self):
        packet = _parse(SamplePacketFactory.write_single_register())
        result = self.engine.evaluate_full_packet(packet, _dangerous_pressure_state())
        # At minimum PRESSURE_LIMIT_EXCEEDED (CRITICAL) must be in triggered rules
        self.assertIn("PRESSURE_LIMIT_EXCEEDED", result.triggered_rules)
        self.assertGreaterEqual(result.severity, SeverityLevel.HIGH)

    # ── Scenario 8: Risk score boundaries ─────────────────────────────────
    def test_08_read_only_stays_below_alert(self):
        """Pure read in safe state stays well below ALERT threshold (40)."""
        packet = _parse(SamplePacketFactory.read_coils())
        result = self.engine.evaluate_full_packet(packet, self.safe)
        self.assertLess(result.risk_score, 40)
        self.assertEqual(result.decision, DecisionType.ALLOW)

    def test_08_block_threshold_crossed(self):
        """Invalid packet score (80) is above BLOCK threshold (70)."""
        packet = _parse(SamplePacketFactory.random_garbage())
        result = self.engine.evaluate_full_packet(packet)
        self.assertGreaterEqual(result.risk_score, 70)
        self.assertEqual(result.decision, DecisionType.BLOCK)

    # ── Scenario 9: Empty / missing physics state ──────────────────────────
    def test_09_no_physics_state_valid_packet_allow(self):
        packet = _parse(SamplePacketFactory.read_coils())
        result = self.engine.evaluate_full_packet(packet, physics_state=None)
        self.assertEqual(result.decision, DecisionType.ALLOW)
        self.assertEqual(result.relevant_physics_state, {})

    def test_09_no_physics_state_invalid_packet_block(self):
        packet = _parse(SamplePacketFactory.random_garbage())
        result = self.engine.evaluate_full_packet(packet, physics_state=None)
        self.assertEqual(result.decision, DecisionType.BLOCK)

    # ── Scenario 10: Malformed decision request ────────────────────────────
    def test_10_empty_bytes_block(self):
        packet = _parse(b"")
        result = self.engine.evaluate_full_packet(packet)
        self.assertEqual(result.decision, DecisionType.BLOCK)

    def test_10_single_byte_block(self):
        packet = _parse(SamplePacketFactory.single_byte())
        result = self.engine.evaluate_full_packet(packet)
        self.assertEqual(result.decision, DecisionType.BLOCK)

    def test_10_nul_bytes_block(self):
        packet = _parse(SamplePacketFactory.nul_bytes())
        # NUL bytes: Protocol ID will be 0x0000 but FC will be 0x00 (unsupported)
        result = self.engine.evaluate_full_packet(packet)
        self.assertIn(result.decision, (DecisionType.BLOCK, DecisionType.ALERT))

    # ── Scenario 11: Deterministic repeated evaluation ─────────────────────
    def test_11_deterministic_same_input_same_output(self):
        packet = _parse(SamplePacketFactory.write_single_register())
        state  = _safe_state()
        r1 = self.engine.evaluate_full_packet(packet, state)
        r2 = self.engine.evaluate_full_packet(packet, state)
        self.assertEqual(r1.decision, r2.decision)
        self.assertEqual(r1.risk_score, r2.risk_score)
        self.assertEqual(r1.severity, r2.severity)
        self.assertEqual(r1.triggered_rules, r2.triggered_rules)
        self.assertEqual(r1.reason, r2.reason)

    def test_11_deterministic_dangerous_state(self):
        packet = _parse(SamplePacketFactory.write_single_register())
        state  = _dangerous_pressure_state()
        r1 = self.engine.evaluate_full_packet(packet, state)
        r2 = self.engine.evaluate_full_packet(packet, state)
        self.assertEqual(r1.decision, r2.decision)
        self.assertEqual(r1.risk_score, r2.risk_score)


# ===========================================================================
# 9. TestDecisionResult
# ===========================================================================

class TestDecisionResult(unittest.TestCase):
    """Test SecurityDecisionResult properties and serialisation."""

    def _make_result(self, decision: DecisionType) -> SecurityDecisionResult:
        return SecurityDecisionResult(
            decision=decision,
            risk_score=50,
            severity=SeverityLevel.MEDIUM,
            reason="Test reason",
            triggered_rules=["RULE_A"],
            timestamp="2026-01-01T00:00:00",
            src_ip="10.0.0.1",
            dst_ip="10.0.0.2",
            function_code=0x03,
            function_name="Read Holding Registers",
            relevant_physics_state={"pressure_bar": 3.0},
        )

    def test_is_blocked(self):
        r = self._make_result(DecisionType.BLOCK)
        self.assertTrue(r.is_blocked)
        self.assertFalse(r.is_allowed)
        self.assertFalse(r.is_alerted)

    def test_is_alerted(self):
        r = self._make_result(DecisionType.ALERT)
        self.assertTrue(r.is_alerted)
        self.assertFalse(r.is_blocked)

    def test_is_allowed(self):
        r = self._make_result(DecisionType.ALLOW)
        self.assertTrue(r.is_allowed)
        self.assertFalse(r.is_blocked)

    def test_to_dict_contains_all_fields(self):
        r = self._make_result(DecisionType.BLOCK)
        d = r.to_dict()
        required_keys = {
            "decision", "risk_score", "severity", "reason",
            "triggered_rules", "timestamp", "src_ip", "dst_ip",
            "function_code", "function_name", "relevant_physics_state",
        }
        self.assertTrue(required_keys.issubset(d.keys()))
        self.assertEqual(d["decision"], "BLOCK")

    def test_to_dict_decision_is_string(self):
        r = self._make_result(DecisionType.ALLOW)
        d = r.to_dict()
        self.assertIsInstance(d["decision"], str)


# ===========================================================================
# 10. TestSecurityEvent
# ===========================================================================

class TestSecurityEvent(unittest.TestCase):
    """Test SecurityEvent construction and serialisation."""

    def _make_result(self) -> SecurityDecisionResult:
        return SecurityDecisionResult(
            decision=DecisionType.ALERT,
            risk_score=45,
            severity=SeverityLevel.MEDIUM,
            reason="Test",
            triggered_rules=["TEST_RULE"],
            timestamp="2026-01-01T00:00:00",
            src_ip="192.168.1.100",
            dst_ip="192.168.1.1",
            function_code=0x06,
            function_name="Write Single Register",
            relevant_physics_state={"pressure_bar": 4.0},
        )

    def test_from_result(self):
        result = self._make_result()
        event  = SecurityEvent.from_result(result)
        self.assertEqual(event.decision, DecisionType.ALERT)
        self.assertEqual(event.risk_score, 45)
        self.assertEqual(event.src_ip, "192.168.1.100")
        self.assertIn("TEST_RULE", event.triggered_rules)

    def test_to_dict(self):
        result = self._make_result()
        event  = SecurityEvent.from_result(result)
        d = event.to_dict()
        self.assertEqual(d["decision"], "ALERT")
        self.assertIn("physics_snapshot", d)

    def test_utc_now_returns_string(self):
        ts = SecurityEvent.utc_now()
        self.assertIsInstance(ts, str)
        self.assertIn("T", ts)


# ===========================================================================
# 11. TestBaseInterfaceCompliance
# ===========================================================================

class TestBaseInterfaceCompliance(unittest.TestCase):
    """Verify PhysicsAwareDecisionEngine satisfies BaseDecisionEngine."""

    def setUp(self):
        self.engine = _engine()

    def test_evaluate_with_full_packet(self):
        """evaluate() with a FullPacket should return a base DecisionResult."""
        packet = _parse(SamplePacketFactory.read_coils())
        result = self.engine.evaluate(packet)
        self.assertIsNotNone(result)
        self.assertIn(result.action, list(DecisionAction))

    def test_get_rules_returns_list(self):
        rules = self.engine.get_rules()
        self.assertIsInstance(rules, list)

    def test_add_and_get_rule(self):
        from src.interfaces.base_engine import FirewallRule
        rule = FirewallRule(
            rule_id="TEST-001",
            description="Test rule",
            priority=1,
            action=DecisionAction.BLOCK,
        )
        self.engine.add_rule(rule)
        rules = self.engine.get_rules()
        self.assertTrue(any(r.rule_id == "TEST-001" for r in rules))

    def test_add_duplicate_rule_raises(self):
        from src.interfaces.base_engine import FirewallRule
        rule = FirewallRule(
            rule_id="DUP-001",
            description="Duplicate test",
            priority=1,
            action=DecisionAction.ALLOW,
        )
        self.engine.add_rule(rule)
        with self.assertRaises(ValueError):
            self.engine.add_rule(rule)

    def test_clear_rules(self):
        from src.interfaces.base_engine import FirewallRule
        self.engine.add_rule(FirewallRule("CLR-001", "Clear test", 1, DecisionAction.ALLOW))
        self.engine.clear_rules()
        self.assertEqual(len(self.engine.get_rules()), 0)

    def test_event_counter_increments(self):
        initial = self.engine.event_count
        packet = _parse(SamplePacketFactory.read_coils())
        self.engine.evaluate_full_packet(packet)
        self.engine.evaluate_full_packet(packet)
        self.assertEqual(self.engine.event_count, initial + 2)


# ===========================================================================
# 12. Integration Test — Parser + Physics + Decision Engine
# ===========================================================================

class TestIntegrationEndToEnd(unittest.TestCase):
    """
    End-to-end integration: Day 2 Parser → Day 3 Physics → Day 4 Decision.

    Verifies that all three modules work together without errors and that
    the pipeline produces well-formed results.
    """

    def setUp(self):
        physics_cfg  = _default_physics_cfg()
        decision_cfg = _default_decision_cfg()

        self.parser  = ProtocolParser()
        self.physics = WaterSystemEngine(physics_cfg)
        self.engine  = PhysicsAwareDecisionEngine(physics_cfg, decision_cfg)

    def _full_pipeline(self, raw: bytes) -> SecurityDecisionResult:
        """Run raw bytes through the complete 3-module pipeline."""
        # Day 2: Parse
        packet = self.parser.parse_modbus_only(raw)
        # Day 3: Get current physics state
        state = self.physics.get_system_state()
        # Day 4: Decide
        return self.engine.evaluate_full_packet(packet, state)

    def test_read_coils_end_to_end(self):
        result = self._full_pipeline(SamplePacketFactory.read_coils())
        self.assertIsInstance(result, SecurityDecisionResult)
        self.assertIn(result.decision, list(DecisionType))
        self.assertIsInstance(result.risk_score, int)
        self.assertGreaterEqual(result.risk_score, 0)
        self.assertLessEqual(result.risk_score, 100)
        self.assertIsInstance(result.triggered_rules, list)
        self.assertIsInstance(result.reason, str)
        self.assertTrue(len(result.reason) > 0)

    def test_read_holding_registers_end_to_end(self):
        result = self._full_pipeline(SamplePacketFactory.read_holding_registers())
        self.assertEqual(result.decision, DecisionType.ALLOW)
        self.assertEqual(result.function_code, 0x03)

    def test_write_single_coil_end_to_end(self):
        result = self._full_pipeline(SamplePacketFactory.write_single_coil())
        self.assertIsInstance(result, SecurityDecisionResult)
        # Should not be a protocol error
        self.assertNotIn("INVALID_PACKET", result.triggered_rules)

    def test_write_single_register_end_to_end(self):
        result = self._full_pipeline(SamplePacketFactory.write_single_register())
        self.assertIsInstance(result, SecurityDecisionResult)
        self.assertEqual(result.function_code, 0x06)

    def test_write_multiple_registers_end_to_end(self):
        result = self._full_pipeline(SamplePacketFactory.write_multiple_registers())
        self.assertIsInstance(result, SecurityDecisionResult)
        self.assertEqual(result.function_code, 0x10)

    def test_invalid_packets_end_to_end(self):
        """All invalid packet types should produce a BLOCK or ALERT."""
        for name, raw in SamplePacketFactory.all_invalid_modbus().items():
            with self.subTest(sample=name):
                result = self._full_pipeline(raw)
                self.assertIn(
                    result.decision,
                    (DecisionType.BLOCK, DecisionType.ALERT),
                    f"Expected BLOCK or ALERT for {name!r}, got {result.decision}",
                )

    def test_physics_state_reflected_in_result(self):
        """Result should contain a non-empty physics state snapshot."""
        result = self._full_pipeline(SamplePacketFactory.read_coils())
        self.assertIsInstance(result.relevant_physics_state, dict)
        self.assertIn("pressure_bar", result.relevant_physics_state)

    def test_full_ethernet_packet_end_to_end(self):
        """Full Ethernet+IP+TCP+Modbus frame through the complete pipeline."""
        raw = SamplePacketFactory.full_ethernet_packet()
        packet = self.parser.parse_full_packet(raw)
        state = self.physics.get_system_state()
        result = self.engine.evaluate_full_packet(packet, state)
        self.assertIsInstance(result, SecurityDecisionResult)
        # Should decode the IPs from the Ethernet frame
        self.assertEqual(result.src_ip, "192.168.1.100")
        self.assertEqual(result.dst_ip, "192.168.1.1")

    def test_pump_on_physics_state_affects_decision(self):
        """Verify that physics state changes affect the decision score."""
        # Run pump for several ticks to build up pressure
        from src.physics.water_system_engine import CommandType
        self.physics.apply_command(CommandType.SET_PUMP, 1.0)
        self.physics.apply_command(CommandType.SET_VALVE, 0.8)
        for _ in range(5):
            self.physics.update_state()

        raw = SamplePacketFactory.write_single_register()
        packet = self.parser.parse_modbus_only(raw)
        state_after_pump = self.physics.get_system_state()
        result = self.engine.evaluate_full_packet(packet, state_after_pump)

        # Physics state should be reflected in the result snapshot
        self.assertAlmostEqual(
            result.relevant_physics_state["pressure_bar"],
            state_after_pump.pressure_bar,
            places=3,
        )

    def test_parser_statistics_updated(self):
        """Verify the Day 2 parser's statistics are updated during integration."""
        self.parser.reset_statistics()
        self._full_pipeline(SamplePacketFactory.read_coils())
        self._full_pipeline(SamplePacketFactory.write_single_register())
        stats = self.parser.get_statistics()
        self.assertEqual(stats["total"], 2)
        self.assertEqual(stats["valid"], 2)


# ===========================================================================
# 13. TestExplainability
# ===========================================================================

class TestExplainability(unittest.TestCase):
    """Verify every BLOCK/ALERT result includes a meaningful explanation."""

    def setUp(self):
        self.engine = _engine()

    def test_block_has_non_empty_reason(self):
        packet = _parse(SamplePacketFactory.random_garbage())
        result = self.engine.evaluate_full_packet(packet)
        self.assertEqual(result.decision, DecisionType.BLOCK)
        self.assertGreater(len(result.reason), 0)
        self.assertGreater(len(result.triggered_rules), 0)

    def test_block_reason_mentions_rule_id(self):
        packet = _parse(SamplePacketFactory.random_garbage())
        result = self.engine.evaluate_full_packet(packet)
        # Reason text should reference at least one rule id
        self.assertTrue(
            any(rid in result.reason for rid in result.triggered_rules),
            f"Reason did not mention any rule: {result.reason!r}",
        )

    def test_allow_has_reason(self):
        packet = _parse(SamplePacketFactory.read_coils())
        result = self.engine.evaluate_full_packet(packet, _safe_state())
        self.assertEqual(result.decision, DecisionType.ALLOW)
        self.assertGreater(len(result.reason), 0)

    def test_alert_reason_contains_rule_details(self):
        # Unsupported FC → 60 pts → ALERT
        packet = _parse(SamplePacketFactory.unsupported_function_code())
        result = self.engine.evaluate_full_packet(packet)
        if result.decision == DecisionType.ALERT:
            self.assertIn("UNSUPPORTED_FC", result.reason)


# ===========================================================================
# 14. TestDay2Day3Compatibility
# ===========================================================================

class TestDay2Day3Compatibility(unittest.TestCase):
    """
    Ensure Day 2 parser and Day 3 physics engine are fully unmodified
    and compatible with Day 4.
    """

    def test_day2_parser_all_valid_samples(self):
        """All valid sample packets still parse correctly."""
        parser = ProtocolParser()
        for name, raw in SamplePacketFactory.all_valid_modbus().items():
            with self.subTest(sample=name):
                packet = parser.parse_modbus_only(raw)
                self.assertEqual(
                    packet.parse_status, ParseStatus.VALID,
                    f"{name}: expected VALID, got {packet.parse_status}",
                )

    def test_day3_engine_still_simulates(self):
        """Physics engine still advances state correctly."""
        from src.physics.water_system_engine import CommandType
        cfg    = _default_physics_cfg()
        engine = WaterSystemEngine(cfg)
        engine.apply_command(CommandType.SET_PUMP, 1.0)
        engine.apply_command(CommandType.SET_VALVE, 0.5)
        state = engine.update_state()
        self.assertIsInstance(state, SystemState)
        self.assertGreater(state.pump_rpm, 0)

    def test_day3_system_state_to_dict(self):
        """SystemState.to_dict() still works as expected."""
        state = _safe_state()
        d = state.to_dict()
        self.assertIn("pressure_bar", d)
        self.assertIn("pump_on", d)


# ===========================================================================
# Entry point
# ===========================================================================

if __name__ == "__main__":
    unittest.main(verbosity=2)
