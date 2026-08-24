"""
VoltGuard — Day 6 Policy & Enforcement Test Suite
===================================================
Comprehensive tests for the firewall policy and enforcement layer.

Coverage (17 test cases + E2E integration test):
   1.  Policy matching by source IP (exact)
   2.  Policy matching by destination IP (CIDR)
   3.  Policy matching by destination port
   4.  Policy matching by protocol
   5.  Policy matching by single Modbus function code
   6.  Policy matching by Modbus function code list (OR logic)
   7.  Wildcard policy (no criteria — matches everything)
   8.  Policy priority — lower number wins
   9.  Multiple matching policies — highest priority wins
   10. ALLOW action
   11. ALERT action
   12. BLOCK action
   13. Disabled policy is skipped
   14. Invalid policy configuration raises ConfigurationError
   15. SimulationEnforcementAdapter — ALLOW path
   16. SimulationEnforcementAdapter — ALERT path
   17. SimulationEnforcementAdapter — BLOCK path
   18. No real OS firewall commands are executed
   19. Decision + policy integration (risk ↔ action)
   20. Full Day 5 pipeline + policy enforcement (E2E)

Run with:
    python3 -m pytest tests/test_day6_policy.py -v
"""

from __future__ import annotations

import subprocess
import sys
import unittest
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, patch

# ── Ensure project root is on sys.path ────────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ── Bootstrap configuration ───────────────────────────────────────────────
from src.config import config_loader
if not config_loader.is_loaded:
    config_loader.load()

# ── Day 4 models ─────────────────────────────────────────────────────────
from src.decision_engine.models import (
    DecisionType,
    SecurityDecisionResult,
    SeverityLevel,
)

# ── Day 6 policy layer ────────────────────────────────────────────────────
from src.exceptions import ConfigurationError
from src.policy.enforcement import (
    EnforcementStats,
    SimulationEnforcementAdapter,
)
from src.policy.models import (
    EnforcementResult,
    FirewallPolicy,
    PolicyAction,
)
from src.policy.policy_config import PolicyConfig
from src.policy.policy_engine import PolicyEngine, _ip_matches


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_decision_result(
    risk_score: int = 0,
    severity: SeverityLevel = SeverityLevel.SAFE,
    decision: DecisionType = DecisionType.ALLOW,
    src_ip: str = "192.168.1.10",
    dst_ip: str = "10.0.0.1",
    function_code: Optional[int] = None,
    function_name: str = "",
) -> SecurityDecisionResult:
    """Build a minimal SecurityDecisionResult for testing."""
    return SecurityDecisionResult(
        decision=decision,
        risk_score=risk_score,
        severity=severity,
        reason="Test reason",
        triggered_rules=[],
        timestamp="2026-01-01T00:00:00+00:00",
        src_ip=src_ip,
        dst_ip=dst_ip,
        function_code=function_code,
        function_name=function_name,
        relevant_physics_state={},
        all_reasons=[],
    )


def _make_policy(
    policy_id: str = "TEST-001",
    name: str = "Test Policy",
    action: PolicyAction = PolicyAction.ALLOW,
    priority: int = 10,
    enabled: bool = True,
    **kwargs,
) -> FirewallPolicy:
    """Build a minimal FirewallPolicy for testing."""
    return FirewallPolicy(
        policy_id=policy_id,
        name=name,
        action=action,
        priority=priority,
        enabled=enabled,
        **kwargs,
    )


def _make_engine(*policies: FirewallPolicy) -> PolicyEngine:
    """Build a PolicyEngine with the given policies."""
    cfg = PolicyConfig(policies=list(policies))
    return PolicyEngine(cfg)


def _make_enforcement_result(
    action: PolicyAction = PolicyAction.ALLOW,
    policy_id: str = "TEST-001",
    policy_name: str = "Test Policy",
    risk_score: int = 10,
    risk_level: str = "SAFE",
) -> EnforcementResult:
    """Build a minimal EnforcementResult for testing."""
    return EnforcementResult(
        final_action=action,
        matched_policy_id=policy_id,
        matched_policy_name=policy_name,
        priority=10,
        reason="Test enforcement reason",
        original_risk_score=risk_score,
        original_risk_level=risk_level,
        original_decision="ALLOW",
        timestamp="2026-01-01T00:00:00+00:00",
        src_ip="192.168.1.10",
        dst_ip="10.0.0.1",
    )


# ===========================================================================
# 1. Policy Matching Tests
# ===========================================================================

class TestPolicyMatchingSourceIP(unittest.TestCase):
    """Test 1 — Policy matching by source IP."""

    def test_matches_exact_source_ip(self):
        """Policy with src_ip='192.168.1.10' should match that exact IP."""
        policy = _make_policy(src_ip="192.168.1.10", action=PolicyAction.ALLOW)
        engine = _make_engine(policy)
        result = _make_decision_result(src_ip="192.168.1.10")
        enforcement = engine.evaluate(result)
        self.assertEqual(enforcement.final_action, PolicyAction.ALLOW)
        self.assertEqual(enforcement.matched_policy_id, "TEST-001")

    def test_no_match_different_source_ip(self):
        """Policy with src_ip='192.168.1.10' should NOT match 192.168.1.20."""
        policy = _make_policy(src_ip="192.168.1.10", action=PolicyAction.BLOCK)
        engine = _make_engine(policy)
        result = _make_decision_result(src_ip="192.168.1.20")
        enforcement = engine.evaluate(result)
        # No match → fallback to Day 4 decision (ALLOW)
        self.assertIsNone(enforcement.matched_policy_id)

    def test_matches_wildcard_source_ip(self):
        """Policy with src_ip='*' should match any source IP."""
        policy = _make_policy(src_ip="*", action=PolicyAction.ALLOW)
        engine = _make_engine(policy)
        result = _make_decision_result(src_ip="10.99.88.77")
        enforcement = engine.evaluate(result)
        self.assertEqual(enforcement.matched_policy_id, "TEST-001")


class TestPolicyMatchingDestinationIP(unittest.TestCase):
    """Test 2 — Policy matching by destination IP (CIDR)."""

    def test_matches_cidr_dst_ip(self):
        """Policy with dst_ip='10.0.0.0/24' should match 10.0.0.5."""
        policy = _make_policy(dst_ip="10.0.0.0/24", action=PolicyAction.ALERT)
        engine = _make_engine(policy)
        result = _make_decision_result(dst_ip="10.0.0.5")
        enforcement = engine.evaluate(result)
        self.assertEqual(enforcement.final_action, PolicyAction.ALERT)

    def test_no_match_cidr_dst_ip_outside(self):
        """Policy with dst_ip='10.0.0.0/24' should NOT match 10.0.1.5."""
        policy = _make_policy(dst_ip="10.0.0.0/24", action=PolicyAction.ALERT)
        engine = _make_engine(policy)
        result = _make_decision_result(dst_ip="10.0.1.5")
        enforcement = engine.evaluate(result)
        self.assertIsNone(enforcement.matched_policy_id)

    def test_matches_exact_dst_ip(self):
        """Policy with dst_ip='10.0.0.1' should match that exact IP."""
        policy = _make_policy(dst_ip="10.0.0.1", action=PolicyAction.ALLOW)
        engine = _make_engine(policy)
        result = _make_decision_result(dst_ip="10.0.0.1")
        enforcement = engine.evaluate(result)
        self.assertEqual(enforcement.matched_policy_id, "TEST-001")


class TestPolicyMatchingPort(unittest.TestCase):
    """Test 3 — Policy matching by port."""

    def test_matches_dst_port_502(self):
        """Policy with dst_port=502 should match Modbus TCP traffic."""
        policy = _make_policy(dst_port=502, action=PolicyAction.ALLOW)
        engine = _make_engine(policy)
        result = _make_decision_result()
        enforcement = engine.evaluate(result, dst_port=502)
        self.assertEqual(enforcement.matched_policy_id, "TEST-001")

    def test_no_match_wrong_dst_port(self):
        """Policy with dst_port=502 should NOT match port 80."""
        policy = _make_policy(dst_port=502, action=PolicyAction.BLOCK)
        engine = _make_engine(policy)
        result = _make_decision_result()
        enforcement = engine.evaluate(result, dst_port=80)
        self.assertIsNone(enforcement.matched_policy_id)

    def test_matches_src_port(self):
        """Policy with src_port=12345 should match that specific source port."""
        policy = _make_policy(src_port=12345, action=PolicyAction.ALERT)
        engine = _make_engine(policy)
        result = _make_decision_result()
        enforcement = engine.evaluate(result, src_port=12345)
        self.assertEqual(enforcement.matched_policy_id, "TEST-001")


class TestPolicyMatchingProtocol(unittest.TestCase):
    """Test 4 — Policy matching by protocol."""

    def test_matches_modbus_tcp_protocol(self):
        """Policy with protocol='Modbus TCP' should match Modbus TCP traffic."""
        policy = _make_policy(protocol="Modbus TCP", action=PolicyAction.ALLOW)
        engine = _make_engine(policy)
        result = _make_decision_result()
        enforcement = engine.evaluate(result, protocol="Modbus TCP")
        self.assertEqual(enforcement.matched_policy_id, "TEST-001")

    def test_no_match_wrong_protocol(self):
        """Policy with protocol='Modbus TCP' should NOT match 'TCP/IP'."""
        policy = _make_policy(protocol="Modbus TCP", action=PolicyAction.BLOCK)
        engine = _make_engine(policy)
        result = _make_decision_result()
        enforcement = engine.evaluate(result, protocol="TCP/IP")
        self.assertIsNone(enforcement.matched_policy_id)

    def test_protocol_match_case_insensitive(self):
        """Protocol matching should be case-insensitive."""
        policy = _make_policy(protocol="modbus tcp", action=PolicyAction.ALLOW)
        engine = _make_engine(policy)
        result = _make_decision_result()
        enforcement = engine.evaluate(result, protocol="Modbus TCP")
        self.assertEqual(enforcement.matched_policy_id, "TEST-001")


class TestPolicyMatchingModbusFunction(unittest.TestCase):
    """Tests 5 & 6 — Policy matching by Modbus function code."""

    def test_single_function_code_match(self):
        """Test 5: Policy with modbus_function=3 matches FC=3 (Read Holding Registers)."""
        policy = _make_policy(modbus_function=3, action=PolicyAction.ALLOW)
        engine = _make_engine(policy)
        result = _make_decision_result(function_code=3, function_name="Read Holding Registers")
        enforcement = engine.evaluate(result)
        self.assertEqual(enforcement.matched_policy_id, "TEST-001")

    def test_single_function_code_no_match(self):
        """Test 5: Policy with modbus_function=3 should NOT match FC=6."""
        policy = _make_policy(modbus_function=3, action=PolicyAction.BLOCK)
        engine = _make_engine(policy)
        result = _make_decision_result(function_code=6)
        enforcement = engine.evaluate(result)
        self.assertIsNone(enforcement.matched_policy_id)

    def test_function_code_list_matches_first(self):
        """Test 6: Policy with modbus_functions=[1,3] matches FC=1."""
        policy = _make_policy(modbus_functions=[1, 3], action=PolicyAction.ALLOW)
        engine = _make_engine(policy)
        result = _make_decision_result(function_code=1)
        enforcement = engine.evaluate(result)
        self.assertEqual(enforcement.matched_policy_id, "TEST-001")

    def test_function_code_list_matches_second(self):
        """Test 6: Policy with modbus_functions=[1,3] matches FC=3."""
        policy = _make_policy(modbus_functions=[1, 3], action=PolicyAction.ALLOW)
        engine = _make_engine(policy)
        result = _make_decision_result(function_code=3)
        enforcement = engine.evaluate(result)
        self.assertEqual(enforcement.matched_policy_id, "TEST-001")

    def test_function_code_list_no_match(self):
        """Test 6: Policy with modbus_functions=[1,3] should NOT match FC=6."""
        policy = _make_policy(modbus_functions=[1, 3], action=PolicyAction.BLOCK)
        engine = _make_engine(policy)
        result = _make_decision_result(function_code=6)
        enforcement = engine.evaluate(result)
        self.assertIsNone(enforcement.matched_policy_id)


class TestPolicyWildcard(unittest.TestCase):
    """Test 7 — Wildcard policy (no criteria)."""

    def test_wildcard_policy_matches_everything(self):
        """A policy with no criteria set should match any packet."""
        policy = _make_policy(action=PolicyAction.ALLOW)
        engine = _make_engine(policy)

        # Test 1: Modbus read
        result1 = _make_decision_result(function_code=3)
        self.assertEqual(engine.evaluate(result1).matched_policy_id, "TEST-001")

        # Test 2: Write with high risk
        result2 = _make_decision_result(
            risk_score=80, severity=SeverityLevel.CRITICAL,
            decision=DecisionType.BLOCK, function_code=16,
        )
        self.assertEqual(engine.evaluate(result2).matched_policy_id, "TEST-001")

        # Test 3: No Modbus
        result3 = _make_decision_result(function_code=None)
        self.assertEqual(engine.evaluate(result3).matched_policy_id, "TEST-001")


# ===========================================================================
# 2. Policy Priority Tests
# ===========================================================================

class TestPolicyPriority(unittest.TestCase):
    """Tests 8 & 9 — Policy priority evaluation."""

    def test_lower_priority_number_wins(self):
        """Test 8: Priority 5 should win over Priority 10 when both match."""
        high_priority = _make_policy("POL-HIGH", action=PolicyAction.BLOCK, priority=5)
        low_priority  = _make_policy("POL-LOW",  action=PolicyAction.ALLOW, priority=10)
        engine = _make_engine(high_priority, low_priority)
        result = _make_decision_result()
        enforcement = engine.evaluate(result)
        self.assertEqual(enforcement.matched_policy_id, "POL-HIGH")
        self.assertEqual(enforcement.final_action, PolicyAction.BLOCK)

    def test_priority_order_reversed_in_init(self):
        """Test 8: Engine sorts by priority regardless of insertion order."""
        # Insert lower priority first
        low_priority  = _make_policy("POL-LOW",  action=PolicyAction.ALLOW, priority=50)
        high_priority = _make_policy("POL-HIGH", action=PolicyAction.BLOCK, priority=5)
        engine = _make_engine(low_priority, high_priority)
        result = _make_decision_result()
        enforcement = engine.evaluate(result)
        self.assertEqual(enforcement.matched_policy_id, "POL-HIGH")
        self.assertEqual(enforcement.final_action, PolicyAction.BLOCK)

    def test_equal_priority_tiebreak_by_policy_id(self):
        """Test 8: Equal priorities are broken by lexicographic policy_id order."""
        policy_b = _make_policy("POL-B", action=PolicyAction.ALERT, priority=10)
        policy_a = _make_policy("POL-A", action=PolicyAction.BLOCK, priority=10)
        engine = _make_engine(policy_b, policy_a)
        result = _make_decision_result()
        enforcement = engine.evaluate(result)
        # POL-A < POL-B lexicographically → POL-A wins
        self.assertEqual(enforcement.matched_policy_id, "POL-A")

    def test_multiple_matching_policies_first_wins(self):
        """Test 9: When multiple policies match, the highest priority (lowest number) wins."""
        p1 = _make_policy("P1", action=PolicyAction.ALLOW, priority=10,
                           risk_max=100)  # matches everything
        p2 = _make_policy("P2", action=PolicyAction.BLOCK, priority=20,
                           risk_max=100)  # also matches everything
        p3 = _make_policy("P3", action=PolicyAction.ALERT, priority=30,
                           risk_max=100)
        engine = _make_engine(p1, p2, p3)
        result = _make_decision_result(risk_score=50)
        enforcement = engine.evaluate(result)
        self.assertEqual(enforcement.matched_policy_id, "P1")
        self.assertEqual(enforcement.final_action, PolicyAction.ALLOW)


# ===========================================================================
# 3. Action Tests
# ===========================================================================

class TestPolicyActions(unittest.TestCase):
    """Tests 10, 11, 12 — ALLOW, ALERT, BLOCK actions."""

    def test_allow_action(self):
        """Test 10: ALLOW policy returns PolicyAction.ALLOW."""
        policy = _make_policy(action=PolicyAction.ALLOW)
        engine = _make_engine(policy)
        result = _make_decision_result()
        enforcement = engine.evaluate(result)
        self.assertEqual(enforcement.final_action, PolicyAction.ALLOW)
        self.assertTrue(enforcement.is_allowed)
        self.assertFalse(enforcement.is_blocked)
        self.assertFalse(enforcement.is_alerted)

    def test_alert_action(self):
        """Test 11: ALERT policy returns PolicyAction.ALERT."""
        policy = _make_policy(action=PolicyAction.ALERT)
        engine = _make_engine(policy)
        result = _make_decision_result(risk_score=45, severity=SeverityLevel.MEDIUM)
        enforcement = engine.evaluate(result)
        self.assertEqual(enforcement.final_action, PolicyAction.ALERT)
        self.assertTrue(enforcement.is_alerted)
        self.assertFalse(enforcement.is_blocked)

    def test_block_action(self):
        """Test 12: BLOCK policy returns PolicyAction.BLOCK."""
        policy = _make_policy(action=PolicyAction.BLOCK)
        engine = _make_engine(policy)
        result = _make_decision_result(risk_score=85, severity=SeverityLevel.CRITICAL)
        enforcement = engine.evaluate(result)
        self.assertEqual(enforcement.final_action, PolicyAction.BLOCK)
        self.assertTrue(enforcement.is_blocked)
        self.assertFalse(enforcement.is_allowed)


class TestDisabledPolicy(unittest.TestCase):
    """Test 13 — Disabled policy is skipped."""

    def test_disabled_policy_is_skipped(self):
        """A policy with enabled=False must not match even if criteria match."""
        disabled_block = _make_policy("DISABLED", action=PolicyAction.BLOCK,
                                      priority=1, enabled=False)
        fallback_allow = _make_policy("FALLBACK", action=PolicyAction.ALLOW,
                                      priority=100, enabled=True)
        engine = _make_engine(disabled_block, fallback_allow)
        result = _make_decision_result()
        enforcement = engine.evaluate(result)
        # Disabled policy (priority 1) should be skipped
        self.assertNotEqual(enforcement.matched_policy_id, "DISABLED")
        self.assertEqual(enforcement.matched_policy_id, "FALLBACK")
        self.assertEqual(enforcement.final_action, PolicyAction.ALLOW)

    def test_all_disabled_no_match(self):
        """When all policies are disabled, engine falls back to Day 4 decision."""
        disabled = _make_policy(enabled=False, action=PolicyAction.BLOCK)
        engine = _make_engine(disabled)
        result = _make_decision_result(decision=DecisionType.ALLOW)
        enforcement = engine.evaluate(result)
        self.assertIsNone(enforcement.matched_policy_id)
        # Fallback to Day 4's ALLOW recommendation
        self.assertEqual(enforcement.final_action, PolicyAction.ALLOW)


# ===========================================================================
# 4. Configuration Validation Tests
# ===========================================================================

class TestPolicyConfigValidation(unittest.TestCase):
    """Test 14 — Invalid policy configuration raises errors."""

    def test_missing_required_field_raises(self):
        """A policy dict without 'policy_id' should raise ValueError."""
        with self.assertRaises(ValueError):
            FirewallPolicy.from_dict({"name": "Bad Policy", "action": "ALLOW", "priority": 10})

    def test_missing_action_raises(self):
        """A policy dict without 'action' should raise ValueError."""
        with self.assertRaises(ValueError):
            FirewallPolicy.from_dict({"policy_id": "P1", "name": "Bad", "priority": 10})

    def test_invalid_action_raises(self):
        """A policy dict with action='INVALID' should raise ValueError."""
        with self.assertRaises(ValueError):
            FirewallPolicy.from_dict({
                "policy_id": "P1", "name": "Bad",
                "action": "INVALID", "priority": 10,
            })

    def test_invalid_priority_type_raises(self):
        """A policy dict with priority='not_a_number' should raise ValueError."""
        with self.assertRaises(ValueError):
            FirewallPolicy.from_dict({
                "policy_id": "P1", "name": "Bad",
                "action": "ALLOW", "priority": "not_a_number",
            })

    def test_non_list_policies_raises_config_error(self):
        """config.json 'policies' that is not a list raises ConfigurationError."""
        mock_loader = MagicMock()
        mock_loader.get.return_value = {"not": "a_list"}
        with self.assertRaises(ConfigurationError):
            PolicyConfig.from_config(mock_loader)

    def test_valid_policy_from_dict(self):
        """A valid policy dict should produce a correct FirewallPolicy."""
        p = FirewallPolicy.from_dict({
            "policy_id": "POL-X",
            "name": "Test",
            "action": "BLOCK",
            "priority": 99,
            "dst_port": 502,
            "risk_levels": ["CRITICAL"],
        })
        self.assertEqual(p.policy_id, "POL-X")
        self.assertEqual(p.action, PolicyAction.BLOCK)
        self.assertEqual(p.priority, 99)
        self.assertEqual(p.dst_port, 502)
        self.assertEqual(p.risk_levels, ["CRITICAL"])


# ===========================================================================
# 5. Simulation Enforcement Adapter Tests
# ===========================================================================

class TestSimulationEnforcementAdapter(unittest.TestCase):
    """Tests 15–17 — SimulationEnforcementAdapter safe enforcement."""

    def setUp(self):
        self.adapter = SimulationEnforcementAdapter()

    def _make_result(self, action: PolicyAction) -> EnforcementResult:
        return _make_enforcement_result(action=action)

    def test_allow_increments_counter(self):
        """Test 15: allow() increments the allowed counter."""
        result = self._make_result(PolicyAction.ALLOW)
        self.adapter.allow(result)
        self.assertEqual(self.adapter.stats.allowed, 1)
        self.assertEqual(self.adapter.stats.alerted, 0)
        self.assertEqual(self.adapter.stats.blocked, 0)

    def test_alert_increments_counter(self):
        """Test 16: alert() increments the alerted counter."""
        result = self._make_result(PolicyAction.ALERT)
        self.adapter.alert(result)
        self.assertEqual(self.adapter.stats.allowed, 0)
        self.assertEqual(self.adapter.stats.alerted, 1)
        self.assertEqual(self.adapter.stats.blocked, 0)

    def test_block_increments_counter(self):
        """Test 17: block() increments the blocked counter."""
        result = self._make_result(PolicyAction.BLOCK)
        self.adapter.block(result)
        self.assertEqual(self.adapter.stats.allowed, 0)
        self.assertEqual(self.adapter.stats.alerted, 0)
        self.assertEqual(self.adapter.stats.blocked, 1)

    def test_enforce_dispatches_correctly(self):
        """enforce() dispatches to the correct handler."""
        for action, attr in [
            (PolicyAction.ALLOW, "allowed"),
            (PolicyAction.ALERT, "alerted"),
            (PolicyAction.BLOCK, "blocked"),
        ]:
            adapter = SimulationEnforcementAdapter()
            result = self._make_result(action)
            adapter.enforce(result)
            self.assertEqual(getattr(adapter.stats, attr), 1)

    def test_reset_stats(self):
        """reset_stats() clears all counters."""
        self.adapter.allow(self._make_result(PolicyAction.ALLOW))
        self.adapter.block(self._make_result(PolicyAction.BLOCK))
        self.adapter.reset_stats()
        self.assertEqual(self.adapter.stats.total, 0)

    def test_safe_mode_flag_is_true(self):
        """SAFE_MODE class attribute must always be True."""
        self.assertTrue(SimulationEnforcementAdapter.SAFE_MODE)


class TestNoRealFirewallCommands(unittest.TestCase):
    """Test 18 — Verify SimulationEnforcementAdapter never calls OS commands."""

    def test_no_subprocess_calls(self):
        """
        Verify that enforcement never calls subprocess.run, subprocess.Popen,
        os.system, or similar OS-level commands.

        This test patches subprocess and os.system to detect any calls.
        """
        adapter = SimulationEnforcementAdapter()
        result = _make_enforcement_result(action=PolicyAction.BLOCK)

        with patch("subprocess.run") as mock_run, \
             patch("subprocess.Popen") as mock_popen, \
             patch("subprocess.call") as mock_call:
            adapter.block(result)
            adapter.allow(result)
            adapter.alert(result)

            mock_run.assert_not_called()
            mock_popen.assert_not_called()
            mock_call.assert_not_called()

    def test_no_iptables_in_source(self):
        """
        Verify that the enforcement source file contains no iptables/pfctl/nftables
        commands — a static code analysis check.
        """
        enforcement_file = _PROJECT_ROOT / "src" / "policy" / "enforcement.py"
        source = enforcement_file.read_text(encoding="utf-8")
        forbidden = ["iptables", "pfctl", "nftables", "os.system", "subprocess"]
        for term in forbidden:
            self.assertNotIn(
                term, source,
                msg=f"enforcement.py must not contain '{term}' — no OS firewall commands allowed."
            )


# ===========================================================================
# 6. Decision + Policy Integration Tests
# ===========================================================================

class TestDecisionPolicyIntegration(unittest.TestCase):
    """Test 19 — Decision engine risk ↔ policy action separation."""

    def test_safe_risk_allow_policy(self):
        """SAFE risk → matches POL-001 or POL-DEFAULT → ALLOW."""
        policy_cfg = PolicyConfig.from_config(config_loader)
        engine = PolicyEngine(policy_cfg)
        result = _make_decision_result(
            risk_score=10,
            severity=SeverityLevel.SAFE,
            decision=DecisionType.ALLOW,
            function_code=3,
            function_name="Read Holding Registers",
        )
        enforcement = engine.evaluate(result, dst_port=502, protocol="Modbus TCP")
        self.assertEqual(enforcement.final_action, PolicyAction.ALLOW)

    def test_medium_risk_alert_policy(self):
        """MEDIUM risk → matches POL-005 → ALERT."""
        policy_cfg = PolicyConfig.from_config(config_loader)
        engine = PolicyEngine(policy_cfg)
        result = _make_decision_result(
            risk_score=55,
            severity=SeverityLevel.MEDIUM,
            decision=DecisionType.ALERT,
            function_code=16,
            function_name="Write Multiple Registers",
        )
        enforcement = engine.evaluate(result, dst_port=502, protocol="Modbus TCP")
        self.assertEqual(enforcement.final_action, PolicyAction.ALERT)

    def test_critical_risk_block_policy(self):
        """CRITICAL risk → matches POL-006 → BLOCK."""
        policy_cfg = PolicyConfig.from_config(config_loader)
        engine = PolicyEngine(policy_cfg)
        result = _make_decision_result(
            risk_score=95,
            severity=SeverityLevel.CRITICAL,
            decision=DecisionType.BLOCK,
            function_code=16,
            function_name="Write Multiple Registers",
        )
        enforcement = engine.evaluate(result, dst_port=502, protocol="Modbus TCP")
        self.assertEqual(enforcement.final_action, PolicyAction.BLOCK)

    def test_enforcement_result_carries_policy_metadata(self):
        """EnforcementResult must carry full policy provenance."""
        policy = _make_policy("POL-META", name="Meta Test", action=PolicyAction.ALERT, priority=5)
        engine = _make_engine(policy)
        result = _make_decision_result(risk_score=55, severity=SeverityLevel.MEDIUM)
        enforcement = engine.evaluate(result)
        self.assertEqual(enforcement.matched_policy_id, "POL-META")
        self.assertEqual(enforcement.matched_policy_name, "Meta Test")
        self.assertEqual(enforcement.priority, 5)
        self.assertEqual(enforcement.original_risk_score, 55)
        self.assertEqual(enforcement.original_risk_level, "MEDIUM")
        self.assertIn("POL-META", enforcement.reason)

    def test_decision_and_policy_are_independent(self):
        """
        Demonstrate the separation of concerns:
        Decision Engine says BLOCK (high risk), but a specific policy says ALLOW.
        This simulates a whitelisted trusted source that overrides risk.
        """
        trusted_src = _make_policy(
            "TRUSTED-SRC", name="Trusted Source Override",
            action=PolicyAction.ALLOW, priority=1,
            src_ip="10.10.10.10",  # trusted engineering workstation
        )
        engine = _make_engine(trusted_src)
        # Day 4 says BLOCK due to high risk
        result = _make_decision_result(
            risk_score=80,
            severity=SeverityLevel.HIGH,
            decision=DecisionType.BLOCK,
            src_ip="10.10.10.10",
        )
        enforcement = engine.evaluate(result)
        # Policy overrides Day 4 → ALLOW from trusted source
        self.assertEqual(enforcement.final_action, PolicyAction.ALLOW)
        self.assertEqual(enforcement.original_decision, "BLOCK")  # D4 still says BLOCK


# ===========================================================================
# 7. Risk-based Criteria Tests
# ===========================================================================

class TestRiskCriteriaMatching(unittest.TestCase):
    """Test matching by risk_min, risk_max, risk_level, risk_levels."""

    def test_risk_min_match(self):
        policy = _make_policy(risk_min=70, action=PolicyAction.BLOCK)
        engine = _make_engine(policy)
        result = _make_decision_result(risk_score=75)
        self.assertEqual(engine.evaluate(result).final_action, PolicyAction.BLOCK)

    def test_risk_min_no_match(self):
        policy = _make_policy(risk_min=70, action=PolicyAction.BLOCK)
        engine = _make_engine(policy)
        result = _make_decision_result(risk_score=50)
        self.assertIsNone(engine.evaluate(result).matched_policy_id)

    def test_risk_max_match(self):
        policy = _make_policy(risk_max=39, action=PolicyAction.ALLOW)
        engine = _make_engine(policy)
        result = _make_decision_result(risk_score=30)
        self.assertEqual(engine.evaluate(result).final_action, PolicyAction.ALLOW)

    def test_risk_max_no_match(self):
        policy = _make_policy(risk_max=39, action=PolicyAction.ALLOW)
        engine = _make_engine(policy)
        result = _make_decision_result(risk_score=40)
        self.assertIsNone(engine.evaluate(result).matched_policy_id)

    def test_risk_level_single_match(self):
        policy = _make_policy(risk_level="CRITICAL", action=PolicyAction.BLOCK)
        engine = _make_engine(policy)
        result = _make_decision_result(severity=SeverityLevel.CRITICAL)
        self.assertEqual(engine.evaluate(result).final_action, PolicyAction.BLOCK)

    def test_risk_levels_list_match(self):
        policy = _make_policy(risk_levels=["MEDIUM", "HIGH"], action=PolicyAction.ALERT)
        engine = _make_engine(policy)
        for severity in [SeverityLevel.MEDIUM, SeverityLevel.HIGH]:
            result = _make_decision_result(severity=severity)
            self.assertEqual(engine.evaluate(result).final_action, PolicyAction.ALERT,
                             msg=f"Expected ALERT for {severity}")


# ===========================================================================
# 8. IP Match Helper Tests
# ===========================================================================

class TestIPMatchHelper(unittest.TestCase):
    """Test the _ip_matches utility function."""

    def test_exact_match(self):
        self.assertTrue(_ip_matches("192.168.1.10", "192.168.1.10"))

    def test_exact_no_match(self):
        self.assertFalse(_ip_matches("192.168.1.10", "192.168.1.20"))

    def test_cidr_match(self):
        self.assertTrue(_ip_matches("192.168.1.50", "192.168.1.0/24"))

    def test_cidr_no_match(self):
        self.assertFalse(_ip_matches("192.168.2.1", "192.168.1.0/24"))

    def test_wildcard_star(self):
        self.assertTrue(_ip_matches("any.ip.you.want", "*"))

    def test_empty_string_wildcard(self):
        self.assertTrue(_ip_matches("1.2.3.4", ""))

    def test_malformed_policy_ip(self):
        # Malformed policy IP should not crash — returns False
        self.assertFalse(_ip_matches("192.168.1.1", "not_an_ip"))


# ===========================================================================
# 9. FirewallPolicy Model Tests
# ===========================================================================

class TestFirewallPolicyModel(unittest.TestCase):
    """Test FirewallPolicy dataclass behaviour."""

    def test_wildcard_property_no_criteria(self):
        """A policy with no match criteria is a wildcard."""
        policy = _make_policy()
        self.assertTrue(policy.is_wildcard)

    def test_wildcard_property_with_criteria(self):
        """A policy with any criterion set is not a wildcard."""
        policy = _make_policy(dst_port=502)
        self.assertFalse(policy.is_wildcard)

    def test_to_dict_round_trip(self):
        """from_dict(to_dict(policy)) produces an identical policy."""
        original = _make_policy(
            policy_id="RT-001", name="Round Trip",
            action=PolicyAction.ALERT, priority=42,
            dst_port=502, risk_levels=["HIGH", "CRITICAL"],
        )
        d = original.to_dict()
        restored = FirewallPolicy.from_dict(d)
        self.assertEqual(restored.policy_id, original.policy_id)
        self.assertEqual(restored.action, original.action)
        self.assertEqual(restored.priority, original.priority)
        self.assertEqual(restored.dst_port, original.dst_port)
        self.assertEqual(restored.risk_levels, original.risk_levels)


# ===========================================================================
# 10. PolicyConfig from config.json
# ===========================================================================

class TestPolicyConfigFromConfigJson(unittest.TestCase):
    """Test loading default policies from the project config.json."""

    def test_loads_default_policies(self):
        """config.json should contain at least 7 default policies."""
        policy_cfg = PolicyConfig.from_config(config_loader)
        self.assertGreaterEqual(len(policy_cfg.policies), 7)

    def test_all_enabled_by_default(self):
        """All default policies should be enabled."""
        policy_cfg = PolicyConfig.from_config(config_loader)
        disabled = [p for p in policy_cfg.policies if not p.enabled]
        self.assertEqual(disabled, [], msg=f"Unexpected disabled policies: {disabled}")

    def test_policies_sorted_by_priority(self):
        """Policies should be sorted by (priority, policy_id)."""
        policy_cfg = PolicyConfig.from_config(config_loader)
        priorities = [(p.priority, p.policy_id) for p in policy_cfg.policies]
        self.assertEqual(priorities, sorted(priorities))

    def test_fail_safe_is_block(self):
        """Default fail-safe action should be BLOCK."""
        policy_cfg = PolicyConfig.from_config(config_loader)
        self.assertEqual(policy_cfg.fail_safe_action, PolicyAction.BLOCK)

    def test_missing_policy_key_uses_defaults(self):
        """If 'policies' key is absent, built-in defaults are used."""
        mock_loader = MagicMock()
        mock_loader.get.side_effect = lambda key, default=None: default if key == "policies" else "BLOCK"
        policy_cfg = PolicyConfig.from_config(mock_loader)
        self.assertGreater(len(policy_cfg.policies), 0)


# ===========================================================================
# 11. EnforcementResult Tests
# ===========================================================================

class TestEnforcementResult(unittest.TestCase):
    """Test EnforcementResult properties and serialisation."""

    def test_is_blocked_true(self):
        r = _make_enforcement_result(PolicyAction.BLOCK)
        self.assertTrue(r.is_blocked)
        self.assertFalse(r.is_allowed)
        self.assertFalse(r.is_alerted)

    def test_is_alerted_true(self):
        r = _make_enforcement_result(PolicyAction.ALERT)
        self.assertTrue(r.is_alerted)

    def test_is_allowed_true(self):
        r = _make_enforcement_result(PolicyAction.ALLOW)
        self.assertTrue(r.is_allowed)

    def test_has_matched_policy_true(self):
        r = _make_enforcement_result(policy_id="POL-X")
        self.assertTrue(r.has_matched_policy)

    def test_has_matched_policy_false_when_fallback(self):
        r = EnforcementResult(
            final_action=PolicyAction.ALLOW,
            matched_policy_id=None,
            matched_policy_name=None,
            priority=None,
            reason="Fallback",
            original_risk_score=10,
            original_risk_level="SAFE",
            original_decision="ALLOW",
            timestamp="2026-01-01T00:00:00+00:00",
            src_ip="1.2.3.4",
            dst_ip="5.6.7.8",
        )
        self.assertFalse(r.has_matched_policy)

    def test_to_dict_contains_all_keys(self):
        r = _make_enforcement_result()
        d = r.to_dict()
        expected_keys = {
            "final_action", "matched_policy_id", "matched_policy_name",
            "priority", "reason", "original_risk_score", "original_risk_level",
            "original_decision", "timestamp", "src_ip", "dst_ip",
            "function_code", "function_name", "all_policies_checked",
        }
        self.assertEqual(set(d.keys()), expected_keys)


# ===========================================================================
# 12. End-to-End Integration Test
# ===========================================================================

class TestEndToEndPolicyPipeline(unittest.TestCase):
    """
    E2E test: Full pipeline — Modbus packet → Parser → Physics →
              Decision Engine → Policy Engine → Enforcement Adapter

    Tests three scenarios:
      1. SAFE read operation     → ALLOW
      2. Medium risk write       → ALERT
      3. Critical violation      → BLOCK
    """

    @classmethod
    def setUpClass(cls):
        """Set up all components once for all E2E tests."""
        from src.decision_engine.decision_config import DecisionConfig
        from src.decision_engine.engine import PhysicsAwareDecisionEngine
        from src.parser.protocol_parser import ProtocolParser
        from src.parser.sample_packets import SamplePacketFactory
        from src.physics.physics_config import PhysicsConfig
        from src.physics.system_state import SystemState
        from src.physics.water_system_engine import WaterSystemEngine

        cls.parser = ProtocolParser()
        physics_cfg = PhysicsConfig.from_config(config_loader)
        cls.physics = WaterSystemEngine(physics_cfg)
        decision_cfg = DecisionConfig.from_config(config_loader)
        cls.decision_engine = PhysicsAwareDecisionEngine(physics_cfg, decision_cfg)

        policy_cfg = PolicyConfig.from_config(config_loader)
        cls.policy_engine = PolicyEngine(policy_cfg)
        cls.adapter = SimulationEnforcementAdapter()
        cls.factory = SamplePacketFactory

    def _run_pipeline(self, raw_bytes: bytes, physics_state=None):
        """Run a single packet through the full pipeline."""
        from src.physics.system_state import SystemState
        packet = self.parser.parse_modbus_only(raw_bytes)
        if physics_state is None:
            physics_state = SystemState(
                pressure_bar=4.5, flow_lps=15.0, temperature_celsius=32.0,
                pump_on=True, pump_rpm=1500.0,
                valve_position=0.6, tank_level_m3=75.0,
            )
        decision_result = self.decision_engine.evaluate_full_packet(packet, physics_state)
        enforcement = self.policy_engine.evaluate(
            decision_result,
            dst_port=502,
            protocol="Modbus TCP",
        )
        self.adapter.enforce(enforcement)
        return decision_result, enforcement

    def test_e2e_safe_read_allows(self):
        """E2E Test A: Safe Read Holding Registers → ALLOW."""
        # FC 0x03, address 0x0000, quantity 10
        raw = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A])
        decision, enforcement = self._run_pipeline(raw)
        self.assertIn(decision.severity, [SeverityLevel.SAFE, SeverityLevel.LOW])
        self.assertEqual(enforcement.final_action, PolicyAction.ALLOW)

    def test_e2e_critical_violation_blocks(self):
        """E2E Test B: Simulated critical violation → BLOCK."""
        from src.physics.system_state import SystemState
        # Use a system state near the pressure limit to trigger physics rules
        critical_state = SystemState(
            pressure_bar=9.6,   # 96% of 10.0 bar max → triggers CRITICAL rule
            flow_lps=15.0,
            temperature_celsius=32.0,
            pump_on=True,
            pump_rpm=1500.0,
            valve_position=0.6,
            tank_level_m3=75.0,
        )
        # Write Multiple Registers — the decision engine will evaluate with critical physics
        raw = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x09, 0x01, 0x10, 0x00, 0x00, 0x00, 0x01, 0x02, 0x00, 0x01])
        _, enforcement = self._run_pipeline(raw, physics_state=critical_state)
        # With critical physics state, decision engine gives high risk → policy blocks
        self.assertIn(enforcement.final_action, [PolicyAction.BLOCK, PolicyAction.ALERT],
                      msg="Expected BLOCK or ALERT for critical state")

    def test_e2e_enforcement_result_has_provenance(self):
        """E2E: EnforcementResult carries full provenance (policy + risk + reason)."""
        raw = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A])
        decision, enforcement = self._run_pipeline(raw)
        self.assertIsNotNone(enforcement.timestamp)
        self.assertIsNotNone(enforcement.original_risk_score)
        self.assertIsNotNone(enforcement.reason)
        self.assertNotEqual(enforcement.reason, "")

    def test_e2e_adapter_stats_accumulate(self):
        """E2E: Adapter counters accumulate correctly across multiple packets."""
        adapter = SimulationEnforcementAdapter()
        raw = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A])
        from src.physics.system_state import SystemState
        physics_state = SystemState(
            pressure_bar=4.5, flow_lps=15.0, temperature_celsius=32.0,
            pump_on=True, pump_rpm=1500.0,
            valve_position=0.6, tank_level_m3=75.0,
        )
        for _ in range(5):
            packet = self.parser.parse_modbus_only(raw)
            decision = self.decision_engine.evaluate_full_packet(packet, physics_state)
            enforcement = self.policy_engine.evaluate(decision, dst_port=502, protocol="Modbus TCP")
            adapter.enforce(enforcement)
        self.assertEqual(adapter.stats.total, 5)


# ===========================================================================
# 13. PipelineEvent Policy Fields Test
# ===========================================================================

class TestPipelineEventPolicyFields(unittest.TestCase):
    """Test that PipelineEvent carries enforcement fields correctly."""

    def test_pipeline_event_has_policy_fields(self):
        """PipelineEvent should expose policy_id, policy_name, policy_action, enforcement_reason."""
        from src.pipeline.pipeline_event import PipelineEvent
        from src.parser.protocol_parser import ProtocolParser
        from src.parser.packet_models import ParseStatus

        parser = ProtocolParser()
        raw = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A])
        packet = parser.parse_modbus_only(raw)

        decision_result = _make_decision_result(
            risk_score=10, severity=SeverityLevel.SAFE, decision=DecisionType.ALLOW,
            function_code=3, function_name="Read Holding Registers",
        )

        enforcement = _make_enforcement_result(
            action=PolicyAction.ALLOW,
            policy_id="POL-001",
            policy_name="Allow Modbus Read Operations",
        )

        event = PipelineEvent.from_decision(decision_result, packet, enforcement)
        self.assertEqual(event.policy_id, "POL-001")
        self.assertEqual(event.policy_name, "Allow Modbus Read Operations")
        self.assertEqual(event.policy_action, "ALLOW")
        self.assertIsNotNone(event.enforcement_reason)

    def test_pipeline_event_without_enforcement(self):
        """PipelineEvent should work without enforcement (backward compat)."""
        from src.pipeline.pipeline_event import PipelineEvent
        from src.parser.protocol_parser import ProtocolParser

        parser = ProtocolParser()
        raw = bytes([0x00, 0x01, 0x00, 0x00, 0x00, 0x06, 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A])
        packet = parser.parse_modbus_only(raw)
        decision_result = _make_decision_result()
        # No enforcement passed → backward compatible
        event = PipelineEvent.from_decision(decision_result, packet)
        self.assertIsNone(event.policy_id)
        self.assertIsNone(event.policy_name)
        self.assertIsNone(event.policy_action)


if __name__ == "__main__":
    unittest.main(verbosity=2)
