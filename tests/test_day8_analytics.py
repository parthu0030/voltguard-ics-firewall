"""
VoltGuard — Day 8 Security Analytics & Threat Intelligence Tests
================================================================
Comprehensive test suite verifying:
  1.  Total event count
  2.  Alert count
  3.  Block count
  4.  Allow count
  5.  Severity distribution (LOW, MEDIUM, HIGH, CRITICAL)
  6.  Action distribution (ALLOW, ALERT, BLOCK)
  7.  Risk statistics (average, max, min, score brackets)
  8.  Highest-risk events retrieval
  9.  Top source IPs ranking and metrics
  10. Top destination IPs ranking
  11. Policy statistics (match count, block/alert/allow counts, percentage)
  12. Modbus function code statistics (read/write distribution, blocked writes)
  13. Time-based filtering (last 1h, 24h, 7d, custom ISO windows)
  14. Empty database behavior (no crashes, valid zero-initialized metrics)
  15. Threat-intelligence provider behavior (exact IP, CIDR matching, confidence)
  16. Optional provider behavior (works gracefully with None / unconfigured provider)
  17. Deterministic analytics & security insight generation
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

# ── Ensure project root is on sys.path ────────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

# ── Bootstrap configuration ───────────────────────────────────────────────
from src.config import config_loader
if not config_loader.is_loaded:
    config_loader.load()

from src.constants import (
    MODBUS_FC_READ_COILS,
    MODBUS_FC_READ_HOLDING_REGISTERS,
    MODBUS_FC_WRITE_MULTIPLE_REGISTERS,
    MODBUS_FC_WRITE_SINGLE_COIL,
    MODBUS_FC_WRITE_SINGLE_REGISTER,
)
from src.database.db_manager import DatabaseManager
from src.models.analytics_models import (
    InsightCategory,
    InsightSeverity,
    ModbusAnalyticsMetrics,
    PolicyAnalyticsSummary,
    SecurityInsight,
    SecuritySummaryMetrics,
)
from src.models.app_models import Alert, AlertSeverity, PacketAction, PacketLog
from src.models.security_event import SecurityEvent
from src.models.threat_intel import (
    IndicatorType,
    ThreatIndicator,
    ThreatReputation,
)
from src.services.database_service import DatabaseService
from src.services.security_analytics_service import SecurityAnalyticsService
from src.services.threat_intel_service import LocalThreatIntelProvider


def _utc_iso_offset(hours: float = 0.0) -> str:
    """Helper to produce consistent ISO-8601 UTC timestamp offset from current time."""
    t = datetime.now(tz=timezone.utc) - timedelta(hours=hours)
    return t.isoformat(timespec="seconds")


class TestThreatIntelProvider(unittest.TestCase):
    """Test 15 & 16: LocalThreatIntelProvider and optional provider behavior."""

    def setUp(self):
        self.provider = LocalThreatIntelProvider()

    def test_add_and_lookup_exact_ip(self):
        ind = ThreatIndicator(
            indicator="192.168.1.100",
            indicator_type=IndicatorType.IP,
            reputation=ThreatReputation.MALICIOUS,
            confidence=0.95,
            description="Known rogue engineering workstation",
        )
        self.provider.add_indicator(ind)

        lookup = self.provider.lookup_ip("192.168.1.100")
        self.assertIsNotNone(lookup)
        self.assertEqual(lookup.reputation, ThreatReputation.MALICIOUS)
        self.assertEqual(lookup.confidence, 0.95)
        self.assertTrue(self.provider.is_suspicious("192.168.1.100"))
        self.assertFalse(self.provider.is_trusted("192.168.1.100"))

    def test_cidr_subnet_matching(self):
        ind = ThreatIndicator(
            indicator="10.200.0.0/16",
            indicator_type=IndicatorType.CIDR,
            reputation=ThreatReputation.SUSPICIOUS,
            confidence=0.75,
            description="Untrusted field network subnet",
        )
        self.provider.add_indicator(ind)

        # Inside subnet
        self.assertTrue(self.provider.is_suspicious("10.200.5.12"))
        lookup = self.provider.lookup_ip("10.200.5.12")
        self.assertIsNotNone(lookup)
        self.assertEqual(lookup.description, "Untrusted field network subnet")

        # Outside subnet
        self.assertFalse(self.provider.is_suspicious("10.100.5.12"))
        self.assertIsNone(self.provider.lookup_ip("10.100.5.12"))

    def test_trusted_reputation(self):
        ind = ThreatIndicator(
            indicator="192.168.1.10",
            indicator_type=IndicatorType.IP,
            reputation=ThreatReputation.TRUSTED,
            confidence=1.0,
            description="Master SCADA HMI",
        )
        self.provider.add_indicator(ind)

        self.assertTrue(self.provider.is_trusted("192.168.1.10"))
        self.assertFalse(self.provider.is_suspicious("192.168.1.10"))

    def test_remove_and_clear_indicators(self):
        ind = ThreatIndicator(indicator="172.16.0.5", reputation=ThreatReputation.SUSPICIOUS)
        self.provider.add_indicator(ind)
        self.assertEqual(self.provider.count(), 1)

        removed = self.provider.remove_indicator("172.16.0.5")
        self.assertTrue(removed)
        self.assertEqual(self.provider.count(), 0)

        # Clear multiple
        self.provider.add_indicator(ThreatIndicator(indicator="1.1.1.1"))
        self.provider.add_indicator(ThreatIndicator(indicator="2.2.2.2"))
        self.assertEqual(self.provider.count(), 2)
        self.provider.clear()
        self.assertEqual(self.provider.count(), 0)

    def test_safe_lookup_with_invalid_ips(self):
        self.assertIsNone(self.provider.lookup_ip(""))
        self.assertIsNone(self.provider.lookup_ip("unknown"))
        self.assertIsNone(self.provider.lookup_ip("0.0.0.0"))
        self.assertFalse(self.provider.is_suspicious("invalid-ip-string"))


class TestSecurityAnalyticsWithSampleData(unittest.TestCase):
    """
    Sets up an isolated SQLite database populated with deterministic
    sample events across different timestamps, policies, function codes,
    and severities.
    """

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        self.db_mgr = DatabaseManager(db_path=self.temp_db.name)
        self.db_service = DatabaseService(db_manager=self.db_mgr)
        self.db_service.initialize()

        self.threat_intel = LocalThreatIntelProvider()
        self.threat_intel.add_indicator(
            ThreatIndicator(
                indicator="192.168.1.99",
                reputation=ThreatReputation.MALICIOUS,
                confidence=0.90,
                description="Known attack injector",
            )
        )

        self.analytics = SecurityAnalyticsService(
            db_service=self.db_service,
            threat_intel=self.threat_intel,
        )

        # Populate deterministic dataset:
        # Event 1: Recent (0.2h ago), ALLOW, FC 3 (Read Holding Regs), Risk 10, Low
        self.db_service.save_security_event(
            SecurityEvent(
                timestamp=_utc_iso_offset(0.2),
                source_ip="192.168.1.10",
                destination_ip="192.168.1.50",
                protocol="Modbus TCP",
                function_code=MODBUS_FC_READ_HOLDING_REGISTERS,
                function_name="Read Holding Registers",
                risk_score=10,
                risk_level="SAFE",
                matched_policy_id="POL-001",
                matched_policy_name="Allow Modbus Read Operations",
                final_action="ALLOW",
                severity=AlertSeverity.LOW,
            )
        )

        # Event 2: Recent (0.5h ago), ALLOW, FC 1 (Read Coils), Risk 15, Low
        self.db_service.save_security_event(
            SecurityEvent(
                timestamp=_utc_iso_offset(0.5),
                source_ip="192.168.1.10",
                destination_ip="192.168.1.50",
                protocol="Modbus TCP",
                function_code=MODBUS_FC_READ_COILS,
                function_name="Read Coils",
                risk_score=15,
                risk_level="SAFE",
                matched_policy_id="POL-001",
                matched_policy_name="Allow Modbus Read Operations",
                final_action="ALLOW",
                severity=AlertSeverity.LOW,
            )
        )

        # Event 3: Medium past (3h ago), ALERT, FC 16 (Write Multiple Regs), Risk 55, Medium
        self.db_service.save_security_event(
            SecurityEvent(
                timestamp=_utc_iso_offset(3.0),
                source_ip="192.168.1.99",
                destination_ip="192.168.1.50",
                protocol="Modbus TCP",
                function_code=MODBUS_FC_WRITE_MULTIPLE_REGISTERS,
                function_name="Write Multiple Registers",
                risk_score=55,
                risk_level="MEDIUM",
                matched_policy_id="POL-004",
                matched_policy_name="Alert on Write Multiple Registers",
                final_action="ALERT",
                severity=AlertSeverity.MEDIUM,
            )
        )

        # Event 4: Medium past (4h ago), BLOCK, FC 6 (Write Single Reg), Risk 80, High
        self.db_service.save_security_event(
            SecurityEvent(
                timestamp=_utc_iso_offset(4.0),
                source_ip="192.168.1.99",
                destination_ip="192.168.1.50",
                protocol="Modbus TCP",
                function_code=MODBUS_FC_WRITE_SINGLE_REGISTER,
                function_name="Write Single Register",
                risk_score=80,
                risk_level="HIGH",
                matched_policy_id="POL-007",
                matched_policy_name="Block High Risk Score Traffic",
                final_action="BLOCK",
                severity=AlertSeverity.HIGH,
            )
        )

        # Event 5: Past 2 days (48h ago), BLOCK, FC 16 (Write Multiple Regs), Risk 98, Critical
        self.db_service.save_security_event(
            SecurityEvent(
                timestamp=_utc_iso_offset(48.0),
                source_ip="10.0.0.77",
                destination_ip="192.168.1.50",
                protocol="Modbus TCP",
                function_code=MODBUS_FC_WRITE_MULTIPLE_REGISTERS,
                function_name="Write Multiple Registers",
                risk_score=98,
                risk_level="CRITICAL",
                matched_policy_id="POL-006",
                matched_policy_name="Block Critical Physical Safety Violations",
                final_action="BLOCK",
                severity=AlertSeverity.CRITICAL,
            )
        )

        # Also add sample Alert and PacketLog
        self.db_service.save_alert(
            Alert(
                timestamp=_utc_iso_offset(3.0),
                severity=AlertSeverity.MEDIUM,
                message="Multiple register write alert",
                source_ip="192.168.1.99",
                destination_ip="192.168.1.50",
                action="ALERT",
                risk_score=55,
                policy_id="POL-004",
            )
        )
        self.db_service.save_alert(
            Alert(
                timestamp=_utc_iso_offset(4.0),
                severity=AlertSeverity.HIGH,
                message="High risk block",
                source_ip="192.168.1.99",
                destination_ip="192.168.1.50",
                action="BLOCK",
                risk_score=80,
                policy_id="POL-007",
            )
        )
        self.db_service.save_packet_log(
            PacketLog(
                timestamp=_utc_iso_offset(0.2),
                src_ip="192.168.1.10",
                dst_ip="192.168.1.50",
                protocol="Modbus TCP",
                port=502,
                action=PacketAction.ALLOW,
                risk_score=0.10,
            )
        )

    def tearDown(self):
        self.db_service.close()
        try:
            os.remove(self.temp_db.name)
        except OSError:
            pass

    def test_total_event_count(self):
        """Test 1: Total event count."""
        total_evts = self.analytics.get_total_security_events()
        self.assertEqual(total_evts, 5)

    def test_alert_count(self):
        """Test 2: Total alert count."""
        alerts = self.analytics.get_total_alerts()
        self.assertEqual(alerts, 2)

    def test_block_count(self):
        """Test 3: Total blocked events count."""
        summary = self.analytics.get_summary_metrics()
        self.assertEqual(summary.total_blocked_events, 2)

    def test_allow_count(self):
        """Test 4: Total allowed events count."""
        summary = self.analytics.get_summary_metrics()
        self.assertEqual(summary.total_allowed_events, 2)

    def test_severity_distribution(self):
        """Test 5: Events by severity."""
        summary = self.analytics.get_summary_metrics()
        dist = summary.events_by_severity
        self.assertEqual(dist.get("LOW"), 2)
        self.assertEqual(dist.get("MEDIUM"), 1)
        self.assertEqual(dist.get("HIGH"), 1)
        self.assertEqual(dist.get("CRITICAL"), 1)

    def test_action_distribution(self):
        """Test 6: Events by enforcement action."""
        summary = self.analytics.get_summary_metrics()
        dist = summary.events_by_action
        self.assertEqual(dist.get("ALLOW"), 2)
        self.assertEqual(dist.get("ALERT"), 1)
        self.assertEqual(dist.get("BLOCK"), 2)

    def test_risk_statistics(self):
        """Test 7: Risk statistics (avg, max, min, risk counts)."""
        risk_stats = self.analytics.get_risk_distribution()
        self.assertEqual(risk_stats["maximum_risk_score"], 98)
        self.assertEqual(risk_stats["minimum_risk_score"], 10)
        # Average of 10, 15, 55, 80, 98 = 258 / 5 = 51.6
        self.assertAlmostEqual(risk_stats["average_risk_score"], 51.6, places=1)
        self.assertEqual(risk_stats["critical_count"], 1)
        self.assertEqual(risk_stats["high_count"], 1)
        self.assertEqual(risk_stats["medium_count"], 1)
        self.assertEqual(risk_stats["low_count"], 2)

    def test_highest_risk_events(self):
        """Test 8: Highest-risk events."""
        high_risk = self.analytics.get_highest_risk_events(limit=3)
        self.assertEqual(len(high_risk), 3)
        self.assertEqual(high_risk[0].risk_score, 98)
        self.assertEqual(high_risk[0].matched_policy_id, "POL-006")
        self.assertEqual(high_risk[1].risk_score, 80)
        self.assertEqual(high_risk[2].risk_score, 55)

    def test_top_source_ips(self):
        """Test 9: Top source IPs and threat enrichment."""
        top_sources = self.analytics.get_top_source_ips(limit=5)
        self.assertGreaterEqual(len(top_sources), 2)
        # 192.168.1.10 and 192.168.1.99 both have 2 events
        ips = [s["source_ip"] for s in top_sources]
        self.assertIn("192.168.1.99", ips)
        self.assertIn("192.168.1.10", ips)

        # Check threat intel enrichment on 192.168.1.99
        rogue_src = next(s for s in top_sources if s["source_ip"] == "192.168.1.99")
        self.assertEqual(rogue_src.get("threat_reputation"), ThreatReputation.MALICIOUS.value)
        self.assertEqual(rogue_src.get("threat_confidence"), 0.90)

    def test_top_destination_ips(self):
        """Test 10: Top destination IPs."""
        top_dst = self.analytics.get_top_destination_ips(limit=5)
        self.assertEqual(len(top_dst), 1)
        self.assertEqual(top_dst[0]["destination_ip"], "192.168.1.50")
        self.assertEqual(top_dst[0]["event_count"], 5)

    def test_policy_statistics(self):
        """Test 11: Policy matching and enforcement metrics."""
        policy_stats = self.analytics.get_policy_analytics()
        self.assertIsInstance(policy_stats, PolicyAnalyticsSummary)
        self.assertGreaterEqual(len(policy_stats.policies), 4)

        # Most triggered policy should be POL-001 (2 matches)
        self.assertEqual(policy_stats.most_triggered_policy_id, "POL-001")
        # Most blocking should be POL-007 or POL-006
        self.assertIn(policy_stats.most_blocking_policy_id, ["POL-007", "POL-006"])
        # Most alerting is POL-004
        self.assertEqual(policy_stats.most_alerting_policy_id, "POL-004")

        pol001 = next(p for p in policy_stats.policies if p.policy_id == "POL-001")
        self.assertEqual(pol001.match_count, 2)
        self.assertEqual(pol001.allow_count, 2)
        self.assertEqual(pol001.percentage_of_total, 40.0)

    def test_modbus_function_statistics(self):
        """Test 12: Modbus function code statistics."""
        modbus_metrics = self.analytics.get_modbus_analytics()
        self.assertIsInstance(modbus_metrics, ModbusAnalyticsMetrics)
        self.assertEqual(modbus_metrics.total_modbus_events, 5)

        # Reads: FC 3 (1) + FC 1 (1) = 2 reads (40%)
        # Writes: FC 16 (2) + FC 6 (1) = 3 writes (60%)
        self.assertEqual(modbus_metrics.read_operations_count, 2)
        self.assertEqual(modbus_metrics.write_operations_count, 3)
        self.assertEqual(modbus_metrics.read_operations_percentage, 40.0)
        self.assertEqual(modbus_metrics.write_operations_percentage, 60.0)

        # Blocked writes: Event 4 (FC 6) and Event 5 (FC 16) = 2 blocked writes
        self.assertEqual(modbus_metrics.blocked_write_operations, 2)
        self.assertIn(MODBUS_FC_WRITE_SINGLE_REGISTER, modbus_metrics.high_risk_function_codes)
        self.assertIn(MODBUS_FC_WRITE_MULTIPLE_REGISTERS, modbus_metrics.high_risk_function_codes)

    def test_time_based_filtering(self):
        """Test 13: Time-based filtering (last 1h, 24h, 7d)."""
        # Last 1h: only Events 1 & 2 (0.2h and 0.5h ago)
        last_1h = self.analytics.get_events_last_hour()
        self.assertEqual(last_1h, 2)

        # Last 24h: Events 1, 2, 3, 4 (0.2h, 0.5h, 3h, 4h ago) -> 4 events
        last_24h = self.analytics.get_events_last_24h()
        self.assertEqual(last_24h, 4)

        # Last 7d: all 5 events
        last_7d = self.analytics.get_events_last_7d()
        self.assertEqual(last_7d, 5)

        # Time series trend
        trend = self.analytics.get_risk_score_trend()
        self.assertIsInstance(trend, list)
        self.assertGreater(len(trend), 0)

    def test_optional_threat_intel_provider(self):
        """Test 16: System behaves normally without threat intelligence provider."""
        service_no_intel = SecurityAnalyticsService(
            db_service=self.db_service,
            threat_intel=None,
        )
        summary = service_no_intel.get_summary_metrics()
        self.assertEqual(summary.total_security_events, 5)

        sources = service_no_intel.get_top_source_ips()
        self.assertGreaterEqual(len(sources), 2)
        # Should not crash and not have threat intel fields populated
        self.assertNotIn("threat_reputation", sources[0])

    def test_deterministic_insights_generation(self):
        """Test 17: Deterministic security insights generation."""
        insights = self.analytics.generate_security_insights()
        self.assertIsInstance(insights, list)
        self.assertGreater(len(insights), 0)

        # Should generate critical physical violation insight
        titles = [ins.title for ins in insights]
        self.assertIn("Critical Physical Safety Events Detected", titles)

        # Check critical insight properties
        crit_ins = next(ins for ins in insights if ins.category == InsightCategory.PHYSICAL_SAFETY)
        self.assertEqual(crit_ins.severity, InsightSeverity.CRITICAL)
        self.assertIn("physical telemetry", crit_ins.recommendation.lower())

        # Check threat intel match insight for 192.168.1.99
        self.assertTrue(any(ins.category == InsightCategory.THREAT_INTEL for ins in insights))


class TestEmptyDatabaseAnalytics(unittest.TestCase):
    """Test 14: Empty database behavior."""

    def setUp(self):
        self.temp_db = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        self.temp_db.close()
        self.db_mgr = DatabaseManager(db_path=self.temp_db.name)
        self.db_service = DatabaseService(db_manager=self.db_mgr)
        self.db_service.initialize()
        self.analytics = SecurityAnalyticsService(db_service=self.db_service)

    def tearDown(self):
        self.db_service.close()
        try:
            os.remove(self.temp_db.name)
        except OSError:
            pass

    def test_empty_database_summary_metrics(self):
        summary = self.analytics.get_summary_metrics()
        self.assertEqual(summary.total_packets, 0)
        self.assertEqual(summary.total_security_events, 0)
        self.assertEqual(summary.total_alerts, 0)
        self.assertEqual(summary.total_blocked_events, 0)
        self.assertEqual(summary.total_allowed_events, 0)
        self.assertEqual(summary.average_risk_score, 0.0)
        self.assertEqual(summary.maximum_risk_score, 0)
        self.assertEqual(summary.minimum_risk_score, 0)
        self.assertEqual(summary.events_by_severity["LOW"], 0)

    def test_empty_database_top_sources_and_destinations(self):
        self.assertEqual(self.analytics.get_top_source_ips(), [])
        self.assertEqual(self.analytics.get_top_destination_ips(), [])
        self.assertEqual(self.analytics.get_highest_risk_events(), [])

    def test_empty_database_modbus_and_policy(self):
        modbus = self.analytics.get_modbus_analytics()
        self.assertEqual(modbus.total_modbus_events, 0)
        self.assertEqual(modbus.read_operations_count, 0)
        self.assertEqual(modbus.write_operations_count, 0)
        self.assertEqual(modbus.blocked_write_operations, 0)

        policies = self.analytics.get_policy_analytics()
        self.assertEqual(policies.policies, [])
        self.assertIsNone(policies.most_triggered_policy_id)

    def test_empty_database_insights(self):
        insights = self.analytics.generate_security_insights()
        self.assertEqual(len(insights), 1)
        self.assertEqual(insights[0].title, "No Security Events Recorded")
        self.assertEqual(insights[0].severity, InsightSeverity.INFO)


if __name__ == "__main__":
    unittest.main()
