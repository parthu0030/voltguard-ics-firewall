"""
VoltGuard — Day 7 Security Event & Alert Management Tests
==========================================================
Tests the SecurityEvent model, AlertManager service, sliding-window
deduplication, database persistence, severity mapping, and end-to-end
pipeline integration.

Test coverage (16 required areas):
  1.  Security event creation & serialization
  2.  Alert creation (standalone & event-driven)
  3.  Alert persistence (SQLite round-trip)
  4.  Alert retrieval by ID
  5.  Recent alerts querying & pagination
  6.  Unacknowledged alert counting
  7.  Alert acknowledgement (single and all)
  8.  Severity filtering (LOW, MEDIUM, HIGH, CRITICAL)
  9.  Action filtering (ALLOW, ALERT, BLOCK)
  10. BLOCK alert generation with HIGH/CRITICAL severity
  11. ALERT generation with MEDIUM/HIGH severity
  12. ALLOW event audit handling (event recorded, no high-priority alert)
  13. Critical alert handling & physical violation prioritization
  14. Duplicate alert deduplication within sliding window
  15. Database restart/persistence behavior across service re-init
  16. End-to-end integration with PacketPipeline & PolicyEngine
"""

from __future__ import annotations

import sqlite3
import sys
import time
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

from src.capture.capture_mode import CaptureMode
from src.capture.packet_source import PacketSource
from src.database.db_manager import DatabaseManager
from src.decision_engine.models import DecisionType, SecurityDecisionResult, SeverityLevel
from src.models.app_models import Alert, AlertSeverity, PacketAction
from src.models.security_event import SecurityEvent
from src.parser.packet_models import FullPacket, ParseStatus
from src.pipeline.packet_pipeline import PacketPipeline
from src.pipeline.pipeline_event import PipelineEvent
from src.policy.models import EnforcementResult, PolicyAction
from src.services.alert_manager import AlertManager, alert_manager
from src.services.database_service import database_service


def _make_sample_pipeline_event(
    decision: str = "BLOCK",
    risk_score: int = 85,
    risk_level: str = "HIGH",
    policy_id: str = "POL-007",
    src_ip: str = "192.168.1.100",
    dst_ip: str = "192.168.1.200",
    fc: int = 16,
    fc_name: str = "Write Multiple Registers",
    reason: str = "Suspicious write command",
) -> PipelineEvent:
    return PipelineEvent(
        timestamp="2026-08-25T12:00:00+00:00",
        source_ip=src_ip,
        destination_ip=dst_ip,
        source_port=54321,
        destination_port=502,
        protocol="Modbus TCP",
        modbus_function=fc_name,
        modbus_fc_int=fc,
        decision=decision,
        risk_score=risk_score,
        risk_level=risk_level,
        reason=reason,
        triggered_rules=["RULE-001"],
        parse_status=ParseStatus.VALID.value,
        is_full_frame=True,
        policy_id=policy_id,
        policy_name="Test Policy",
        policy_action=decision,
        enforcement_reason=f"Policy {policy_id} matched: {reason}",
    )


class TestSecurityEventModel(unittest.TestCase):
    """Test 1: SecurityEvent creation and serialization."""

    def test_security_event_defaults(self):
        event = SecurityEvent()
        self.assertIsNotNone(event.event_id)
        self.assertIsNotNone(event.timestamp)
        self.assertEqual(event.final_action, "ALLOW")
        self.assertEqual(event.severity, AlertSeverity.LOW)
        self.assertFalse(event.acknowledged)

    def test_from_pipeline_event(self):
        pe = _make_sample_pipeline_event(
            decision="BLOCK",
            risk_score=95,
            risk_level="CRITICAL",
            policy_id="POL-006",
        )
        se = SecurityEvent.from_pipeline_event(pe)
        self.assertEqual(se.source_ip, "192.168.1.100")
        self.assertEqual(se.destination_ip, "192.168.1.200")
        self.assertEqual(se.function_code, 16)
        self.assertEqual(se.risk_score, 95)
        self.assertEqual(se.severity, AlertSeverity.CRITICAL)
        self.assertEqual(se.matched_policy_id, "POL-006")
        self.assertEqual(se.final_action, "BLOCK")
        self.assertEqual(se.event_type, "CRITICAL_PHYSICAL_VIOLATION")

    def test_to_dict_and_from_dict(self):
        pe = _make_sample_pipeline_event(decision="ALERT", risk_score=55, risk_level="MEDIUM")
        se = SecurityEvent.from_pipeline_event(pe)
        d = se.to_dict()
        self.assertIsInstance(d, dict)
        self.assertEqual(d["source_ip"], "192.168.1.100")
        self.assertEqual(d["severity"], "MEDIUM")

        reconstructed = SecurityEvent.from_dict(d)
        self.assertEqual(reconstructed.event_id, se.event_id)
        self.assertEqual(reconstructed.severity, AlertSeverity.MEDIUM)
        self.assertEqual(reconstructed.final_action, "ALERT")


class TestAlertModel(unittest.TestCase):
    """Test 2 & 3: Alert creation and persistence round-trip."""

    @classmethod
    def setUpClass(cls):
        database_service.initialize()

    def test_alert_creation_with_extended_fields(self):
        alert = Alert(
            timestamp="2026-08-25T12:00:00+00:00",
            severity=AlertSeverity.HIGH,
            message="Test high risk alert",
            source_ip="10.0.0.1",
            destination_ip="10.0.0.2",
            function_code=6,
            action="BLOCK",
            risk_score=75,
            policy_id="POL-007",
            repeat_count=3,
        )
        self.assertEqual(alert.repeat_count, 3)
        d = alert.to_dict()
        self.assertEqual(d["severity"], "HIGH")
        self.assertEqual(d["repeat_count"], 3)

        from_d = Alert.from_dict(d)
        self.assertEqual(from_d.source_ip, "10.0.0.1")
        self.assertEqual(from_d.severity, AlertSeverity.HIGH)
        self.assertEqual(from_d.repeat_count, 3)


class TestDatabaseServiceAlerts(unittest.TestCase):
    """Tests 3–9: Database CRUD operations for Alerts and SecurityEvents."""

    def setUp(self):
        database_service.initialize()

    def test_save_and_retrieve_alert_by_id(self):
        alert = Alert(
            timestamp="2026-08-25T12:01:00+00:00",
            severity=AlertSeverity.MEDIUM,
            message="Medium severity alert test",
            source_ip="192.168.1.50",
            destination_ip="192.168.1.51",
            action="ALERT",
        )
        alert_id = database_service.save_alert(alert)
        self.assertIsInstance(alert_id, int)
        self.assertGreater(alert_id, 0)

        retrieved = database_service.get_alert(alert_id)
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.id, alert_id)
        self.assertEqual(retrieved.message, "Medium severity alert test")
        self.assertEqual(retrieved.severity, AlertSeverity.MEDIUM)
        self.assertEqual(retrieved.source_ip, "192.168.1.50")
        self.assertFalse(retrieved.acknowledged)

    def test_get_nonexistent_alert_returns_none(self):
        self.assertIsNone(database_service.get_alert(999999))

    def test_unacknowledged_alert_count_and_acknowledge(self):
        initial_unack = database_service.get_unacknowledged_alert_count()
        alert = Alert(
            timestamp="2026-08-25T12:02:00+00:00",
            severity=AlertSeverity.HIGH,
            message="Unacknowledged test alert",
            acknowledged=False,
        )
        alert_id = database_service.save_alert(alert)
        self.assertEqual(database_service.get_unacknowledged_alert_count(), initial_unack + 1)

        # Acknowledge single
        ok = database_service.acknowledge_alert(alert_id)
        self.assertTrue(ok)
        self.assertEqual(database_service.get_unacknowledged_alert_count(), initial_unack)

        retrieved = database_service.get_alert(alert_id)
        self.assertTrue(retrieved.acknowledged)

    def test_acknowledge_all_alerts(self):
        database_service.save_alert(Alert(
            timestamp="2026-08-25T12:03:00+00:00",
            severity=AlertSeverity.LOW,
            message="Ack all test 1",
            acknowledged=False,
        ))
        database_service.save_alert(Alert(
            timestamp="2026-08-25T12:03:01+00:00",
            severity=AlertSeverity.MEDIUM,
            message="Ack all test 2",
            acknowledged=False,
        ))
        count = database_service.acknowledge_all_alerts()
        self.assertGreaterEqual(count, 2)
        self.assertEqual(database_service.get_unacknowledged_alert_count(), 0)

    def test_filter_alerts_by_severity(self):
        database_service.save_alert(Alert(
            timestamp="2026-08-25T12:04:00+00:00",
            severity=AlertSeverity.CRITICAL,
            message="Filter test critical",
        ))
        database_service.save_alert(Alert(
            timestamp="2026-08-25T12:04:01+00:00",
            severity=AlertSeverity.LOW,
            message="Filter test low",
        ))
        crit_alerts = database_service.load_recent_alerts(limit=50, severity="CRITICAL")
        self.assertTrue(all(a.severity == AlertSeverity.CRITICAL for a in crit_alerts))
        self.assertTrue(any(a.message == "Filter test critical" for a in crit_alerts))

    def test_filter_alerts_by_action(self):
        database_service.save_alert(Alert(
            timestamp="2026-08-25T12:05:00+00:00",
            severity=AlertSeverity.HIGH,
            message="Action filter BLOCK",
            action="BLOCK",
        ))
        database_service.save_alert(Alert(
            timestamp="2026-08-25T12:05:01+00:00",
            severity=AlertSeverity.MEDIUM,
            message="Action filter ALERT",
            action="ALERT",
        ))
        blocked = database_service.load_recent_alerts(limit=50, action="BLOCK")
        self.assertTrue(all(a.action == "BLOCK" for a in blocked))
        self.assertTrue(any(a.message == "Action filter BLOCK" for a in blocked))

    def test_save_and_load_security_events(self):
        se = SecurityEvent(
            source_ip="192.168.1.80",
            destination_ip="192.168.1.81",
            function_code=16,
            function_name="Write Multiple Registers",
            risk_score=92,
            risk_level="CRITICAL",
            final_action="BLOCK",
            reason="Pressure upper safety violation",
            severity=AlertSeverity.CRITICAL,
        )
        row_id = database_service.save_security_event(se)
        self.assertIsInstance(row_id, int)

        loaded = database_service.get_security_event(row_id)
        self.assertIsNotNone(loaded)
        self.assertEqual(loaded.source_ip, "192.168.1.80")
        self.assertEqual(loaded.risk_score, 92)
        self.assertEqual(loaded.severity, AlertSeverity.CRITICAL)
        self.assertEqual(loaded.final_action, "BLOCK")

        recent = database_service.load_recent_security_events(limit=10, severity="CRITICAL")
        self.assertTrue(any(e.id == row_id for e in recent))

        # Acknowledge event
        ok = database_service.acknowledge_security_event(row_id)
        self.assertTrue(ok)
        ack_event = database_service.get_security_event(row_id)
        self.assertTrue(ack_event.acknowledged)


class TestAlertManagerService(unittest.TestCase):
    """Tests 10–14: AlertManager severity mapping, event processing, and deduplication."""

    def setUp(self):
        database_service.initialize()
        self.mgr = AlertManager(dedup_window_sec=5.0)

    def test_severity_mapping(self):
        # Critical
        self.assertEqual(AlertManager.map_severity(95, "CRITICAL", "BLOCK"), AlertSeverity.CRITICAL)
        self.assertEqual(AlertManager.map_severity(92, "HIGH", "BLOCK"), AlertSeverity.CRITICAL)
        # High
        self.assertEqual(AlertManager.map_severity(75, "HIGH", "BLOCK"), AlertSeverity.HIGH)
        self.assertEqual(AlertManager.map_severity(72, "LOW", "BLOCK"), AlertSeverity.HIGH)
        # Medium
        self.assertEqual(AlertManager.map_severity(50, "MEDIUM", "ALERT"), AlertSeverity.MEDIUM)
        self.assertEqual(AlertManager.map_severity(20, "LOW", "ALERT"), AlertSeverity.MEDIUM)
        # Low
        self.assertEqual(AlertManager.map_severity(10, "SAFE", "ALLOW"), AlertSeverity.LOW)

    def test_block_action_generates_high_or_critical_alert(self):
        pe = _make_sample_pipeline_event(
            decision="BLOCK",
            risk_score=75,
            risk_level="HIGH",
            policy_id="POL-007",
            reason="Blocked by high risk policy",
        )
        se, alert = self.mgr.process_pipeline_event(pe)
        self.assertIsNotNone(se)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, AlertSeverity.HIGH)
        self.assertEqual(alert.action, "BLOCK")
        self.assertIn("BLOCKED", alert.message)
        self.assertEqual(alert.policy_id, "POL-007")

    def test_alert_action_generates_security_alert(self):
        pe = _make_sample_pipeline_event(
            decision="ALERT",
            risk_score=50,
            risk_level="MEDIUM",
            policy_id="POL-004",
            reason="Write multiple registers alert",
        )
        se, alert = self.mgr.process_pipeline_event(pe)
        self.assertIsNotNone(se)
        self.assertIsNotNone(alert)
        self.assertEqual(alert.severity, AlertSeverity.MEDIUM)
        self.assertEqual(alert.action, "ALERT")
        self.assertIn("SECURITY ALERT", alert.message)

    def test_allow_action_records_event_without_high_priority_alert(self):
        pe = _make_sample_pipeline_event(
            decision="ALLOW",
            risk_score=10,
            risk_level="SAFE",
            policy_id="POL-001",
            reason="Routine safe read command",
        )
        se, alert = self.mgr.process_pipeline_event(pe)
        self.assertIsNotNone(se)
        # Safe ALLOW should not create an alert flood
        self.assertIsNone(alert)
        self.assertEqual(se.final_action, "ALLOW")

    def test_critical_alert_handling(self):
        pe = _make_sample_pipeline_event(
            decision="BLOCK",
            risk_score=98,
            risk_level="CRITICAL",
            policy_id="POL-006",
            reason="Critical physical safety limit violation",
        )
        se, alert = self.mgr.process_pipeline_event(pe)
        self.assertEqual(se.severity, AlertSeverity.CRITICAL)
        self.assertEqual(alert.severity, AlertSeverity.CRITICAL)
        self.assertEqual(alert.action, "BLOCK")

    def test_sliding_window_deduplication(self):
        self.mgr.clear_dedup_cache()

        pe1 = _make_sample_pipeline_event(
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            fc=16,
            decision="BLOCK",
            policy_id="POL-007",
            reason="Duplicate test flood",
        )
        _, alert1 = self.mgr.process_pipeline_event(pe1)
        self.assertIsNotNone(alert1)
        self.assertEqual(alert1.repeat_count, 1)
        first_alert_id = alert1.id

        # Send identical event immediately within 5s window
        pe2 = _make_sample_pipeline_event(
            src_ip="192.168.1.10",
            dst_ip="192.168.1.20",
            fc=16,
            decision="BLOCK",
            policy_id="POL-007",
            reason="Duplicate test flood",
        )
        _, alert2 = self.mgr.process_pipeline_event(pe2)
        self.assertIsNotNone(alert2)
        # Should be deduplicated into the same alert ID with repeat_count = 2
        self.assertEqual(alert2.id, first_alert_id)
        self.assertEqual(alert2.repeat_count, 2)

        # Verify in DB
        db_alert = database_service.get_alert(first_alert_id)
        self.assertEqual(db_alert.repeat_count, 2)


class TestDatabasePersistenceRestart(unittest.TestCase):
    """Test 15: Database persistence behavior across restarts."""

    def test_alerts_and_events_survive_reinitialization(self):
        database_service.initialize()
        initial_alert = Alert(
            timestamp="2026-08-25T12:10:00+00:00",
            severity=AlertSeverity.HIGH,
            message="Persistence across restart test",
            acknowledged=False,
            repeat_count=5,
        )
        alert_id = database_service.save_alert(initial_alert)

        # Simulate service restart
        database_service.close()
        self.assertFalse(database_service.is_ready)

        # Re-initialize
        ok = database_service.initialize()
        self.assertTrue(ok)
        self.assertTrue(database_service.is_ready)

        # Verify persisted alert
        reloaded_alert = database_service.get_alert(alert_id)
        self.assertIsNotNone(reloaded_alert)
        self.assertEqual(reloaded_alert.message, "Persistence across restart test")
        self.assertEqual(reloaded_alert.repeat_count, 5)
        self.assertFalse(reloaded_alert.acknowledged)


class TestPipelineAlertIntegration(unittest.TestCase):
    """Test 16: Full pipeline, policy engine, and alert manager integration."""

    def test_pipeline_dispatches_events_to_alert_manager(self):
        database_service.initialize()
        alert_manager.clear_dedup_cache()

        # Dummy packet source providing one Modbus packet
        # MBAP (7 bytes) + FC 0x06 (Write Single Register)
        dummy_packet = b"\x00\x01\x00\x00\x00\x06\x01\x06\x00\x01\x00\x02"

        class SinglePacketSource(PacketSource):
            def __init__(self):
                self._sent = False
                self._active = False

            def start(self) -> None:
                self._active = True

            def stop(self) -> None:
                self._active = False

            def get_packet(self) -> Optional[bytes]:
                if self._active and not self._sent:
                    self._sent = True
                    return dummy_packet
                return None

            def get_mode(self) -> CaptureMode:
                return CaptureMode.SIMULATION

            def is_running(self) -> bool:
                return self._active

        pipeline = PacketPipeline(source=SinglePacketSource())
        captured_events = []
        pipeline.on_event(lambda e: captured_events.append(e))

        pipeline.start()
        time.sleep(0.3)
        pipeline.stop()

        self.assertGreaterEqual(len(captured_events), 1)
        evt = captured_events[0]
        self.assertEqual(evt.modbus_function, "Write Single Register")

        # Verify alert or security event was persisted in database
        recent_events = database_service.load_recent_security_events(limit=5)
        self.assertGreaterEqual(len(recent_events), 1)
        self.assertTrue(any(e.function_name == "Write Single Register" for e in recent_events))


if __name__ == "__main__":
    unittest.main()
