"""
VoltGuard Test Suite
---------------------
Week 1: Smoke tests for core modules.
"""

import sys
from pathlib import Path

# Ensure project root is on path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


def test_database_initialises():
    """DatabaseManager should create all four tables on first run."""
    from database.database import DatabaseManager
    import tempfile, os

    with tempfile.TemporaryDirectory() as tmp:
        db_path = Path(tmp) / "test.db"
        db = DatabaseManager(db_path=db_path)

        settings = db.get_all_settings()
        assert "interface" in settings, "Default settings not seeded"
        assert "dark_mode" in settings

        stats = db.get_packet_stats()
        assert stats["total"] == 0


def test_settings_round_trip():
    """Setting a value and reading it back should return the same string."""
    from database.database import DatabaseManager
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        db = DatabaseManager(db_path=Path(tmp) / "test.db")
        db.set_setting("interface", "eth0")
        assert db.get_setting("interface") == "eth0"


def test_packet_insert_and_retrieve():
    """Inserting a packet log should be retrievable via get_recent_packets."""
    from database.database import DatabaseManager
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        db = DatabaseManager(db_path=Path(tmp) / "test.db")
        row_id = db.insert_packet_log(
            src_ip="192.168.1.1",
            dst_ip="10.0.0.1",
            src_port=1234,
            dst_port=502,
            protocol="MODBUS",
            function_code=3,
            payload_length=10,
            action="ALLOWED",
        )
        assert row_id > 0

        packets = db.get_recent_packets(limit=10)
        assert len(packets) == 1
        assert packets[0]["protocol"] == "MODBUS"


def test_protocol_parser_unknown():
    """Parsing a non-IP mock should not crash and return a ParsedPacket."""
    from core.protocol_parser import ProtocolParser, ParsedPacket

    class MockPkt:
        def haslayer(self, _):
            return False
        def summary(self):
            return "mock-packet"

    parser = ProtocolParser()
    result = parser.parse(MockPkt())  # type: ignore
    assert isinstance(result, ParsedPacket)


def test_physics_engine_thresholds():
    """Physics engine should detect anomaly when value is out of range."""
    from core.physics_engine import PhysicsEngine, PhysicsThresholds

    engine = PhysicsEngine(
        thresholds=PhysicsThresholds(pressure_min=0.0, pressure_max=50.0)
    )
    engine.simulate_pressure(75.0)  # above max → anomaly
    assert engine.is_anomaly()

    engine.simulate_pressure(25.0)  # within range
    engine.simulate_flow(25.0)
    engine.simulate_temperature(20.0)
    engine.simulate_rpm(1800.0)
    assert not engine.is_anomaly()


def test_config_manager_load():
    """ConfigManager.load() should return a valid AppConfig."""
    from database.database import DatabaseManager
    from config.config_manager import ConfigManager, AppConfig
    import tempfile

    with tempfile.TemporaryDirectory() as tmp:
        import database.database as db_mod
        original = db_mod._db_instance
        db_mod._db_instance = DatabaseManager(db_path=Path(tmp) / "test.db")
        try:
            cfg_mgr = ConfigManager()
            cfg = cfg_mgr.load()
            assert isinstance(cfg, AppConfig)
            assert cfg.app_version == "1.0.0"
        finally:
            db_mod._db_instance = original


if __name__ == "__main__":
    # Run all tests manually without pytest
    tests = [
        test_database_initialises,
        test_settings_round_trip,
        test_packet_insert_and_retrieve,
        test_protocol_parser_unknown,
        test_physics_engine_thresholds,
        test_config_manager_load,
    ]
    passed = failed = 0
    for test in tests:
        try:
            test()
            print(f"  ✓ {test.__name__}")
            passed += 1
        except Exception as exc:
            print(f"  ✗ {test.__name__}: {exc}")
            failed += 1
    print(f"\n{passed} passed, {failed} failed")
