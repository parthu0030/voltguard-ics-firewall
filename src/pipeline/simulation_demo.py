"""
VoltGuard — Simulation Mode Demo
===================================
Standalone demonstration of the complete Day 5 packet security pipeline
running in SIMULATION mode.

Runs all 5 simulation scenarios through the full pipeline:
  1. Safe read         → expected: ALLOW
  2. Safe write        → expected: ALLOW
  3. Suspicious write  → expected: ALERT
  4. Unsafe command    → expected: ALERT or BLOCK
  5. Malformed packet  → expected: parse failure (logged, not evaluated)

Usage::

    python3 -m src.pipeline.simulation_demo

No network access, no root privileges, no ICS network required.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

# ── Ensure project root is on sys.path ───────────────────────────────────
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from src.capture.capture_mode import CaptureMode
from src.capture.simulation_source import SimulationPacketSource
from src.config import config_loader
from src.decision_engine.decision_config import DecisionConfig
from src.decision_engine.engine import PhysicsAwareDecisionEngine
from src.decision_engine.models import DecisionType
from src.logger import get_logger
from src.parser.packet_models import ParseStatus
from src.parser.protocol_parser import ProtocolParser
from src.physics.physics_config import PhysicsConfig
from src.physics.water_system_engine import CommandType, WaterSystemEngine
from src.pipeline.pipeline_event import PipelineEvent

_log = get_logger(__name__)

# ANSI colours for terminal output
_GREEN  = "\033[92m"
_YELLOW = "\033[93m"
_RED    = "\033[91m"
_CYAN   = "\033[96m"
_RESET  = "\033[0m"
_BOLD   = "\033[1m"


def _decision_colour(decision: str) -> str:
    """Return the ANSI colour for a decision string."""
    if decision == DecisionType.ALLOW.value:
        return _GREEN
    if decision == DecisionType.ALERT.value:
        return _YELLOW
    if decision == DecisionType.BLOCK.value:
        return _RED
    return _CYAN


def run_simulation_demo() -> list[PipelineEvent]:
    """
    Execute the 5-scenario simulation pipeline and return all events.

    This function is the self-contained simulation runner:
      - Initialises Day 2–4 components from config.
      - Runs each scenario through the full pipeline synchronously.
      - Prints a coloured, formatted report.
      - Returns the list of events for programmatic use / tests.

    Returns:
        List of ``PipelineEvent`` objects, one per processed packet.
    """
    print(f"\n{_BOLD}{_CYAN}{'=' * 62}{_RESET}")
    print(f"{_BOLD}{_CYAN}  VoltGuard ICS Firewall — Day 5 Simulation Demo{_RESET}")
    print(f"{_BOLD}{_CYAN}{'=' * 62}{_RESET}\n")

    # ── Bootstrap config ─────────────────────────────────────────────────
    if not config_loader.is_loaded:
        config_loader.load()

    physics_cfg  = PhysicsConfig.from_config(config_loader)
    decision_cfg = DecisionConfig.from_config(config_loader)

    # ── Initialise Day 2–4 components ────────────────────────────────────
    parser   = ProtocolParser()
    engine   = WaterSystemEngine(physics_cfg)
    decider  = PhysicsAwareDecisionEngine(physics_cfg, decision_cfg)

    # Seed the physics engine with a realistic running state
    engine.apply_command(CommandType.SET_PUMP, 1.0)
    engine.apply_command(CommandType.SET_VALVE, 0.6)
    engine.update_state()

    # ── Build simulation source (single cycle — no loop) ─────────────────
    source = SimulationPacketSource(loop=False)
    source.start()

    events: list[PipelineEvent] = []
    scenario_num = 0

    print(f"  {'Scen':<5}  {'Protocol':<14}  {'FC':<30}  {'Decision':<8}  {'Risk':>5}  {'Level':<10}")
    print(f"  {'-'*5}  {'-'*14}  {'-'*30}  {'-'*8}  {'-'*5}  {'-'*10}")

    while True:
        raw = source.get_packet()
        if raw is None:
            break  # All 5 scenarios consumed

        scenario_num += 1

        # ── Step 1: Parse ─────────────────────────────────────────────────
        if len(raw) >= 54:
            packet = parser.parse_full_packet(raw)
        else:
            packet = parser.parse_modbus_only(raw)

        if not packet.is_valid:
            # Parse failure — create an event without decision engine
            from datetime import datetime, timezone
            ts = datetime.now(tz=timezone.utc).isoformat(timespec="seconds")
            evt = PipelineEvent.from_parse_failure(packet, ts)
            events.append(evt)

            status_str = f"PARSE FAIL ({packet.parse_status.value})"
            print(
                f"  {scenario_num:<5}  {'Unknown':<14}  {status_str:<30}  "
                f"{_CYAN}SKIP    {_RESET}  {'N/A':>5}  {'N/A':<10}"
            )
            _log.warning(
                "Simulation scenario %d: parse failure status=%s",
                scenario_num,
                packet.parse_status.value,
            )
            continue

        # ── Step 2: Physics state ─────────────────────────────────────────
        try:
            from src.pipeline.packet_pipeline import _patch_engine_state_method
        except ImportError:
            pass

        import copy
        with engine._lock:
            physics_state = copy.copy(engine._state)

        # ── Step 3: Decision engine ───────────────────────────────────────
        result = decider.evaluate_full_packet(packet, physics_state)

        # ── Step 4: Build event ───────────────────────────────────────────
        evt = PipelineEvent.from_decision(result, packet)
        events.append(evt)

        fc_str = (
            f"FC 0x{result.function_code:02X} {result.function_name}"
            if result.function_code is not None
            else "N/A"
        )
        protocol_str = evt.protocol
        colour = _decision_colour(evt.decision)

        print(
            f"  {scenario_num:<5}  {protocol_str:<14}  {fc_str:<30}  "
            f"{colour}{evt.decision:<8}{_RESET}  {evt.risk_score:>5}  {evt.risk_level:<10}"
        )

        if result.triggered_rules:
            rules_str = ", ".join(result.triggered_rules[:3])
            if len(result.triggered_rules) > 3:
                rules_str += f" (+{len(result.triggered_rules) - 3} more)"
            print(f"  {'':5}  Rules: {_YELLOW}{rules_str}{_RESET}")

    source.stop()

    # ── Summary ───────────────────────────────────────────────────────────
    total    = len(events)
    allowed  = sum(1 for e in events if e.is_allowed)
    alerted  = sum(1 for e in events if e.is_alerted)
    blocked  = sum(1 for e in events if e.is_blocked)
    failures = sum(1 for e in events if e.is_parse_failure)

    print(f"\n{_BOLD}  Summary{_RESET}")
    print(f"  {'─' * 40}")
    print(f"  Total processed : {total}")
    print(f"  {_GREEN}ALLOW           : {allowed}{_RESET}")
    print(f"  {_YELLOW}ALERT           : {alerted}{_RESET}")
    print(f"  {_RED}BLOCK           : {blocked}{_RESET}")
    print(f"  {_CYAN}Parse failures  : {failures}{_RESET}")

    parser_stats = parser.get_statistics()
    print(f"\n  Parser stats    : {parser_stats}")
    print(f"\n{_BOLD}{_CYAN}{'=' * 62}{_RESET}\n")

    return events


if __name__ == "__main__":
    events = run_simulation_demo()
    sys.exit(0)
