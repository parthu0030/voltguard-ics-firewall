"""
VoltGuard Decision Engine
--------------------------
Evaluates parsed packet records and physics states against configurable
rule sets to determine allow / block decisions and raise alerts.

Week 1: Rule-based skeleton with extensible architecture.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Callable, List, Optional

from core.logger import get_logger, log_security_event
from core.protocol_parser import ParsedPacket
from core.physics_engine import PhysicsState

log = get_logger(__name__)


class Decision(str, Enum):
    """Possible packet decisions."""
    ALLOW = "ALLOWED"
    BLOCK = "BLOCKED"
    ALERT = "ALERT"


@dataclass
class RuleResult:
    """Result produced by evaluating a single rule."""
    decision: Decision
    rule_name: str
    reason: str
    severity: str = "INFO"


class DecisionEngine:
    """Evaluates packets and physics states against a priority-ordered rule chain.

    Rules are simple callables with the signature::

        (ParsedPacket) -> Optional[RuleResult]

    If a rule returns ``None`` it abstains (no match); the next rule is tried.
    The first non-``None`` result wins.  If no rule matches, the packet is
    allowed by default.

    Example::

        engine = DecisionEngine()
        result = engine.evaluate_packet(parsed_packet)
    """

    def __init__(self) -> None:
        self._packet_rules: List[Callable[[ParsedPacket], Optional[RuleResult]]] = []
        self._register_builtin_rules()
        log.info("DecisionEngine initialised with %d built-in rules.", len(self._packet_rules))

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def evaluate_packet(self, pkt: ParsedPacket) -> Decision:
        """Evaluate a parsed packet against all rules.

        Args:
            pkt: :class:`ParsedPacket` to evaluate.

        Returns:
            :class:`Decision` indicating what action to take.
        """
        for rule in self._packet_rules:
            result = rule(pkt)
            if result is not None:
                log.debug(
                    "Rule '%s' fired: %s — %s",
                    result.rule_name,
                    result.decision,
                    result.reason,
                )
                if result.decision in (Decision.BLOCK, Decision.ALERT):
                    log_security_event(
                        event_type=result.rule_name,
                        source_ip=pkt.src_ip,
                        destination_ip=pkt.dst_ip,
                        description=result.reason,
                        severity=result.severity,
                    )
                return result.decision

        # Default policy: allow
        return Decision.ALLOW

    def evaluate_physics(self, state: PhysicsState) -> Optional[RuleResult]:
        """Evaluate a physics state snapshot for anomalies.

        Args:
            state: :class:`PhysicsState` to inspect.

        Returns:
            :class:`RuleResult` if an anomaly is detected, else ``None``.
        """
        if state.anomaly:
            reason = (
                f"Physics anomaly — pressure={state.pressure:.2f}, "
                f"flow={state.flow:.2f}, temp={state.temperature:.2f}, "
                f"rpm={state.rpm:.2f}"
            )
            log.warning(reason)
            return RuleResult(
                decision=Decision.ALERT,
                rule_name="PHYSICS_ANOMALY",
                reason=reason,
                severity="HIGH",
            )
        return None

    def add_rule(self, rule: Callable[[ParsedPacket], Optional[RuleResult]]) -> None:
        """Append a custom rule to the evaluation chain.

        Args:
            rule: Callable that accepts a :class:`ParsedPacket` and returns
                  a :class:`RuleResult` or ``None``.
        """
        self._packet_rules.append(rule)
        log.info("Custom rule added. Total rules: %d", len(self._packet_rules))

    # ------------------------------------------------------------------
    # Built-in rule definitions
    # ------------------------------------------------------------------

    def _register_builtin_rules(self) -> None:
        """Register the default Week-1 rule set."""
        self._packet_rules.extend(
            [
                self._rule_private_src_only,
                self._rule_modbus_write_alert,
                self._rule_dnp3_direct_operate,
                self._rule_unknown_protocol,
            ]
        )

    @staticmethod
    def _rule_private_src_only(pkt: ParsedPacket) -> Optional[RuleResult]:
        """Block packets from non-RFC-1918 source addresses targeting ICS ports."""
        ics_ports = {502, 20000, 44818, 2404}
        if pkt.dst_port not in ics_ports:
            return None
        # Simple check: private ranges start with 10., 192.168., 172.16-31.
        src = pkt.src_ip
        if src.startswith(("10.", "192.168.", "127.")):
            return None
        parts = src.split(".")
        if len(parts) == 4 and parts[0] == "172":
            second = int(parts[1])
            if 16 <= second <= 31:
                return None
        return RuleResult(
            decision=Decision.BLOCK,
            rule_name="NON_PRIVATE_SRC_ICS",
            reason=f"Non-private source IP {src} targeting ICS port {pkt.dst_port}",
            severity="CRITICAL",
        )

    @staticmethod
    def _rule_modbus_write_alert(pkt: ParsedPacket) -> Optional[RuleResult]:
        """Alert on Modbus write function codes (FC 5, 6, 15, 16)."""
        if pkt.protocol != "MODBUS":
            return None
        write_fcs = {5, 6, 15, 16}
        if pkt.function_code in write_fcs:
            return RuleResult(
                decision=Decision.ALERT,
                rule_name="MODBUS_WRITE_FC",
                reason=f"Modbus write FC={pkt.function_code} from {pkt.src_ip}",
                severity="MEDIUM",
            )
        return None

    @staticmethod
    def _rule_dnp3_direct_operate(pkt: ParsedPacket) -> Optional[RuleResult]:
        """Alert on DNP3 Direct Operate commands (FC 5, 6)."""
        if pkt.protocol != "DNP3":
            return None
        direct_operate_fcs = {5, 6}
        if pkt.function_code in direct_operate_fcs:
            return RuleResult(
                decision=Decision.ALERT,
                rule_name="DNP3_DIRECT_OPERATE",
                reason=f"DNP3 Direct Operate FC={pkt.function_code} from {pkt.src_ip}",
                severity="HIGH",
            )
        return None

    @staticmethod
    def _rule_unknown_protocol(pkt: ParsedPacket) -> Optional[RuleResult]:
        """Alert on completely unknown protocols on ICS ports."""
        ics_ports = {502, 20000, 44818, 2404}
        if pkt.protocol not in ("MODBUS", "DNP3", "TCP", "UDP", "NON-IP"):
            return None
        if pkt.protocol == "UNKNOWN" and pkt.dst_port in ics_ports:
            return RuleResult(
                decision=Decision.ALERT,
                rule_name="UNKNOWN_ICS_PROTOCOL",
                reason=f"Unknown protocol on ICS port {pkt.dst_port} from {pkt.src_ip}",
                severity="HIGH",
            )
        return None
