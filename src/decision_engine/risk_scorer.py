"""
VoltGuard — Deterministic Risk Scorer
======================================
Converts a list of triggered ``DecisionReason`` objects into a single,
deterministic ``RiskAssessment``.

Scoring algorithm
-----------------
1. Sum all ``risk_contribution`` values from every triggered reason.
2. Clamp the total to [0, 100].
3. Derive the overall ``SeverityLevel`` from the *highest* severity
   seen among all triggered reasons (not from the score alone).
4. Map the risk score to a decision-level ``SeverityLevel`` using the
   configured thresholds as a cross-check.

Design principles:
  - **Deterministic** — same input always produces the same output.
  - **Explainable** — every point in the score traces to a specific rule.
  - **No randomness** — no AI-generated or random scores.
  - **Configurable** — thresholds come from ``DecisionConfig``, not magic numbers.

Usage::

    from src.decision_engine.risk_scorer import RiskScorer
    from src.decision_engine.decision_config import DecisionConfig

    scorer = RiskScorer(cfg)
    assessment = scorer.calculate(reasons)
    print(assessment.risk_score, assessment.severity)
"""

from __future__ import annotations

from src.decision_engine.decision_config import DecisionConfig
from src.decision_engine.models import DecisionReason, RiskAssessment, SeverityLevel


# ---------------------------------------------------------------------------
# Severity score → SeverityLevel thresholds (used when no reasons fire)
# ---------------------------------------------------------------------------

_SCORE_TO_SEVERITY: list[tuple[int, SeverityLevel]] = [
    (0,   SeverityLevel.SAFE),
    (15,  SeverityLevel.LOW),
    (40,  SeverityLevel.MEDIUM),
    (70,  SeverityLevel.HIGH),
    (90,  SeverityLevel.CRITICAL),
]
"""
Ordered (min_score, severity) pairs used when deriving severity from score.
The highest entry whose min_score is ≤ actual_score wins.
"""


class RiskScorer:
    """
    Deterministic risk scorer for the VoltGuard decision pipeline.

    Accepts a list of ``DecisionReason`` objects and produces a single
    ``RiskAssessment`` with a score and a severity level.

    Parameters
    ----------
    cfg : DecisionConfig
        Configuration providing alert/block thresholds (used only for the
        ``assess_decision_level`` helper).
    """

    def __init__(self, cfg: DecisionConfig) -> None:
        """
        Initialise the scorer with the given configuration.

        Args:
            cfg: ``DecisionConfig`` with risk and severity thresholds.
        """
        self._cfg = cfg

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def calculate(self, reasons: list[DecisionReason]) -> RiskAssessment:
        """
        Aggregate a list of triggered ``DecisionReason`` objects into a
        ``RiskAssessment``.

        Algorithm:
            1. Sum ``risk_contribution`` for every reason.
            2. Clamp total to [0, 100].
            3. Determine overall severity as the maximum severity seen
               across all triggered reasons.
            4. If no reasons fired, return a SAFE assessment with score 0.

        Args:
            reasons: List of triggered ``DecisionReason`` instances.
                     An empty list means no rules fired.

        Returns:
            A ``RiskAssessment`` with a deterministic score and severity.
        """
        if not reasons:
            return RiskAssessment(
                risk_score=0,
                severity=SeverityLevel.SAFE,
                triggered_rules=[],
                reasons=[],
            )

        # 1. Accumulate score
        raw_score: int = sum(r.risk_contribution for r in reasons)
        clamped_score: int = min(max(raw_score, 0), 100)

        # 2. Derive severity from the *highest* severity among all reasons.
        #    This means a single CRITICAL rule dominates the result even if
        #    other reasons are LOW.
        max_severity: SeverityLevel = max(r.severity for r in reasons)

        # 3. Cross-check: if the score itself warrants a higher severity than
        #    what individual rules reported, upgrade (never downgrade).
        score_severity = self._severity_from_score(clamped_score)
        overall_severity = max_severity if max_severity >= score_severity else score_severity

        triggered_rules = [r.rule_id for r in reasons]

        return RiskAssessment(
            risk_score=clamped_score,
            severity=overall_severity,
            triggered_rules=triggered_rules,
            reasons=list(reasons),
        )

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _severity_from_score(score: int) -> SeverityLevel:
        """
        Map an integer risk score to the corresponding ``SeverityLevel``
        using the static threshold table ``_SCORE_TO_SEVERITY``.

        The highest threshold that is ≤ the score wins.

        Args:
            score: Integer in [0, 100].

        Returns:
            The matching ``SeverityLevel``.
        """
        result = SeverityLevel.SAFE
        for min_score, level in _SCORE_TO_SEVERITY:
            if score >= min_score:
                result = level
            else:
                break
        return result
