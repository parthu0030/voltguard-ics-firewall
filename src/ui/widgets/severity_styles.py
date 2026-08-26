"""
VoltGuard — Severity & Action Colour Helpers (Day 9)
=====================================================
Consistent colour tokens for severity levels and enforcement actions
across all dashboard widgets.
"""

from __future__ import annotations

from PyQt6.QtGui import QColor

from src.models.app_models import AlertSeverity

SEVERITY_COLOURS: dict[str, str] = {
    AlertSeverity.CRITICAL.value: "#FF7B72",
    AlertSeverity.HIGH.value: "#F85149",
    AlertSeverity.MEDIUM.value: "#F0883E",
    AlertSeverity.LOW.value: "#58A6FF",
}

ACTION_COLOURS: dict[str, str] = {
    "ALLOW": "#3FB950",
    "ALERT": "#F0883E",
    "BLOCK": "#F85149",
}

POSTURE_COLOURS: dict[str, str] = {
    "NORMAL": "#3FB950",
    "ELEVATED": "#D29922",
    "HIGH": "#F85149",
    "CRITICAL": "#FF7B72",
}


def severity_colour(severity: str) -> str:
    """Return hex colour for a severity string."""
    return SEVERITY_COLOURS.get(severity.upper(), "#C9D1D9")


def severity_qcolor(severity: str) -> QColor:
    """Return QColor for a severity string."""
    return QColor(severity_colour(severity))


def action_colour(action: str) -> str:
    """Return hex colour for an enforcement action."""
    return ACTION_COLOURS.get(action.upper(), "#8B949E")


def action_qcolor(action: str) -> QColor:
    """Return QColor for an enforcement action."""
    return QColor(action_colour(action))


def format_timestamp(ts: str) -> str:
    """Format an ISO timestamp for compact table display."""
    if not ts:
        return "—"
    if "T" in ts:
        parts = ts.split("T")
        time_part = parts[-1].split("+")[0].split("Z")[0]
        if len(time_part) >= 8:
            return time_part[:8]
        return time_part
    return ts[:19] if len(ts) > 19 else ts
