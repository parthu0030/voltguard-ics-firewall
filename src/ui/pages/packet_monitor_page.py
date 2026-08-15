"""
VoltGuard — Packet Monitor Page
=================================
Placeholder page for the live packet capture and inspection view.

This page is scaffolded for Day 1 (application foundation).
Packet capture, parsing, and live display will be implemented in
Week 1 / Day 2+ milestones as defined in the development plan.

The page renders a professionally styled placeholder that clearly
communicates the upcoming feature without any broken UI elements.
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QFrame,
    QHBoxLayout,
    QLabel,
    QSizePolicy,
    QVBoxLayout,
    QWidget,
)


class PacketMonitorPage(QWidget):
    """
    Packet Monitor placeholder page.

    Will display live Modbus TCP / industrial protocol packet capture,
    inspection results, risk scores, and per-packet allow/block decisions
    once the packet capture engine is integrated (Week 1 milestone).
    """

    PAGE_TITLE = "Packet Monitor"
    PAGE_ICON  = "📡"
    PAGE_DESC  = (
        "Real-time industrial protocol packet capture and inspection.\n"
        "Supports Modbus TCP with per-packet risk scoring and allow/block decisions.\n\n"
        "Implementation scheduled for Week 1 — Packet Capture Milestone."
    )
    FEATURES = [
        "Live packet capture from selected network interface",
        "Modbus TCP protocol parsing and field extraction",
        "Risk score computation per packet",
        "Allow / Block decision display with colour coding",
        "Packet replay and filtering",
    ]

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._build_ui()

    def _build_ui(self) -> None:
        """Construct the placeholder layout."""
        layout = QVBoxLayout(self)
        layout.setContentsMargins(28, 28, 28, 28)
        layout.setSpacing(20)

        layout.addWidget(_build_page_header(self.PAGE_ICON, self.PAGE_TITLE, self.PAGE_DESC))
        layout.addWidget(_build_feature_list(self.FEATURES))
        layout.addStretch()


# ---------------------------------------------------------------------------
# Shared helper builders (used by all placeholder pages)
# ---------------------------------------------------------------------------

def _build_page_header(icon: str, title: str, description: str) -> QWidget:
    """
    Build a reusable page header widget with icon, title, and description.

    Args:
        icon:        Emoji or unicode character for the page icon.
        title:       Page title string.
        description: Multi-line description of the page's purpose.

    Returns:
        A styled QWidget containing the header layout.
    """
    widget = QWidget()
    widget.setStyleSheet("background: transparent;")
    layout = QVBoxLayout(widget)
    layout.setContentsMargins(0, 0, 0, 0)
    layout.setSpacing(6)

    # Title row
    title_row = QHBoxLayout()
    title_row.setSpacing(12)

    icon_label = QLabel(icon)
    icon_label.setStyleSheet(
        "font-size: 30px; background: transparent; color: #E6EDF3;"
    )
    title_row.addWidget(icon_label)

    title_label = QLabel(title)
    title_label.setStyleSheet(
        "font-size: 22px; font-weight: 700; color: #E6EDF3; background: transparent;"
    )
    title_row.addWidget(title_label)
    title_row.addStretch()
    layout.addLayout(title_row)

    # Separator line
    sep = QFrame()
    sep.setFrameShape(QFrame.Shape.HLine)
    sep.setStyleSheet("color: #30363D; background-color: #30363D; max-height: 1px;")
    layout.addWidget(sep)

    # Description
    desc_label = QLabel(description)
    desc_label.setStyleSheet(
        "font-size: 13px; color: #8B949E; background: transparent; line-height: 160%;"
    )
    desc_label.setWordWrap(True)
    layout.addWidget(desc_label)

    return widget


def _build_feature_list(features: list[str]) -> QFrame:
    """
    Build a styled card listing planned features for a placeholder page.

    Args:
        features: List of feature description strings.

    Returns:
        A styled QFrame card widget.
    """
    card = QFrame()
    card.setObjectName("featureCard")
    card.setStyleSheet(
        """
        QFrame#featureCard {
            background-color: #161B22;
            border: 1px solid #30363D;
            border-radius: 10px;
        }
        """
    )
    card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)

    layout = QVBoxLayout(card)
    layout.setContentsMargins(20, 16, 20, 16)
    layout.setSpacing(10)

    header_label = QLabel("Planned Features")
    header_label.setStyleSheet(
        "font-size: 11px; font-weight: 600; color: #8B949E; "
        "letter-spacing: 0.5px; text-transform: uppercase; background: transparent;"
    )
    layout.addWidget(header_label)

    for feature in features:
        row = QHBoxLayout()
        row.setSpacing(10)

        bullet = QLabel("›")
        bullet.setFixedWidth(14)
        bullet.setStyleSheet("color: #1F6FEB; font-size: 16px; font-weight: bold; background: transparent;")
        bullet.setAlignment(Qt.AlignmentFlag.AlignTop)
        row.addWidget(bullet)

        text = QLabel(feature)
        text.setStyleSheet("color: #E6EDF3; font-size: 13px; background: transparent;")
        text.setWordWrap(True)
        row.addWidget(text, 1)

        layout.addLayout(row)

    return card
