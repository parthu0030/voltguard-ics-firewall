"""
VoltGuard — Dashboard Stat Card Widget (Day 9)
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QFont
from PyQt6.QtWidgets import QFrame, QHBoxLayout, QLabel, QSizePolicy, QVBoxLayout, QWidget


class StatCard(QFrame):
    """Single metric card for dashboard summary grids."""

    def __init__(
        self,
        title: str,
        icon: str,
        initial_value: str = "—",
        accent_colour: str = "#58A6FF",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._accent = accent_colour
        self._build_ui(title, icon, initial_value)
        self.setObjectName("statcard")
        self.setFrameShape(QFrame.Shape.StyledPanel)
        self.setMinimumHeight(100)
        self.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        self.setStyleSheet(
            """
            QFrame#statcard {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 10px;
            }
            QFrame#statcard:hover {
                border-color: #388BFD;
            }
            """
        )

    def _build_ui(self, title: str, icon: str, initial_value: str) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(18, 16, 18, 16)
        layout.setSpacing(6)

        header = QHBoxLayout()
        header.setSpacing(8)

        icon_label = QLabel(icon)
        icon_label.setFont(QFont("Segoe UI Emoji, Arial", 18))
        icon_label.setFixedSize(28, 28)
        icon_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        icon_label.setStyleSheet("background: transparent;")
        header.addWidget(icon_label)

        title_label = QLabel(title)
        title_label.setStyleSheet(
            "color: #8B949E; font-size: 11px; font-weight: 600; "
            "letter-spacing: 0.4px; background: transparent;"
        )
        header.addWidget(title_label, 1)
        layout.addLayout(header)

        self._value_label = QLabel(initial_value)
        self._value_label.setStyleSheet(
            f"color: {self._accent}; font-size: 24px; font-weight: 700; "
            "background: transparent; letter-spacing: -0.5px;"
        )
        layout.addWidget(self._value_label)

    def set_value(self, text: str) -> None:
        self._value_label.setText(text)

    def set_value_colour(self, hex_colour: str) -> None:
        self._accent = hex_colour
        self._value_label.setStyleSheet(
            f"color: {hex_colour}; font-size: 24px; font-weight: 700; "
            "background: transparent; letter-spacing: -0.5px;"
        )
