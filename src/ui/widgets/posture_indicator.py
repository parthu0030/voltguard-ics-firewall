"""
VoltGuard — Security Posture Indicator Widget (Day 9)
"""

from __future__ import annotations

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QFrame, QLabel, QVBoxLayout, QWidget

from src.dashboard.security_posture import SecurityPosture, SecurityPostureResult
from src.ui.widgets.severity_styles import POSTURE_COLOURS


class PostureIndicator(QFrame):
    """Visual badge showing current ICS security posture."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self.setStyleSheet(
            """
            QFrame {
                background-color: #161B22;
                border: 1px solid #30363D;
                border-radius: 10px;
            }
            """
        )
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 16, 20, 16)
        layout.setSpacing(8)

        hdr = QLabel("SECURITY POSTURE")
        hdr.setStyleSheet(
            "color: #8B949E; font-size: 10px; font-weight: 700; "
            "letter-spacing: 0.6px; background: transparent;"
        )
        layout.addWidget(hdr)

        self._level_label = QLabel("NORMAL")
        self._level_label.setStyleSheet(
            "color: #3FB950; font-size: 28px; font-weight: 800; background: transparent;"
        )
        layout.addWidget(self._level_label)

        self._summary_label = QLabel("Evaluating…")
        self._summary_label.setWordWrap(True)
        self._summary_label.setStyleSheet(
            "color: #C9D1D9; font-size: 12px; background: transparent;"
        )
        layout.addWidget(self._summary_label)

        self._factors_label = QLabel("")
        self._factors_label.setWordWrap(True)
        self._factors_label.setStyleSheet(
            "color: #8B949E; font-size: 11px; background: transparent;"
        )
        layout.addWidget(self._factors_label)

    def update_posture(self, result: SecurityPostureResult | None) -> None:
        if result is None:
            self._level_label.setText("—")
            self._summary_label.setText("Unable to evaluate posture.")
            self._factors_label.setText("")
            return

        level = result.level.value
        colour = POSTURE_COLOURS.get(level, "#8B949E")
        self._level_label.setText(level)
        self._level_label.setStyleSheet(
            f"color: {colour}; font-size: 28px; font-weight: 800; background: transparent;"
        )
        self._summary_label.setText(result.summary)
        if result.factors:
            self._factors_label.setText("Factors: " + "; ".join(result.factors))
        else:
            self._factors_label.setText("")

        border_colour = colour if result.level != SecurityPosture.NORMAL else "#30363D"
        self.setStyleSheet(
            f"""
            QFrame {{
                background-color: #161B22;
                border: 2px solid {border_colour};
                border-radius: 10px;
            }}
            """
        )
