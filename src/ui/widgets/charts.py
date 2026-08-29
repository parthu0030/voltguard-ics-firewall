"""
VoltGuard — Lightweight Chart Widgets (Day 9)
==============================================
Custom QPainter-based charts avoiding external charting dependencies.
"""

from __future__ import annotations

from typing import Optional

from PyQt6.QtCore import Qt
from PyQt6.QtGui import QColor, QFont, QPainter, QPen
from PyQt6.QtWidgets import QLabel, QVBoxLayout, QWidget


class _ChartBase(QWidget):
    """Base chart panel with title and empty-state support."""

    def __init__(
        self,
        title: str,
        empty_message: str = "No data available",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self._title = title
        self._empty_message = empty_message
        self._is_empty = True
        self.setMinimumHeight(180)
        self.setStyleSheet(
            """
            background-color: #161B22;
            border: 1px solid #30363D;
            border-radius: 10px;
            """
        )

    def set_empty(self, empty: bool) -> None:
        self._is_empty = empty
        self.update()

    def paintEvent(self, event) -> None:  # noqa: N802
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Title
        painter.setPen(Qt.GlobalColor.white)
        font = QFont()
        font.setPointSize(10)
        font.setBold(True)
        painter.setFont(font)
        painter.drawText(14, 22, self._title)

        if self._is_empty:
            painter.setPen(QColor("#484F58"))
            font.setBold(False)
            font.setPointSize(9)
            painter.setFont(font)
            painter.drawText(14, 60, self._empty_message)
            painter.end()
            return

        self._paint_chart(painter)
        painter.end()

    def _paint_chart(self, painter: QPainter) -> None:
        raise NotImplementedError


class BarChartWidget(_ChartBase):
    """Vertical or horizontal bar chart from label→value pairs."""

    def __init__(
        self,
        title: str,
        horizontal: bool = False,
        bar_colours: Optional[list[str]] = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(title, parent=parent)
        self._horizontal = horizontal
        self._bar_colours = bar_colours or ["#58A6FF", "#3FB950", "#F0883E", "#F85149", "#BC8CFF"]
        self._data: list[tuple[str, float]] = []

    def set_data(self, data: dict[str, int] | list[tuple[str, int]]) -> None:
        if isinstance(data, dict):
            items = list(data.items())
        else:
            items = [(str(k), float(v)) for k, v in data]
        self._data = [(str(k), float(v)) for k, v in items if v > 0]
        self.set_empty(len(self._data) == 0)
        self.update()

    def _paint_chart(self, painter: QPainter) -> None:
        if not self._data:
            return
        margin = 14
        top = 36
        w = self.width() - margin * 2
        h = self.height() - top - margin
        max_val = max(v for _, v in self._data) or 1.0

        if self._horizontal:
            bar_h = max(12, min(28, h // max(len(self._data), 1) - 4))
            gap = 6
            y = top
            for i, (label, val) in enumerate(self._data):
                bar_w = int((val / max_val) * (w - 80))
                colour = self._bar_colours[i % len(self._bar_colours)]
                painter.fillRect(margin + 70, y, bar_w, bar_h, QColor(colour))
                painter.setPen(QColor("#8B949E"))
                font = QFont()
                font.setPointSize(8)
                painter.setFont(font)
                short = label if len(label) <= 12 else label[:11] + "…"
                painter.drawText(margin, y + bar_h - 2, short)
                painter.setPen(QColor("#E6EDF3"))
                painter.drawText(margin + 74 + bar_w + 4, y + bar_h - 2, str(int(val)))
                y += bar_h + gap
        else:
            n = len(self._data)
            bar_w = max(8, (w - (n + 1) * 6) // max(n, 1))
            x = margin + 6
            bottom = top + h
            for i, (label, val) in enumerate(self._data):
                bar_h = int((val / max_val) * (h - 20))
                colour = self._bar_colours[i % len(self._bar_colours)]
                painter.fillRect(x, bottom - bar_h, bar_w, bar_h, QColor(colour))
                painter.setPen(QColor("#8B949E"))
                font = QFont()
                font.setPointSize(7)
                painter.setFont(font)
                short = label if len(label) <= 6 else label[:5] + "…"
                painter.drawText(x, bottom + 12, bar_w + 4, 14, Qt.AlignmentFlag.AlignCenter, short)
                x += bar_w + 6


class LineChartWidget(_ChartBase):
    """Simple line chart for time-series numeric data."""

    def __init__(
        self,
        title: str,
        line_colour: str = "#58A6FF",
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(title, parent=parent)
        self._line_colour = line_colour
        self._points: list[tuple[str, float]] = []

    def set_data(self, points: list[dict]) -> None:
        """Accept list of dicts with ``time_bucket`` and a numeric value key."""
        value_keys = ("event_count", "alert_count", "blocked_count", "value")
        self._points = []
        for pt in points:
            val = 0.0
            for k in value_keys:
                if k in pt:
                    val = float(pt[k])
                    break
            bucket = pt.get("time_bucket", "")
            label = bucket.split("T")[-1][:5] if "T" in bucket else bucket[-5:]
            self._points.append((label, val))
        self.set_empty(len(self._points) == 0)
        self.update()

    def _paint_chart(self, painter: QPainter) -> None:
        if len(self._points) < 1:
            return
        margin = 14
        top = 36
        w = self.width() - margin * 2
        h = self.height() - top - margin - 16
        max_val = max(v for _, v in self._points) or 1.0

        n = len(self._points)
        if n == 1:
            xs = [margin + w // 2]
        else:
            xs = [margin + int(i * w / (n - 1)) for i in range(n)]

        ys = [top + h - int((v / max_val) * h) for _, v in self._points]

        pen = QPen(QColor(self._line_colour))
        pen.setWidth(2)
        painter.setPen(pen)
        for i in range(1, len(xs)):
            painter.drawLine(xs[i - 1], ys[i - 1], xs[i], ys[i])

        painter.setBrush(QColor(self._line_colour))
        for x, y in zip(xs, ys):
            painter.drawEllipse(x - 3, y - 3, 6, 6)

        painter.setPen(QColor("#484F58"))
        font = QFont()
        font.setPointSize(7)
        painter.setFont(font)
        step = max(1, n // 5)
        for i in range(0, n, step):
            painter.drawText(xs[i] - 16, top + h + 14, 32, 12, Qt.AlignmentFlag.AlignCenter, self._points[i][0])


class PieChartWidget(_ChartBase):
    """Simple pie chart for categorical distributions."""

    PIE_COLOURS = ["#3FB950", "#F0883E", "#F85149", "#58A6FF", "#BC8CFF", "#D29922"]

    def __init__(self, title: str, parent: QWidget | None = None) -> None:
        super().__init__(title, parent=parent)
        self._data: list[tuple[str, float]] = []

    def set_data(self, data: dict[str, int]) -> None:
        self._data = [(k, float(v)) for k, v in data.items() if v > 0]
        self.set_empty(len(self._data) == 0)
        self.update()

    def _paint_chart(self, painter: QPainter) -> None:
        if not self._data:
            return
        total = sum(v for _, v in self._data) or 1.0
        cx = self.width() // 2 - 40
        cy = self.height() // 2 + 10
        radius = min(50, self.height() // 2 - 30)
        start_angle = 90 * 16

        for i, (label, val) in enumerate(self._data):
            span = int(-360 * 16 * val / total)
            colour = self.PIE_COLOURS[i % len(self.PIE_COLOURS)]
            painter.setBrush(QColor(colour))
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawPie(cx - radius, cy - radius, radius * 2, radius * 2, start_angle, span)
            start_angle += span

        # Legend
        lx = self.width() - 110
        ly = 40
        font = QFont()
        font.setPointSize(8)
        painter.setFont(font)
        for i, (label, val) in enumerate(self._data):
            colour = self.PIE_COLOURS[i % len(self.PIE_COLOURS)]
            painter.fillRect(lx, ly, 10, 10, QColor(colour))
            pct = val / total * 100
            painter.setPen(QColor("#C9D1D9"))
            painter.drawText(lx + 14, ly + 10, f"{label} ({int(val)}, {pct:.0f}%)")
            ly += 18


class ChartPanel(QWidget):
    """Wrapper with title label for embedding charts in grids."""

    def __init__(self, chart: _ChartBase, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(chart)
        self.chart = chart
