"""
VoltGuard Settings UI
-----------------------
Allows the user to configure:
  - Network interface
  - Logging level
  - Physics safe thresholds (pressure, flow, temperature, RPM)
  - Alert-on-unknown-protocol toggle
All settings are persisted immediately to SQLite on save.
"""

from __future__ import annotations

from typing import Optional

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFormLayout,
    QFrame,
    QHBoxLayout,
    QLabel,
    QPushButton,
    QScrollArea,
    QVBoxLayout,
    QWidget,
    QMessageBox,
)

from core.packet_capture import PacketCapture
from config.config_manager import get_config, PhysicsThresholds
from core.logger import get_logger

log = get_logger(__name__)


class SettingsPage(QWidget):
    """Settings page for all user-configurable application parameters."""

    def __init__(self, parent: Optional[QWidget] = None) -> None:
        super().__init__(parent)
        self._config = get_config()
        self._capture_ref: Optional[PacketCapture] = None
        self._setup_ui()
        self._load_values()

    # ------------------------------------------------------------------
    # UI
    # ------------------------------------------------------------------

    def _setup_ui(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(0, 0, 0, 0)

        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setFrameShape(QFrame.NoFrame)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)

        container = QWidget()
        layout = QVBoxLayout(container)
        layout.setContentsMargins(28, 24, 28, 24)
        layout.setSpacing(24)

        scroll.setWidget(container)
        outer.addWidget(scroll)

        # Header
        header = QHBoxLayout()
        title = QLabel("Settings")
        title.setObjectName("PageTitle")
        header.addWidget(title)
        header.addStretch()

        self._save_btn = QPushButton("💾  Save Settings")
        self._save_btn.setObjectName("PrimaryButton")
        self._save_btn.clicked.connect(self._save)
        header.addWidget(self._save_btn)

        self._reset_btn = QPushButton("↺  Reset Defaults")
        self._reset_btn.setObjectName("SecondaryButton")
        self._reset_btn.clicked.connect(self._reset_defaults)
        header.addWidget(self._reset_btn)

        layout.addLayout(header)

        # --- Network section ---
        layout.addWidget(_section_label("Network"))
        net_card = _card()
        net_form = QFormLayout(net_card)
        net_form.setContentsMargins(16, 14, 16, 14)
        net_form.setSpacing(12)
        net_form.setLabelAlignment(Qt.AlignRight)

        self._iface_combo = QComboBox()
        self._iface_combo.setObjectName("VGCombo")
        self._iface_combo.addItem("auto (system default)")
        # Dynamically populate
        try:
            from scapy.arch import get_if_list
            for iface in sorted(get_if_list()):
                self._iface_combo.addItem(iface)
        except Exception:
            pass

        net_form.addRow(_form_label("Network Interface"), self._iface_combo)
        layout.addWidget(net_card)

        # --- Application section ---
        layout.addWidget(_section_label("Application"))
        app_card = _card()
        app_form = QFormLayout(app_card)
        app_form.setContentsMargins(16, 14, 16, 14)
        app_form.setSpacing(12)
        app_form.setLabelAlignment(Qt.AlignRight)

        self._log_level_combo = QComboBox()
        self._log_level_combo.setObjectName("VGCombo")
        for level in ("DEBUG", "INFO", "WARNING", "ERROR"):
            self._log_level_combo.addItem(level)

        self._unknown_proto_chk = QCheckBox("Alert on unknown protocol targeting ICS ports")
        self._unknown_proto_chk.setObjectName("VGCheckBox")

        app_form.addRow(_form_label("Logging Level"), self._log_level_combo)
        app_form.addRow(_form_label("Alerts"), self._unknown_proto_chk)
        layout.addWidget(app_card)

        # --- Physics thresholds section ---
        layout.addWidget(_section_label("Physics Safe Thresholds"))

        physics_card = _card()
        physics_form = QFormLayout(physics_card)
        physics_form.setContentsMargins(16, 14, 16, 14)
        physics_form.setSpacing(12)
        physics_form.setLabelAlignment(Qt.AlignRight)

        def _spin(lo: float, hi: float, val: float) -> QDoubleSpinBox:
            s = QDoubleSpinBox()
            s.setObjectName("VGSpinBox")
            s.setRange(lo, hi)
            s.setValue(val)
            s.setDecimals(1)
            s.setSingleStep(1.0)
            return s

        self._pres_min = _spin(-9999, 9999, 0.0)
        self._pres_max = _spin(-9999, 9999, 100.0)
        self._flow_min = _spin(-9999, 9999, 0.0)
        self._flow_max = _spin(-9999, 9999, 50.0)
        self._temp_min = _spin(-9999, 9999, -20.0)
        self._temp_max = _spin(-9999, 9999, 150.0)
        self._rpm_min = _spin(-9999, 9999, 0.0)
        self._rpm_max = _spin(-9999, 9999, 3600.0)

        def _range_row(label: str, w_min: QDoubleSpinBox, w_max: QDoubleSpinBox) -> QHBoxLayout:
            row = QHBoxLayout()
            row.setSpacing(8)
            row.addWidget(QLabel("Min"))
            row.addWidget(w_min)
            row.addSpacing(16)
            row.addWidget(QLabel("Max"))
            row.addWidget(w_max)
            row.addStretch()
            wrapper = QWidget()
            wrapper.setLayout(row)
            return wrapper

        physics_form.addRow(_form_label("Pressure (bar)"), _range_row("Pressure", self._pres_min, self._pres_max))
        physics_form.addRow(_form_label("Flow Rate (m³/h)"), _range_row("Flow", self._flow_min, self._flow_max))
        physics_form.addRow(_form_label("Temperature (°C)"), _range_row("Temp", self._temp_min, self._temp_max))
        physics_form.addRow(_form_label("RPM"), _range_row("RPM", self._rpm_min, self._rpm_max))

        layout.addWidget(physics_card)
        layout.addStretch()

    # ------------------------------------------------------------------
    # Load / Save
    # ------------------------------------------------------------------

    def _load_values(self) -> None:
        """Populate all controls from the current persisted configuration."""
        cfg = self._config.load()

        # Interface
        idx = self._iface_combo.findText(cfg.interface)
        self._iface_combo.setCurrentIndex(max(idx, 0))

        # Logging level
        idx = self._log_level_combo.findText(cfg.logging_level)
        self._log_level_combo.setCurrentIndex(max(idx, 0))

        self._unknown_proto_chk.setChecked(cfg.alert_on_unknown_protocol)

        t = cfg.physics
        self._pres_min.setValue(t.pressure_min)
        self._pres_max.setValue(t.pressure_max)
        self._flow_min.setValue(t.flow_min)
        self._flow_max.setValue(t.flow_max)
        self._temp_min.setValue(t.temperature_min)
        self._temp_max.setValue(t.temperature_max)
        self._rpm_min.setValue(t.rpm_min)
        self._rpm_max.setValue(t.rpm_max)

    def _save(self) -> None:
        """Persist all settings to the database."""
        try:
            self._config.set_interface(self._iface_combo.currentText())
            self._config.set_logging_level(self._log_level_combo.currentText())
            self._config.set_alert_on_unknown_protocol(self._unknown_proto_chk.isChecked())
            self._config.set_physics_thresholds(
                PhysicsThresholds(
                    pressure_min=self._pres_min.value(),
                    pressure_max=self._pres_max.value(),
                    flow_min=self._flow_min.value(),
                    flow_max=self._flow_max.value(),
                    temperature_min=self._temp_min.value(),
                    temperature_max=self._temp_max.value(),
                    rpm_min=self._rpm_min.value(),
                    rpm_max=self._rpm_max.value(),
                )
            )
            QMessageBox.information(self, "Settings Saved", "All settings have been saved successfully.")
            log.info("Settings saved by user.")
        except Exception as exc:
            QMessageBox.critical(self, "Save Failed", str(exc))
            log.error("Settings save failed: %s", exc)

    def _reset_defaults(self) -> None:
        """Reset all controls to factory defaults without saving."""
        confirm = QMessageBox.question(
            self,
            "Reset Defaults",
            "Reset all settings to factory defaults?",
            QMessageBox.Yes | QMessageBox.No,
        )
        if confirm != QMessageBox.Yes:
            return

        self._iface_combo.setCurrentIndex(0)
        idx = self._log_level_combo.findText("INFO")
        self._log_level_combo.setCurrentIndex(max(idx, 0))
        self._unknown_proto_chk.setChecked(True)
        self._pres_min.setValue(0.0)
        self._pres_max.setValue(100.0)
        self._flow_min.setValue(0.0)
        self._flow_max.setValue(50.0)
        self._temp_min.setValue(-20.0)
        self._temp_max.setValue(150.0)
        self._rpm_min.setValue(0.0)
        self._rpm_max.setValue(3600.0)
        log.info("Settings reset to defaults (not yet saved).")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _section_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("SectionLabel")
    return lbl


def _form_label(text: str) -> QLabel:
    lbl = QLabel(text)
    lbl.setObjectName("FieldLabel")
    return lbl


def _card() -> QFrame:
    frame = QFrame()
    frame.setObjectName("SettingsCard")
    return frame
