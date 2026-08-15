"""
VoltGuard — Project Constants
===============================
Single source of truth for all project-wide constant values.

Rules:
  - No mutable state here — every binding is truly constant.
  - Import from this module; never hard-code strings elsewhere.
  - Paths are computed relative to the project root so the app runs
    correctly regardless of where the user invokes it from.

Usage:
    from src.constants import PROJECT_ROOT, MODBUS_PORT, APP_VERSION
"""

from __future__ import annotations

from pathlib import Path

# ---------------------------------------------------------------------------
# Application Identity
# ---------------------------------------------------------------------------

APP_NAME: str = "VoltGuard"
APP_VERSION: str = "1.0.0"
APP_AUTHOR: str = "VoltGuard Security"
APP_DESCRIPTION: str = "Physics-Aware ICS/SCADA Intrusion Detection System"

# ---------------------------------------------------------------------------
# Filesystem Paths
# ---------------------------------------------------------------------------

# The project root is the parent of the ``src/`` directory.
PROJECT_ROOT: Path = Path(__file__).resolve().parents[1]

LOGS_DIR: Path = PROJECT_ROOT / "logs"
REPORTS_DIR: Path = PROJECT_ROOT / "reports"
ASSETS_DIR: Path = PROJECT_ROOT / "assets"
DOCS_DIR: Path = PROJECT_ROOT / "docs"
TESTS_DIR: Path = PROJECT_ROOT / "tests"
CONFIG_FILE: Path = PROJECT_ROOT / "config.json"
DB_FILE: Path = PROJECT_ROOT / "voltguard.db"

# Directories that must exist for the application to operate correctly.
REQUIRED_DIRS: list[Path] = [
    LOGS_DIR,
    REPORTS_DIR,
    ASSETS_DIR,
    DOCS_DIR,
    TESTS_DIR,
]

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

DEFAULT_LOG_LEVEL: str = "INFO"
LOG_FILE_NAME: str = "application.log"
LOG_MAX_BYTES: int = 5 * 1024 * 1024   # 5 MB per rotating file
LOG_BACKUP_COUNT: int = 5              # Keep up to 5 rotated backups
LOG_DATE_FORMAT: str = "%Y-%m-%d %H:%M:%S"
LOG_FORMAT: str = "%(asctime)s [%(levelname)-8s] [%(name)s] %(message)s"

# ---------------------------------------------------------------------------
# Industrial Protocol Constants
# ---------------------------------------------------------------------------

MODBUS_PORT: int = 502       # Modbus TCP well-known port
DNP3_PORT: int = 20000       # DNP3 default TCP port
ENIP_PORT: int = 44818       # EtherNet/IP (Allen-Bradley) port
OPC_UA_PORT: int = 4840      # OPC-UA default port

# Modbus function codes (most commonly seen in ICS traffic).
MODBUS_FC_READ_COILS: int = 0x01
MODBUS_FC_READ_DISCRETE_INPUTS: int = 0x02
MODBUS_FC_READ_HOLDING_REGISTERS: int = 0x03
MODBUS_FC_READ_INPUT_REGISTERS: int = 0x04
MODBUS_FC_WRITE_SINGLE_COIL: int = 0x05
MODBUS_FC_WRITE_SINGLE_REGISTER: int = 0x06
MODBUS_FC_WRITE_MULTIPLE_COILS: int = 0x0F
MODBUS_FC_WRITE_MULTIPLE_REGISTERS: int = 0x10

# ---------------------------------------------------------------------------
# Health Check / Status Flags
# ---------------------------------------------------------------------------

STATUS_PASS: str = "PASS"
STATUS_FAIL: str = "FAIL"
STATUS_WARN: str = "WARN"
STATUS_UNKNOWN: str = "UNKNOWN"

# ---------------------------------------------------------------------------
# Physics / Simulation Safety Limits (defaults; overridden by config)
# ---------------------------------------------------------------------------

PHYSICS_PRESSURE_MAX_BAR: float = 10.0    # Maximum safe pressure in bar
PHYSICS_FLOW_MAX_LPS: float = 50.0        # Maximum safe flow in litres/sec
PHYSICS_TEMP_MAX_CELSIUS: float = 150.0   # Maximum safe temperature in °C
PHYSICS_RPM_MAX: float = 3600.0           # Maximum safe rotational speed in RPM

# ---------------------------------------------------------------------------
# Decision Engine
# ---------------------------------------------------------------------------

RISK_SCORE_LOW: float = 0.25       # Below this → LOW risk
RISK_SCORE_MEDIUM: float = 0.50    # Between LOW and this → MEDIUM
RISK_SCORE_HIGH: float = 0.75      # Between MEDIUM and this → HIGH
RISK_SCORE_CRITICAL: float = 1.0   # At or above HIGH → CRITICAL / BLOCK

# ---------------------------------------------------------------------------
# Configuration Keys
# ---------------------------------------------------------------------------

# Keys used in config.json (and validated by ConfigLoader).
CFG_KEY_APP_VERSION: str = "app_version"
CFG_KEY_LOG_LEVEL: str = "log_level"
CFG_KEY_INTERFACE: str = "selected_interface"
CFG_KEY_THEME: str = "theme"
CFG_KEY_DB_PATH: str = "db_path"
CFG_KEY_PHYSICS: str = "physics"
CFG_KEY_PRESSURE_MAX: str = "pressure_max_bar"
CFG_KEY_FLOW_MAX: str = "flow_max_lps"
CFG_KEY_TEMP_MAX: str = "temp_max_celsius"
CFG_KEY_RPM_MAX: str = "rpm_max"
