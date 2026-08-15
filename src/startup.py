"""
VoltGuard — Startup Sequence
===============================
Orchestrates the headless pre-Qt startup sequence:

  1. Print ASCII art banner.
  2. Display system information (version, Python, OS, memory, CWD).
  3. Verify required Python dependencies.
  4. Run the system health check and print the PASS/FAIL table.

This module is Qt-free so it runs in CI environments, during tests,
and before the QApplication object exists.

Usage:
    from src.startup import run_startup_sequence

    run_startup_sequence()   # Prints banner + info + deps + health check
    # Or use individual functions:
    from src.startup import print_banner, print_startup_info, verify_dependencies
"""

from __future__ import annotations

import importlib
import os
import platform
import sys
from pathlib import Path
from typing import Optional

from src.constants import APP_NAME, APP_VERSION, APP_AUTHOR, APP_DESCRIPTION


# ---------------------------------------------------------------------------
# ANSI helpers (gracefully degraded on non-TTY)
# ---------------------------------------------------------------------------

_IS_TTY: bool = hasattr(sys.stdout, "isatty") and sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    """Wrap ``text`` in an ANSI escape ``code`` when stdout is a TTY."""
    if _IS_TTY:
        return f"{code}{text}\033[0m"
    return text


_CYAN    = "\033[96m"
_GREEN   = "\033[92m"
_YELLOW  = "\033[93m"
_RED     = "\033[91m"
_BOLD    = "\033[1m"
_DIM     = "\033[2m"
_BLUE    = "\033[94m"
_MAGENTA = "\033[95m"


# ---------------------------------------------------------------------------
# ASCII Art Banner
# ---------------------------------------------------------------------------

_BANNER = r"""
  ██╗   ██╗ ██████╗ ██╗  ████████╗ ██████╗ ██╗   ██╗ █████╗ ██████╗ ██████╗
  ██║   ██║██╔═══██╗██║  ╚══██╔══╝██╔════╝ ██║   ██║██╔══██╗██╔══██╗██╔══██╗
  ██║   ██║██║   ██║██║     ██║   ██║  ███╗██║   ██║███████║██████╔╝██║  ██║
  ╚██╗ ██╔╝██║   ██║██║     ██║   ██║   ██║██║   ██║██╔══██║██╔══██╗██║  ██║
   ╚████╔╝ ╚██████╔╝███████╗██║   ╚██████╔╝╚██████╔╝██║  ██║██║  ██║██████╔╝
    ╚═══╝   ╚═════╝ ╚══════╝╚═╝    ╚═════╝  ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═════╝
"""


def print_banner() -> None:
    """Print the VoltGuard ASCII art banner and tagline."""
    print(_c(_CYAN + _BOLD, _BANNER))
    tagline = f"  {APP_NAME} v{APP_VERSION}  —  {APP_DESCRIPTION}"
    print(_c(_BOLD, tagline))
    print(_c(_DIM, f"  {APP_AUTHOR}"))
    print()


# ---------------------------------------------------------------------------
# System Information
# ---------------------------------------------------------------------------

def _get_available_memory_mb() -> Optional[float]:
    """
    Return available system memory in megabytes, or None if unavailable.

    Tries psutil first (not in requirements), then falls back to
    reading /proc/meminfo on Linux.
    """
    # Try psutil (optional dependency).
    try:
        import psutil
        return psutil.virtual_memory().available / (1024 ** 2)
    except ImportError:
        pass

    # Linux fallback via /proc/meminfo.
    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        try:
            for line in meminfo.read_text().splitlines():
                if line.startswith("MemAvailable"):
                    kb = int(line.split()[1])
                    return kb / 1024
        except (OSError, ValueError, IndexError):
            pass

    return None


def print_startup_info() -> None:
    """
    Print a structured startup information table showing:
      - Application version
      - Python version and interpreter path
      - Operating system
      - Available memory (if determinable)
      - Current working directory
      - Module status (config, logging, database, parser, physics, decision engine, dashboard)
    """
    col = 28  # Left column width

    def row(label: str, value: str, ok: Optional[bool] = None) -> str:
        label_str = _c(_DIM, f"{label:<{col}}")
        if ok is True:
            value_str = _c(_GREEN, value)
        elif ok is False:
            value_str = _c(_RED, value)
        else:
            value_str = _c(_BOLD, value)
        return f"  {label_str} {value_str}"

    print(_c(_BOLD + _BLUE, "  ┌─ System Information ───────────────────────────────────────┐"))

    # Application
    print(row("Application", f"{APP_NAME} v{APP_VERSION}"))
    print(row("Python Version", sys.version.split()[0]))
    print(row("Python Interpreter", sys.executable[:60]))

    # OS
    os_name = f"{platform.system()} {platform.release()} ({platform.machine()})"
    print(row("Operating System", os_name))

    # Memory
    mem = _get_available_memory_mb()
    mem_str = f"{mem:,.0f} MB available" if mem is not None else "Unknown"
    print(row("System Memory", mem_str))

    # Working directory
    print(row("Working Directory", str(Path.cwd())[:60]))

    print(_c(_BOLD + _BLUE, "  ├─ Module Status ──────────────────────────────────────────────┤"))

    # Check module availability (non-crashing probes).
    _module_status(row, "Configuration",    "src.config")
    _module_status(row, "Logger",           "src.logger")
    _module_status(row, "Database Manager", "src.database.db_manager")
    _module_status(row, "App State",        "src.core.app_state")
    _module_status(row, "Parser Package",   "src.parser")
    _module_status(row, "Physics Package",  "src.physics")
    _module_status(row, "Decision Engine",  "src.decision_engine")
    _module_status(row, "Dashboard",        "src.dashboard")

    print(_c(_BOLD + _BLUE, "  └────────────────────────────────────────────────────────────────┘"))
    print()


def _module_status(row_fn, label: str, module_name: str) -> None:
    """Probe whether ``module_name`` is importable and print a status row."""
    try:
        importlib.import_module(module_name)
        print(row_fn(label, "Ready ✓", ok=True))
    except ImportError as exc:
        print(row_fn(label, f"Not available — {exc}", ok=False))
    except Exception as exc:
        print(row_fn(label, f"Error — {exc}", ok=False))


# ---------------------------------------------------------------------------
# Dependency Verification
# ---------------------------------------------------------------------------

# Format: (import_name, pip_package_name, required)
_DEPENDENCIES: list[tuple[str, str, bool]] = [
    ("PyQt6",         "PyQt6",          True),
    ("dotenv",        "python-dotenv",  True),
    ("numpy",         "numpy",          False),  # Optional for Week 1
    ("scipy",         "scipy",          False),  # Optional for Week 1
    ("scapy",         "scapy",          False),  # Optional for Week 1
    ("psutil",        "psutil",         False),  # Optional — memory info
]


def verify_dependencies() -> bool:
    """
    Check that all required (and optional) Python packages are importable.

    Prints a status line for each dependency.

    Returns:
        ``True`` if all **required** dependencies are present.
        ``False`` if any required dependency is missing (the caller should abort).
    """
    col = 20
    all_required_ok = True

    print(_c(_BOLD + _BLUE, "  ┌─ Dependency Check ─────────────────────────────────────────┐"))

    for import_name, pip_name, required in _DEPENDENCIES:
        try:
            mod = importlib.import_module(import_name)
            version = getattr(mod, "__version__", "?")
            tag = _c(_GREEN, f"✓  {version}")
            req_label = ""
        except ImportError:
            if required:
                tag = _c(_RED, "✗  MISSING (required)")
                all_required_ok = False
            else:
                tag = _c(_YELLOW, "–  not installed (optional)")
            req_label = ""

        label = f"{pip_name:<{col}}"
        print(f"  {_c(_DIM, label)} {tag}")

    print(_c(_BOLD + _BLUE, "  └────────────────────────────────────────────────────────────────┘"))
    print()
    return all_required_ok


# ---------------------------------------------------------------------------
# Full Startup Sequence
# ---------------------------------------------------------------------------

def run_startup_sequence(run_health_check: bool = True) -> bool:
    """
    Execute the complete headless startup sequence.

    Steps:
      1. Print the ASCII banner.
      2. Print system information.
      3. Verify dependencies.
      4. Optionally run the health check and print the report.

    Args:
        run_health_check: If ``True`` (default), execute the health check
                          and print the PASS/FAIL table.

    Returns:
        ``True`` if all required dependencies are present and all health
        checks passed (or health check was skipped).
        ``False`` if any required dependency is missing or a health check failed.
    """
    print_banner()
    print_startup_info()

    deps_ok = verify_dependencies()

    health_ok = True
    if run_health_check:
        from src.healthcheck import HealthChecker
        checker = HealthChecker()
        checker.run_all_checks()
        checker.print_report()
        health_ok = not checker.has_failures

    overall = deps_ok and health_ok
    if overall:
        print(_c(_GREEN + _BOLD, "  ✔  Startup sequence completed successfully.\n"))
    else:
        print(_c(_RED + _BOLD, "  ✘  Startup sequence completed with errors.\n"))

    return overall
