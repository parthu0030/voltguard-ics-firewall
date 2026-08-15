"""
VoltGuard — System Health Checker
=====================================
Verifies that the application environment meets all requirements before
the main application loop starts.

Checks performed:
  1. Required directories exist (logs/, reports/, assets/).
  2. Critical directories are writable.
  3. Configuration file can be loaded without errors.
  4. Log directory is writable.
  5. Reports directory exists (or can be created).
  6. Python version is 3.10 or higher.

Usage:
    from src.healthcheck import HealthChecker

    checker = HealthChecker()
    results = checker.run_all_checks()
    checker.print_report()

    # Programmatic access:
    if not all(r.passed for r in results):
        sys.exit(1)
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from src.constants import (
    LOGS_DIR,
    REPORTS_DIR,
    ASSETS_DIR,
    REQUIRED_DIRS,
    STATUS_PASS,
    STATUS_FAIL,
    STATUS_WARN,
)
from src.utils import is_writable, create_directories


# ---------------------------------------------------------------------------
# Health Result
# ---------------------------------------------------------------------------

@dataclass
class HealthResult:
    """
    The outcome of a single health check.

    Attributes:
        name:   Short human-readable name for the check.
        status: One of ``STATUS_PASS``, ``STATUS_FAIL``, or ``STATUS_WARN``.
        detail: Optional explanation, especially for failures.
        passed: Convenience boolean — True only when status is PASS.
    """
    name: str
    status: str
    detail: str = ""

    @property
    def passed(self) -> bool:
        """True if this result represents a passing check."""
        return self.status == STATUS_PASS

    @property
    def is_warning(self) -> bool:
        """True if this result is a warning (non-fatal)."""
        return self.status == STATUS_WARN


# ---------------------------------------------------------------------------
# Health Checker
# ---------------------------------------------------------------------------

class HealthChecker:
    """
    Runs a battery of environment health checks and produces a structured report.

    Each check is a method of the form ``_check_<name>`` that returns a
    ``HealthResult``.  The ``run_all_checks()`` method discovers and runs
    them in registration order.

    Design:
      - Checks never raise exceptions — all errors are caught and
        converted to ``HealthResult(status=STATUS_FAIL)``.
      - WARN results indicate non-fatal issues that the app can survive.
      - FAIL results indicate blockers; the startup sequence should abort.
    """

    def __init__(self) -> None:
        self._results: list[HealthResult] = []
        # Ordered list of (display_name, method) pairs.
        self._checks: list[tuple[str, Callable[[], HealthResult]]] = [
            ("Required Directories",    self._check_required_dirs),
            ("Logs Directory Writable", self._check_logs_writable),
            ("Reports Directory",       self._check_reports_dir),
            ("Assets Directory",        self._check_assets_dir),
            ("Python Version",          self._check_python_version),
            ("Config File",             self._check_config_file),
            ("Log File Writable",       self._check_log_file_writable),
        ]

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def run_all_checks(self) -> list[HealthResult]:
        """
        Execute all registered health checks.

        Returns:
            List of ``HealthResult`` instances, one per check, in order.
        """
        self._results = []
        for _name, method in self._checks:
            try:
                result = method()
            except Exception as exc:  # Defensive — checks must never propagate.
                result = HealthResult(
                    name=_name,
                    status=STATUS_FAIL,
                    detail=f"Unexpected error: {exc}",
                )
            self._results.append(result)
        return list(self._results)

    def print_report(self) -> None:
        """
        Print a formatted PASS/FAIL/WARN table to stdout.

        Ensures checks have been run first (calls ``run_all_checks()``
        automatically if not already done).
        """
        if not self._results:
            self.run_all_checks()

        col_name = 30
        col_status = 6
        col_detail = 45

        header = (
            f"{'Check':<{col_name}} "
            f"{'Status':<{col_status}} "
            f"{'Detail':<{col_detail}}"
        )
        separator = "─" * (col_name + col_status + col_detail + 2)

        print()
        print("  VoltGuard — System Health Report")
        print(f"  {separator}")
        print(f"  {header}")
        print(f"  {separator}")

        for result in self._results:
            # Colour-code the status for TTY output.
            status_display = _colour_status(result.status)
            detail = result.detail[:col_detail] if result.detail else ""
            print(f"  {result.name:<{col_name}} {status_display:<{col_status}} {detail}")

        print(f"  {separator}")

        passed = sum(1 for r in self._results if r.passed)
        warned = sum(1 for r in self._results if r.is_warning)
        failed = sum(1 for r in self._results if not r.passed and not r.is_warning)
        total = len(self._results)

        print(f"  {total} checks — {passed} passed, {warned} warnings, {failed} failed")
        print()

    @property
    def all_passed(self) -> bool:
        """True only if every check has status PASS (no warnings, no failures)."""
        return all(r.passed for r in self._results)

    @property
    def has_failures(self) -> bool:
        """True if at least one check returned STATUS_FAIL."""
        return any(
            r.status == STATUS_FAIL
            for r in self._results
        )

    @property
    def results(self) -> list[HealthResult]:
        """Return the last set of results (may be empty before first run)."""
        return list(self._results)

    # ------------------------------------------------------------------ #
    #  Individual checks                                                   #
    # ------------------------------------------------------------------ #

    def _check_required_dirs(self) -> HealthResult:
        """Verify that all required directories exist (create them if possible)."""
        missing: list[str] = []
        for path in REQUIRED_DIRS:
            if not path.exists():
                created = create_directories([path])
                if not created.get(path, False):
                    missing.append(path.name)

        if missing:
            return HealthResult(
                name="Required Directories",
                status=STATUS_FAIL,
                detail=f"Could not create: {', '.join(missing)}",
            )
        return HealthResult(
            name="Required Directories",
            status=STATUS_PASS,
            detail=f"All {len(REQUIRED_DIRS)} directories present",
        )

    def _check_logs_writable(self) -> HealthResult:
        """Verify that the logs directory is writable."""
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        if is_writable(LOGS_DIR):
            return HealthResult(
                name="Logs Directory Writable",
                status=STATUS_PASS,
                detail=str(LOGS_DIR),
            )
        return HealthResult(
            name="Logs Directory Writable",
            status=STATUS_FAIL,
            detail=f"No write permission: {LOGS_DIR}",
        )

    def _check_reports_dir(self) -> HealthResult:
        """Verify that the reports directory exists or can be created."""
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        if REPORTS_DIR.is_dir():
            return HealthResult(
                name="Reports Directory",
                status=STATUS_PASS,
                detail=str(REPORTS_DIR),
            )
        return HealthResult(
            name="Reports Directory",
            status=STATUS_FAIL,
            detail=f"Cannot create: {REPORTS_DIR}",
        )

    def _check_assets_dir(self) -> HealthResult:
        """Verify that the assets directory exists (warning only if absent)."""
        ASSETS_DIR.mkdir(parents=True, exist_ok=True)
        if ASSETS_DIR.is_dir():
            return HealthResult(
                name="Assets Directory",
                status=STATUS_PASS,
                detail=str(ASSETS_DIR),
            )
        return HealthResult(
            name="Assets Directory",
            status=STATUS_WARN,
            detail=f"Assets directory missing: {ASSETS_DIR}",
        )

    def _check_python_version(self) -> HealthResult:
        """Verify Python ≥ 3.10 is running."""
        major, minor = sys.version_info[:2]
        version_str = f"{major}.{minor}.{sys.version_info.micro}"
        if (major, minor) >= (3, 10):
            return HealthResult(
                name="Python Version",
                status=STATUS_PASS,
                detail=f"Python {version_str} ≥ 3.10 ✓",
            )
        return HealthResult(
            name="Python Version",
            status=STATUS_FAIL,
            detail=f"Python {version_str} < 3.10 — upgrade required",
        )

    def _check_config_file(self) -> HealthResult:
        """Verify that config.json exists and is valid JSON (auto-generate if missing)."""
        from src.config import ConfigLoader
        from src.exceptions import ConfigurationError

        loader = ConfigLoader()
        try:
            loader.load()
            return HealthResult(
                name="Config File",
                status=STATUS_PASS,
                detail=str(loader.config_path),
            )
        except ConfigurationError as exc:
            return HealthResult(
                name="Config File",
                status=STATUS_FAIL,
                detail=str(exc)[:45],
            )

    def _check_log_file_writable(self) -> HealthResult:
        """Verify that the application log file path is writable."""
        from src.constants import LOG_FILE_NAME

        log_file = LOGS_DIR / LOG_FILE_NAME
        LOGS_DIR.mkdir(parents=True, exist_ok=True)

        # Try to open the log file in append mode as a real write probe.
        try:
            with log_file.open("a", encoding="utf-8"):
                pass
            return HealthResult(
                name="Log File Writable",
                status=STATUS_PASS,
                detail=str(log_file),
            )
        except OSError as exc:
            return HealthResult(
                name="Log File Writable",
                status=STATUS_FAIL,
                detail=f"Cannot write log: {exc}",
            )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _colour_status(status: str) -> str:
    """Wrap a status string in ANSI colour codes for TTY output."""
    if status == STATUS_PASS:
        return f"\033[32m{status}\033[0m"   # Green
    if status == STATUS_WARN:
        return f"\033[33m{status}\033[0m"   # Yellow
    if status == STATUS_FAIL:
        return f"\033[31m{status}\033[0m"   # Red
    return status
