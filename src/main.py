"""
VoltGuard — Application Entry Point
======================================
Bootstraps the complete VoltGuard application in the correct order:

  1. Install global exception handler (before anything else).
  2. Create the QApplication instance.
  3. Initialise LoggingService.
  4. Initialise DatabaseService and apply schema.
  5. Initialise ConfigService (loads / seeds settings).
  6. Apply ThemeService dark stylesheet.
  7. Update AppState with settings-derived values.
  8. Create and show the MainWindow.
  9. Enter the Qt event loop.

All initialisation failures are caught, logged, and presented to
the user as a friendly dialog — the application never crashes silently.
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path

# Ensure the project root is on sys.path so ``src.*`` imports resolve
# whether the script is run from the project root or from src/.
_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import QApplication, QMessageBox

from src.core.app_state import app_state
from src.models.app_models import APP_DEFAULT_SETTINGS, EventLog, LogLevel
from src.services.config_service import config_service
from src.services.database_service import database_service
from src.services.logging_service import logging_service
from src.services.theme_service import theme_service
from src.ui.main_window import MainWindow


# ---------------------------------------------------------------------------
# Global Exception Handler
# ---------------------------------------------------------------------------

def _install_global_exception_handler(app: QApplication) -> None:
    """
    Replace the default ``sys.excepthook`` with a handler that:
      - Logs the full stack trace to the log file.
      - Shows a user-friendly error dialog instead of crashing.
      - Does NOT silently swallow exceptions.

    Args:
        app: The running QApplication instance (used for dialog parent).
    """
    def _handler(exc_type: type, exc_value: BaseException, exc_tb) -> None:
        # Always log the full traceback first.
        logging_service.log_exception_to_file(exc_type, exc_value, exc_tb)

        # Write to event_logs if the database is ready.
        if database_service.is_ready:
            tb_str = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
            event = EventLog(
                timestamp=EventLog.now_timestamp(),
                level=LogLevel.ERROR,
                source="GlobalExceptionHandler",
                message=f"{exc_type.__name__}: {exc_value}\n{tb_str[:2000]}",
            )
            try:
                database_service.save_event_log(event)
            except Exception:
                pass  # Database logging must never cause a secondary crash.

        # Update AppState so the UI reflects the error.
        app_state.app_status = f"Error: {exc_type.__name__}"

        # Show a user-friendly dialog.
        dialog = QMessageBox()
        dialog.setWindowTitle("VoltGuard — Unexpected Error")
        dialog.setIcon(QMessageBox.Icon.Critical)
        dialog.setText(
            f"<b>An unexpected error occurred:</b><br><br>"
            f"<code>{exc_type.__name__}: {exc_value}</code>"
        )
        detail = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        dialog.setDetailedText(detail)
        dialog.setInformativeText(
            "The error has been written to the application log file.\n"
            "The application will attempt to continue running."
        )
        dialog.exec()

    sys.excepthook = _handler


# ---------------------------------------------------------------------------
# Service Initialisation
# ---------------------------------------------------------------------------

def _initialise_services() -> bool:
    """
    Initialise all singleton services in dependency order.

    Returns:
        True if all services initialised successfully, False otherwise.
    """
    # 1. Database (no dependencies)
    db_ok = database_service.initialize()
    if db_ok:
        app_state.db_status = "Connected"
        logging_service.info(
            f"Database initialised at: {database_service.db_path}",
            source="Bootstrap",
        )
        # Verify schema health
        if database_service.health_check():
            logging_service.info("Database health check passed.", source="Bootstrap")
        else:
            logging_service.warning(
                "Database health check failed — schema may be incomplete.",
                source="Bootstrap",
            )
            app_state.db_status = "Schema Error"
    else:
        app_state.db_status = "Error"
        logging_service.error(
            "Failed to initialise the database.", source="Bootstrap"
        )
        return False

    # 2. Config (depends on database)
    config_service.initialize(database_service)
    logging_service.info(
        f"Configuration loaded — theme={config_service.theme}, "
        f"interface={config_service.selected_interface}",
        source="Bootstrap",
    )

    # 3. Write startup event to database event_logs
    startup_event = EventLog(
        timestamp=EventLog.now_timestamp(),
        level=LogLevel.INFO,
        source="Bootstrap",
        message="VoltGuard application started successfully.",
    )
    database_service.save_event_log(startup_event)

    return True


# ---------------------------------------------------------------------------
# AppState Population
# ---------------------------------------------------------------------------

def _populate_app_state() -> None:
    """
    Populate AppState with values derived from ConfigService after
    settings have been loaded.  This ensures the Dashboard shows correct
    values on first render.
    """
    app_state.app_status = "Ready"
    app_state.selected_interface = config_service.selected_interface


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------

def main() -> int:
    """
    Main application entry point.

    Returns:
        The Qt event loop exit code (0 = clean exit).
    """
    # High-DPI support
    QApplication.setHighDpiScaleFactorRoundingPolicy(
        Qt.HighDpiScaleFactorRoundingPolicy.PassThrough
    )

    app = QApplication(sys.argv)
    app.setApplicationName("VoltGuard")
    app.setApplicationVersion("1.0.0")
    app.setOrganizationName("VoltGuard Security")

    # 1. Install exception handler immediately after QApplication exists.
    _install_global_exception_handler(app)

    # 2. Initialise logging (must happen before any other service logs).
    logging_service.initialize(log_level="INFO")
    logging_service.log_startup(version="1.0.0")

    # 3. Initialise all other services.
    services_ok = _initialise_services()
    if not services_ok:
        QMessageBox.critical(
            None,
            "VoltGuard — Startup Failed",
            "Failed to initialise the application database.\n"
            "Please check the log file for details and ensure the application "
            "directory is writable.",
        )
        return 1

    # 4. Apply dark theme to the QApplication.
    theme_service.apply_dark_theme(app)
    logging_service.info("Dark theme applied.", source="Bootstrap")

    # 5. Populate AppState from loaded config.
    _populate_app_state()

    # 6. Create and show the main window.
    window = MainWindow()
    window.show()

    logging_service.info("MainWindow displayed. Entering event loop.", source="Bootstrap")

    # 7. Enter the Qt event loop.
    exit_code = app.exec()

    # 8. Clean shutdown.
    logging_service.info(
        f"Application exiting with code {exit_code}.", source="Bootstrap"
    )
    database_service.close()

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
