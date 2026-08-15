"""
VoltGuard — Dashboard Package (src/dashboard)
===============================================
This package will contain the pure-Python business logic that backs
the Qt dashboard UI pages.  The actual Qt widgets live in ``src/ui/``.

Week 1 Status: Package scaffold only.
               Dashboard logic will be implemented in Week 2.

Planned sub-modules:
  - ``live_stats.LiveStatsController``   — Packet counter aggregation
  - ``alert_manager.AlertManager``       — Alert queuing and acknowledgement
  - ``report_generator.ReportGenerator`` — PDF/CSV export logic

Architecture note:
  Business logic (this package) must remain separated from Qt widgets
  (``src/ui/``).  Widgets call into this package; they never contain logic.
"""
