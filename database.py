"""
HawkEye Database Layer (Module 10 / Module 11 naming)
This module is the canonical "database.py" requested by the target
project structure. All actual SQLite logic lives in history.py (kept
under its original name for backward compatibility with existing
imports elsewhere in the app) — this module simply re-exports it so
new code can `import database` per the standard structure while
nothing that already does `import history as history_db` breaks.
"""

from history import (
    DB_PATH,
    init_db,
    save_scan,
    update_report_paths,
    get_history,
    get_scan,
    delete_history,
)

__all__ = [
    "DB_PATH",
    "init_db",
    "save_scan",
    "update_report_paths",
    "get_history",
    "get_scan",
    "delete_history",
]
