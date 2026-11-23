"""Feature flag mechanism for intentional weakness control.

Flags are stored in SQLite (settings table, key='weakness_flags') so both
the public app (port 8000) and evaluator app (port 8001) share the same state
even when running as separate processes.

Each weakness has a unique flag ID. When ON, the vulnerable path runs.
When OFF (default), the secure path runs. Unknown flags return OFF.
"""
import json

_db = None


def init(db):
    """Bind the flag module to a Database instance."""
    global _db
    _db = db


def is_on(flag_id: str) -> bool:
    """Check if a weakness flag is active. Unknown IDs return False."""
    if _db is None:
        return False
    return flag_id in set(_db.get_weakness_flags())


def get_active(db=None) -> list[str]:
    """Return the list of currently active flag IDs."""
    d = db or _db
    if d is None:
        return []
    return d.get_weakness_flags()


def set_flags(flags_on: list[str], db=None):
    """Set active flags (writes to SQLite)."""
    d = db or _db
    if d is None:
        return
    d.set_weakness_flags(flags_on)


def clear_flags(db=None):
    """Reset all flags to OFF."""
    set_flags([], db)
