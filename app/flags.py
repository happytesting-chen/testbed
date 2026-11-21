"""Feature flag mechanism for intentional weakness control.

Each weakness has a unique flag ID. When ON, the vulnerable path runs.
When OFF (default), the secure path runs. Unknown flags return OFF.
"""
import json
from pathlib import Path

_active_flags: set[str] = set()
_loaded = False


def load_flags(config_path: str | Path | None = None):
    """Load active flags from a JSON config file or reset to empty."""
    global _active_flags, _loaded
    _active_flags = set()
    if config_path:
        p = Path(config_path)
        if p.exists():
            data = json.loads(p.read_text(encoding="utf-8"))
            _active_flags = set(data.get("flags_on", []))
    _loaded = True


def set_flags(flags_on: list[str]):
    """Programmatically set active flags (for tests)."""
    global _active_flags, _loaded
    _active_flags = set(flags_on)
    _loaded = True


def clear_flags():
    """Reset all flags to OFF."""
    global _active_flags, _loaded
    _active_flags = set()
    _loaded = True


def is_on(flag_id: str) -> bool:
    """Check if a weakness flag is active. Unknown IDs return False."""
    return flag_id in _active_flags
