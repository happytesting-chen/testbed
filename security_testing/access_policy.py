"""Backward-compatible re-export from the Red-Team Skill scripts."""
import sys
from pathlib import Path
_scripts = str(Path(__file__).resolve().parent.parent / ".claude" / "skills" / "red-team" / "scripts")
if _scripts not in sys.path:
    sys.path.insert(0, _scripts)
from access_policy import AccessPolicy, VALID_MODES  # noqa: E402
__all__ = ["AccessPolicy", "VALID_MODES"]
