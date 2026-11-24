"""Backward-compatible re-export from the Red-Team Skill scripts."""
import sys
from pathlib import Path
_scripts = str(Path(__file__).resolve().parent.parent / ".claude" / "skills" / "red-team" / "scripts")
if _scripts not in sys.path:
    sys.path.insert(0, _scripts)
from scenario_loader import load_scenario, load_scenario_attacker_view  # noqa: E402
__all__ = ["load_scenario", "load_scenario_attacker_view"]
