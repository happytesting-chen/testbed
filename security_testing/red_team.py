"""Backward-compatible re-export from the Red-Team Skill scripts."""
import sys
from pathlib import Path

_scripts = str(Path(__file__).resolve().parent.parent / ".claude" / "skills" / "red-team" / "scripts")
if _scripts not in sys.path:
    sys.path.insert(0, _scripts)

# Import from the skill's scripts package (now on sys.path as standalone modules)
from runner import RedTeamRunner  # noqa: E402
from access_policy import AccessPolicy  # noqa: E402
from scenario_loader import load_scenario, load_scenario_attacker_view  # noqa: E402

__all__ = ["RedTeamRunner", "AccessPolicy", "load_scenario", "load_scenario_attacker_view"]
