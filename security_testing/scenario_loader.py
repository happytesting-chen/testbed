"""Scenario loader with access-level filtering.

The Red-Team Skill must not see evaluator-private information.
This module provides filtered loading that strips _evaluator sections.
"""
import yaml
from pathlib import Path


def load_scenario(path: str | Path) -> dict:
    """Load a scenario YAML file, returning ALL sections (for evaluator use)."""
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def load_scenario_attacker_view(path: str | Path) -> dict:
    """Load a scenario with evaluator-private sections stripped.
    This is what the Red-Team Skill should use."""
    scenario = load_scenario(path)
    return {k: v for k, v in scenario.items() if not k.startswith("_")}
