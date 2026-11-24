"""Scenario loader with access-level filtering.

The Red-Team Skill must not see evaluator-private information.
This module provides filtered loading that strips _evaluator sections.
The access policy is enforced through the loader, not just by instruction.
"""
import yaml
from pathlib import Path

from .access_policy import AccessPolicy


def load_scenario(path: str | Path) -> dict:
    """Load a scenario YAML file, returning ALL sections (for evaluator use)."""
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def load_scenario_attacker_view(path: str | Path,
                                 policy: AccessPolicy | None = None) -> dict:
    """Load a scenario with evaluator-private sections stripped.

    This is what the Red-Team Skill should use. The policy parameter
    is accepted for future extension but all modes strip _evaluator.
    """
    if policy is None:
        policy = AccessPolicy("black_box")
    return policy.filter_scenario(load_scenario(path))
