"""Scenario loader with access-level filtering.

Strips _evaluator sections so the attack process never sees
evaluator-private information regardless of access mode.
"""
import yaml
from pathlib import Path

try:
    from .access_policy import AccessPolicy
except ImportError:
    from access_policy import AccessPolicy


def load_scenario(path: str | Path) -> dict:
    """Load full scenario (for evaluator use)."""
    return yaml.safe_load(Path(path).read_text(encoding="utf-8"))


def load_scenario_attacker_view(path: str | Path,
                                 policy: AccessPolicy | None = None) -> dict:
    """Load scenario with _evaluator sections stripped."""
    if policy is None:
        policy = AccessPolicy("black_box")
    return policy.filter_scenario(load_scenario(path))
