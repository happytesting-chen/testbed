"""Tests for the three-skill security testing framework."""
import json
import yaml
from pathlib import Path

SCENARIOS_DIR = Path(__file__).parent.parent / "security_testing" / "scenarios"


def test_scenario_yaml_valid():
    """The generated scenario is valid YAML with required fields."""
    path = SCENARIOS_DIR / "S1-RP1-001.yaml"
    assert path.exists()
    s = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert s["id"] == "S1-RP1-001"
    assert s["status"] == "draft"
    assert s["threat_category"] == "RP.1"
    assert "objective" in s
    assert "payload" in s
    assert s["payload"]["type"] == "uploaded_document"
    assert len(s["payload"]["content"]) > 100
    assert "attack_steps" in s
    assert len(s["attack_steps"]) >= 3
    assert "success_criteria" in s
    assert s["success_criteria"]["primary"]["type"] == "db_state_change"
    assert "required_flags" in s
    assert "RP1-03" in s["required_flags"]
    assert "configurations" in s


def test_scenario_has_no_evaluator_secrets():
    """The attacker-visible scenario must not contain canary values or internal flag keys."""
    path = SCENARIOS_DIR / "S1-RP1-001.yaml"
    text = path.read_text(encoding="utf-8")
    assert "DOCASSIST-CANARY" not in text
    assert "CANARY-SYS-9F2K" not in text
    assert "_ground_truth" not in text


def test_red_team_runner_importable():
    from security_testing.red_team import RedTeamRunner
    assert RedTeamRunner is not None


def test_evaluator_importable():
    from security_testing.evaluate import SecurityEvaluator
    assert SecurityEvaluator is not None


def test_target_adapter_importable():
    from security_testing.target_adapter import TargetClient, EvaluatorClient
    assert TargetClient is not None
    assert EvaluatorClient is not None


def test_red_team_runner_creates_records_dir(tmp_path):
    from security_testing.red_team import RedTeamRunner
    runner = RedTeamRunner("http://localhost:9999", "fake-token",
                           records_dir=str(tmp_path / "records"))
    assert (tmp_path / "records").exists()


def test_evaluator_creates_results_dir(tmp_path):
    from security_testing.evaluate import SecurityEvaluator
    evaluator = SecurityEvaluator("http://localhost:9999", "fake-token",
                                   results_dir=str(tmp_path / "results"))
    assert (tmp_path / "results").exists()


def test_skill_files_exist():
    """All three skill definition files exist."""
    root = Path(__file__).parent.parent
    assert (root / ".claude/skills/threat-model/threat-model.md").exists()
    assert (root / ".claude/skills/red-team/red-team.md").exists()
    assert (root / ".claude/skills/evaluate/evaluate.md").exists()
