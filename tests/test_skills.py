"""Tests for the three-skill security testing framework."""
import json
import yaml
from pathlib import Path

SCENARIOS_DIR = Path(__file__).parent.parent / "security_testing" / "scenarios"
TRA_DIR = Path(__file__).parent.parent / "security_testing" / "tra"


# ── TRA tests ─────────────────────────────────────────────────────────────────

def test_tra_yaml_valid():
    path = TRA_DIR / "tra_document_assistant.yaml"
    assert path.exists()
    tra = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert "threat_applicability" in tra
    assert "risk_register" in tra
    assert len(tra["threat_applicability"]) == 7
    assert len(tra["risk_register"]) >= 1


def test_tra_covers_all_seven_threats():
    tra = yaml.safe_load((TRA_DIR / "tra_document_assistant.yaml").read_text())
    threat_ids = {t["threat_id"] for t in tra["threat_applicability"]}
    assert threat_ids == {"RP.1", "RP.2", "KM.1", "TA.1", "IA.1", "IA.2", "XA.1"}


def test_tra_all_threats_applicable():
    tra = yaml.safe_load((TRA_DIR / "tra_document_assistant.yaml").read_text())
    for t in tra["threat_applicability"]:
        assert t["status"] == "Applicable", f"{t['threat_id']} should be Applicable"


def test_tra_risk_register_has_required_fields():
    tra = yaml.safe_load((TRA_DIR / "tra_document_assistant.yaml").read_text())
    required = {"risk_id", "threat_category", "risk_scenario", "impact",
                "security_concerns", "proposed_controls", "preliminary_likelihood",
                "risk_rating", "risk_level"}
    for risk in tra["risk_register"]:
        missing = required - set(risk.keys())
        assert not missing, f"{risk['risk_id']} missing: {missing}"


def test_tra_risk_ids_unique():
    tra = yaml.safe_load((TRA_DIR / "tra_document_assistant.yaml").read_text())
    ids = [r["risk_id"] for r in tra["risk_register"]]
    assert len(ids) == len(set(ids)), "Duplicate risk IDs found"


# ── Scenario tests ────────────────────────────────────────────────────────────

def test_scenario_yaml_valid():
    path = SCENARIOS_DIR / "S1-RP1-001.yaml"
    assert path.exists()
    s = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert s["id"] == "S1-RP1-001"
    assert s["status"] == "draft"
    assert s["type"] in ("individual", "attack_chain")
    assert s["threat_category"] == "RP.1"
    assert "objective" in s
    assert "legitimate_task" in s
    assert "attack_path" in s
    assert "success_criteria" in s
    assert s["success_criteria"]["primary"]["type"] == "db_state_change"
    assert "weakness_mapping" in s
    assert any(w["id"] == "RP1-03" for w in s["weakness_mapping"]["required"])
    assert "configurations" in s


def test_scenario_has_no_payload():
    """Technique-independent scenarios must NOT contain attack payloads."""
    s = yaml.safe_load((SCENARIOS_DIR / "S1-RP1-001.yaml").read_text())
    assert "payload" not in s, "Scenarios should not contain payloads (Approach B)"
    assert "attack_steps" not in s or not any(
        "message" in step for step in s.get("attack_steps", [])
    ), "Scenarios should not contain specific chat messages"


def test_scenario_references_tra_risks():
    s = yaml.safe_load((SCENARIOS_DIR / "S1-RP1-001.yaml").read_text())
    assert "related_risk_ids" in s
    assert len(s["related_risk_ids"]) >= 1
    tra = yaml.safe_load((TRA_DIR / "tra_document_assistant.yaml").read_text())
    tra_ids = {r["risk_id"] for r in tra["risk_register"]}
    for rid in s["related_risk_ids"]:
        assert rid in tra_ids, f"Scenario references {rid} but it's not in the TRA"


def test_scenario_has_no_evaluator_secrets():
    text = (SCENARIOS_DIR / "S1-RP1-001.yaml").read_text(encoding="utf-8")
    assert "DOCASSIST-CANARY" not in text
    assert "CANARY-SYS-9F2K" not in text
    assert "_ground_truth" not in text


def test_red_team_runner_accepts_technique_params(tmp_path):
    """Runner requires technique and payload as separate params."""
    from security_testing.red_team import RedTeamRunner
    runner = RedTeamRunner("http://localhost:9999", "fake-token",
                           records_dir=str(tmp_path / "records"))
    import inspect
    sig = inspect.signature(runner.execute_scenario)
    params = list(sig.parameters.keys())
    assert "technique" in params
    assert "payload_content" in params
    assert "chat_message" in params


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
