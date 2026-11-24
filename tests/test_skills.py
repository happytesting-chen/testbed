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


def test_tra_threat_status_valid():
    """Each threat must have a valid status — but not all must be Applicable."""
    tra = yaml.safe_load((TRA_DIR / "tra_document_assistant.yaml").read_text())
    valid_statuses = {"Applicable", "Not Applicable", "Needs Verification"}
    for t in tra["threat_applicability"]:
        assert t["status"] in valid_statuses, \
            f"{t['threat_id']} has invalid status '{t['status']}'"
        assert "rationale" in t, f"{t['threat_id']} must have a rationale"


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


def test_tra_risk_rating_format():
    """Risk rating should be 'Likelihood × Impact' format."""
    tra = yaml.safe_load((TRA_DIR / "tra_document_assistant.yaml").read_text())
    for risk in tra["risk_register"]:
        rating = risk["risk_rating"]
        assert "×" in rating, f"{risk['risk_id']}: risk_rating should use 'Likelihood × Impact' format, got '{rating}'"


def test_tra_risk_005_006_split():
    """RISK-005 and RISK-006 should be split into distinct risks."""
    tra = yaml.safe_load((TRA_DIR / "tra_document_assistant.yaml").read_text())
    ids = {r["risk_id"] for r in tra["risk_register"]}
    assert "RISK-005a" in ids, "RISK-005 should be split (scope validation)"
    assert "RISK-005b" in ids, "RISK-005 should be split (input validation)"
    assert "RISK-005c" in ids, "RISK-005 should be split (data exposure)"
    assert "RISK-006a" in ids, "RISK-006 should be split (credential leakage)"
    assert "RISK-006b" in ids, "RISK-006 should be split (role bypass)"
    assert "RISK-005" not in ids, "RISK-005 should not exist as a combined entry"
    assert "RISK-006" not in ids, "RISK-006 should not exist as a combined entry"


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
    assert "observable_outcome" in s["success_criteria"]


def test_scenario_has_no_payload():
    """Technique-independent scenarios must NOT contain attack payloads."""
    s = yaml.safe_load((SCENARIOS_DIR / "S1-RP1-001.yaml").read_text())
    assert "payload" not in s, "Scenarios should not contain payloads (Approach B)"


def test_scenario_attacker_visible_has_no_internal_details():
    """The attacker-visible section should not reference internal weakness IDs,
    flag names, trace event types, or evaluator evidence formats."""
    s = yaml.safe_load((SCENARIOS_DIR / "S1-RP1-001.yaml").read_text())
    # Attacker-visible fields
    attacker_text = json.dumps({
        "objective": s["objective"],
        "legitimate_task": s["legitimate_task"],
        "attacker": s["attacker"],
        "preconditions": s["preconditions"],
        "attack_path": s["attack_path"],
        "success_criteria": s["success_criteria"],
    })
    assert "RP1-03" not in attacker_text, "Attacker section should not reference flag IDs"
    assert "shadow_violation" not in attacker_text, "Attacker section should not reference internal trace events"
    assert "authorized_by_grant" not in attacker_text, "Attacker section should not reference DB column names"


def test_scenario_evaluator_section_exists():
    """The _evaluator section should contain weakness mapping and evidence requirements."""
    s = yaml.safe_load((SCENARIOS_DIR / "S1-RP1-001.yaml").read_text())
    assert "_evaluator" in s
    ev = s["_evaluator"]
    assert "weakness_mapping" in ev
    assert "potentially_required" in ev["weakness_mapping"]
    assert "evidence_requirements" in ev
    assert "configurations" in ev


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


def test_scenario_loader_attacker_view_strips_evaluator():
    """The attacker-view loader must strip _evaluator sections."""
    from security_testing.scenario_loader import load_scenario, load_scenario_attacker_view
    full = load_scenario(SCENARIOS_DIR / "S1-RP1-001.yaml")
    assert "_evaluator" in full

    filtered = load_scenario_attacker_view(SCENARIOS_DIR / "S1-RP1-001.yaml")
    assert "_evaluator" not in filtered
    assert "objective" in filtered
    assert "attacker" in filtered
    assert "success_criteria" in filtered


def test_scenario_loader_attacker_view_has_no_flag_ids():
    """Filtered scenario should not contain weakness flag IDs."""
    from security_testing.scenario_loader import load_scenario_attacker_view
    filtered = load_scenario_attacker_view(SCENARIOS_DIR / "S1-RP1-001.yaml")
    text = json.dumps(filtered)
    assert "RP1-03" not in text
    assert "XA1-02" not in text
    assert "IA2-01" not in text
    assert "shadow_violation" not in text


def test_tra_matrix_marked_provisional():
    """The TRA must clearly label its risk matrix as provisional."""
    text = (TRA_DIR / "tra_document_assistant.yaml").read_text(encoding="utf-8")
    assert "PROVISIONAL" in text
    assert "approved organizational risk methodology" in text.lower() or \
           "approved methodology" in text.lower()


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
