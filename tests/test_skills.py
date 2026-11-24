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


def test_red_team_runner_generic_interface(tmp_path):
    """Runner accepts a generic target adapter, not hardcoded URLs."""
    from security_testing.red_team import RedTeamRunner

    class MockTarget:
        def chat(self, message, run_tag=None):
            return {"run_id": "mock", "response": "ok"}
        def upload(self, filename, content):
            return {"id": "mock"}
        def snapshot_state(self):
            return {"findings": {}}

    runner = RedTeamRunner(target=MockTarget(),
                           records_dir=str(tmp_path / "records"))
    assert runner.target is not None
    assert runner.records_dir.exists()

    import inspect
    sig = inspect.signature(runner.execute_attempt)
    params = list(sig.parameters.keys())
    assert "technique_id" in params
    assert "payload_content" in params
    assert "chat_message" in params


def test_red_team_runner_baseline(tmp_path):
    """Runner can execute a baseline."""
    from security_testing.red_team import RedTeamRunner

    class MockTarget:
        def chat(self, message, run_tag=None):
            return {"run_id": "baseline-run", "response": "Normal response."}
        def upload(self, filename, content):
            return {"id": "mock"}
        def snapshot_state(self):
            return {"findings": {"f1": {"severity": "Critical"}}}

    runner = RedTeamRunner(target=MockTarget(),
                           records_dir=str(tmp_path / "records"))
    scenario = {"id": "TEST-001", "status": "approved", "objective": "test", "attacker": {"role": "a", "capabilities": ["chat"]}, "success_criteria": {}, "legitimate_task": "Summarise reports"}
    baseline = runner.run_baseline(scenario)
    assert baseline["phase"] == "baseline"
    assert "run_id" in baseline
    assert any(f.name.endswith("_baseline.json") for f in (tmp_path / "records").glob("TEST-001_*"))


def test_red_team_runner_discovery_attempt(tmp_path):
    """Runner can execute a discovery attempt and evaluate."""
    from security_testing.red_team import RedTeamRunner

    call_count = {"n": 0}
    class MockTarget:
        def chat(self, message, run_tag=None):
            call_count["n"] += 1
            return {"run_id": f"run-{call_count['n']}", "response": "Processed."}
        def upload(self, filename, content):
            return {"id": "uploaded"}
        def snapshot_state(self):
            return {"findings": {"f1": {"severity": "Critical"}}}

    def mock_eval(record, scenario):
        return {"verdict": "FAILED", "evidence": []}

    runner = RedTeamRunner(target=MockTarget(), evaluator=mock_eval,
                           records_dir=str(tmp_path / "records"))
    scenario = {
        "id": "TEST-001", "status": "approved",
        "objective": "Test",
        "attacker": {"role": "analyst", "capabilities": ["Upload reports", "Send chat messages"],
                      "entry_point": {"method": "POST /api/upload"}},
        "success_criteria": {"observable_outcome": "severity changed"},
    }
    record = runner.execute_attempt(
        scenario, technique_id="PI-001",
        payload_content="malicious content",
        chat_message="summarise")
    assert record["verdict"] == "FAILED"
    assert record["technique_id"] == "PI-001"
    assert any("attempt_1" in f.name for f in (tmp_path / "records").glob("TEST-001_*"))


def test_document_assistant_adapter_importable():
    from security_testing.adapters.document_assistant import (
        DocumentAssistantTarget, make_evaluator_for_document_assistant)
    assert DocumentAssistantTarget is not None
    assert make_evaluator_for_document_assistant is not None


# ── Access policy tests ──────────────────────────────────────────────────────

def test_access_policy_black_box_blocks_traces():
    from security_testing.access_policy import AccessPolicy
    policy = AccessPolicy("black_box")
    assert not policy.can_access_traces
    assert not policy.can_access_source
    trace = {"run": {"id": "r1"}, "events": [
        {"seq": 1, "stage": "llm_request", "ts": "t", "payload": {"body": "secret"}},
        {"seq": 2, "stage": "tool_call", "ts": "t", "payload": {"name": "read"}},
    ]}
    filtered = policy.filter_trace(trace)
    assert filtered == {}


def test_access_policy_grey_box_filters_traces():
    from security_testing.access_policy import AccessPolicy
    policy = AccessPolicy("grey_box")
    assert policy.can_access_traces
    assert not policy.can_access_source
    trace = {"run": {"id": "r1", "model": "test"}, "events": [
        {"seq": 1, "stage": "llm_request", "ts": "t", "payload": {"body": {"messages": ["secret"]}}},
        {"seq": 2, "stage": "tool_call", "ts": "t", "payload": {"name": "read_report", "step": 1, "agent": "reader"}},
        {"seq": 3, "stage": "shadow_violation", "ts": "t", "payload": {"vuln_id": "IA2-01"}},
        {"seq": 4, "stage": "delegation", "ts": "t", "payload": {"to_agent": "fm", "task": "update", "context": "raw"}},
    ]}
    filtered = policy.filter_trace(trace)
    stages = [e["stage"] for e in filtered["events"]]
    assert "llm_request" not in stages
    assert "shadow_violation" not in stages
    assert "tool_call" in stages
    assert "delegation" in stages
    tc = next(e for e in filtered["events"] if e["stage"] == "tool_call")
    assert "name" in tc["payload"]
    assert "arguments" not in tc.get("payload", {})
    deleg = next(e for e in filtered["events"] if e["stage"] == "delegation")
    assert "context" not in deleg["payload"]


def test_access_policy_white_box_strips_evaluator_events():
    from security_testing.access_policy import AccessPolicy
    policy = AccessPolicy("white_box")
    assert policy.can_access_traces
    assert policy.can_access_source
    trace = {"run": {"id": "r1", "agent_config": {"secret": True}}, "events": [
        {"seq": 1, "stage": "llm_request", "ts": "t", "payload": {"body": "ok"}},
        {"seq": 2, "stage": "shadow_violation", "ts": "t", "payload": {"vuln_id": "IA2-01"}},
        {"seq": 3, "stage": "scope_grant", "ts": "t", "payload": {"grant_id": "g1"}},
        {"seq": 4, "stage": "tool_call", "ts": "t", "payload": {"name": "read"}},
    ]}
    filtered = policy.filter_trace(trace)
    stages = [e["stage"] for e in filtered["events"]]
    assert "shadow_violation" not in stages
    assert "scope_grant" not in stages
    assert "llm_request" in stages
    assert "tool_call" in stages
    assert "agent_config" not in filtered.get("run", {})


def test_access_policy_strips_evaluator_from_scenario():
    from security_testing.access_policy import AccessPolicy
    for mode in ("black_box", "grey_box", "white_box"):
        policy = AccessPolicy(mode)
        scenario = {"id": "T1", "objective": "test", "_evaluator": {"secret": True}}
        filtered = policy.filter_scenario(scenario)
        assert "_evaluator" not in filtered, f"{mode} should strip _evaluator"
        assert "objective" in filtered


def test_runner_records_access_mode(tmp_path):
    from security_testing.red_team import RedTeamRunner

    class MockTarget:
        def chat(self, message, run_tag=None):
            return {"run_id": "r1", "response": "ok"}
        def upload(self, filename, content):
            return {"id": "u1"}
        def snapshot_state(self):
            return {}

    for mode in ("black_box", "grey_box", "white_box"):
        runner = RedTeamRunner(target=MockTarget(), access_mode=mode,
                               records_dir=str(tmp_path / mode))
        baseline = runner.run_baseline({"id": "T1", "status": "approved", "objective": "test", "attacker": {"role": "a", "capabilities": ["chat"]}, "success_criteria": {}, "legitimate_task": "test"})
        assert baseline["access_mode"] == mode
        record = runner.execute_attempt(
            {"id": "T1", "status": "approved", "objective": "t", "attacker": {"role": "a", "capabilities": ["Send chat messages"], "entry_point": {}}, "success_criteria": {}},
            technique_id="PI-001", chat_message="test")
        assert record["access_mode"] == mode


def test_runner_black_box_no_trace_in_record(tmp_path):
    from security_testing.red_team import RedTeamRunner

    class MockTarget:
        def chat(self, message, run_tag=None):
            return {"run_id": "r1", "response": "ok"}
        def upload(self, filename, content):
            return {"id": "u1"}
        def snapshot_state(self):
            return {}

    def mock_trace_provider(run_id):
        return {"run": {"id": run_id}, "events": [{"stage": "llm_request", "payload": {}}]}

    runner = RedTeamRunner(target=MockTarget(), access_mode="black_box",
                           trace_provider=mock_trace_provider,
                           records_dir=str(tmp_path / "records"))
    record = runner.execute_attempt(
        {"id": "T1", "status": "approved", "objective": "t", "attacker": {"role": "a", "capabilities": ["Send chat messages"], "entry_point": {}}, "success_criteria": {}},
        technique_id="PI-001", chat_message="test")
    assert "trace" not in record


def test_runner_grey_box_has_filtered_trace(tmp_path):
    from security_testing.red_team import RedTeamRunner

    class MockTarget:
        def chat(self, message, run_tag=None):
            return {"run_id": "r1", "response": "ok"}
        def upload(self, filename, content):
            return {"id": "u1"}
        def snapshot_state(self):
            return {}

    def mock_trace_provider(run_id):
        return {"run": {"id": run_id, "model": "test"}, "events": [
            {"seq": 1, "stage": "llm_request", "ts": "t", "payload": {"body": "secret"}},
            {"seq": 2, "stage": "tool_call", "ts": "t", "payload": {"name": "read", "step": 1, "agent": "reader"}},
        ]}

    runner = RedTeamRunner(target=MockTarget(), access_mode="grey_box",
                           trace_provider=mock_trace_provider,
                           records_dir=str(tmp_path / "records"))
    record = runner.execute_attempt(
        {"id": "T1", "status": "approved", "objective": "t", "attacker": {"role": "a", "capabilities": ["Send chat messages"], "entry_point": {}}, "success_criteria": {}},
        technique_id="PI-001", chat_message="test")
    assert "trace" in record
    stages = [e["stage"] for e in record["trace"]["events"]]
    assert "tool_call" in stages
    assert "llm_request" not in stages


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
    """All three skill definition files exist (Threat Model, Red-Team, Mitigation)."""
    root = Path(__file__).parent.parent
    assert (root / ".claude/skills/threat-model/SKILL.md").exists()
    assert (root / ".claude/skills/red-team/SKILL.md").exists()
    assert (root / ".claude/skills/mitigation/SKILL.md").exists()
    assert not (root / ".claude/skills/evaluate").exists(), \
        "Evaluation is internal to Red-Team, not a separate Skill"


def test_threat_model_skill_is_generic():
    """The generic skill instructions must not contain hardcoded application paths."""
    root = Path(__file__).parent.parent
    text = (root / ".claude/skills/threat-model/SKILL.md").read_text(encoding="utf-8")
    assert "coordinator.py" not in text
    assert "reader.py" not in text
    assert "findings_manager.py" not in text
    assert "app/agents/" not in text
    assert "app/weakness_registry.py" not in text
    assert "DocAssist" not in text


def test_threat_model_has_bundled_taxonomy():
    """The generic taxonomy is bundled inside the skill, not in app/."""
    root = Path(__file__).parent.parent
    tax = root / ".claude/skills/threat-model/references/agentic_ai_threat_taxonomy.yaml"
    assert tax.exists()
    data = yaml.safe_load(tax.read_text(encoding="utf-8"))
    assert "threat_categories" in data
    ids = {t["id"] for t in data["threat_categories"]}
    assert ids == {"RP.1", "RP.2", "KM.1", "TA.1", "IA.1", "IA.2", "XA.1"}
    for t in data["threat_categories"]:
        assert "potential_weaknesses" in t
        assert len(t["potential_weaknesses"]) >= 1


def test_threat_model_has_reference_file():
    """Document Assistant-specific guidance is in a reference file, not the skill."""
    root = Path(__file__).parent.parent
    ref = root / ".claude/skills/threat-model/references/document_assistant.md"
    assert ref.exists()
    text = ref.read_text(encoding="utf-8")
    assert "coordinator.py" in text
