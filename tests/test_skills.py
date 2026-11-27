"""Tests for the three-skill security testing framework."""
import json
import yaml
from pathlib import Path

SCENARIOS_DIR = Path(__file__).parent.parent / "security_testing" / "scenarios"
TAXONOMY_PATH = (Path(__file__).parent.parent / ".claude" / "skills" / "threat-model"
                 / "references" / "agentic_ai_threat_taxonomy.yaml")


# ── Taxonomy tests ───────────────────────────────────────────────────────────

def test_taxonomy_has_12_weaknesses():
    data = yaml.safe_load(TAXONOMY_PATH.read_text(encoding="utf-8"))
    assert len(data["weaknesses"]) == 12
    ids = {w["id"] for w in data["weaknesses"]}
    assert ids == {f"W{i}" for i in range(1, 13)}

def test_taxonomy_has_20_threats():
    data = yaml.safe_load(TAXONOMY_PATH.read_text(encoding="utf-8"))
    assert len(data["threats"]) == 20

def test_taxonomy_has_6_impacts():
    data = yaml.safe_load(TAXONOMY_PATH.read_text(encoding="utf-8"))
    assert len(data["impacts"]) == 6
    ids = {i["id"] for i in data["impacts"]}
    assert ids == {f"I{i}" for i in range(1, 7)}

def test_taxonomy_testbed_scope_has_7_threats():
    data = yaml.safe_load(TAXONOMY_PATH.read_text(encoding="utf-8"))
    in_scope = [t for t in data["threats"] if t.get("in_testbed_scope")]
    assert len(in_scope) == 7
    scope_ids = {t["id"] for t in in_scope}
    assert scope_ids == {"RP.1", "RP.2", "KM.1", "TA.1", "IA.1", "IA.2", "XA.1"}

def test_taxonomy_out_of_scope_threats_present():
    """Out-of-scope threats exist as reference but are not in testbed scope."""
    data = yaml.safe_load(TAXONOMY_PATH.read_text(encoding="utf-8"))
    out_of_scope = [t for t in data["threats"] if not t.get("in_testbed_scope")]
    assert len(out_of_scope) == 13
    assert any(t["id"] == "HI.1" for t in out_of_scope)

def test_taxonomy_in_scope_threats_have_weaknesses():
    data = yaml.safe_load(TAXONOMY_PATH.read_text(encoding="utf-8"))
    for t in data["threats"]:
        if t.get("in_testbed_scope"):
            assert "potential_weaknesses" in t, f"{t['id']} missing potential_weaknesses"
            assert len(t["potential_weaknesses"]) >= 1


# ── Scenario tests ────────────────────────────────────────────────────────────

def test_scenario_yaml_valid():
    """Existing S1-RP1-001 remains loadable (backward compatibility)."""
    path = SCENARIOS_DIR / "S1-RP1-001.yaml"
    assert path.exists()
    s = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert s["id"] == "S1-RP1-001"
    assert s["status"] in ("draft", "approved")
    assert "objective" in s
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


def test_scenario_has_no_evaluator_secrets():
    text = (SCENARIOS_DIR / "S1-RP1-001.yaml").read_text(encoding="utf-8")
    assert "DOCASSIST-CANARY" not in text
    assert "CANARY-SYS-9F2K" not in text
    assert "_ground_truth" not in text


# ── New impact-first scenario tests ──────────────────────────────────────────

def test_new_scenario_impact_first_format():
    """S2-I3-001 follows the impact-first scenario template."""
    s = yaml.safe_load((SCENARIOS_DIR / "S2-I3-001.yaml").read_text())
    assert s["id"] == "S2-I3-001"
    assert s["status"] == "draft"
    assert s["impact"] == "I3"
    assert s["impact_description"] == "Misinformation"
    assert s["threat"] == "RP.1"
    assert "trigger" in s
    assert "potential_weakness" in s
    assert s["potential_weakness"]["generic"] == "W9"
    assert "objective" in s
    assert "success_criteria" in s

def test_new_scenario_has_no_risk_ids():
    """New scenarios must not contain TRA risk IDs."""
    s = yaml.safe_load((SCENARIOS_DIR / "S2-I3-001.yaml").read_text())
    assert "related_risk_ids" not in s
    assert "risk_rating" not in s
    assert "risk_level" not in s
    assert "likelihood" not in s

def test_new_scenario_has_no_payload():
    """Technique-independent scenarios must not contain attack payloads."""
    s = yaml.safe_load((SCENARIOS_DIR / "S2-I3-001.yaml").read_text())
    assert "payload" not in s

def test_new_scenario_planted_weakness_in_evaluator_only():
    """Application-specific weakness IDs must be in _evaluator, not attacker-visible."""
    full = yaml.safe_load((SCENARIOS_DIR / "S2-I3-001.yaml").read_text())
    assert "_evaluator" in full
    # Application-specific weakness is in evaluator section
    ev_text = json.dumps(full["_evaluator"])
    assert "RP1-03" in ev_text

    # Attacker-visible section has no planted weakness IDs
    from security_testing.scenario_loader import load_scenario_attacker_view
    att = load_scenario_attacker_view(SCENARIOS_DIR / "S2-I3-001.yaml")
    att_text = json.dumps(att)
    for wid in ["RP1-01", "RP1-02", "RP1-03", "RP1-04", "RP2-03", "XA1-02", "IA2-01"]:
        assert wid not in att_text, f"Planted weakness {wid} leaked to attacker view"

def test_new_scenario_generic_weakness_visible():
    """Generic weakness category (W1-W12) is visible in attacker summary."""
    from security_testing.scenario_loader import load_scenario_attacker_view
    att = load_scenario_attacker_view(SCENARIOS_DIR / "S2-I3-001.yaml")
    assert att["potential_weakness"]["generic"] == "W9"
    assert "application_specific" not in att["potential_weakness"]

def test_new_scenario_permitted_actions():
    """New scenario has explicit permitted_actions."""
    s = yaml.safe_load((SCENARIOS_DIR / "S2-I3-001.yaml").read_text())
    assert "permitted_actions" in s["attacker"]
    assert "upload_document" in s["attacker"]["permitted_actions"]
    assert "send_chat_message" in s["attacker"]["permitted_actions"]

def test_old_scenario_still_loadable():
    """S1-RP1-001 (old format) remains loadable and backward compatible."""
    from security_testing.scenario_loader import load_scenario_attacker_view
    s = load_scenario_attacker_view(SCENARIOS_DIR / "S1-RP1-001.yaml")
    assert s["id"] == "S1-RP1-001"
    assert "_evaluator" not in s
    assert "threat_category" in s or "threat" in s

def test_runner_summary_no_risk_ids(tmp_path):
    """Runner summary uses impact/threat, not related_risk_ids."""
    import sys
    sys.path.insert(0, str(Path(__file__).parent.parent / ".claude/skills/red-team/scripts"))
    from runner import RedTeamRunner

    class MT:
        def chat(self, m, run_tag=None): return {"run_id": "r1", "response": "ok"}
        def upload(self, f, c): return {"id": "u1"}
        def snapshot_state(self): return {}

    scenario = {"id": "T1", "status": "approved", "objective": "t",
                "impact": "I3", "threat": "RP.1",
                "attacker": {"role": "a", "permitted_actions": ["send_chat_message"]},
                "success_criteria": {}}
    runner = RedTeamRunner(target=MT(), records_dir=str(tmp_path / "r"))
    baseline = runner.run_baseline(scenario)
    summary = runner.generate_summary(scenario, baseline, [])
    assert summary["impact"] == "I3"
    assert summary["threat"] == "RP.1"
    assert "related_risk_ids" not in summary


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
    scenario = {"id": "TEST-001", "status": "approved", "objective": "test", "attacker": {"role": "a", "permitted_actions": ["send_chat_message"], "capabilities": ["chat"]}, "success_criteria": {}, "legitimate_task": "Summarise reports"}
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
        "attacker": {"role": "analyst", "permitted_actions": ["upload_document", "send_chat_message"], "capabilities": ["Upload reports", "Send chat messages"],
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
        baseline = runner.run_baseline({"id": "T1", "status": "approved", "objective": "test", "attacker": {"role": "a", "permitted_actions": ["send_chat_message"], "capabilities": ["chat"]}, "success_criteria": {}, "legitimate_task": "test"})
        assert baseline["access_mode"] == mode
        record = runner.execute_attempt(
            {"id": "T1", "status": "approved", "objective": "t", "attacker": {"role": "a", "permitted_actions": ["send_chat_message"], "capabilities": ["Send chat messages"], "entry_point": {}}, "success_criteria": {}},
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
        {"id": "T1", "status": "approved", "objective": "t", "attacker": {"role": "a", "permitted_actions": ["send_chat_message"], "capabilities": ["Send chat messages"], "entry_point": {}}, "success_criteria": {}},
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
        {"id": "T1", "status": "approved", "objective": "t", "attacker": {"role": "a", "permitted_actions": ["send_chat_message"], "capabilities": ["Send chat messages"], "entry_point": {}}, "success_criteria": {}},
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
    assert "weaknesses" in data
    assert "threats" in data
    assert "impacts" in data


def test_threat_model_has_reference_file():
    """Document Assistant-specific guidance is in a reference file, not the skill."""
    root = Path(__file__).parent.parent
    ref = root / ".claude/skills/threat-model/references/document_assistant.md"
    assert ref.exists()
    text = ref.read_text(encoding="utf-8")
    assert "coordinator.py" in text
