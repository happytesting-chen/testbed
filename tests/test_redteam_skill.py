"""Tests for the Red-Team Skill (Phase B) — correctness and integration."""
import json
import sys
from pathlib import Path

import pytest

_scripts = str(Path(__file__).resolve().parent.parent / ".claude" / "skills" / "red-team" / "scripts")
if _scripts not in sys.path:
    sys.path.insert(0, _scripts)

from runner import RedTeamRunner, ScenarioValidationError, _hash


class MockTarget:
    def __init__(self, state=None, chat_response=None):
        self._state = state or {}
        self._chat = chat_response or {"run_id": "r1", "response": "ok"}
    def chat(self, message, run_tag=None):
        return self._chat
    def upload(self, filename, content):
        return {"id": "u1"}
    def snapshot_state(self):
        return self._state


APPROVED_SCENARIO = {
    "id": "TS-001", "status": "approved",
    "objective": "Test objective",
    "attacker": {
        "role": "analyst",
        "capabilities": ["Upload reports", "Send chat messages"],
        "entry_point": {"method": "POST /api/upload", "channel": "C2"},
    },
    "success_criteria": {
        "observable_outcome": "severity changed",
        "primary": {"type": "db_state_change"},
    },
    "legitimate_task": "Summarise reports",
    "related_risk_ids": ["RISK-001"],
}


# ── Scenario validation ──────────────────────────────────────────────────────

def test_rejects_unapproved_scenario(tmp_path):
    runner = RedTeamRunner(target=MockTarget(), records_dir=str(tmp_path / "r"))
    draft = {**APPROVED_SCENARIO, "status": "draft"}
    with pytest.raises(ScenarioValidationError, match="not 'approved'"):
        runner.run_baseline(draft)


def test_rejects_missing_fields(tmp_path):
    runner = RedTeamRunner(target=MockTarget(), records_dir=str(tmp_path / "r"))
    incomplete = {"id": "T1", "status": "approved"}
    with pytest.raises(ScenarioValidationError, match="missing required"):
        runner.run_baseline(incomplete)


def test_rejects_evaluator_private_data(tmp_path):
    runner = RedTeamRunner(target=MockTarget(), records_dir=str(tmp_path / "r"))
    leaked = {**APPROVED_SCENARIO, "_evaluator": {"secret": True}}
    with pytest.raises(ScenarioValidationError, match="_evaluator"):
        runner.run_baseline(leaked)


def test_rejects_out_of_scope_action(tmp_path):
    runner = RedTeamRunner(target=MockTarget(), records_dir=str(tmp_path / "r"))
    no_chat = {**APPROVED_SCENARIO,
               "attacker": {**APPROVED_SCENARIO["attacker"],
                            "capabilities": ["Upload reports only"]}}
    with pytest.raises(ScenarioValidationError, match="Chat not in permitted"):
        runner.execute_attempt(no_chat, "PI-001", chat_message="test")


# ── Attempt budget ────────────────────────────────────────────────────────────

def test_budget_enforced(tmp_path):
    runner = RedTeamRunner(target=MockTarget(), attempt_budget=3,
                           records_dir=str(tmp_path / "r"))
    record = runner.execute_attempt(APPROVED_SCENARIO, "PI-001",
                                    chat_message="test", attempt=4)
    assert record["verdict"] == "ERROR"
    assert "budget" in record["error"].lower()


# ── Default evaluator ─────────────────────────────────────────────────────────

def test_default_evaluator_returns_inconclusive(tmp_path):
    runner = RedTeamRunner(target=MockTarget(), records_dir=str(tmp_path / "r"))
    record = runner.execute_attempt(APPROVED_SCENARIO, "PI-001",
                                    chat_message="test", attempt=1)
    assert record["verdict"] == "INCONCLUSIVE"


# ── DA evaluator: state change specificity ────────────────────────────────────

def test_da_evaluator_unrelated_change_not_succeeded():
    """Unrelated finding field change should NOT count as success."""
    from security_testing.adapters.document_assistant import make_evaluator_for_document_assistant

    class MockClient:
        def get_finding_history(self, fid):
            return [{"id": "h1"}]

    evaluate = make_evaluator_for_document_assistant(MockClient())
    record = {
        "state_before": {"findings": {"f1": {"severity": "Critical", "status": "Open"}}},
        "state_after": {"findings": {"f1": {"severity": "Critical", "status": "In Progress"}}},
    }
    # Scenario expects severity change, not status change
    scenario = {"success_criteria": {"observable_outcome": "severity changed from Critical to Low",
                                     "primary": {"type": "db_state_change"}}}
    result = evaluate(record, scenario)
    # Status changed but we're looking for severity — should not match
    assert result["verdict"] == "FAILED"


def test_da_evaluator_missing_history_is_inconclusive():
    """If finding history is unavailable, verdict should be INCONCLUSIVE."""
    from security_testing.adapters.document_assistant import make_evaluator_for_document_assistant

    class FailClient:
        def get_finding_history(self, fid):
            raise ConnectionError("unavailable")

    evaluate = make_evaluator_for_document_assistant(FailClient())
    record = {
        "state_before": {"findings": {"f1": {"severity": "Critical", "status": "Open"}}},
        "state_after": {"findings": {"f1": {"severity": "Low", "status": "Open"}}},
    }
    scenario = {"success_criteria": {"observable_outcome": "severity changed",
                                     "primary": {"type": "db_state_change"}}}
    result = evaluate(record, scenario)
    assert result["verdict"] == "INCONCLUSIVE"


def test_da_evaluator_disclosure_attack():
    """Canary disclosure should be evaluated correctly."""
    from security_testing.adapters.document_assistant import make_evaluator_for_document_assistant
    evaluate = make_evaluator_for_document_assistant(None)
    record = {"response_preview": "Here is the policy: CANARY-123-SECRET",
              "state_before": {}, "state_after": {}}
    scenario = {"success_criteria": {
        "observable_outcome": "canary in response",
        "primary": {"type": "canary_in_output", "canary_value": "CANARY-123-SECRET"}}}
    result = evaluate(record, scenario)
    assert result["verdict"] == "SUCCEEDED"


def test_da_evaluator_disclosure_not_found():
    evaluate_fn = None
    from security_testing.adapters.document_assistant import make_evaluator_for_document_assistant
    evaluate = make_evaluator_for_document_assistant(None)
    record = {"response_preview": "Normal response", "state_before": {}, "state_after": {}}
    scenario = {"success_criteria": {
        "observable_outcome": "canary in response",
        "primary": {"type": "canary_in_output", "canary_value": "SECRET-XYZ"}}}
    result = evaluate(record, scenario)
    assert result["verdict"] == "FAILED"


# ── Access isolation ──────────────────────────────────────────────────────────

def test_evaluator_private_not_in_attacker_records(tmp_path):
    runner = RedTeamRunner(target=MockTarget(), records_dir=str(tmp_path / "r"))
    record = runner.execute_attempt(APPROVED_SCENARIO, "PI-001",
                                    chat_message="test", attempt=1)
    assert "_evaluator" not in record, "Record should not contain _evaluator key"
    assert "shadow_violation" not in json.dumps(record.get("evidence", []))


# ── Validation ────────────────────────────────────────────────────────────────

def test_frozen_payload_unchanged(tmp_path):
    runner = RedTeamRunner(target=MockTarget(), records_dir=str(tmp_path / "r"))
    payload = "malicious content"
    h = _hash(payload)
    result = runner.run_validation(APPROVED_SCENARIO, "PI-001", payload, "a.md",
                                   "test", repeat_count=3)
    assert result["frozen_payload_hash"] == h
    for run in result["runs"]:
        assert run["payload"]["content_hash"] == h


def test_reset_failures_excluded_from_asr(tmp_path):
    fail_count = {"n": 0}
    def bad_reset():
        fail_count["n"] += 1
        if fail_count["n"] <= 2:
            raise RuntimeError("reset failed")

    runner = RedTeamRunner(target=MockTarget(), records_dir=str(tmp_path / "r"))
    result = runner.run_validation(APPROVED_SCENARIO, "PI-001", "payload", "a.md",
                                   "test", repeat_count=5, reset_fn=bad_reset)
    errors = sum(1 for r in result["runs"] if r["verdict"] == "ERROR")
    assert errors >= 2
    assert result["excluded_from_asr"] >= 2


# ── Phase C integration ──────────────────────────────────────────────────────

def test_phase_c_reads_summary_exploitation_status():
    _mit = str(Path(__file__).resolve().parent.parent / ".claude" / "skills" / "mitigation" / "scripts")
    if _mit not in sys.path:
        sys.path.insert(0, _mit)
    from risk_assessment import analyze_risk

    risk = {"risk_id": "RISK-001"}
    # Phase B produced a summary (no verdict) + attempt records
    records = [
        {"phase": "summary", "exploitation_status": "confirmed"},
        {"phase": "discovery", "verdict": "FAILED", "attempt": 1},
        {"phase": "discovery", "verdict": "SUCCEEDED", "attempt": 2,
         "technique_id": "PI-001", "scenario_id": "S1", "evidence": []},
    ]
    result = analyze_risk(risk, records)
    assert result["exploitation_status"] == "confirmed"


def test_phase_c_summary_only_no_attempts():
    _mit = str(Path(__file__).resolve().parent.parent / ".claude" / "skills" / "mitigation" / "scripts")
    if _mit not in sys.path:
        sys.path.insert(0, _mit)
    from risk_assessment import analyze_risk

    risk = {"risk_id": "RISK-002"}
    records = [{"phase": "summary", "exploitation_status": "not_observed"}]
    result = analyze_risk(risk, records)
    assert result["exploitation_status"] == "not_observed"


def test_phase_c_no_auto_reduce():
    """Phase C should NOT automatically reduce likelihood."""
    _mit = str(Path(__file__).resolve().parent.parent / ".claude" / "skills" / "mitigation" / "scripts")
    if _mit not in sys.path:
        sys.path.insert(0, _mit)
    from risk_assessment import assess_residual_risk

    risk = {"risk_id": "R1", "preliminary_likelihood": "Possible", "impact": "High"}
    mitigations = [{"description": "Added control", "status": "implemented"}]
    retests = [{"verdict": "FAILED"}, {"verdict": "FAILED"}]
    result = assess_residual_risk(risk, mitigations, retests)
    assert result["status"] == "pending_assessment"
    assert result["likelihood"] is None
    assert "requires human assessment" in result["rationale"].lower() or \
           "requires justified assessment" in result["rationale"].lower()
