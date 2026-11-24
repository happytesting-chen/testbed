"""Focused tests for the Red-Team Skill (Phase B)."""
import json
import sys
from pathlib import Path

import pytest

_scripts = str(Path(__file__).resolve().parent.parent / ".claude" / "skills" / "red-team" / "scripts")
if _scripts not in sys.path:
    sys.path.insert(0, _scripts)

from runner import RedTeamRunner, ScenarioValidationError, _hash


class MockTarget:
    def __init__(self, state=None, response="ok", upload_result=None):
        self._state = state or {}
        self._response = response
        self._upload = upload_result or {"id": "u1"}
        self.uploads = []
        self.chats = []
    def chat(self, message, run_tag=None):
        self.chats.append(message)
        return {"run_id": "r1", "response": self._response}
    def upload(self, filename, content):
        self.uploads.append((filename, content))
        return self._upload
    def snapshot_state(self):
        return self._state


APPROVED = {
    "id": "TS-001", "status": "approved", "objective": "Test",
    "attacker": {
        "role": "analyst",
        "capabilities": ["Upload reports", "Send chat messages"],
        "entry_point": {"method": "POST /api/upload", "channel": "C2"},
    },
    "success_criteria": {"observable_outcome": "severity changed",
                         "primary": {"type": "db_state_change"}},
    "legitimate_task": "Summarise", "related_risk_ids": ["RISK-001"],
}

UPLOAD_ONLY = {
    **APPROVED,
    "attacker": {**APPROVED["attacker"],
                 "capabilities": ["Upload reports"]},
}

CHAT_ONLY = {
    **APPROVED,
    "attacker": {**APPROVED["attacker"],
                 "capabilities": ["Send chat messages"],
                 "entry_point": {"method": "POST /api/chat"}},
}


# ── Scenario validation ──────────────────────────────────────────────────────

def test_rejects_unapproved(tmp_path):
    runner = RedTeamRunner(target=MockTarget(), records_dir=str(tmp_path / "r"))
    with pytest.raises(ScenarioValidationError, match="not 'approved'"):
        runner.run_baseline({**APPROVED, "status": "draft"})

def test_rejects_missing_fields(tmp_path):
    runner = RedTeamRunner(target=MockTarget(), records_dir=str(tmp_path / "r"))
    with pytest.raises(ScenarioValidationError, match="Missing"):
        runner.run_baseline({"id": "T1", "status": "approved"})

def test_rejects_evaluator_leak(tmp_path):
    runner = RedTeamRunner(target=MockTarget(), records_dir=str(tmp_path / "r"))
    with pytest.raises(ScenarioValidationError, match="evaluator-private"):
        runner.run_baseline({**APPROVED, "_evaluator": {"s": True}})

def test_rejects_no_action(tmp_path):
    runner = RedTeamRunner(target=MockTarget(), records_dir=str(tmp_path / "r"))
    with pytest.raises(ScenarioValidationError, match="No attack action"):
        runner.execute_attempt(APPROVED, "PI-001")

def test_rejects_unauthorized_chat(tmp_path):
    runner = RedTeamRunner(target=MockTarget(), records_dir=str(tmp_path / "r"))
    with pytest.raises(ScenarioValidationError, match="Chat not permitted"):
        runner.execute_attempt(UPLOAD_ONLY, "PI-001", chat_message="test")

def test_rejects_unauthorized_upload(tmp_path):
    runner = RedTeamRunner(target=MockTarget(), records_dir=str(tmp_path / "r"))
    with pytest.raises(ScenarioValidationError, match="Upload not permitted"):
        runner.execute_attempt(CHAT_ONLY, "PI-001", payload_content="data")


# ── Execution ─────────────────────────────────────────────────────────────────

def test_upload_only_executes(tmp_path):
    target = MockTarget()
    runner = RedTeamRunner(target=target, records_dir=str(tmp_path / "r"))
    record = runner.execute_attempt(UPLOAD_ONLY, "PI-001",
                                    payload_content="malicious", payload_filename="a.md")
    assert len(target.uploads) == 1
    assert target.uploads[0] == ("a.md", "malicious")
    assert len(target.chats) == 0

def test_chat_only_executes(tmp_path):
    target = MockTarget()
    runner = RedTeamRunner(target=target, records_dir=str(tmp_path / "r"))
    record = runner.execute_attempt(CHAT_ONLY, "PI-001", chat_message="attack")
    assert len(target.chats) == 1
    assert len(target.uploads) == 0

def test_combined_executes(tmp_path):
    target = MockTarget()
    runner = RedTeamRunner(target=target, records_dir=str(tmp_path / "r"))
    record = runner.execute_attempt(APPROVED, "PI-001",
                                    payload_content="doc", chat_message="summarise")
    assert len(target.uploads) == 1
    assert len(target.chats) == 1


# ── Budget enforcement ────────────────────────────────────────────────────────

def test_budget_tracked_internally(tmp_path):
    runner = RedTeamRunner(target=MockTarget(), attempt_budget=2,
                           records_dir=str(tmp_path / "r"))
    r1 = runner.execute_attempt(APPROVED, "PI-001", chat_message="a")
    assert r1["attempt"] == 1
    r2 = runner.execute_attempt(APPROVED, "PI-001", chat_message="b")
    assert r2["attempt"] == 2
    r3 = runner.execute_attempt(APPROVED, "PI-001", chat_message="c")
    assert r3["verdict"] == "ERROR"
    assert "budget" in r3["error"].lower()

def test_budget_rejects_zero(tmp_path):
    runner = RedTeamRunner(target=MockTarget(), attempt_budget=0,
                           records_dir=str(tmp_path / "r"))
    assert runner.attempt_budget == 1  # clamped to minimum 1


# ── Evaluator isolation ───────────────────────────────────────────────────────

def test_attacker_view_hides_evaluator_evidence(tmp_path):
    def mock_eval(record, scenario):
        return {"verdict": "SUCCEEDED",
                "evidence": [{"type": "secret_db_check", "grant_id": "g1"}],
                "attacker_feedback": "SUCCEEDED"}
    runner = RedTeamRunner(target=MockTarget(), evaluator=mock_eval,
                           records_dir=str(tmp_path / "r"))
    record = runner.execute_attempt(APPROVED, "PI-001", chat_message="test")
    assert "_evaluator_evidence" not in record
    assert "_full_response" not in record
    assert record["verdict"] == "SUCCEEDED"
    assert record["attacker_feedback"] == "SUCCEEDED"

def test_saved_file_has_no_private_fields(tmp_path):
    def mock_eval(record, scenario):
        return {"verdict": "FAILED", "evidence": [{"type": "internal"}]}
    runner = RedTeamRunner(target=MockTarget(), evaluator=mock_eval,
                           records_dir=str(tmp_path / "r"))
    runner.execute_attempt(APPROVED, "PI-001", chat_message="test")
    files = list((tmp_path / "r").glob("*.json"))
    assert len(files) >= 1
    content = json.loads(files[0].read_text())
    assert "_evaluator_evidence" not in content
    assert "_full_response" not in content


# ── Full response for disclosure ──────────────────────────────────────────────

def test_evaluator_receives_full_response(tmp_path):
    long_response = "A" * 600 + "CANARY-SECRET-HIDDEN" + "B" * 200
    target = MockTarget(response=long_response)
    received = {}
    def capture_eval(record, scenario):
        received["full"] = record.get("_full_response")
        received["preview"] = record.get("response_preview")
        return {"verdict": "FAILED", "evidence": []}
    runner = RedTeamRunner(target=target, evaluator=capture_eval,
                           records_dir=str(tmp_path / "r"))
    runner.execute_attempt(APPROVED, "SPL-001", chat_message="reveal")
    assert "CANARY-SECRET-HIDDEN" in received["full"]
    assert "CANARY-SECRET-HIDDEN" not in received["preview"]


# ── Validation ────────────────────────────────────────────────────────────────

def test_frozen_attack_includes_all_inputs(tmp_path):
    runner = RedTeamRunner(target=MockTarget(), records_dir=str(tmp_path / "r"))
    frozen = {"technique_id": "PI-001", "payload_content": "doc",
              "payload_filename": "attack.md", "chat_message": "summarise"}
    result = runner.run_validation(APPROVED, frozen, repeat_count=2)
    assert result["frozen_payload_hash"] == _hash("doc")
    assert result["repetitions"] == 2

def test_no_reset_marked_not_independent(tmp_path):
    runner = RedTeamRunner(target=MockTarget(), records_dir=str(tmp_path / "r"))
    frozen = {"technique_id": "PI-001", "chat_message": "test"}
    result = runner.run_validation(APPROVED, frozen, repeat_count=2)
    assert result["independently_validated"] is False

def test_reset_failures_excluded(tmp_path):
    n = {"c": 0}
    def bad_reset():
        n["c"] += 1
        if n["c"] <= 2: raise RuntimeError("fail")
    runner = RedTeamRunner(target=MockTarget(), records_dir=str(tmp_path / "r"))
    frozen = {"technique_id": "PI-001", "chat_message": "test"}
    result = runner.run_validation(APPROVED, frozen, repeat_count=4, reset_fn=bad_reset)
    assert result["errors"] >= 2
    assert result["excluded_from_asr"] >= 2
    assert result["independently_validated"] is True


# ── Record uniqueness ─────────────────────────────────────────────────────────

def test_records_have_unique_execution_id(tmp_path):
    runner1 = RedTeamRunner(target=MockTarget(), records_dir=str(tmp_path / "r"))
    runner2 = RedTeamRunner(target=MockTarget(), records_dir=str(tmp_path / "r"))
    b1 = runner1.run_baseline(APPROVED)
    b2 = runner2.run_baseline(APPROVED)
    assert b1["execution_id"] != b2["execution_id"]
    files = list((tmp_path / "r").glob("*baseline*"))
    assert len(files) == 2  # no overwrite


# ── Bundled script imports ────────────────────────────────────────────────────

def test_bundled_imports():
    from runner import RedTeamRunner as R1
    from access_policy import AccessPolicy as AP
    from scenario_loader import load_scenario_attacker_view as LSA
    assert R1 is not None
    assert AP is not None
    assert LSA is not None


# ── Phase C integration ──────────────────────────────────────────────────────

def test_summary_has_exploitation_status(tmp_path):
    def ok_eval(record, scenario):
        return {"verdict": "SUCCEEDED", "evidence": []}
    runner = RedTeamRunner(target=MockTarget(), evaluator=ok_eval,
                           records_dir=str(tmp_path / "r"))
    baseline = runner.run_baseline(APPROVED)
    r1 = runner.execute_attempt(APPROVED, "PI-001", chat_message="test")
    summary = runner.generate_summary(APPROVED, baseline, [r1])
    assert summary["exploitation_status"] == "confirmed"
    assert summary["phase"] == "summary"
    assert summary["related_risk_ids"] == ["RISK-001"]
