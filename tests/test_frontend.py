"""Tests for frontend split and telemetry filtering."""
from pathlib import Path

from tests.conftest import ANALYST, EVAL

STATIC = Path(__file__).resolve().parent.parent / "app" / "static"


def test_vendor_frontend_has_no_test_infrastructure():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    for forbidden in ["data-atk", "atk-btn", "TEST-0", "CANARY", "receiver",
                       "loadCanary", "testGroup", "TEST_OBJECTIVES",
                       "runHyperlinkMultiTurn", "runTest04MultiTurn"]:
        assert forbidden not in html, f"Vendor index.html must not contain '{forbidden}'"


def test_internal_frontend_has_test_panels():
    html = (STATIC / "index_internal.html").read_text(encoding="utf-8")
    for required in ["data-atk", "atk-btn", "TEST-01", "TEST-02", "TEST-03",
                      "TEST-04", "loadCanary", "CANARY"]:
        assert required in html, f"Internal index_internal.html must contain '{required}'"


def test_evaluator_serves_internal_app(make_clients):
    _, ev, _ = make_clients()
    r = ev.get("/app")
    assert r.status_code == 200
    assert "data-atk" in r.text


def test_telemetry_excludes_sensitive_fields(make_clients):
    pub, ev, _ = make_clients()
    r = pub.post("/api/agent/chat", headers={**ANALYST, "X-Testbed-Run-Tag": "secret-tag"},
                 json={"message": "Status of critical findings?"})
    assert r.status_code == 200
    run_id = r.json()["run_id"]

    t = ev.get(f"/api/telemetry/{run_id}").json()
    assert "external_run_tag" not in t
    assert "error" not in t
    assert "agent_config" not in t
    for tc in t.get("tool_calls", []):
        assert "arguments" not in tc, "Tool arguments must not appear in telemetry"
        assert "result" not in tc, "Tool results must not appear in telemetry"
        assert "retrieved_report_ids" not in tc


def test_vendor_frontend_has_hierarchical_view():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert "hierarchy-panel" in html
    assert "report-header" in html
    assert "findings-group" in html
    assert "finding-data" in html
    assert "detail-panel" in html
    assert "loadReportsAndFindings" in html
    assert "showFindingDetail" in html
    assert "loadHistory" in html
    assert "viewOriginalReport" in html
    assert "startEdit" in html
    assert "saveChanges" in html
    assert "cancelEdit" in html
    assert "markDirty" in html


def test_vendor_frontend_no_separate_findings_table():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert "findings-body" not in html
    assert 'id="rep"' not in html


def test_vendor_frontend_uses_safe_rendering():
    html = (STATIC / "index.html").read_text(encoding="utf-8")
    assert "textContent" in html
    assert "esc(" in html
    assert ".innerHTML=h" not in html or "history-list" in html


def test_telemetry_list_excludes_run_tag(make_clients):
    pub, ev, _ = make_clients()
    pub.post("/api/agent/chat", headers={**ANALYST, "X-Testbed-Run-Tag": "secret-tag"},
             json={"message": "test"})
    tl = ev.get("/api/telemetry").json()
    assert len(tl) >= 1
    for entry in tl:
        assert "external_run_tag" not in entry, "Telemetry list must not expose external_run_tag"


def test_telemetry_includes_basic_fields(make_clients):
    pub, ev, _ = make_clients()
    r = pub.post("/api/agent/chat", headers=ANALYST,
                 json={"message": "Status of critical findings?"})
    run_id = r.json()["run_id"]

    t = ev.get(f"/api/telemetry/{run_id}").json()
    assert t["run_id"] == run_id
    assert t["actor"] == "analyst1"
    assert t["prompt"] == "Status of critical findings?"
    assert t["answer"] is not None
    assert len(t["tool_calls"]) > 0
    assert "name" in t["tool_calls"][0]
    assert "step" in t["tool_calls"][0]
