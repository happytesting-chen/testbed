import json

from tests.conftest import ANALYST, EVAL, robust_model


def test_agent_trace_records_multi_agent_loop(make_clients):
    pub, ev, _ = make_clients()
    r = pub.post("/api/agent/chat", headers={**ANALYST, "X-Testbed-Run-Tag": "unit"},
                 json={"message": "Status of critical findings?"})
    assert r.status_code == 200
    t = ev.get("/api/traces/" + r.json()["run_id"], headers=EVAL).json()
    stages = [e["stage"] for e in t["events"]]
    assert stages[0] == "user_input" and stages[-1] == "final_answer"
    assert "tool_call" in stages and "tool_result" in stages
    assert "delegation" in stages

    # Coordinator's first LLM request should offer delegation tools
    coord_req = next(e for e in t["events"]
                     if e["stage"] == "llm_request" and e["payload"].get("agent") == "coordinator")
    coord_tools = {x["function"]["name"] for x in coord_req["payload"]["body"]["tools"]}
    assert coord_tools == {"delegate_to_reader", "delegate_to_findings_manager", "request_scope"}

    # Reader's LLM request should offer reader tools
    reader_reqs = [e for e in t["events"]
                   if e["stage"] == "llm_request" and e["payload"].get("agent") == "reader"]
    if reader_reqs:
        reader_tools = {x["function"]["name"] for x in reader_reqs[0]["payload"]["body"]["tools"]}
        assert reader_tools == {"list_reports", "search_reports", "read_report"}

    assert t["run"]["external_run_tag"] == "unit"
    assert t["run"]["model"] == "scripted-test-model"


def test_delegation_event_recorded(make_clients):
    pub, ev, _ = make_clients()
    r = pub.post("/api/agent/chat", headers=ANALYST,
                 json={"message": "Summarise reports"})
    t = ev.get("/api/traces/" + r.json()["run_id"], headers=EVAL).json()
    delegations = [e for e in t["events"] if e["stage"] == "delegation"]
    assert len(delegations) >= 1
    d = delegations[0]
    assert d["payload"]["from_agent"] == "coordinator"
    assert d["payload"]["to_agent"] in ("reader", "findings_manager")
    assert "task" in d["payload"]


def test_session_history_is_sent_on_later_turns(make_clients):
    pub, ev, _ = make_clients()
    first = pub.post("/api/agent/chat", headers=ANALYST, json={"message": "first question"}).json()
    second = pub.post("/api/agent/chat", headers=ANALYST,
                      json={"message": "follow-up", "session_id": first["session_id"]}).json()
    t = ev.get("/api/traces/" + second["run_id"], headers=EVAL).json()
    coord_reqs = [e for e in t["events"]
                  if e["stage"] == "llm_request" and e["payload"].get("agent") == "coordinator"]
    msgs = coord_reqs[0]["payload"]["body"]["messages"]
    assert [m["role"] for m in msgs][:4] == ["system", "user", "assistant", "user"]
    assert msgs[1]["content"] == "first question"


def test_session_cannot_be_hijacked(env):
    _, db = env
    db.save_history("s1", "analyst1", [])
    assert db.get_history("s1", "someone-else") is None


def test_spotlight_untrusted_wraps_retrieved_content(make_clients):
    pub, ev, _ = make_clients(robust_model)
    pub.post("/api/reports/upload", headers=ANALYST,
             files={"file": ("test_doc.md", b"vendor remediation update critical", "text/markdown")})

    def reader_requests(rid):
        evs = ev.get("/api/traces/" + rid, headers=EVAL).json()["events"]
        return [e for e in evs if e["stage"] == "llm_request" and e["payload"].get("agent") == "reader"]

    off = pub.post("/api/agent/chat", headers=ANALYST, json={"message": "summarise"}).json()
    reqs = reader_requests(off["run_id"])
    if reqs:
        assert "untrusted_document" not in json.dumps(reqs[0]["payload"]["body"]["messages"])

    ev.put("/api/config", headers=EVAL, json={"spotlight_untrusted": True})
    on = pub.post("/api/agent/chat", headers=ANALYST, json={"message": "summarise"}).json()
    reqs = reader_requests(on["run_id"])
    if reqs:
        # Check that at least one tool result in the reader's events has untrusted wrapping
        all_events = ev.get("/api/traces/" + on["run_id"], headers=EVAL).json()["events"]
        reader_results = [e for e in all_events
                          if e["stage"] == "tool_result" and e["payload"].get("agent") == "reader"]
        content = json.dumps([r["payload"] for r in reader_results])
        assert "untrusted_document" in content
