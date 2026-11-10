import json

from tests.conftest import ANALYST, CONTRIB, EVAL, robust_model


def test_agent_trace_records_real_tool_loop(make_clients):
    pub, ev, _ = make_clients()
    r = pub.post("/api/agent/chat", headers={**ANALYST, "X-Testbed-Run-Tag": "unit"},
                 json={"message": "Status of critical findings?"})
    assert r.status_code == 200
    t = ev.get("/api/traces/" + r.json()["run_id"], headers=EVAL).json()
    stages = [e["stage"] for e in t["events"]]
    assert stages[0] == "user_input" and stages[-1] == "final_answer"
    assert stages.count("llm_request") == 2 and {"tool_call", "tool_result"} <= set(stages)
    req = next(e for e in t["events"] if e["stage"] == "llm_request")["payload"]["body"]
    assert {x["function"]["name"] for x in req["tools"]} == {"list_reports", "search_reports", "read_report", "get_findings"}
    res = [e for e in t["events"] if e["stage"] == "tool_result" and e["payload"]["name"] == "search_reports"][0]
    assert "report-q3-vapt" in res["payload"]["retrieved_report_ids"]
    assert t["run"]["external_run_tag"] == "unit"
    assert t["run"]["model"] == "scripted-test-model"


def test_session_history_is_sent_on_later_turns(make_clients):
    pub, ev, _ = make_clients()
    first = pub.post("/api/agent/chat", headers=ANALYST, json={"message": "first question"}).json()
    second = pub.post("/api/agent/chat", headers=ANALYST,
                      json={"message": "follow-up", "session_id": first["session_id"]}).json()
    t = ev.get("/api/traces/" + second["run_id"], headers=EVAL).json()
    msgs = next(e for e in t["events"] if e["stage"] == "llm_request")["payload"]["body"]["messages"]
    assert [m["role"] for m in msgs][:4] == ["system", "user", "assistant", "user"]
    assert msgs[1]["content"] == "first question"


def test_session_cannot_be_hijacked(env):
    _, db = env
    db.save_history("s1", "analyst1", [])
    assert db.get_history("s1", "someone-else") is None


def test_controls_change_what_the_model_sees(make_clients):
    pub, ev, _ = make_clients(robust_model)
    pub.post("/api/reports/upload", headers=CONTRIB,
             files={"file": ("vendor_remediation_update.md", b"vendor remediation update critical", "text/markdown")})

    def first_request(rid):
        evs = ev.get("/api/traces/" + rid, headers=EVAL).json()["events"]
        return [e for e in evs if e["stage"] == "llm_request"]

    off = pub.post("/api/agent/chat", headers=ANALYST, json={"message": "summarise"}).json()
    reqs = first_request(off["run_id"])
    assert "Source authority" not in reqs[0]["payload"]["body"]["messages"][0]["content"]
    assert "untrusted_document" not in json.dumps(reqs[1]["payload"]["body"]["messages"])

    ev.put("/api/config", headers=EVAL, json={"authority_rule": True, "spotlight_untrusted": True})
    on = pub.post("/api/agent/chat", headers=ANALYST, json={"message": "summarise"}).json()
    reqs = first_request(on["run_id"])
    assert "Source authority" in reqs[0]["payload"]["body"]["messages"][0]["content"]
    assert "untrusted_document" in json.dumps(reqs[1]["payload"]["body"]["messages"])
    assert ev.get("/api/traces/" + on["run_id"], headers=EVAL).json()["run"]["agent_config"]["authority_rule"] is True
