"""Tests for scope-request and grant management (Phase 3).

Covers:
- Direct auth_service function tests
- REST endpoint tests
- End-to-end three-agent workflow tests via chat API
- Grant expiry and session binding
"""
import json

from tests.conftest import (ANALYST, MANAGER, _first_step, _answer, _tool_call)


# ---- Direct auth_service tests -----------------------------------------------

def test_analyst_scope_request_pending(make_clients, seeded_report_and_finding):
    pub, _, db = make_clients()
    _, f = seeded_report_and_finding
    from app.auth_service import handle_scope_request
    result = handle_scope_request(db, "analyst1", "analyst", f["id"],
                                  "update_severity", "Need to fix", "sess1")
    assert result["status"] == "pending"
    assert "request_id" in result


def test_manager_self_approves(make_clients, seeded_report_and_finding):
    pub, _, db = make_clients()
    _, f = seeded_report_and_finding
    from app.auth_service import handle_scope_request
    result = handle_scope_request(db, "manager1", "manager", f["id"],
                                  "update_severity", "Fix", "sess1")
    assert result["status"] == "approved"
    assert "grant_id" in result


def test_manager_approves_analyst_request(make_clients, seeded_report_and_finding):
    pub, _, db = make_clients()
    _, f = seeded_report_and_finding
    from app.auth_service import handle_scope_request, approve_scope_request
    req = handle_scope_request(db, "analyst1", "analyst", f["id"],
                               "update_severity", "Fix", "sess1")
    assert req["status"] == "pending"

    result = approve_scope_request(db, req["request_id"], "manager1")
    assert result["status"] == "approved"

    grant = db.get_scope_grant(result["grant_id"])
    assert grant["approved_by"] == "manager1"
    assert grant["finding_id"] == f["id"]
    assert grant["session_id"] == "sess1"


def test_analyst_updates_with_grant(make_clients, seeded_report_and_finding):
    pub, _, db = make_clients()
    _, f = seeded_report_and_finding
    from app.auth_service import handle_scope_request, approve_scope_request, check_effective_permissions

    req = handle_scope_request(db, "analyst1", "analyst", f["id"],
                               "update_severity", "Fix", "sess1")
    approve_scope_request(db, req["request_id"], "manager1")

    allowed, grant_id = check_effective_permissions(db, "analyst1", "analyst", f["id"], "sess1")
    assert allowed
    assert grant_id is not None

    db.update_finding_and_log(f["id"], "Low", None, "analyst1", grant_id)
    assert db.get_finding(f["id"])["severity"] == "Low"
    history = db.get_finding_history(f["id"])
    assert len(history) == 1
    assert history[0]["authorized_by_grant"] == grant_id


def test_analyst_denied_without_grant(make_clients, seeded_report_and_finding):
    pub, _, db = make_clients()
    _, f = seeded_report_and_finding
    from app.auth_service import check_effective_permissions
    allowed, grant_id = check_effective_permissions(db, "analyst1", "analyst", f["id"], "sess1")
    assert not allowed
    assert grant_id is None


def test_grant_scoped_to_specific_finding(make_clients, seeded_report_and_finding):
    pub, _, db = make_clients()
    _, f = seeded_report_and_finding
    f2 = db.add_finding(f["report_id"], "F-002", "XSS", "High", "Open", "Reflected XSS.")
    from app.auth_service import handle_scope_request, approve_scope_request, check_effective_permissions

    req = handle_scope_request(db, "analyst1", "analyst", f["id"],
                               "update_severity", "Fix", "sess1")
    approve_scope_request(db, req["request_id"], "manager1")

    allowed_f1, _ = check_effective_permissions(db, "analyst1", "analyst", f["id"], "sess1")
    allowed_f2, _ = check_effective_permissions(db, "analyst1", "analyst", f2["id"], "sess1")
    assert allowed_f1
    assert not allowed_f2


def test_grant_scoped_to_session(make_clients, seeded_report_and_finding):
    pub, _, db = make_clients()
    _, f = seeded_report_and_finding
    from app.auth_service import handle_scope_request, approve_scope_request, check_effective_permissions

    req = handle_scope_request(db, "analyst1", "analyst", f["id"],
                               "update_severity", "Fix", "sess1")
    approve_scope_request(db, req["request_id"], "manager1")

    allowed_same, _ = check_effective_permissions(db, "analyst1", "analyst", f["id"], "sess1")
    allowed_other, _ = check_effective_permissions(db, "analyst1", "analyst", f["id"], "sess2")
    assert allowed_same
    assert not allowed_other


def test_manager_updates_directly_no_grant(make_clients, seeded_report_and_finding):
    pub, _, db = make_clients()
    _, f = seeded_report_and_finding
    from app.auth_service import check_effective_permissions
    allowed, grant_id = check_effective_permissions(db, "manager1", "manager", f["id"], "sess1")
    assert allowed
    assert grant_id is None


def test_expired_grant_rejected(make_clients, seeded_report_and_finding):
    """A grant whose expires_at is in the past must not be usable."""
    pub, _, db = make_clients()
    _, f = seeded_report_and_finding
    import uuid
    from app.db import now
    from datetime import datetime, timezone, timedelta
    past = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(timespec="milliseconds")
    grant_id = str(uuid.uuid4())
    with db.conn() as c:
        c.execute(
            "INSERT INTO scope_grants(id, request_id, actor, finding_id, scope, "
            "approved_by, session_id, created_at, expires_at) VALUES(?,?,?,?,?,?,?,?,?)",
            (grant_id, "req-fake", "analyst1", f["id"], "findings:write",
             "manager1", "sess1", past, past),
        )
    from app.auth_service import check_effective_permissions
    allowed, _ = check_effective_permissions(db, "analyst1", "analyst", f["id"], "sess1")
    assert not allowed


def test_grant_with_future_expiry_usable(make_clients, seeded_report_and_finding):
    """A grant whose expires_at is in the future should be usable."""
    pub, _, db = make_clients()
    _, f = seeded_report_and_finding
    from app.auth_service import handle_scope_request, approve_scope_request, check_effective_permissions
    req = handle_scope_request(db, "analyst1", "analyst", f["id"],
                               "update_severity", "Fix", "sess1")
    approve_scope_request(db, req["request_id"], "manager1")
    allowed, gid = check_effective_permissions(db, "analyst1", "analyst", f["id"], "sess1")
    assert allowed
    grant = db.get_scope_grant(gid)
    assert grant["expires_at"] is not None
    from app.db import now
    assert grant["expires_at"] > now()


# ---- REST endpoint tests -----------------------------------------------------

def test_scope_request_rest_endpoints(make_clients, seeded_report_and_finding):
    pub, _, db = make_clients()
    _, f = seeded_report_and_finding
    from app.auth_service import handle_scope_request

    req = handle_scope_request(db, "analyst1", "analyst", f["id"],
                               "update_severity", "Fix", "sess1")

    r = pub.get("/api/scope-requests", headers=ANALYST)
    assert r.status_code == 200
    assert len(r.json()) == 1
    assert r.json()[0]["status"] == "pending"

    r = pub.patch(f"/api/scope-requests/{req['request_id']}", headers=ANALYST,
                  json={"action": "approve"})
    assert r.status_code == 403

    r = pub.patch(f"/api/scope-requests/{req['request_id']}", headers=MANAGER,
                  json={"action": "approve"})
    assert r.status_code == 200
    assert r.json()["status"] == "approved"


def test_rest_approved_grant_bound_to_analyst_session(make_clients, seeded_report_and_finding):
    """Issue 1 regression: Manager-approved grant must use the analyst's session_id
    from the original scope request, not the Manager's session or empty string."""
    pub, _, db = make_clients()
    _, f = seeded_report_and_finding
    from app.auth_service import handle_scope_request, check_effective_permissions

    req = handle_scope_request(db, "analyst1", "analyst", f["id"],
                               "update_severity", "Fix", "analyst-session-42")

    r = pub.patch(f"/api/scope-requests/{req['request_id']}", headers=MANAGER,
                  json={"action": "approve"})
    assert r.status_code == 200
    grant = db.get_scope_grant(r.json()["grant_id"])
    assert grant["session_id"] == "analyst-session-42"

    allowed, _ = check_effective_permissions(db, "analyst1", "analyst",
                                            f["id"], "analyst-session-42")
    assert allowed

    allowed_other, _ = check_effective_permissions(db, "analyst1", "analyst",
                                                   f["id"], "other-session")
    assert not allowed_other


def test_deny_scope_request(make_clients, seeded_report_and_finding):
    pub, _, db = make_clients()
    _, f = seeded_report_and_finding
    from app.auth_service import handle_scope_request

    req = handle_scope_request(db, "analyst1", "analyst", f["id"],
                               "update_severity", "Fix", "sess1")

    r = pub.patch(f"/api/scope-requests/{req['request_id']}", headers=MANAGER,
                  json={"action": "deny"})
    assert r.status_code == 200
    assert r.json()["status"] == "denied"


# ---- End-to-end three-agent workflow tests -----------------------------------

def _scope_workflow_script(fid):
    """Script that drives the full scope workflow:
    Coordinator calls request_scope, then delegates to FM for update."""
    call_count = {"n": 0}

    def script(messages, tools):
        tool_names = {t["function"]["name"] for t in tools} if tools else set()
        call_count["n"] += 1

        if "request_scope" in tool_names:
            tool_results = " ".join(m.get("content") or "" for m in messages
                                    if m.get("role") == "tool")
            if _first_step(messages):
                return _tool_call("s1", "request_scope", {
                    "finding_id": fid, "action": "update_severity",
                    "justification": "User requested severity change"})
            if '"approved"' in tool_results or '"status": "approved"' in tool_results:
                return _tool_call("d1", "delegate_to_findings_manager", {
                    "task": f"Update finding {fid} severity to Low.",
                    "context": "Scope granted."})
            if '"pending"' in tool_results:
                return _answer("Your request to update the finding has been submitted. "
                               "A manager must approve it first.")
            return _answer("Done.")

        if "update_finding" in tool_names:
            if _first_step(messages):
                return _tool_call("u1", "update_finding", {
                    "finding_id": fid, "severity": "Low"})
            return _answer("Finding updated to Low.")

        return _answer("OK")
    return script


def test_e2e_analyst_scope_request_pending(make_clients, seeded_report_and_finding):
    """Analyst asks to update → Coordinator calls request_scope → pending."""
    _, f = seeded_report_and_finding
    pub, _, db = make_clients(script=_scope_workflow_script(f["id"]))
    r = pub.post("/api/agent/chat", headers=ANALYST,
                 json={"message": "Update finding severity to Low"})
    assert r.status_code == 200
    assert "pending" in r.json()["response"].lower() or "submitted" in r.json()["response"].lower()
    assert db.get_finding(f["id"])["severity"] == "Critical"


def test_e2e_manager_approves_then_analyst_updates(make_clients, seeded_report_and_finding):
    """Full workflow: analyst requests → pending → manager approves via REST →
    analyst retries → FM updates → DB changes → grant_id in history.

    The second chat call uses a script that skips request_scope (grant already exists)
    and goes directly to delegate_to_findings_manager."""
    _, f = seeded_report_and_finding
    fid = f["id"]

    # First call: request_scope → pending
    pub, _, db = make_clients(script=_scope_workflow_script(fid))
    r1 = pub.post("/api/agent/chat", headers=ANALYST,
                  json={"message": "Update finding severity to Low"})
    assert r1.status_code == 200
    assert db.get_finding(fid)["severity"] == "Critical"
    session_id = r1.json()["session_id"]

    pending = [r for r in db.list_scope_requests(actor="analyst1") if r["status"] == "pending"]
    assert len(pending) >= 1

    r_approve = pub.patch(f"/api/scope-requests/{pending[0]['id']}", headers=MANAGER,
                          json={"action": "approve"})
    assert r_approve.status_code == 200
    grant_id = r_approve.json()["grant_id"]

    # Second call: skip request_scope, go straight to FM update
    def retry_script(messages, tools):
        tool_names = {t["function"]["name"] for t in tools} if tools else set()
        if "delegate_to_findings_manager" in tool_names:
            if _first_step(messages):
                return _tool_call("d1", "delegate_to_findings_manager", {
                    "task": f"Update finding {fid} severity to Low.",
                    "context": "Scope previously approved."})
            return _answer("Done.")
        if "update_finding" in tool_names:
            if _first_step(messages):
                return _tool_call("u1", "update_finding", {
                    "finding_id": fid, "severity": "Low"})
            return _answer("Updated.")
        return _answer("OK")

    pub2, _, _ = make_clients(script=retry_script)
    r2 = pub2.post("/api/agent/chat", headers=ANALYST,
                   json={"message": "Now update the finding",
                         "session_id": session_id})
    assert r2.status_code == 200
    assert db.get_finding(fid)["severity"] == "Low"

    history = db.get_finding_history(fid)
    assert len(history) == 1
    assert history[0]["authorized_by_grant"] == grant_id
    assert history[0]["old_severity"] == "Critical"
    assert history[0]["new_severity"] == "Low"


def test_e2e_analyst_update_denied_without_grant(make_clients, seeded_report_and_finding):
    """Analyst tries to update without any scope grant — denied, DB unchanged."""
    _, f = seeded_report_and_finding

    def direct_update_script(messages, tools):
        tool_names = {t["function"]["name"] for t in tools} if tools else set()
        if "delegate_to_findings_manager" in tool_names:
            if _first_step(messages):
                return _tool_call("d1", "delegate_to_findings_manager", {
                    "task": f"Update finding {f['id']} severity to Low.",
                    "context": "No scope requested."})
            return _answer("Done.")
        if "update_finding" in tool_names:
            if _first_step(messages):
                return _tool_call("u1", "update_finding", {
                    "finding_id": f["id"], "severity": "Low"})
            return _answer("Permission denied.")
        return _answer("OK")

    pub, _, db = make_clients(script=direct_update_script)
    pub.post("/api/agent/chat", headers=ANALYST,
             json={"message": "Update finding"})
    assert db.get_finding(f["id"])["severity"] == "Critical"
    assert len(db.get_finding_history(f["id"])) == 0


def test_e2e_manager_updates_directly(make_clients, seeded_report_and_finding):
    """Manager can update findings without scope requests."""
    _, f = seeded_report_and_finding

    def manager_update_script(messages, tools):
        tool_names = {t["function"]["name"] for t in tools} if tools else set()
        if "delegate_to_findings_manager" in tool_names:
            if _first_step(messages):
                return _tool_call("d1", "delegate_to_findings_manager", {
                    "task": f"Update finding {f['id']} severity to Low.",
                    "context": "Manager direct update."})
            return _answer("Done.")
        if "update_finding" in tool_names:
            if _first_step(messages):
                return _tool_call("u1", "update_finding", {
                    "finding_id": f["id"], "severity": "Low"})
            return _answer("Updated.")
        return _answer("OK")

    pub, _, db = make_clients(script=manager_update_script)
    pub.post("/api/agent/chat", headers=MANAGER,
             json={"message": "Update finding severity"})
    assert db.get_finding(f["id"])["severity"] == "Low"
    history = db.get_finding_history(f["id"])
    assert len(history) == 1
    assert history[0]["authorized_by_grant"] is None


def test_e2e_cross_session_grant_rejected(make_clients, seeded_report_and_finding):
    """Grant from session 1 must not be usable in session 2."""
    _, f = seeded_report_and_finding
    fid = f["id"]
    pub, _, db = make_clients(script=_scope_workflow_script(fid))

    r1 = pub.post("/api/agent/chat", headers=ANALYST,
                  json={"message": "Update finding severity to Low"})
    session1 = r1.json()["session_id"]

    pending = [r for r in db.list_scope_requests(actor="analyst1") if r["status"] == "pending"]
    pub.patch(f"/api/scope-requests/{pending[0]['id']}", headers=MANAGER,
              json={"action": "approve"})

    r2 = pub.post("/api/agent/chat", headers=ANALYST,
                  json={"message": "Update finding severity to Low"})
    session2 = r2.json()["session_id"]
    assert session1 != session2

    assert db.get_finding(fid)["severity"] == "Critical"
