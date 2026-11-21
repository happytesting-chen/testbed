"""Tests for scope-request and grant management (Phase 3)."""
from tests.conftest import ANALYST, MANAGER


def test_analyst_scope_request_pending(make_clients, seeded_report_and_finding):
    pub, _, db = make_clients()
    _, f = seeded_report_and_finding
    r = pub.get("/api/scope-requests", headers=ANALYST)
    assert r.status_code == 200

    from app.auth_service import handle_scope_request
    result = handle_scope_request(db, "analyst1", "analyst", f["id"], "update_severity", "Need to fix", "sess1")
    assert result["status"] == "pending"
    assert "request_id" in result


def test_manager_self_approves(make_clients, seeded_report_and_finding):
    pub, _, db = make_clients()
    _, f = seeded_report_and_finding
    from app.auth_service import handle_scope_request
    result = handle_scope_request(db, "manager1", "manager", f["id"], "update_severity", "Fix", "sess1")
    assert result["status"] == "approved"
    assert "grant_id" in result


def test_manager_approves_analyst_request(make_clients, seeded_report_and_finding):
    pub, _, db = make_clients()
    _, f = seeded_report_and_finding
    from app.auth_service import handle_scope_request, approve_scope_request
    req = handle_scope_request(db, "analyst1", "analyst", f["id"], "update_severity", "Fix", "sess1")
    assert req["status"] == "pending"

    result = approve_scope_request(db, req["request_id"], "manager1", "sess1")
    assert result["status"] == "approved"
    assert "grant_id" in result

    grant = db.get_scope_grant(result["grant_id"])
    assert grant["approved_by"] == "manager1"
    assert grant["finding_id"] == f["id"]
    assert grant["session_id"] == "sess1"


def test_analyst_updates_with_grant(make_clients, seeded_report_and_finding):
    pub, _, db = make_clients()
    _, f = seeded_report_and_finding
    from app.auth_service import handle_scope_request, approve_scope_request, check_effective_permissions

    req = handle_scope_request(db, "analyst1", "analyst", f["id"], "update_severity", "Fix", "sess1")
    approve_scope_request(db, req["request_id"], "manager1", "sess1")

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

    req = handle_scope_request(db, "analyst1", "analyst", f["id"], "update_severity", "Fix", "sess1")
    approve_scope_request(db, req["request_id"], "manager1", "sess1")

    allowed_f1, _ = check_effective_permissions(db, "analyst1", "analyst", f["id"], "sess1")
    allowed_f2, _ = check_effective_permissions(db, "analyst1", "analyst", f2["id"], "sess1")
    assert allowed_f1
    assert not allowed_f2


def test_grant_scoped_to_session(make_clients, seeded_report_and_finding):
    pub, _, db = make_clients()
    _, f = seeded_report_and_finding
    from app.auth_service import handle_scope_request, approve_scope_request, check_effective_permissions

    req = handle_scope_request(db, "analyst1", "analyst", f["id"], "update_severity", "Fix", "sess1")
    approve_scope_request(db, req["request_id"], "manager1", "sess1")

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


def test_scope_request_rest_endpoints(make_clients, seeded_report_and_finding):
    pub, _, db = make_clients()
    _, f = seeded_report_and_finding
    from app.auth_service import handle_scope_request

    req = handle_scope_request(db, "analyst1", "analyst", f["id"], "update_severity", "Fix", "sess1")

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


def test_deny_scope_request(make_clients, seeded_report_and_finding):
    pub, _, db = make_clients()
    _, f = seeded_report_and_finding
    from app.auth_service import handle_scope_request

    req = handle_scope_request(db, "analyst1", "analyst", f["id"], "update_severity", "Fix", "sess1")

    r = pub.patch(f"/api/scope-requests/{req['request_id']}", headers=MANAGER,
                  json={"action": "deny"})
    assert r.status_code == 200
    assert r.json()["status"] == "denied"
