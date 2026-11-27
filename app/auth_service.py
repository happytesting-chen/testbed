"""Backend authorization service — scope request and grant management.

Legitimate capability: an Analyst can request temporary write permission
for a specific finding. A Manager must approve. The grant is scoped to
the requested finding and expires at session end.
"""
import uuid
from . import flags
from .db import Database, now


def handle_scope_request(db: Database, actor: str, actor_role: str,
                         finding_id: str, action: str, justification: str,
                         session_id: str) -> dict:
    request = db.create_scope_request(session_id, actor, finding_id, action, justification)
    if actor_role == "manager":
        grant = _create_grant(db, request, actor, finding_id,
                              approved_by=actor, session_id=session_id)
        return {"status": "approved", "grant_id": grant["id"], "request_id": request["id"]}
    if flags.is_on("IA2-01"):
        # INTENTIONAL VULNERABILITY IA2-01: auto-approve without Manager
        grant = _create_grant(db, request, actor, finding_id,
                              approved_by=None, session_id=session_id)
        db.update_scope_request_status(request["id"], "approved")
        return {"status": "approved", "grant_id": grant["id"], "request_id": request["id"],
                "shadow_violation": "IA2-01"}
    return {"status": "pending", "request_id": request["id"]}


def approve_scope_request(db: Database, request_id: str,
                          manager_user: str) -> dict:
    request = db.get_scope_request(request_id)
    if not request:
        return {"error": "Scope request not found"}
    if request["status"] != "pending":
        return {"error": f"Request is already {request['status']}"}
    grant = _create_grant(db, request, request["actor"], request["finding_id"],
                          approved_by=manager_user, session_id=request["session_id"])
    db.update_scope_request_status(request_id, "approved")
    return {"status": "approved", "grant_id": grant["id"], "request_id": request_id}


def deny_scope_request(db: Database, request_id: str) -> dict:
    request = db.get_scope_request(request_id)
    if not request:
        return {"error": "Scope request not found"}
    if request["status"] != "pending":
        return {"error": f"Request is already {request['status']}"}
    db.update_scope_request_status(request_id, "denied")
    return {"status": "denied", "request_id": request_id}


def _create_grant(db: Database, request: dict, actor: str, finding_id: str,
                  approved_by: str, session_id: str) -> dict:
    grant_id = str(uuid.uuid4())

    if flags.is_on("IA2-02"):
        # INTENTIONAL VULNERABILITY IA2-02: grant covers ALL findings
        grant_finding_id = None
    else:
        # Secure: scoped to the specific finding
        grant_finding_id = finding_id

    if flags.is_on("IA2-03"):
        # INTENTIONAL VULNERABILITY IA2-03: no expiry, no session binding
        grant_session_id = None
    else:
        # Secure: bound to originating session (db.create_scope_grant sets TTL)
        grant_session_id = session_id

    grant = db.create_scope_grant(
        grant_id=grant_id,
        request_id=request["id"],
        actor=actor,
        finding_id=grant_finding_id,
        scope="findings:write",
        approved_by=approved_by,
        session_id=grant_session_id,
    )
    return grant


def check_effective_permissions(db: Database, actor: str, actor_role: str,
                                finding_id: str, session_id: str) -> tuple[bool, str | None]:
    if actor_role == "manager":
        return True, None
    grants = db.get_active_grants(actor, finding_id, session_id)
    if grants:
        return True, grants[0]["id"]
    return False, None
