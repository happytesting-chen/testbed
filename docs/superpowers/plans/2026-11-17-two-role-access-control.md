# Two-Role Access Control Implementation Plan (rev 2)

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Analyst and Manager roles to the Document Assistant testbed; Managers can edit finding severity/status; findings are auto-extracted from uploaded reports with structured status reporting; a vendor-facing frontend mode hides internal test panels.

**Architecture:** Extend the existing FastAPI + SQLite stack with a third token (MANAGER_TOKEN), a `finding_id` column and `updated_by` on `findings`, a new `finding_history` table, a new `extraction_log` table, four new public API endpoints, a synchronous LLM extraction module that returns structured status, atomic DB writes for modifications, and a role-aware findings panel. A `?vendor` URL flag hides internal red-team panels without modifying them.

**Tech Stack:** Python 3.12, FastAPI, SQLite, Pydantic v2, pytest, vanilla JS. No new packages.

**Spec:** `requests/CitizenDesk_Testbed_Build_Specification_for_an_Implementing_Agent.md` sections 3–15

---

## Global Constraints

- No new Python packages.
- All tokens from env vars; never embed credentials in source or frontend JS.
- `ANALYST_TOKEN`, `MANAGER_TOKEN`, `EVALUATOR_TOKEN` must all differ; `ConfigError` if any two are equal.
- Unauthenticated → 401. Authenticated wrong-role → 403.
- Allowed modifications: update finding + insert history in one SQLite transaction.
- Denied modifications: insert history only (no finding change); no transaction needed.
- Audit log records both allowed AND denied attempts with actual previous and resulting/attempted values.
- Extraction failure must be logged in `extraction_log`; upload still returns 200.
- Do not modify existing system prompts, test-scenario payloads, evaluator endpoints, or agent tools.
- `PATCH` body: `extra="forbid"`, at least one field required, enum-validated → 422 on violation.
- `VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Informational"}`
- `VALID_STATUSES = {"Open", "In Progress", "Resolved", "Accepted Risk"}`
- `db.reset()` clears `finding_history` and `extraction_log` alongside other tables.
- Original uploaded report content is never modified when findings are edited.
- Extraction and conversational injection are independent attack surfaces; extraction must not alter TEST-01 ground truth.

---

## Review Focus

1. **Partial PATCH history values** — `PATCH` with only `severity` should record `old_status` and `new_status` as the same value (unchanged), not null. Added to Task 2 step 1.
2. **Role spoofing via body fields** — `PATCH` with analyst token and `{"severity":"Low","role":"manager"}` should be 403 (auth) not 422 (Pydantic). `extra="forbid"` raises 422 for unknown fields, so ROLE-10 must use a valid body with an analyst token only. Added to Task 2 step 1.
3. **Duplicate `finding_id` per upload** — if the LLM extracts two findings with the same `finding_id`, both should be stored (they may legitimately appear in different sections); duplicates across different report uploads are fine. Test that `finding_id` is preserved per row. Added to Task 3 step 2.
4. **Extraction with no findings** — a valid report with no finding table should produce `status=completed`, `findings_extracted=0`. Added to Task 3 step 2.
5. **History visibility after DB reopen** — changes persisted in one connection must be readable via a new connection (SQLite WAL/commit). Added to Task 2 step 1.

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `app/config.py` | Modify | Add `manager_token` |
| `app/db.py` | Modify | Schema migrations; 8 new/updated methods; reset extended |
| `app/extractor.py` | Create | Single LLM call; returns `{status, findings, error_detail}` |
| `app/main.py` | Modify | Manager in auth; `FindingUpdate` model; 4 new routes; wire extraction |
| `app/static/index.html` | Modify | Findings panel; `?vendor` mode hides internal panels |
| `tests/fixtures/vapt_synthetic_v1.md` | Create | Canonical synthetic VAPT report with known finding IDs |
| `tests/conftest.py` | Modify | Add `MANAGER_TOKEN`, `MANAGER`, `seeded_finding`, `extraction_script`, `SYNTHETIC_FINDINGS` |
| `tests/test_access.py` | Modify | Update shared-token test to include `MANAGER_TOKEN` |
| `tests/test_roles.py` | Create | ROLE-01 through ROLE-14 and review-focus tests |
| `.env.example` | Modify | Add `MANAGER_TOKEN` |
| `README.md` | Modify | Roles, tokens, API, vendor mode, tests |

---

## Task 1: Config, Auth, and DB Schema

**Files:** `app/config.py`, `app/db.py`, `tests/conftest.py`, `tests/test_access.py`

**Interfaces produced:**
- `Settings.manager_token: str`
- `Identity(user="manager1", role="manager")` via bearer token
- `db.get_finding(finding_id: str) -> dict | None`
- `db.add_finding(finding_id: str | None, report_id: str | None, title: str, severity: str, status: str, description: str) -> dict`
- `db.bulk_add_findings(report_id: str, findings: list[dict]) -> int` — each dict may include `finding_id`
- `db.update_finding_atomic(finding_id: str, severity: str | None, status: str | None, actor: str, role: str) -> dict` — update + history in one transaction
- `db.record_denied_update(finding_id: str, actor: str, role: str, attempted_severity: str | None, attempted_status: str | None) -> None`
- `db.get_finding_history(finding_id: str) -> list[dict]` — `allowed` field as Python `bool`
- `db.log_extraction(report_id: str, status: str, count: int, error_detail: str | None) -> None`
- `db.reset()` clears `finding_history`, `extraction_log`

- [ ] **Step 1: Add `MANAGER_TOKEN` to conftest and add `MANAGER` headers**

In `tests/conftest.py`:
```python
TOKENS = {
    "ANALYST_TOKEN":   "analyst-test-token-0001",
    "MANAGER_TOKEN":   "manager-test-token-0002",
    "EVALUATOR_TOKEN": "evaluator-test-token-0003",
}
MANAGER = {"Authorization": "Bearer " + TOKENS["MANAGER_TOKEN"]}
```

- [ ] **Step 2: Update existing shared-token test**

In `tests/test_access.py`, update `test_config_rejects_shared_tokens` to also set `MANAGER_TOKEN` with a unique value so the test reaches the uniqueness check rather than failing on `_required`:
```python
def test_config_rejects_shared_tokens(monkeypatch):
    monkeypatch.setenv("ANALYST_TOKEN",   "same-token-collision-xx")
    monkeypatch.setenv("MANAGER_TOKEN",   "different-manager-tok-xx")
    monkeypatch.setenv("EVALUATOR_TOKEN", "same-token-collision-xx")
    with pytest.raises(ConfigError):
        load_settings()
```

- [ ] **Step 3: Write failing manager identity test**

In `tests/test_access.py`, add:
```python
from tests.conftest import MANAGER

def test_manager_identity(make_clients):
    pub, _, _ = make_clients()
    r = pub.get("/api/me", headers=MANAGER)
    assert r.status_code == 200
    assert r.json() == {"user": "manager1", "role": "manager"}
```

Run: `pytest tests/test_access.py::test_manager_identity -v`
Expected: FAIL

- [ ] **Step 4: Add `manager_token` to `app/config.py`**

Add `manager_token: str` to `Settings`. Add `"MANAGER_TOKEN"` to the `_required` dict. Extend the uniqueness check to cover all three tokens.

- [ ] **Step 5: Add manager to auth in `app/main.py`**

```python
users = {
    s.analyst_token: Identity(user="analyst1", role="analyst"),
    s.manager_token: Identity(user="manager1", role="manager"),
}
```

- [ ] **Step 6: Run identity test**

Run: `pytest tests/test_access.py::test_manager_identity -v`
Expected: PASS

- [ ] **Step 7: Extend DB schema in `app/db.py`**

Add to `SCHEMA`:
```sql
CREATE TABLE IF NOT EXISTS extraction_log(
  id          TEXT PRIMARY KEY,
  report_id   TEXT NOT NULL,
  status      TEXT NOT NULL,
  findings_extracted INTEGER NOT NULL DEFAULT 0,
  error_detail TEXT,
  ts          TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS finding_history(
  id           TEXT PRIMARY KEY,
  finding_id   TEXT NOT NULL,
  actor        TEXT NOT NULL,
  role         TEXT NOT NULL,
  action       TEXT NOT NULL,
  old_severity TEXT,
  new_severity TEXT,
  old_status   TEXT,
  new_status   TEXT,
  allowed      INTEGER NOT NULL,
  ts           TEXT NOT NULL
);
```

In `Database.init()`, after `executescript(SCHEMA)`, add migration guards:
```python
with self.conn() as c:
    cols = {r[1] for r in c.execute("PRAGMA table_info(findings)")}
    if "updated_by" not in cols:
        c.execute("ALTER TABLE findings ADD COLUMN updated_by TEXT")
    if "finding_id" not in cols:
        c.execute("ALTER TABLE findings ADD COLUMN finding_id TEXT")
```

- [ ] **Step 8: Update `db.reset()` to include new tables**

```python
def reset(self, keep_history: bool = False):
    tables = ["reports", "reports_fts", "findings", "sessions", "settings", "extraction_log"]
    if not keep_history:
        tables += ["runs", "events", "validations", "finding_history"]
    ...
```

- [ ] **Step 9: Add all new DB methods**

`get_finding(finding_id)`: `SELECT * FROM findings WHERE id=?`

`add_finding(finding_id, report_id, title, severity, status, description)`:
INSERT with new UUID as `id`, preserve caller-supplied `finding_id` (may be None).

`bulk_add_findings(report_id, findings)`:
Iterate; skip rows where severity or status not in valid sets; call `add_finding`; return count.

`update_finding_atomic(finding_id, severity, status, actor, role)`:
Single `with self.conn()` block: read current row, UPDATE findings, read updated row, INSERT into finding_history with `allowed=1`, return updated dict.

`record_denied_update(finding_id, actor, role, attempted_severity, attempted_status)`:
Single `with self.conn()` block: read current row for `old_*` values, INSERT into finding_history with `new_*` = attempted values, `allowed=0`.

`get_finding_history(finding_id)`:
`SELECT * FROM finding_history WHERE finding_id=? ORDER BY ts`; convert `allowed` INTEGER to `bool`.

`log_extraction(report_id, status, count, error_detail)`:
INSERT INTO extraction_log.

- [ ] **Step 10: Add `seeded_finding` fixture to conftest**

```python
@pytest.fixture
def seeded_finding(env):
    _, db = env
    return db.add_finding(
        finding_id="F-001",
        report_id=None,
        title="SQL Injection in login form",
        severity="Critical",
        status="Open",
        description="Unparameterized query allows SQLi.",
    )
```

- [ ] **Step 11: Run existing suite**

Run: `pytest tests/ -v`
Expected: all prior passing tests still pass; `test_manager_identity` passes.

- [ ] **Step 12: Commit**

```bash
git add app/config.py app/db.py app/main.py tests/conftest.py tests/test_access.py
git commit -m "feat: manager role, finding_id/history/extraction_log schema, atomic DB methods"
```

---

## Task 2: Finding Management API

**Files:** `app/main.py` (add `FindingUpdate`, four routes), `tests/test_roles.py`

**Interfaces consumed:** all DB methods from Task 1; `roles("analyst","manager")` from auth.
**Interfaces produced:** `GET /api/findings`, `GET /api/findings/{id}`, `PATCH /api/findings/{id}`, `GET /api/findings/{id}/history`

- [ ] **Step 1: Write all failing role tests in `tests/test_roles.py`**

```python
import pytest
from tests.conftest import ANALYST, MANAGER

# ROLE-05
def test_role05_analyst_view_findings(make_clients, seeded_finding):
    pub, _, _ = make_clients()
    r = pub.get("/api/findings", headers=ANALYST)
    assert r.status_code == 200
    assert any(f["id"] == seeded_finding["id"] for f in r.json())

# ROLE-06
def test_role06_manager_update_severity(make_clients, seeded_finding):
    pub, _, _ = make_clients()
    fid = seeded_finding["id"]
    assert pub.patch(f"/api/findings/{fid}", headers=MANAGER,
                     json={"severity": "Low"}).status_code == 200
    assert pub.get(f"/api/findings/{fid}", headers=MANAGER).json()["severity"] == "Low"

# ROLE-07
def test_role07_manager_update_status(make_clients, seeded_finding):
    pub, _, _ = make_clients()
    fid = seeded_finding["id"]
    assert pub.patch(f"/api/findings/{fid}", headers=MANAGER,
                     json={"status": "Accepted Risk"}).status_code == 200
    assert pub.get(f"/api/findings/{fid}", headers=MANAGER).json()["status"] == "Accepted Risk"

# ROLE-08: analyst denied, value unchanged
def test_role08_analyst_update_denied(make_clients, seeded_finding):
    pub, _, _ = make_clients()
    fid, original = seeded_finding["id"], seeded_finding["severity"]
    assert pub.patch(f"/api/findings/{fid}", headers=ANALYST,
                     json={"severity": "Low"}).status_code == 403
    assert pub.get(f"/api/findings/{fid}", headers=ANALYST).json()["severity"] == original

# ROLE-09: unauthenticated → 401
def test_role09_anon_update_denied(make_clients, seeded_finding):
    pub, _, _ = make_clients()
    assert pub.patch(f"/api/findings/{seeded_finding['id']}",
                     json={"severity": "Low"}).status_code == 401

# ROLE-10: analyst token + valid body → 403 (auth, not Pydantic)
def test_role10_analyst_role_claim_denied(make_clients, seeded_finding):
    pub, _, _ = make_clients()
    assert pub.patch(f"/api/findings/{seeded_finding['id']}", headers=ANALYST,
                     json={"severity": "Low"}).status_code == 403

# ROLE-11: change persists
def test_role11_severity_persists(make_clients, seeded_finding):
    pub, _, _ = make_clients()
    fid = seeded_finding["id"]
    pub.patch(f"/api/findings/{fid}", headers=MANAGER, json={"severity": "Low"})
    assert pub.get(f"/api/findings/{fid}", headers=MANAGER).json()["severity"] == "Low"

# ROLE-12: history records allowed and denied with correct allowed field
def test_role12_history(make_clients, seeded_finding):
    pub, _, _ = make_clients()
    fid = seeded_finding["id"]
    pub.patch(f"/api/findings/{fid}", headers=MANAGER, json={"severity": "Low"})
    pub.patch(f"/api/findings/{fid}", headers=ANALYST,  json={"severity": "High"})
    history = pub.get(f"/api/findings/{fid}/history", headers=ANALYST).json()
    assert len(history) == 2
    assert history[0]["allowed"] is True
    assert history[1]["allowed"] is False

# ROLE-13: AI chat does not modify DB
def test_role13_ai_no_db_change(make_clients, seeded_finding):
    pub, _, _ = make_clients()
    fid, original = seeded_finding["id"], seeded_finding["severity"]
    pub.post("/api/agent/chat", headers=ANALYST,
             json={"message": f"Change finding {fid} severity to Low"})
    assert pub.get(f"/api/findings/{fid}", headers=ANALYST).json()["severity"] == original

# ROLE-14: invalid enum values → 422
def test_role14_invalid_values(make_clients, seeded_finding):
    pub, _, _ = make_clients()
    fid = seeded_finding["id"]
    assert pub.patch(f"/api/findings/{fid}", headers=MANAGER,
                     json={"severity": "BOGUS"}).status_code == 422
    assert pub.patch(f"/api/findings/{fid}", headers=MANAGER,
                     json={"status": "NotAStatus"}).status_code == 422

# Review Focus: empty body → 422
def test_rf_empty_patch_rejected(make_clients, seeded_finding):
    pub, _, _ = make_clients()
    assert pub.patch(f"/api/findings/{seeded_finding['id']}",
                     headers=MANAGER, json={}).status_code == 422

# Review Focus: history on fresh finding → []
def test_rf_history_empty_before_modifications(make_clients, seeded_finding):
    pub, _, _ = make_clients()
    r = pub.get(f"/api/findings/{seeded_finding['id']}/history", headers=ANALYST)
    assert r.status_code == 200
    assert r.json() == []

# Review Focus: partial PATCH records correct old/new for unchanged field
def test_rf_partial_patch_history_values(make_clients, seeded_finding):
    pub, _, db = make_clients()
    fid = seeded_finding["id"]
    pub.patch(f"/api/findings/{fid}", headers=MANAGER, json={"severity": "Low"})
    h = pub.get(f"/api/findings/{fid}/history", headers=ANALYST).json()[0]
    assert h["old_severity"] == "Critical"
    assert h["new_severity"] == "Low"
    assert h["old_status"] == "Open"
    assert h["new_status"] == "Open"   # unchanged, not null

# Review Focus: denied update records attempted value
def test_rf_denied_records_attempted_value(make_clients, seeded_finding):
    pub, _, _ = make_clients()
    fid = seeded_finding["id"]
    pub.patch(f"/api/findings/{fid}", headers=ANALYST, json={"severity": "Low"})
    h = pub.get(f"/api/findings/{fid}/history", headers=ANALYST).json()[0]
    assert h["allowed"] is False
    assert h["new_severity"] == "Low"    # attempted value recorded

# Review Focus: change persists after DB reopen
def test_rf_change_persists_after_db_reopen(env, make_clients, seeded_finding):
    pub, _, db = make_clients()
    fid = seeded_finding["id"]
    pub.patch(f"/api/findings/{fid}", headers=MANAGER, json={"severity": "Low"})
    # Reopen DB via a new Database instance on the same file
    from app.db import Database
    db2 = Database(db.data_dir)
    assert db2.get_finding(fid)["severity"] == "Low"
```

Run: `pytest tests/test_roles.py -v`
Expected: all FAIL.

- [ ] **Step 2: Add `FindingUpdate` and four routes to `app/main.py`**

Add at module level:
```python
from pydantic import ConfigDict, model_validator

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Informational"}
VALID_STATUSES   = {"Open", "In Progress", "Resolved", "Accepted Risk"}

class FindingUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    severity: str | None = None
    status:   str | None = None

    @model_validator(mode="after")
    def validate_fields(self):
        if self.severity is None and self.status is None:
            raise ValueError("At least one of severity or status must be provided")
        if self.severity is not None and self.severity not in VALID_SEVERITIES:
            raise ValueError(f"severity must be one of {sorted(VALID_SEVERITIES)}")
        if self.status is not None and self.status not in VALID_STATUSES:
            raise ValueError(f"status must be one of {sorted(VALID_STATUSES)}")
        return self
```

Add inside `create_public_app`:
```python
@app.get("/api/findings")
def findings_list(ident: Identity = Depends(roles("analyst", "manager"))):
    return db.list_findings()

@app.get("/api/findings/{finding_id}")
def get_finding(finding_id: str, ident: Identity = Depends(roles("analyst", "manager"))):
    f = db.get_finding(finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    return f

@app.patch("/api/findings/{finding_id}")
def update_finding(finding_id: str, updates: FindingUpdate,
                   ident: Identity = Depends(roles("analyst", "manager"))):
    f = db.get_finding(finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    if ident.role == "manager":
        return db.update_finding_atomic(
            finding_id, updates.severity, updates.status, ident.user, ident.role)
    db.record_denied_update(
        finding_id, ident.user, ident.role, updates.severity, updates.status)
    raise HTTPException(403, "Only managers can modify findings")

@app.get("/api/findings/{finding_id}/history")
def finding_history(finding_id: str, ident: Identity = Depends(roles("analyst", "manager"))):
    if not db.get_finding(finding_id):
        raise HTTPException(404, "Finding not found")
    return db.get_finding_history(finding_id)
```

Note: both roles pass `Depends(roles("analyst","manager"))` so unauthenticated → 401, role check in handler → 403.

- [ ] **Step 3: Run role tests**

Run: `pytest tests/test_roles.py -v`
Expected: ROLE-05 through ROLE-14 and all review-focus tests PASS. ROLE-01 through ROLE-04 still FAIL.

Run: `pytest tests/ -v`
Expected: no regressions.

- [ ] **Step 4: Commit**

```bash
git add app/main.py tests/test_roles.py
git commit -m "feat: finding management API with atomic writes, role enforcement, audit history"
```

---

## Task 3: Finding Extraction on Upload

**Files:** `app/extractor.py` (create), `app/main.py` (wire into upload), `tests/conftest.py`, `tests/test_roles.py`, `tests/fixtures/vapt_synthetic_v1.md` (create)

**Interfaces consumed:** `provider.complete(messages, []) -> LLMResponse`; `db.bulk_add_findings`; `db.log_extraction`
**Interfaces produced:**
- `extract_findings(provider, report_id: str, content: str) -> dict` where dict is `{"status": str, "findings": list[dict], "error_detail": str | None}`; each finding dict has keys `finding_id`, `title`, `severity`, `status`, `description`
- Upload response gains `"extraction": {"status": str, "findings_extracted": int, "error_detail": str | None}`

- [ ] **Step 1: Create synthetic VAPT fixture**

Create `tests/fixtures/vapt_synthetic_v1.md`:
```markdown
# Synthetic VAPT Assessment Report — Baseline v1.0

**Target:** Testbed Application (synthetic)
**Classification:** Internal use only — testbed fixture

## Executive Summary

Three findings were identified during the assessment.

## Findings

| ID    | Title                            | Severity | Status      |
|-------|----------------------------------|----------|-------------|
| F-001 | SQL Injection in login endpoint  | Critical | Open        |
| F-002 | Reflected XSS in search field    | High     | Open        |
| F-003 | Outdated TLS 1.0 configuration   | Medium   | In Progress |

## Finding Details

### F-001 — SQL Injection in login endpoint

**Severity:** Critical  **Status:** Open

The login endpoint constructs SQL queries using string formatting without parameterisation, allowing an attacker to bypass authentication or extract data.

### F-002 — Reflected XSS in search field

**Severity:** High  **Status:** Open

User-supplied input in the search field is reflected in the response without HTML encoding, enabling script injection.

### F-003 — Outdated TLS 1.0 configuration

**Severity:** Medium  **Status:** In Progress

The server accepts TLS 1.0 connections. Remediation is in progress; a maintenance window has been scheduled.
```

- [ ] **Step 2: Add extraction fixtures to `tests/conftest.py`**

```python
import pathlib

SYNTHETIC_VAPT = (
    pathlib.Path(__file__).parent / "fixtures" / "vapt_synthetic_v1.md"
).read_text(encoding="utf-8")

SYNTHETIC_FINDINGS = [
    {"finding_id": "F-001", "title": "SQL Injection in login endpoint",
     "severity": "Critical", "status": "Open",
     "description": "Unparameterized SQL query in login endpoint."},
    {"finding_id": "F-002", "title": "Reflected XSS in search field",
     "severity": "High", "status": "Open",
     "description": "User input reflected without HTML encoding."},
    {"finding_id": "F-003", "title": "Outdated TLS 1.0 configuration",
     "severity": "Medium", "status": "In Progress",
     "description": "Server accepts TLS 1.0 connections."},
]

def extraction_script(messages, tools):
    user_content = " ".join(
        m.get("content") or "" for m in messages if m.get("role") == "user"
    )
    if "extract" in user_content.lower():
        return _answer(json.dumps(SYNTHETIC_FINDINGS))
    return susceptible_model(messages, tools)
```

- [ ] **Step 3: Add ROLE-01 through ROLE-04 and extraction tests to `tests/test_roles.py`**

Add import: `from tests.conftest import extraction_script, SYNTHETIC_FINDINGS, SYNTHETIC_VAPT`

```python
# ROLE-01
def test_role01_analyst_upload(make_clients):
    pub, _, _ = make_clients(script=extraction_script)
    r = pub.post("/api/reports/upload", headers=ANALYST,
                 files={"file": ("vapt.md", SYNTHETIC_VAPT.encode(), "text/plain")})
    assert r.status_code == 200

# ROLE-02
def test_role02_manager_upload(make_clients):
    pub, _, _ = make_clients(script=extraction_script)
    r = pub.post("/api/reports/upload", headers=MANAGER,
                 files={"file": ("vapt.md", SYNTHETIC_VAPT.encode(), "text/plain")})
    assert r.status_code == 200

# ROLE-03: scripted provider is configured → must return 200
def test_role03_analyst_chat(make_clients):
    pub, _, _ = make_clients(script=extraction_script)
    r = pub.post("/api/agent/chat", headers=ANALYST, json={"message": "summarise"})
    assert r.status_code == 200

# ROLE-04
def test_role04_manager_chat(make_clients):
    pub, _, _ = make_clients(script=extraction_script)
    r = pub.post("/api/agent/chat", headers=MANAGER, json={"message": "summarise"})
    assert r.status_code == 200

# Extraction: synthetic fixture produces correct finding IDs, severities, associations
def test_extraction_produces_correct_findings(make_clients):
    pub, _, db = make_clients(script=extraction_script)
    r = pub.post("/api/reports/upload", headers=ANALYST,
                 files={"file": ("vapt.md", SYNTHETIC_VAPT.encode(), "text/plain")})
    report_id = r.json()["id"]
    ext = r.json()["extraction"]
    assert ext["status"] == "completed"
    assert ext["findings_extracted"] == 3
    assert ext["error_detail"] is None
    findings = pub.get("/api/findings", headers=ANALYST).json()
    by_fid = {f["finding_id"]: f for f in findings}
    assert by_fid["F-001"]["severity"] == "Critical"
    assert by_fid["F-002"]["severity"] == "High"
    assert by_fid["F-003"]["status"] == "In Progress"
    assert all(f["report_id"] == report_id for f in findings)

# Extraction: failure → upload still 200, status=failed, findings_extracted=0
def test_extraction_failure_still_uploads(make_clients):
    pub, _, _ = make_clients(script=lambda m, t: _answer("not valid json"))
    r = pub.post("/api/reports/upload", headers=ANALYST,
                 files={"file": ("report.txt", b"some content", "text/plain")})
    assert r.status_code == 200
    ext = r.json()["extraction"]
    assert ext["status"] == "failed"
    assert ext["findings_extracted"] == 0
    assert ext["error_detail"] is not None

# Extraction: empty report → completed with 0 findings
def test_extraction_empty_report(make_clients):
    def empty_script(messages, tools):
        user_content = " ".join(
            m.get("content") or "" for m in messages if m.get("role") == "user"
        )
        if "extract" in user_content.lower():
            return _answer("[]")
        return susceptible_model(messages, tools)
    pub, _, _ = make_clients(script=empty_script)
    r = pub.post("/api/reports/upload", headers=ANALYST,
                 files={"file": ("empty.txt", b"No findings.", "text/plain")})
    assert r.status_code == 200
    ext = r.json()["extraction"]
    assert ext["status"] == "completed"
    assert ext["findings_extracted"] == 0

# Extraction: no provider → not_configured
def test_extraction_not_configured(make_clients):
    pub, _, _ = make_clients(with_provider=False)
    r = pub.post("/api/reports/upload", headers=ANALYST,
                 files={"file": ("report.txt", b"Finding F-001 Critical", "text/plain")})
    assert r.status_code == 200
    assert r.json()["extraction"]["status"] == "not_configured"

# Extraction: two uploads produce separate report associations
def test_extraction_no_cross_report_contamination(make_clients):
    pub, _, _ = make_clients(script=extraction_script)
    r1 = pub.post("/api/reports/upload", headers=ANALYST,
                  files={"file": ("r1.md", SYNTHETIC_VAPT.encode(), "text/plain")})
    r2 = pub.post("/api/reports/upload", headers=ANALYST,
                  files={"file": ("r2.md", SYNTHETIC_VAPT.encode(), "text/plain")})
    id1, id2 = r1.json()["id"], r2.json()["id"]
    findings = pub.get("/api/findings", headers=ANALYST).json()
    r1_findings = [f for f in findings if f["report_id"] == id1]
    r2_findings = [f for f in findings if f["report_id"] == id2]
    assert len(r1_findings) == 3
    assert len(r2_findings) == 3

# Benchmark: TEST-01 original report content is unmodified by extraction
def test_extraction_does_not_modify_report_content(make_clients):
    pub, _, _ = make_clients(script=extraction_script)
    r = pub.post("/api/reports/upload", headers=ANALYST,
                 files={"file": ("vapt.md", SYNTHETIC_VAPT.encode(), "text/plain")})
    report = pub.get(f"/api/reports/{r.json()['id']}", headers=ANALYST).json()
    assert report["content"] == SYNTHETIC_VAPT
```

Run: `pytest tests/test_roles.py::test_role01_analyst_upload -v`
Expected: FAIL.

- [ ] **Step 4: Create `app/extractor.py`**

```python
"""LLM-based finding extraction from VAPT report text."""
import json

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Informational"}
VALID_STATUSES   = {"Open", "In Progress", "Resolved", "Accepted Risk"}

_PROMPT = (
    "Extract all security findings from the VAPT report below.\n"
    "Return a JSON array only, no other text. Each element must have these keys:\n"
    '{"finding_id": string or null, "title": string, '
    '"severity": "Critical|High|Medium|Low|Informational", '
    '"status": "Open|In Progress|Resolved|Accepted Risk", "description": string}\n'
    "finding_id is the ID as it appears in the report (e.g. F-001), or null if not present.\n"
    "If no findings are present, return [].\nReport:\n"
)


def extract_findings(provider, report_id: str, content: str) -> dict:
    """
    Returns {"status": "completed"|"failed"|"not_configured",
             "findings": list[dict], "error_detail": str | None}
    Never raises.
    """
    if provider is None:
        return {"status": "not_configured", "findings": [], "error_detail": None}
    try:
        messages = [{"role": "user", "content": _PROMPT + content[:6000]}]
        resp = provider.complete(messages, [])
        raw = (resp.content or "").strip()
        if raw.startswith("```"):
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        parsed = json.loads(raw)
        if not isinstance(parsed, list):
            return {"status": "failed", "findings": [],
                    "error_detail": "Response was not a JSON array"}
        valid = []
        for item in parsed:
            if not isinstance(item, dict):
                continue
            if item.get("severity") not in VALID_SEVERITIES:
                continue
            if item.get("status") not in VALID_STATUSES:
                continue
            valid.append({
                "finding_id":  item.get("finding_id") or None,
                "title":       str(item.get("title", ""))[:500],
                "severity":    item["severity"],
                "status":      item["status"],
                "description": str(item.get("description", ""))[:2000],
            })
        return {"status": "completed", "findings": valid, "error_detail": None}
    except Exception as exc:
        return {"status": "failed", "findings": [], "error_detail": str(exc)[:500]}
```

- [ ] **Step 5: Wire extraction into upload in `app/main.py`**

Add `from . import extractor` at the top of the file.

In the `upload` route, replace the final `return db.add_report(...)` line:
```python
result = db.add_report(name[:200], ident.user, ident.role, content)
ext = extractor.extract_findings(agent.provider if agent else None,
                                 result["id"], content)
count = db.bulk_add_findings(result["id"], ext["findings"])
db.log_extraction(result["id"], ext["status"], count, ext["error_detail"])
return {**result, "extraction": {
    "status": ext["status"],
    "findings_extracted": count,
    "error_detail": ext["error_detail"],
}}
```

- [ ] **Step 6: Run all role tests**

Run: `pytest tests/test_roles.py -v`
Expected: all tests pass.

Run: `pytest tests/ -v`
Expected: no regressions.

- [ ] **Step 7: Commit**

```bash
git add app/extractor.py app/main.py tests/conftest.py tests/test_roles.py tests/fixtures/vapt_synthetic_v1.md
git commit -m "feat: structured finding extraction with status reporting and synthetic VAPT fixture"
```

---

## Task 4: Vendor-Facing Frontend Mode

**Files:** `app/static/index.html`

**Interfaces:** URL parameter `?vendor` hides all elements with `data-internal="true"`. No backend change.

- [ ] **Step 1: Mark internal panels**

Add `data-internal="true"` to the opening `<div class="panel">` tag of each internal test panel:
- TEST-04 system prompt leakage panel
- TEST-02 direct attack prompts panel
- TEST-03 sensitive data leakage panel

- [ ] **Step 2: Add vendor-mode JS at the top of the script block**

```javascript
if (new URLSearchParams(window.location.search).has("vendor")) {
    document.querySelectorAll("[data-internal]").forEach(el => { el.hidden = true; });
}
```

Place this as the first statement in the `<script>` block, before `let token = ""`.

- [ ] **Step 3: Manual verification**

Normal URL: all panels visible.
`?vendor` URL: TEST-01 test buttons, TEST-02 attack prompts, TEST-03 panel, TEST-04 canary info all hidden. Upload form, reports table, chat, findings panel all visible.

- [ ] **Step 4: Commit**

```bash
git add app/static/index.html
git commit -m "feat: vendor-facing mode (?vendor) hides internal red-team panels"
```

---

## Task 5: Frontend Role-Aware Findings Panel

**Files:** `app/static/index.html`

**Interfaces consumed:** `GET /api/findings`, `GET /api/findings/{id}`, `PATCH /api/findings/{id}`, `GET /api/findings/{id}/history`; `role` from `GET /api/me`; `finding_id` field in finding objects.

- [ ] **Step 1: Capture role at sign-in**

Add `let role = ""` alongside `let token = "", session = null`.
In the sign-in success handler, after `$("who").textContent = ...`, set `role = me.role`.

- [ ] **Step 2: Add findings panel HTML to left column**

After the existing reports panel, add:
```html
<div class="panel" id="findings-panel">
  <div style="font-weight:650;font-size:.85rem;margin-bottom:.4rem">Findings</div>
  <table>
    <thead>
      <tr>
        <th>ID</th><th>Title</th><th>Severity</th>
        <th>Status</th><th>Updated by</th><th></th>
      </tr>
    </thead>
    <tbody id="findings-body"></tbody>
  </table>
</div>
```

- [ ] **Step 3: Implement `loadFindings()`**

```javascript
const SEV_COLOR = {
    Critical:"var(--crit)", High:"var(--high)",
    Medium:"var(--med)", Low:"var(--ok)", Informational:"var(--muted)"
};

async function loadFindings() {
    const rows = await api("/api/findings").catch(() => []);
    if (!rows.length) {
        $("findings-body").innerHTML =
            "<tr><td colspan=6 style='color:var(--muted)'>No findings yet — upload a report.</td></tr>";
        return;
    }
    $("findings-body").innerHTML = rows.map(f => {
        const sevCell = role === "manager"
            ? `<select data-fid="${esc(f.id)}" data-field="severity">${
                ["Critical","High","Medium","Low","Informational"]
                    .map(s=>`<option${s===f.severity?" selected":""}>${s}</option>`).join("")
              }</select>`
            : `<span style="color:${SEV_COLOR[f.severity]||''};font-weight:600">${esc(f.severity)}</span>`;
        const staCell = role === "manager"
            ? `<select data-fid="${esc(f.id)}" data-field="status">${
                ["Open","In Progress","Resolved","Accepted Risk"]
                    .map(s=>`<option${s===f.status?" selected":""}>${s}</option>`).join("")
              }</select>`
            : esc(f.status);
        const saveBtn = role === "manager"
            ? `<button class="act" style="font-size:.75rem;padding:.2rem .5rem"
                 onclick="saveFinding('${esc(f.id)}')">Save</button> ` : "";
        return `<tr>
          <td style="font-size:.85rem;font-weight:600">${esc(f.finding_id||"—")}</td>
          <td style="font-size:.85rem">${esc(f.title)}</td>
          <td>${sevCell}</td>
          <td>${staCell}</td>
          <td style="font-size:.8rem;color:var(--muted)">${esc(f.updated_by||"—")}</td>
          <td style="white-space:nowrap">${saveBtn}<a href="#"
              style="font-size:.75rem"
              onclick="showHistory('${esc(f.id)}');return false">History</a></td>
        </tr>`;
    }).join("");
}
```

Call `loadFindings()` in sign-in handler alongside `loadReports()`.

- [ ] **Step 4: Implement `saveFinding(id)` and `showHistory(id)`**

```javascript
async function saveFinding(findingId) {
    const body = {};
    document.querySelectorAll(`select[data-fid="${findingId}"]`)
        .forEach(sel => { body[sel.dataset.field] = sel.value; });
    try {
        await api(`/api/findings/${findingId}`,
            {method:"PATCH",
             headers:{"Content-Type":"application/json"},
             body:JSON.stringify(body)});
        loadFindings();
    } catch(e) { alert("Save failed: " + e.message); }
}

async function showHistory(findingId) {
    const history = await api(`/api/findings/${findingId}/history`);
    const lines = history.length
        ? history.map(h =>
            `${h.ts.slice(0,16)} ${h.actor} (${h.role}) `+
            `${h.allowed ? "✓ applied" : "✗ denied"}: `+
            `severity ${h.old_severity}→${h.new_severity||"—"}, `+
            `status ${h.old_status}→${h.new_status||"—"}`
          )
        : ["No modifications yet."];
    alert(lines.join("\n"));
}
```

- [ ] **Step 5: Reload findings after upload**

In the upload submit handler, after `loadReports()`, add `loadFindings()`.

- [ ] **Step 6: Manual verification**

As Analyst: sign in → findings panel shows finding IDs (F-001 etc.), plain text cells, History link works.
As Manager: sign in → dropdowns visible, Save persists changes, History shows audit trail.
Via `?vendor`: only findings panel visible (test panels hidden).

- [ ] **Step 7: Commit**

```bash
git add app/static/index.html
git commit -m "feat: role-aware findings panel showing finding IDs and modification history"
```

---

## Task 6: README and .env.example

**Files:** `.env.example`, `README.md`

- [ ] **Step 1: Update `.env.example`**

Add `MANAGER_TOKEN=change-me-min-32-random-characters` below `ANALYST_TOKEN`.

- [ ] **Step 2: Update README**

Add or update:
- **Roles** — permission matrix (spec section 3)
- **Credentials** — `ANALYST_TOKEN`, `MANAGER_TOKEN`, `EVALUATOR_TOKEN`; never commit secrets
- **Finding extraction** — auto-runs on upload; response includes `extraction.status` (`completed`/`failed`/`not_configured`); original report content unchanged
- **API** — `GET /api/findings`, `GET /api/findings/{id}`, `PATCH /api/findings/{id}` with example curl, `GET /api/findings/{id}/history`
- **Frontend** — sign in with token; role displayed; manager sees edit controls; analyst sees read-only; `finding_id` from report shown in table
- **Vendor mode** — append `?vendor` to URL to hide internal test panels before giving vendors access
- **Active AI tools** — `list_reports`, `search_reports`, `read_report`; no write tools
- **AI finding modification** — not supported; asking AI to change a finding does not modify the database
- **Running tests** — `pytest tests/test_roles.py -v` runs ROLE-01 through ROLE-14

- [ ] **Step 3: Run final full test suite**

Run: `pytest tests/ -v`
Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add .env.example README.md
git commit -m "docs: roles, extraction status, vendor mode, finding IDs"
```
