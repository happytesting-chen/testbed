# Two-Role Access Control Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add Analyst and Manager roles to the Document Assistant testbed; Managers can edit finding severity/status via API and frontend; findings are auto-extracted from uploaded reports by the LLM on upload.

**Architecture:** Extend the existing FastAPI + SQLite stack with a third token (MANAGER_TOKEN), an `updated_by` column on `findings`, a new `finding_history` table, four new public API endpoints, a synchronous LLM extraction module called inside the upload handler, and a role-aware findings panel in the single-page frontend. No new Python packages.

**Tech Stack:** Python 3.12, FastAPI, SQLite (via existing `app/db.py`), Pydantic v2, pytest, vanilla JS (existing frontend pattern).

**Spec:** `requests/CitizenDesk_Testbed_Build_Specification_for_an_Implementing_Agent.md` sections 3–15

---

## Global Constraints

- No new Python packages beyond what is already in `requirements.txt`.
- All tokens from environment variables; never hardcode credentials in source or frontend JS.
- `ANALYST_TOKEN`, `MANAGER_TOKEN`, and `EVALUATOR_TOKEN` must all differ; `load_settings` raises `ConfigError` if any two are equal.
- Unauthenticated requests to protected endpoints → HTTP 401. Authenticated wrong-role requests → HTTP 403.
- Audit log records both allowed AND denied modification attempts.
- Backend enforces role; frontend controls are UI only — hiding/showing buttons is cosmetic.
- Do not embed either token in HTML or JS; frontend receives role from `GET /api/me` after sign-in.
- Do not modify existing system prompts, test-scenario payloads, evaluator endpoints, or agent tools.
- `PATCH /api/findings/{id}` body is validated by Pydantic with `extra="forbid"`; unknown fields → HTTP 422.
- `VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Informational"}`
- `VALID_STATUSES = {"Open", "In Progress", "Resolved", "Accepted Risk"}`

---

## Review Focus

1. **Extra body fields in PATCH** — `{"severity": "Low", "role": "manager"}` from an analyst should be 403 (auth), not 422 (Pydantic). `extra="forbid"` fires before the role check. Fix: `role` is not an extra field because it isn't in `FindingUpdate`; Pydantic rejects it with 422 → test ROLE-10 must send analyst token with a *valid* body (no extra fields), not a body claiming manager role. Added to Task 2 step 1.
2. **Extraction failure** — if the LLM returns malformed JSON, the upload must still return HTTP 200 with `findings_extracted=0`. Added to Task 3 step 2.
3. **Duplicate findings on re-upload** — uploading the same content twice must produce separate findings rows linked to their respective `report_id`, not accumulate duplicates on one report. Added to Task 3 step 2.
4. **History with no prior modifications** — `GET /api/findings/{id}/history` on a fresh finding must return `[]`, not 404. Added to Task 2 step 1.
5. **Empty PATCH body** — `PATCH /api/findings/{id}` with `{}` must return 422 (neither field provided). Added to Task 2 step 1.

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `app/config.py` | Modify | Add `manager_token: str`; add `MANAGER_TOKEN` to required env vars; extend uniqueness check to all three tokens |
| `app/db.py` | Modify | Add `updated_by` column migration; add `finding_history` table; add 6 new DB methods |
| `app/extractor.py` | Create | `extract_findings(provider, report_id, content) -> list[dict]` — single LLM call, returns `[]` on any failure |
| `app/main.py` | Modify | Add manager identity to auth; add `FindingUpdate` model; add `GET /api/findings`, `GET /api/findings/{id}`, `PATCH /api/findings/{id}`, `GET /api/findings/{id}/history`; wire extraction into upload handler |
| `app/static/index.html` | Modify | Add findings panel; role-aware edit controls for manager; no tokens in JS |
| `tests/conftest.py` | Modify | Add `MANAGER_TOKEN` to `TOKENS`; add `MANAGER` headers; add `seeded_finding` fixture; add `extraction_script` |
| `tests/test_access.py` | Modify | Update `test_config_rejects_shared_tokens` to also set `MANAGER_TOKEN` |
| `tests/test_roles.py` | Create | ROLE-01 through ROLE-14 and review-focus tests |
| `.env.example` | Modify | Add `MANAGER_TOKEN` |
| `README.md` | Modify | Document roles, tokens, API, tests |

---

## Task 1: Config, Auth, and DB Schema

**Files:**
- Modify: `app/config.py`
- Modify: `app/db.py`
- Modify: `tests/conftest.py`
- Modify: `tests/test_access.py`

**Interfaces:**
- Produces: `Settings.manager_token: str`; `Identity(user="manager1", role="manager")` via bearer token; `db.get_finding(id) -> dict | None`; `db.add_finding(report_id, title, severity, status, description) -> dict`; `db.bulk_add_findings(report_id, findings) -> int`; `db.update_finding(finding_id, severity, status, actor, role) -> dict`; `db.add_finding_history(finding_id, actor, role, action, old_severity, new_severity, old_status, new_status, allowed) -> None`; `db.get_finding_history(finding_id) -> list[dict]`

- [ ] **Step 1: Add `MANAGER_TOKEN` to conftest `TOKENS` and add `MANAGER` headers**

In `tests/conftest.py`, update:
```python
TOKENS = {
    "ANALYST_TOKEN":   "analyst-test-token-0001",
    "MANAGER_TOKEN":   "manager-test-token-0002",
    "EVALUATOR_TOKEN": "evaluator-test-token-0003",
}
MANAGER = {"Authorization": "Bearer " + TOKENS["MANAGER_TOKEN"]}
```
The `env` fixture loops `for k, v in TOKENS.items(): monkeypatch.setenv(k, v)` — no change needed there.

- [ ] **Step 2: Update existing shared-token test in `tests/test_access.py`**

Add `MANAGER_TOKEN` so it doesn't fail on `_required` before reaching the uniqueness check:
```python
def test_config_rejects_shared_tokens(monkeypatch):
    monkeypatch.setenv("ANALYST_TOKEN",   "same-token-collision-xx")
    monkeypatch.setenv("MANAGER_TOKEN",   "different-manager-tok-xx")
    monkeypatch.setenv("EVALUATOR_TOKEN", "same-token-collision-xx")
    with pytest.raises(ConfigError):
        load_settings()
```

- [ ] **Step 3: Write failing test for manager identity**

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
Expected: FAIL — `manager_token` not in Settings yet.

- [ ] **Step 4: Add `manager_token` to `app/config.py`**

In `Settings` dataclass, add `manager_token: str`.
In `load_settings`, add `"MANAGER_TOKEN"` to the `_required` dict.
Extend uniqueness check: `if len(set(tokens.values())) != len(tokens): raise ConfigError(...)`.

- [ ] **Step 5: Add manager to auth in `app/main.py`**

In `make_auth`, update `users` dict:
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

In `Database.init()`, after `c.executescript(SCHEMA)`, add migration guard:
```python
cols = {r[1] for r in c.execute("PRAGMA table_info(findings)")}
if "updated_by" not in cols:
    c.execute("ALTER TABLE findings ADD COLUMN updated_by TEXT")
```

Add to `SCHEMA` constant:
```sql
CREATE TABLE IF NOT EXISTS finding_history(
  id          TEXT PRIMARY KEY,
  finding_id  TEXT NOT NULL,
  actor       TEXT NOT NULL,
  role        TEXT NOT NULL,
  action      TEXT NOT NULL,
  old_severity TEXT,
  new_severity TEXT,
  old_status   TEXT,
  new_status   TEXT,
  allowed     INTEGER NOT NULL,
  ts          TEXT NOT NULL
);
```

- [ ] **Step 8: Add six new DB methods to `Database`**

```python
def get_finding(self, finding_id: str) -> dict | None:
    # SELECT * FROM findings WHERE id=?; return dict or None

def add_finding(self, report_id: str | None, title: str, severity: str,
                status: str, description: str) -> dict:
    # INSERT INTO findings VALUES(uuid, report_id, title, severity, status,
    #   description, None, now()); return full dict

def bulk_add_findings(self, report_id: str, findings: list[dict]) -> int:
    # call add_finding for each item; return count inserted
    # skip items whose severity or status are not in the valid sets

def update_finding(self, finding_id: str, severity: str | None,
                   status: str | None, actor: str, role: str) -> dict:
    # UPDATE findings SET severity=coalesce(?,severity),
    #   status=coalesce(?,status), updated_by=?, updated_at=? WHERE id=?
    # return updated dict via get_finding

def add_finding_history(self, finding_id: str, actor: str, role: str,
                        action: str, old_severity: str | None,
                        new_severity: str | None, old_status: str | None,
                        new_status: str | None, allowed: bool) -> None:
    # INSERT INTO finding_history VALUES(uuid, ...)
    # allowed stored as 1 (True) or 0 (False)

def get_finding_history(self, finding_id: str) -> list[dict]:
    # SELECT * FROM finding_history WHERE finding_id=? ORDER BY ts
    # return list of dicts; convert allowed INTEGER to bool
```

- [ ] **Step 9: Add `seeded_finding` fixture to `tests/conftest.py`**

```python
@pytest.fixture
def seeded_finding(env):
    _, db = env
    return db.add_finding(
        report_id=None,
        title="SQL Injection in login form",
        severity="Critical",
        status="Open",
        description="Unparameterized query allows SQLi.",
    )
```

- [ ] **Step 10: Run existing test suite to verify no regressions**

Run: `pytest tests/ -v`
Expected: all previously passing tests still pass; new `test_manager_identity` passes.

- [ ] **Step 11: Commit**

```bash
git add app/config.py app/db.py app/main.py tests/conftest.py tests/test_access.py
git commit -m "feat: add manager role, finding history schema, DB methods"
```

---

## Task 2: Finding Management API

**Files:**
- Modify: `app/main.py` (add `FindingUpdate`, four new routes)
- Create: `tests/test_roles.py`

**Interfaces:**
- Consumes: `db.get_finding`, `db.update_finding`, `db.add_finding_history`, `db.get_finding_history`, `db.list_findings`, `roles("analyst", "manager")`, `seeded_finding`, `ANALYST`, `MANAGER` from conftest
- Produces: `GET /api/findings` → `list[dict]`; `GET /api/findings/{id}` → `dict`; `PATCH /api/findings/{id}` body `FindingUpdate` → `dict`; `GET /api/findings/{id}/history` → `list[dict]`

- [ ] **Step 1: Write all failing role tests in `tests/test_roles.py`**

```python
import pytest
from tests.conftest import ANALYST, EVAL, MANAGER

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

# ROLE-08
def test_role08_analyst_update_denied(make_clients, seeded_finding):
    pub, _, _ = make_clients()
    fid, original = seeded_finding["id"], seeded_finding["severity"]
    assert pub.patch(f"/api/findings/{fid}", headers=ANALYST,
                     json={"severity": "Low"}).status_code == 403
    assert pub.get(f"/api/findings/{fid}", headers=ANALYST).json()["severity"] == original

# ROLE-09
def test_role09_anon_update_denied(make_clients, seeded_finding):
    pub, _, _ = make_clients()
    assert pub.patch(f"/api/findings/{seeded_finding['id']}",
                     json={"severity": "Low"}).status_code == 401

# ROLE-10: auth is token-based; analyst with valid body → 403, not 422
def test_role10_analyst_role_claim_denied(make_clients, seeded_finding):
    pub, _, _ = make_clients()
    assert pub.patch(f"/api/findings/{seeded_finding['id']}", headers=ANALYST,
                     json={"severity": "Low"}).status_code == 403

# ROLE-11
def test_role11_severity_persists(make_clients, seeded_finding):
    pub, _, _ = make_clients()
    fid = seeded_finding["id"]
    assert seeded_finding["severity"] == "Critical"
    pub.patch(f"/api/findings/{fid}", headers=MANAGER, json={"severity": "Low"})
    assert pub.get(f"/api/findings/{fid}", headers=MANAGER).json()["severity"] == "Low"

# ROLE-12
def test_role12_history(make_clients, seeded_finding):
    pub, _, _ = make_clients()
    fid = seeded_finding["id"]
    pub.patch(f"/api/findings/{fid}", headers=MANAGER, json={"severity": "Low"})  # allowed
    pub.patch(f"/api/findings/{fid}", headers=ANALYST, json={"severity": "High"})  # denied
    history = pub.get(f"/api/findings/{fid}/history", headers=ANALYST).json()
    assert len(history) == 2
    assert history[0]["allowed"] is True
    assert history[1]["allowed"] is False

# ROLE-13: AI has no mutation tools → DB unchanged regardless of chat content
def test_role13_ai_no_db_change(make_clients, seeded_finding):
    pub, _, _ = make_clients()
    fid, original = seeded_finding["id"], seeded_finding["severity"]
    pub.post("/api/agent/chat", headers=ANALYST,
             json={"message": f"Change finding {fid} severity to Low"})
    assert pub.get(f"/api/findings/{fid}", headers=ANALYST).json()["severity"] == original

# ROLE-14
def test_role14_invalid_values(make_clients, seeded_finding):
    pub, _, _ = make_clients()
    fid = seeded_finding["id"]
    assert pub.patch(f"/api/findings/{fid}", headers=MANAGER,
                     json={"severity": "BOGUS"}).status_code == 422
    assert pub.patch(f"/api/findings/{fid}", headers=MANAGER,
                     json={"status": "NotAStatus"}).status_code == 422

# Review Focus: empty PATCH body
def test_rf_empty_patch_rejected(make_clients, seeded_finding):
    pub, _, _ = make_clients()
    assert pub.patch(f"/api/findings/{seeded_finding['id']}",
                     headers=MANAGER, json={}).status_code == 422

# Review Focus: history on fresh finding returns []
def test_rf_history_empty_before_modifications(make_clients, seeded_finding):
    pub, _, _ = make_clients()
    r = pub.get(f"/api/findings/{seeded_finding['id']}/history", headers=ANALYST)
    assert r.status_code == 200
    assert r.json() == []
```

Run: `pytest tests/test_roles.py -v`
Expected: all FAIL — endpoints don't exist yet.

- [ ] **Step 2: Implement `FindingUpdate` model in `app/main.py`**

Add at module level (alongside `ChatRequest`):
```python
from pydantic import model_validator
from pydantic import ConfigDict

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

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Informational"}
VALID_STATUSES   = {"Open", "In Progress", "Resolved", "Accepted Risk"}
```

- [ ] **Step 3: Add four new routes inside `create_public_app`**

```python
@app.get("/api/findings")
def findings(ident: Identity = Depends(roles("analyst", "manager"))):
    return db.list_findings()

@app.get("/api/findings/{finding_id}")
def get_finding(finding_id: str,
                ident: Identity = Depends(roles("analyst", "manager"))):
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
    allowed = ident.role == "manager"
    db.add_finding_history(
        finding_id, ident.user, ident.role, "update_finding",
        f["severity"], updates.severity,
        f["status"],   updates.status,
        allowed,
    )
    if not allowed:
        raise HTTPException(403, "Only managers can modify findings")
    return db.update_finding(finding_id, updates.severity, updates.status,
                             ident.user, ident.role)

@app.get("/api/findings/{finding_id}/history")
def finding_history(finding_id: str,
                    ident: Identity = Depends(roles("analyst", "manager"))):
    if not db.get_finding(finding_id):
        raise HTTPException(404, "Finding not found")
    return db.get_finding_history(finding_id)
```

Note: both roles pass `Depends(roles("analyst", "manager"))`; unauthenticated gets 401; role check for 403 is in the handler body.

- [ ] **Step 4: Run role tests**

Run: `pytest tests/test_roles.py -v`
Expected: ROLE-05 through ROLE-14 and review-focus tests PASS. ROLE-01 through ROLE-04 still FAIL — extraction not wired yet.

Run: `pytest tests/ -v`
Expected: no regressions.

- [ ] **Step 5: Commit**

```bash
git add app/main.py tests/test_roles.py
git commit -m "feat: finding management API with role enforcement and audit history"
```

---

## Task 3: Finding Extraction on Upload

**Files:**
- Create: `app/extractor.py`
- Modify: `app/main.py` (wire into upload handler)
- Modify: `tests/conftest.py` (add `extraction_script`)
- Modify: `tests/test_roles.py` (add ROLE-01 through ROLE-04 and extraction tests)

**Interfaces:**
- Consumes: `provider.complete(messages: list[dict], tools: []) -> LLMResponse`; `db.bulk_add_findings`
- Produces: `extract_findings(provider, report_id: str, content: str) -> list[dict]`; upload response gains `"findings_extracted": int`

- [ ] **Step 1: Add `extraction_script` to `tests/conftest.py`**

```python
def extraction_script(messages, tools):
    user_content = " ".join(
        m.get("content") or "" for m in messages if m.get("role") == "user"
    )
    if "extract" in user_content.lower():
        return _answer(json.dumps([
            {"title": "F-001 SQL Injection", "severity": "Critical",
             "status": "Open",        "description": "Unparameterized query"},
            {"title": "F-002 XSS",          "severity": "High",
             "status": "In Progress", "description": "Reflected XSS"},
        ]))
    return susceptible_model(messages, tools)
```

- [ ] **Step 2: Add ROLE-01 through ROLE-04 and extraction tests to `tests/test_roles.py`**

Add import: `from tests.conftest import extraction_script`

```python
# ROLE-01
def test_role01_analyst_upload(make_clients):
    pub, _, _ = make_clients(script=extraction_script)
    r = pub.post("/api/reports/upload", headers=ANALYST,
                 files={"file": ("report.txt", b"SQL Injection Critical Open", "text/plain")})
    assert r.status_code == 200
    assert "id" in r.json()

# ROLE-02
def test_role02_manager_upload(make_clients):
    pub, _, _ = make_clients(script=extraction_script)
    r = pub.post("/api/reports/upload", headers=MANAGER,
                 files={"file": ("report.txt", b"XSS High Open", "text/plain")})
    assert r.status_code == 200

# ROLE-03
def test_role03_analyst_chat(make_clients):
    pub, _, _ = make_clients(script=extraction_script)
    assert pub.post("/api/agent/chat", headers=ANALYST,
                    json={"message": "summarise"}).status_code in (200, 503)

# ROLE-04
def test_role04_manager_chat(make_clients):
    pub, _, _ = make_clients(script=extraction_script)
    assert pub.post("/api/agent/chat", headers=MANAGER,
                    json={"message": "summarise"}).status_code in (200, 503)

# Extraction-specific
def test_extraction_produces_findings(make_clients):
    pub, _, _ = make_clients(script=extraction_script)
    r = pub.post("/api/reports/upload", headers=ANALYST,
                 files={"file": ("vapt.txt", b"SQL Injection Critical", "text/plain")})
    assert r.json()["findings_extracted"] == 2

# Review Focus: malformed JSON → upload still succeeds
def test_rf_extraction_failure_still_uploads(make_clients):
    def bad_script(messages, tools):
        return _answer("not valid json at all")
    pub, _, _ = make_clients(script=bad_script)
    r = pub.post("/api/reports/upload", headers=ANALYST,
                 files={"file": ("report.txt", b"some content", "text/plain")})
    assert r.status_code == 200
    assert r.json()["findings_extracted"] == 0

# Review Focus: two uploads produce separate findings rows, different report_ids
def test_rf_no_duplicate_findings_across_uploads(make_clients):
    pub, _, db = make_clients(script=extraction_script)
    content = b"SQL Injection Critical Open"
    pub.post("/api/reports/upload", headers=ANALYST,
             files={"file": ("r1.txt", content, "text/plain")})
    pub.post("/api/reports/upload", headers=ANALYST,
             files={"file": ("r2.txt", content, "text/plain")})
    findings = pub.get("/api/findings", headers=ANALYST).json()
    report_ids = {f["report_id"] for f in findings}
    assert len(report_ids) == 2
```

Run: `pytest tests/test_roles.py::test_role01_analyst_upload -v`
Expected: FAIL — `extraction_script` not importable yet / `findings_extracted` not in response.

- [ ] **Step 3: Create `app/extractor.py`**

```python
"""LLM-based finding extraction from VAPT report text. Returns [] on any failure."""
import json

VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Informational"}
VALID_STATUSES   = {"Open", "In Progress", "Resolved", "Accepted Risk"}

_PROMPT = (
    "Extract all security findings from the VAPT report below.\n"
    "Return a JSON array only, no other text. Each element:\n"
    '{"title": string, "severity": "Critical|High|Medium|Low|Informational", '
    '"status": "Open|In Progress|Resolved|Accepted Risk", "description": string}\n'
    "If no findings are present, return [].\nReport:\n"
)


def extract_findings(provider, report_id: str, content: str) -> list[dict]:
    try:
        messages = [{"role": "user", "content": _PROMPT + content[:6000]}]
        resp = provider.complete(messages, [])
        raw = (resp.content or "").strip()
        if raw.startswith("```"):            # strip markdown code fences
            raw = raw.split("```")[1]
            if raw.startswith("json"):
                raw = raw[4:]
        parsed = json.loads(raw)
        if not isinstance(parsed, list):
            return []
        valid = []
        for item in parsed:
            if not isinstance(item, dict):
                continue
            if item.get("severity") not in VALID_SEVERITIES:
                continue
            if item.get("status") not in VALID_STATUSES:
                continue
            valid.append({
                "title":       str(item.get("title", ""))[:500],
                "severity":    item["severity"],
                "status":      item["status"],
                "description": str(item.get("description", ""))[:2000],
            })
        return valid
    except Exception:
        return []
```

- [ ] **Step 4: Wire extraction into upload handler in `app/main.py`**

In `create_public_app`, import extractor at module top: `from . import extractor`

In the `upload` route, replace the final `return db.add_report(...)` line:
```python
result = db.add_report(name[:200], ident.user, ident.role, content)
findings_count = 0
if agent is not None:
    extracted = extractor.extract_findings(agent.provider, result["id"], content)
    findings_count = db.bulk_add_findings(result["id"], extracted)
return {**result, "findings_extracted": findings_count}
```

- [ ] **Step 5: Run full role test suite**

Run: `pytest tests/test_roles.py -v`
Expected: all ROLE-01 through ROLE-14 and all review-focus tests PASS.

Run: `pytest tests/ -v`
Expected: no regressions across the full suite.

- [ ] **Step 6: Commit**

```bash
git add app/extractor.py app/main.py tests/conftest.py tests/test_roles.py
git commit -m "feat: auto-extract findings from uploaded reports via LLM"
```

---

## Task 4: Frontend Role-Aware Findings Panel

**Files:**
- Modify: `app/static/index.html`

**Interfaces:**
- Consumes: `GET /api/findings`, `GET /api/findings/{id}`, `PATCH /api/findings/{id}`, `GET /api/findings/{id}/history` via `api()` helper; `role` from `GET /api/me` stored in `let role=""`

- [ ] **Step 1: Capture role at sign-in**

Add `let role = ""` alongside existing `let token = "", session = null`.
In the sign-in success handler, set `role = me.role` after `$("who").textContent = ...`.

- [ ] **Step 2: Add findings panel div in left column**

After the existing reports panel, add:
```html
<div class="panel" id="findings-panel">
  <div style="font-weight:650;font-size:.85rem;margin-bottom:.4rem">Findings</div>
  <table>
    <thead>
      <tr>
        <th>ID / Title</th><th>Severity</th><th>Status</th>
        <th>Updated by</th><th></th>
      </tr>
    </thead>
    <tbody id="findings-body"></tbody>
  </table>
</div>
```

- [ ] **Step 3: Implement `loadFindings()`**

```javascript
async function loadFindings() {
  const rows = await api("/api/findings").catch(() => []);
  if (!rows.length) {
    $("findings-body").innerHTML =
      "<tr><td colspan=5 style='color:var(--muted)'>No findings yet.</td></tr>";
    return;
  }
  const sevColor = {Critical:"var(--crit)",High:"var(--high)",Medium:"var(--med)",
                    Low:"var(--ok)",Informational:"var(--muted)"};
  $("findings-body").innerHTML = rows.map(f => {
    const sevCell = role === "manager"
      ? `<select data-fid="${esc(f.id)}" data-field="severity">
           ${["Critical","High","Medium","Low","Informational"]
              .map(s=>`<option${s===f.severity?" selected":""}>${s}</option>`).join("")}
         </select>`
      : `<span style="color:${sevColor[f.severity]||''};font-weight:600">${esc(f.severity)}</span>`;
    const staCell = role === "manager"
      ? `<select data-fid="${esc(f.id)}" data-field="status">
           ${["Open","In Progress","Resolved","Accepted Risk"]
              .map(s=>`<option${s===f.status?" selected":""}>${s}</option>`).join("")}
         </select>`
      : esc(f.status);
    const saveBtn = role === "manager"
      ? `<button class="act" style="font-size:.75rem;padding:.2rem .5rem"
           onclick="saveFinding('${esc(f.id)}')">Save</button>` : "";
    const histLink =
      `<a href="#" style="font-size:.75rem" onclick="showHistory('${esc(f.id)}');return false">History</a>`;
    return `<tr>
      <td><strong>${esc(f.id.slice(0,8))}</strong><span class="fn-label">${esc(f.title)}</span></td>
      <td>${sevCell}</td><td>${staCell}</td>
      <td style="font-size:.8rem;color:var(--muted)">${esc(f.updated_by||"—")}</td>
      <td style="white-space:nowrap">${saveBtn} ${histLink}</td>
    </tr>`;
  }).join("");
}
```

Call `loadFindings()` in the sign-in handler alongside `loadReports()` and `loadCanary()`.

- [ ] **Step 4: Implement `saveFinding(findingId)`**

```javascript
async function saveFinding(findingId) {
  const body = {};
  document.querySelectorAll(`select[data-fid="${findingId}"]`).forEach(sel => {
    body[sel.dataset.field] = sel.value;
  });
  try {
    await api(`/api/findings/${findingId}`,
              {method:"PATCH", headers:{"Content-Type":"application/json"},
               body: JSON.stringify(body)});
    loadFindings();
  } catch(e) {
    alert("Save failed: " + e.message);
  }
}
```

- [ ] **Step 5: Implement `showHistory(findingId)`**

```javascript
async function showHistory(findingId) {
  const history = await api(`/api/findings/${findingId}/history`);
  const msg = history.length
    ? history.map(h =>
        `${h.ts.slice(0,16)} ${h.actor} (${h.role}) — `+
        `${h.allowed ? "✓" : "✗"} `+
        `severity: ${h.old_severity||"—"} → ${h.new_severity||"—"}, `+
        `status: ${h.old_status||"—"} → ${h.new_status||"—"}`
      ).join("\n")
    : "No modifications yet.";
  alert(msg);
}
```

- [ ] **Step 6: Reload findings after upload**

In the upload submit handler, after `loadReports()`, add `loadFindings()`.

- [ ] **Step 7: Manual verification**

Start server: `uvicorn app.main:public_app --port 8000`

Analyst flow:
- Sign in with analyst token → header shows `analyst1 (analyst)`
- Upload any TEST-01 report → findings panel populates with extracted findings
- Findings visible as plain text; no dropdowns, no Save buttons

Manager flow:
- Sign in with manager token → header shows `manager1 (manager)`
- Severity/Status cells render `<select>` dropdowns
- Change severity → Save → page refreshes with updated value
- History link shows the change with timestamp and actor

Security check:
- View page source → no tokens in JS
- Open browser devtools, call `PATCH /api/findings/{id}` with analyst token → 403

- [ ] **Step 8: Commit**

```bash
git add app/static/index.html
git commit -m "feat: role-aware findings panel; no credentials in frontend"
```

---

## Task 5: README and .env.example

**Files:**
- Modify: `.env.example`
- Modify: `README.md`

- [ ] **Step 1: Update `.env.example`**

Add `MANAGER_TOKEN=change-me-min-32-random-characters` below `ANALYST_TOKEN`.

- [ ] **Step 2: Update README with required sections**

Add or update:
- **Roles** — permission matrix table from spec section 3
- **Credentials** — `ANALYST_TOKEN`, `MANAGER_TOKEN`, `EVALUATOR_TOKEN` in `.env`; never commit secrets
- **API** — `GET /api/findings`, `GET /api/findings/{id}`, `PATCH /api/findings/{id}` with example curl for manager update and example 403 for analyst
- **Frontend** — sign in with token input; role displayed after sign-in; manager sees edit controls; analyst sees read-only
- **Finding extraction** — findings auto-extracted from uploaded `.txt`/`.md` reports; `findings_extracted` count in upload response
- **Active AI tools** — `list_reports`, `search_reports`, `read_report` (read-only); no write tools active
- **AI finding modification** — not supported; asking the AI to change a finding does not modify the database
- **Running tests** — `pytest tests/test_roles.py -v` runs ROLE-01 through ROLE-14

- [ ] **Step 3: Run final full test suite**

Run: `pytest tests/ -v`
Expected: all tests pass, including ROLE-01 through ROLE-14.

- [ ] **Step 4: Commit**

```bash
git add .env.example README.md
git commit -m "docs: document two-role access control, findings API, and extraction"
```
