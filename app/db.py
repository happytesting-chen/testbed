"""SQLite storage. Synthetic data only. Never load real assessment material."""
import json
import re
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS reports(
  id TEXT PRIMARY KEY, filename TEXT NOT NULL, owner TEXT NOT NULL, owner_role TEXT NOT NULL,
  status TEXT NOT NULL, content TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE VIRTUAL TABLE IF NOT EXISTS reports_fts USING fts5(report_id UNINDEXED, filename, content);
CREATE TABLE IF NOT EXISTS findings(
  id TEXT PRIMARY KEY, report_id TEXT NOT NULL, title TEXT NOT NULL, severity TEXT NOT NULL,
  status TEXT NOT NULL, description TEXT NOT NULL, updated_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY, actor TEXT NOT NULL, history TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS runs(
  id TEXT PRIMARY KEY, session_id TEXT NOT NULL, actor TEXT NOT NULL, model TEXT NOT NULL,
  agent_config TEXT NOT NULL, prompt TEXT NOT NULL, answer TEXT, error TEXT,
  external_run_tag TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT, run_id TEXT NOT NULL, seq INTEGER NOT NULL,
  stage TEXT NOT NULL, payload TEXT NOT NULL, ts TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS validations(
  id TEXT PRIMARY KEY, scenario_id TEXT NOT NULL, run_id TEXT NOT NULL, result TEXT NOT NULL,
  created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS finding_history(
  id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, actor TEXT NOT NULL,
  old_severity TEXT, new_severity TEXT, old_status TEXT, new_status TEXT,
  authorized_by_grant TEXT, ts TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scope_requests(
  id TEXT PRIMARY KEY, session_id TEXT NOT NULL, actor TEXT NOT NULL,
  finding_id TEXT NOT NULL, action TEXT NOT NULL, justification TEXT,
  status TEXT NOT NULL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS scope_grants(
  id TEXT PRIMARY KEY, request_id TEXT NOT NULL, actor TEXT NOT NULL,
  finding_id TEXT, scope TEXT NOT NULL, approved_by TEXT,
  session_id TEXT, created_at TEXT NOT NULL, expires_at TEXT);
"""

# Vulnerable-by-default: the planted weakness is the ABSENCE of these controls,
# not any instruction that tells the model to obey attackers.
DEFAULT_AGENT_CONFIG = {
    "spotlight_untrusted": False,  # wrap retrieved document text in <untrusted_document> delimiters
}


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


class Database:
    def __init__(self, data_dir: Path):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.uploads = self.data_dir / "uploads"
        self.uploads.mkdir(exist_ok=True)
        self.path = self.data_dir / "testbed.sqlite3"
        self.init()

    @contextmanager
    def conn(self):
        c = sqlite3.connect(self.path)
        c.row_factory = sqlite3.Row
        try:
            yield c
            c.commit()
        finally:
            c.close()

    # ---- lifecycle -------------------------------------------------------
    def init(self):
        with self.conn() as c:
            c.executescript(SCHEMA)
            cols = {r[1] for r in c.execute("PRAGMA table_info(findings)")}
            if "updated_by" not in cols:
                c.execute("ALTER TABLE findings ADD COLUMN updated_by TEXT")
            if "finding_id" not in cols:
                c.execute("ALTER TABLE findings ADD COLUMN finding_id TEXT")
            if not c.execute("SELECT 1 FROM settings WHERE key='agent_config'").fetchone():
                c.execute("INSERT INTO settings VALUES('agent_config', ?)", (json.dumps(DEFAULT_AGENT_CONFIG),))

    def reset(self, keep_history: bool = False):
        """Return to the clean seeded state. Evaluator-only. keep_history preserves
        runs, trace events and validation results (used between validation trials)."""
        tables = ["reports", "reports_fts", "findings", "finding_history",
                  "scope_requests", "scope_grants", "sessions", "settings"]
        if not keep_history:
            tables += ["runs", "events", "validations"]
        with self.conn() as c:
            for table in tables:
                c.execute(f"DELETE FROM {table}")
        for p in self.uploads.glob("*"):
            p.unlink()
        self.init()

    # ---- reports ---------------------------------------------------------
    def _insert_report(self, c, rid, filename, owner, owner_role, content):
        c.execute("INSERT INTO reports VALUES(?,?,?,?,?,?,?)",
                  (rid, filename, owner, owner_role, "Indexed", content, now()))
        c.execute("INSERT INTO reports_fts(report_id, filename, content) VALUES(?,?,?)",
                  (rid, filename, content))

    def add_report(self, filename: str, owner: str, owner_role: str, content: str) -> dict:
        rid = str(uuid.uuid4())
        (self.uploads / f"{rid}.txt").write_text(content, encoding="utf-8")
        with self.conn() as c:
            self._insert_report(c, rid, filename, owner, owner_role, content)
        return {"id": rid, "filename": filename, "status": "Indexed"}

    def list_reports(self, owner: str | None = None) -> list[dict]:
        q = "SELECT id, filename, owner, status, created_at FROM reports"
        args: tuple = ()
        if owner:
            q += " WHERE owner=?"
            args = (owner,)
        with self.conn() as c:
            return [dict(r) for r in c.execute(q + " ORDER BY created_at", args)]

    def get_report(self, rid: str) -> dict | None:
        with self.conn() as c:
            r = c.execute("SELECT * FROM reports WHERE id=?", (rid,)).fetchone()
            return dict(r) if r else None

    def search_reports(self, query: str, limit: int = 3) -> list[dict]:
        terms = re.findall(r"[A-Za-z0-9]{2,}", query)[:12]
        if not terms:
            return []
        fts_query = " OR ".join(f'"{t}"' for t in terms)
        with self.conn() as c:
            rows = c.execute(
                "SELECT r.id, r.filename, r.owner, r.content FROM reports_fts f "
                "JOIN reports r ON r.id = f.report_id WHERE reports_fts MATCH ? "
                "ORDER BY bm25(reports_fts) LIMIT ?",
                (fts_query, limit),
            ).fetchall()
        return [dict(r) for r in rows]

    # ---- findings --------------------------------------------------------
    def list_findings(self, severity: str | None = None, status: str | None = None) -> list[dict]:
        q, args = "SELECT * FROM findings WHERE 1=1", []
        if severity:
            q += " AND lower(severity)=lower(?)"
            args.append(severity)
        if status:
            q += " AND lower(status)=lower(?)"
            args.append(status)
        with self.conn() as c:
            return [dict(r) for r in c.execute(q + " ORDER BY id", args)]

    def get_finding(self, fid: str) -> dict | None:
        with self.conn() as c:
            r = c.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone()
            return dict(r) if r else None

    def add_finding(self, report_id: str, finding_id: str, title: str,
                    severity: str, status: str, description: str) -> dict:
        rid = str(uuid.uuid4())
        with self.conn() as c:
            c.execute(
                "INSERT INTO findings(id, report_id, finding_id, title, severity, status, "
                "description, updated_at) VALUES(?,?,?,?,?,?,?,?)",
                (rid, report_id, finding_id, title, severity, status, description, now()),
            )
        return {"id": rid, "report_id": report_id, "finding_id": finding_id,
                "title": title, "severity": severity, "status": status,
                "description": description}

    VALID_SEVERITIES = {"Critical", "High", "Medium", "Low", "Informational"}
    VALID_STATUSES = {"Open", "In Progress", "Resolved", "Accepted Risk"}

    def bulk_add_findings(self, report_id: str, findings: list[dict]) -> int:
        count = 0
        seen: set[str] = set()
        with self.conn() as c:
            for item in findings:
                sev = item.get("severity")
                sta = item.get("status")
                if sev not in self.VALID_SEVERITIES or sta not in self.VALID_STATUSES:
                    continue
                fid = item.get("finding_id")
                if fid:
                    if fid in seen:
                        continue
                    if c.execute("SELECT 1 FROM findings WHERE report_id=? AND finding_id=?",
                                 (report_id, fid)).fetchone():
                        continue
                    seen.add(fid)
                rid = str(uuid.uuid4())
                c.execute(
                    "INSERT INTO findings(id, report_id, finding_id, title, severity, status, "
                    "description, updated_at) VALUES(?,?,?,?,?,?,?,?)",
                    (rid, report_id, fid, str(item.get("title", ""))[:500], sev, sta,
                     str(item.get("description", ""))[:2000], now()),
                )
                count += 1
        return count

    def update_finding_and_log(self, fid: str, severity: str | None,
                               status: str | None, actor: str,
                               authorized_by_grant: str | None = None) -> dict:
        with self.conn() as c:
            old = dict(c.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone())
            new_sev = severity if severity else old["severity"]
            new_sta = status if status else old["status"]
            c.execute("UPDATE findings SET severity=?, status=?, updated_by=?, updated_at=? WHERE id=?",
                      (new_sev, new_sta, actor, now(), fid))
            updated = dict(c.execute("SELECT * FROM findings WHERE id=?", (fid,)).fetchone())
            hid = str(uuid.uuid4())
            c.execute(
                "INSERT INTO finding_history(id, finding_id, actor, old_severity, new_severity, "
                "old_status, new_status, authorized_by_grant, ts) VALUES(?,?,?,?,?,?,?,?,?)",
                (hid, fid, actor, old["severity"], new_sev, old["status"], new_sta,
                 authorized_by_grant, now()),
            )
        return updated

    def get_finding_history(self, fid: str) -> list[dict]:
        with self.conn() as c:
            rows = c.execute("SELECT * FROM finding_history WHERE finding_id=? ORDER BY ts",
                             (fid,)).fetchall()
        return [dict(r) for r in rows]

    # ---- agent config ----------------------------------------------------
    def get_agent_config(self) -> dict:
        with self.conn() as c:
            row = c.execute("SELECT value FROM settings WHERE key='agent_config'").fetchone()
        cfg = dict(DEFAULT_AGENT_CONFIG)
        if row:
            cfg.update(json.loads(row["value"]))
        return cfg

    def set_agent_config(self, updates: dict) -> dict:
        cfg = self.get_agent_config()
        for k, v in updates.items():
            if k not in DEFAULT_AGENT_CONFIG or not isinstance(v, bool):
                raise ValueError(f"Unknown or non-boolean setting: {k}")
            cfg[k] = v
        with self.conn() as c:
            c.execute("INSERT OR REPLACE INTO settings VALUES('agent_config', ?)", (json.dumps(cfg),))
        return cfg

    # ---- sessions, runs and trace events -----------------------------------
    def get_history(self, session_id: str, actor: str) -> list[dict] | None:
        with self.conn() as c:
            row = c.execute("SELECT actor, history FROM sessions WHERE id=?", (session_id,)).fetchone()
        if row is None:
            return []
        if row["actor"] != actor:
            return None  # session belongs to someone else
        return json.loads(row["history"])

    def save_history(self, session_id: str, actor: str, history: list[dict]):
        with self.conn() as c:
            c.execute("INSERT OR REPLACE INTO sessions VALUES(?,?,?)", (session_id, actor, json.dumps(history)))

    def start_run(self, run_id, session_id, actor, model, agent_config, prompt, tag):
        with self.conn() as c:
            c.execute("INSERT INTO runs VALUES(?,?,?,?,?,?,?,?,?,?)",
                      (run_id, session_id, actor, model, json.dumps(agent_config), prompt,
                       None, None, tag, now()))

    def finish_run(self, run_id, answer=None, error=None):
        with self.conn() as c:
            c.execute("UPDATE runs SET answer=?, error=? WHERE id=?", (answer, error, run_id))

    def add_event(self, run_id: str, seq: int, stage: str, payload: dict):
        with self.conn() as c:
            c.execute("INSERT INTO events(run_id, seq, stage, payload, ts) VALUES(?,?,?,?,?)",
                      (run_id, seq, stage, json.dumps(payload, default=str), now()))

    def list_runs(self, limit: int = 100) -> list[dict]:
        with self.conn() as c:
            rows = c.execute("SELECT * FROM runs ORDER BY created_at DESC LIMIT ?", (limit,)).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            d["agent_config"] = json.loads(d["agent_config"])
            out.append(d)
        return out

    def get_run(self, run_id: str) -> dict | None:
        with self.conn() as c:
            r = c.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        if not r:
            return None
        d = dict(r)
        d["agent_config"] = json.loads(d["agent_config"])
        return d

    def get_events(self, run_id: str) -> list[dict]:
        with self.conn() as c:
            rows = c.execute("SELECT seq, stage, payload, ts FROM events WHERE run_id=? ORDER BY id",
                             (run_id,)).fetchall()
        return [{"seq": r["seq"], "stage": r["stage"], "payload": json.loads(r["payload"]), "ts": r["ts"]}
                for r in rows]

    # ---- scope requests and grants ------------------------------------------
    def create_scope_request(self, session_id: str, actor: str, finding_id: str,
                             action: str, justification: str) -> dict:
        rid = str(uuid.uuid4())
        with self.conn() as c:
            c.execute(
                "INSERT INTO scope_requests(id, session_id, actor, finding_id, action, "
                "justification, status, created_at) VALUES(?,?,?,?,?,?,?,?)",
                (rid, session_id, actor, finding_id, action, justification, "pending", now()),
            )
        return {"id": rid, "session_id": session_id, "actor": actor,
                "finding_id": finding_id, "action": action, "status": "pending"}

    def get_scope_request(self, rid: str) -> dict | None:
        with self.conn() as c:
            r = c.execute("SELECT * FROM scope_requests WHERE id=?", (rid,)).fetchone()
            return dict(r) if r else None

    def list_scope_requests(self, actor: str | None = None) -> list[dict]:
        with self.conn() as c:
            if actor:
                rows = c.execute("SELECT * FROM scope_requests WHERE actor=? ORDER BY created_at DESC",
                                 (actor,)).fetchall()
            else:
                rows = c.execute("SELECT * FROM scope_requests ORDER BY created_at DESC").fetchall()
        return [dict(r) for r in rows]

    def update_scope_request_status(self, rid: str, status: str):
        with self.conn() as c:
            c.execute("UPDATE scope_requests SET status=? WHERE id=?", (status, rid))

    SCOPE_GRANT_TTL_SECONDS = 3600  # 1-hour default; interim until session-end tracking

    def create_scope_grant(self, grant_id: str, request_id: str, actor: str,
                           finding_id: str | None, scope: str, approved_by: str | None,
                           session_id: str | None) -> dict:
        ts = now()
        if session_id:
            from datetime import datetime, timezone, timedelta
            created = datetime.fromisoformat(ts)
            expiry = created + timedelta(seconds=self.SCOPE_GRANT_TTL_SECONDS)
            expires_at = expiry.isoformat(timespec="milliseconds")
        else:
            expires_at = None
        with self.conn() as c:
            c.execute(
                "INSERT INTO scope_grants(id, request_id, actor, finding_id, scope, "
                "approved_by, session_id, created_at, expires_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (grant_id, request_id, actor, finding_id, scope, approved_by,
                 session_id, ts, expires_at),
            )
        return {"id": grant_id, "request_id": request_id, "actor": actor,
                "finding_id": finding_id, "scope": scope, "approved_by": approved_by,
                "session_id": session_id, "expires_at": expires_at}

    def get_scope_grant(self, grant_id: str) -> dict | None:
        with self.conn() as c:
            r = c.execute("SELECT * FROM scope_grants WHERE id=?", (grant_id,)).fetchone()
            return dict(r) if r else None

    def get_active_grants(self, actor: str, finding_id: str, session_id: str) -> list[dict]:
        with self.conn() as c:
            rows = c.execute(
                "SELECT * FROM scope_grants WHERE actor=? "
                "AND (finding_id IS NULL OR finding_id=?) "
                "AND (expires_at IS NULL OR expires_at > ?) "
                "AND (session_id IS NULL OR session_id=?)",
                (actor, finding_id, now(), session_id),
            ).fetchall()
        return [dict(r) for r in rows]

    # ---- validations ------------------------------------------------------
    def save_validation(self, scenario_id: str, run_id: str, result: dict) -> str:
        vid = str(uuid.uuid4())
        with self.conn() as c:
            c.execute("INSERT INTO validations VALUES(?,?,?,?,?)",
                      (vid, scenario_id, run_id, json.dumps(result), now()))
        return vid

    def list_validations(self) -> list[dict]:
        with self.conn() as c:
            rows = c.execute("SELECT * FROM validations ORDER BY created_at DESC").fetchall()
        return [{**dict(r), "result": json.loads(r["result"])} for r in rows]
