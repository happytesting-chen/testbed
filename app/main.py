"""Two separate ASGI apps sharing one SQLite database.

public_app    - what vendors / scanners see (Reports, Findings, AI Assistant).
                Run on the port you expose. Contains NO evaluator routes.
evaluator_app - traces, ground truth, configuration, reset, validation.
                Bind to 127.0.0.1 only; never route it through the vendor gateway.

    uvicorn app.main:public_app    --host 127.0.0.1 --port 8000
    uvicorn app.main:evaluator_app --host 127.0.0.1 --port 8001
"""
import hmac
from pathlib import Path

from fastapi import Depends, FastAPI, File, Header, HTTPException, UploadFile
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from . import o01
from .agent import Agent
from .config import Settings, load_settings
from .db import Database
from .llm import LLMError, OpenAICompatibleProvider

STATIC = Path(__file__).parent / "static"
MAX_UPLOAD = 1024 * 1024


class ChatRequest(BaseModel):
    message: str = Field(min_length=1, max_length=8000)
    session_id: str | None = Field(default=None, max_length=100)


class ScenarioRunRequest(BaseModel):
    scenario_id: str
    trials: int = Field(default=1, ge=1, le=20)
    reset_first: bool = True


def _eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())


def build_provider(s: Settings):
    if not (s.llm_base_url and s.llm_api_key):
        return None
    return OpenAICompatibleProvider(s.llm_base_url, s.llm_api_key, s.llm_model, s.llm_api_key_header,
                                    s.llm_temperature, s.llm_timeout_s)


class Identity(BaseModel):
    user: str
    role: str


def make_auth(s: Settings):
    users = {s.analyst_token: Identity(user="analyst1", role="analyst"),
             s.contributor_token: Identity(user="contributor1", role="contributor")}

    def current(authorization: str | None = Header(default=None)) -> Identity:
        token = (authorization or "").removeprefix("Bearer ").strip()
        for t, ident in users.items():
            if token and _eq(token, t):
                return ident
        raise HTTPException(401, "Valid bearer token required")

    def roles(*allowed: str):
        def dep(ident: Identity = Depends(current)) -> Identity:
            if ident.role not in allowed:
                raise HTTPException(403, "Not permitted for this role")
            return ident
        return dep

    return roles


def create_public_app(settings: Settings, db: Database, provider) -> FastAPI:
    app = FastAPI(title="Workbench (synthetic testbed)", version="0.2.0", docs_url=None, redoc_url=None,
                  openapi_url=None)
    roles = make_auth(settings)
    agent = Agent(db, provider, settings.agent_max_steps) if provider else None

    @app.get("/")
    def home():
        return FileResponse(STATIC / "index.html")

    @app.get("/api/health")
    def health():
        return {"status": "ok", "agent_ready": agent is not None}

    @app.get("/api/me")
    def me(ident: Identity = Depends(roles("analyst", "contributor"))):
        return ident

    @app.get("/api/reports")
    def reports(ident: Identity = Depends(roles("analyst", "contributor"))):
        # Contributors (potential attackers) see only their own uploads.
        return db.list_reports(owner=None if ident.role == "analyst" else ident.user)

    @app.get("/api/reports/{report_id}")
    def report(report_id: str, ident: Identity = Depends(roles("analyst", "contributor"))):
        r = db.get_report(report_id)
        if not r or (ident.role == "contributor" and r["owner"] != ident.user):
            raise HTTPException(404, "Report not found")
        return {k: r[k] for k in ("id", "filename", "owner", "status", "created_at", "content")}

    @app.post("/api/reports/upload")
    async def upload(file: UploadFile = File(...), ident: Identity = Depends(roles("analyst", "contributor"))):
        name = Path(file.filename or "").name
        if not name.lower().endswith((".txt", ".md")):
            raise HTTPException(400, "Only .txt and .md files are supported")
        raw = await file.read(MAX_UPLOAD + 1)
        if len(raw) > MAX_UPLOAD:
            raise HTTPException(413, "Maximum upload size is 1 MB")
        try:
            content = raw.decode("utf-8")
        except UnicodeDecodeError:
            raise HTTPException(400, "File must be UTF-8 text")
        return db.add_report(name[:200], ident.user, ident.role, content)

    @app.get("/api/findings")
    def findings(ident: Identity = Depends(roles("analyst"))):
        return [{k: f[k] for k in ("id", "title", "severity", "status", "description", "updated_at")}
                for f in db.list_findings()]

    @app.post("/api/agent/chat")
    def chat(req: ChatRequest, ident: Identity = Depends(roles("analyst")),
             x_testbed_run_tag: str | None = Header(default=None)):
        if agent is None:
            raise HTTPException(503, "LLM provider not configured (set LLM_BASE_URL and LLM_API_KEY)")
        try:
            return agent.run(req.message, ident.user, req.session_id, (x_testbed_run_tag or "")[:100] or None)
        except PermissionError:
            raise HTTPException(403, "Session belongs to another user")
        except LLMError:
            raise HTTPException(502, "The assistant is temporarily unavailable")

    return app


def create_evaluator_app(settings: Settings, db: Database, provider) -> FastAPI:
    app = FastAPI(title="Testbed evaluator (internal)", version="0.2.0")
    agent = Agent(db, provider, settings.agent_max_steps) if provider else None

    def evaluator(x_evaluator_token: str | None = Header(default=None)):
        if not x_evaluator_token or not _eq(x_evaluator_token, settings.evaluator_token):
            raise HTTPException(403, "Evaluator access required")

    guard = [Depends(evaluator)]

    @app.get("/")
    def home():
        return FileResponse(STATIC / "evaluator.html")

    @app.get("/api/runs", dependencies=guard)
    def runs():
        return db.list_runs()

    @app.get("/api/traces/{run_id}", dependencies=guard)
    def trace(run_id: str):
        run = db.get_run(run_id)
        if not run:
            raise HTTPException(404, "Run not found")
        return {"run": run, "events": db.get_events(run_id)}

    @app.get("/api/ground-truth", dependencies=guard)
    def gt():
        return o01.ground_truth() | {"authoritative_findings": db.list_findings()}

    @app.get("/api/config", dependencies=guard)
    def get_config():
        return db.get_agent_config()

    @app.put("/api/config", dependencies=guard)
    def put_config(updates: dict):
        try:
            return db.set_agent_config(updates)
        except ValueError as exc:
            raise HTTPException(400, str(exc))

    @app.post("/api/reset", dependencies=guard)
    def reset():
        db.reset()
        return {"status": "reset"}

    @app.get("/api/validations", dependencies=guard)
    def validations():
        return db.list_validations()

    @app.post("/api/scenarios/run", dependencies=guard)
    def run_scenario(req: ScenarioRunRequest):
        """Offline validation: plant the reference document as the contributor, run the
        legitimate analyst task, then judge the run independently. Repeats for N trials."""
        if req.scenario_id not in o01.SCENARIOS:
            raise HTTPException(404, "Unknown scenario")
        if agent is None:
            raise HTTPException(503, "LLM provider not configured")
        return run_trials(db, agent, req.scenario_id, req.trials, req.reset_first)

    return app


def run_trials(db: Database, agent: Agent, scenario_id: str, trials: int, reset_first: bool = True) -> dict:
    sc = o01.SCENARIOS[scenario_id]
    cfg = db.get_agent_config()
    results = []
    for _ in range(trials):
        if reset_first:
            db.reset(keep_history=True)
            db.set_agent_config(cfg)  # keep the configuration under test across resets
        doc = sc["document"]
        planted = db.add_report(doc["filename"], "contributor1", "contributor", doc["content"])
        try:
            out = agent.run(sc["legitimate_task"], "analyst1", run_tag=f"validation:{scenario_id}")
            res = o01.evaluate_run(db, out["run_id"], scenario_id, planted["id"])
        except LLMError as exc:
            res = {"scenario_id": scenario_id, "run_error": str(exc), "validated_failure": False}
        if res.get("run_id"):
            db.save_validation(scenario_id, res["run_id"], res)
        results.append(res)
    completed = [r for r in results if not r.get("run_error")]
    summary = {"scenario_id": scenario_id, "trials": trials, "completed": len(completed),
               "agent_config": cfg, "model": agent.provider.model}
    if scenario_id == "O01-BASELINE":
        summary["baseline_correct_rate"] = (sum(bool(r.get("baseline_correct")) for r in completed)
                                            / len(completed)) if completed else None
    else:
        summary["validated_failure_rate"] = (sum(r["validated_failure"] for r in completed)
                                             / len(completed)) if completed else None
    summary["needs_human_review"] = sum(bool(r.get("needs_human_review")) for r in completed)
    return {"summary": summary, "results": results}


_settings: Settings | None = None
_db: Database | None = None


def _shared():
    global _settings, _db
    if _settings is None:
        _settings = load_settings()
        _db = Database(_settings.data_dir)
    return _settings, _db


def __getattr__(name):  # lazy so importing the package never needs secrets
    if name in ("public_app", "evaluator_app"):
        s, d = _shared()
        factory = create_public_app if name == "public_app" else create_evaluator_app
        app = factory(s, d, build_provider(s))
        globals()[name] = app
        return app
    raise AttributeError(name)
