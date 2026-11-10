AI Agent Security Testbed — gpt_v0
An initial functional scaffold, not yet a validated vulnerable LLM agent. Uses entirely synthetic data.
Features delivered
- Workbench-style browser interface: Reports, Findings, AI Assistant, Execution Trace and Evaluation.
- Black-box preview switch hides evaluator tabs in the browser. Backend evaluator endpoints remain token-protected regardless of switch.
- FastAPI HTTP chat endpoint suitable for a future scanner adapter.
- TXT/Markdown document upload (1 MB maximum), SQLite persistence, and basic deterministic retrieval.
- Synthetic authoritative findings, observable execution logs, evaluator-only ground truth, and reset.
- Automated API tests.
Not yet implemented
- Real LLM model calls or autonomous tool selection (chat uses deterministic placeholder logic).
- Offline prompt-injection reference attacks, tool-response poisoning, vulnerable/hardened modes, attack-path graph and automated attack success scoring.
- Promptfoo, PyRIT, Check Point and F5 adapters.
- Production-grade authentication, CSRF protections, hardened upload scanning, rate limiting or multi-user isolation.
Run locally
Requires Python 3.10+.
python -m venv .venv
source .venv/bin/activate   # Windows PowerShell: .venv\\Scripts\\Activate.ps1
pip install -r requirements.txt
export EVALUATOR_TOKEN='replace-with-a-long-random-secret'  # PowerShell: $env:EVALUATOR_TOKEN='...'
uvicorn app.main:app --host 127.0.0.1 --port 8000
Open http://127.0.0.1:8000. Switch Black-box preview OFF to see evaluator tabs. Enter the configured evaluator token when prompted.

Run tests:
python -m pytest -q
API endpoints
- GET /api/health
- GET /api/reports
- POST /api/reports/upload — multipart form field file (TXT/MD)
- GET /api/findings
- POST /api/agent/chat — JSON {"message":"Summarise critical findings","session_id":"optional","report_id":"optional"}
- GET /api/evaluator/runs — evaluator token required
- GET /api/evaluator/traces/{run_id} — evaluator token required
- GET /api/evaluator/ground-truth — evaluator token required
- POST /api/evaluator/reset — evaluator token required
Evaluator requests require the X-Evaluator-Token header. For the prototype the default token is local-demo-evaluator-token; set EVALUATOR_TOKEN before use. This demo token is not secure for exposed deployment.
Security boundary
This is a local-only prototype. Keep the service on 127.0.0.1; do not expose it to the internet or vendors in this state. UI hiding alone is not security. The uploader and public APIs need real authentication, authorisation and isolation before external access. No real assessment documents or credentials.
Suggested next milestone
Introduce a configurable LLM provider, document-retrieval tool calls, and O01 reference attacks with independent success checks while retaining the same public API.
