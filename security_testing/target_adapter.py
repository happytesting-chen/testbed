"""HTTP client for the Document Assistant testbed.

Used by the Red-Team Skill to interact with the target via its public API.
Also used by the Evaluation Skill to read traces via the evaluator API.
"""
import httpx


class TargetClient:
    """Public API client — same access as an external vendor tool."""

    def __init__(self, base_url: str, token: str, timeout: float = 120):
        self.base_url = base_url.rstrip("/")
        self.headers = {"Authorization": f"Bearer {token}"}
        self.timeout = timeout

    def chat(self, message: str, session_id: str | None = None,
             run_tag: str | None = None) -> dict:
        headers = {**self.headers, "Content-Type": "application/json"}
        if run_tag:
            headers["X-Testbed-Run-Tag"] = run_tag
        body = {"message": message}
        if session_id:
            body["session_id"] = session_id
        r = httpx.post(f"{self.base_url}/api/agent/chat",
                       headers=headers, json=body, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def upload_report(self, filename: str, content: str) -> dict:
        r = httpx.post(f"{self.base_url}/api/reports/upload",
                       headers=self.headers,
                       files={"file": (filename, content.encode(), "text/plain")},
                       timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def get_reports(self) -> list[dict]:
        r = httpx.get(f"{self.base_url}/api/reports",
                      headers=self.headers, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def get_findings(self) -> list[dict]:
        r = httpx.get(f"{self.base_url}/api/findings",
                      headers=self.headers, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def get_finding(self, finding_id: str) -> dict:
        r = httpx.get(f"{self.base_url}/api/findings/{finding_id}",
                      headers=self.headers, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def get_finding_history(self, finding_id: str) -> list[dict]:
        r = httpx.get(f"{self.base_url}/api/findings/{finding_id}/history",
                      headers=self.headers, timeout=self.timeout)
        r.raise_for_status()
        return r.json()


class EvaluatorClient:
    """Evaluator API client — privileged access for verification."""

    def __init__(self, base_url: str, token: str, timeout: float = 30):
        self.base_url = base_url.rstrip("/")
        self.headers = {"X-Evaluator-Token": token}
        self.timeout = timeout

    def get_trace(self, run_id: str) -> dict:
        r = httpx.get(f"{self.base_url}/api/traces/{run_id}",
                      headers=self.headers, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def get_weakness_flags(self) -> list[str]:
        r = httpx.get(f"{self.base_url}/api/weakness-flags",
                      headers=self.headers, timeout=self.timeout)
        r.raise_for_status()
        return r.json().get("flags_on", [])

    def set_weakness_flags(self, flags_on: list[str]) -> dict:
        r = httpx.put(f"{self.base_url}/api/weakness-flags",
                      headers={**self.headers, "Content-Type": "application/json"},
                      json={"flags_on": flags_on}, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def reset(self) -> dict:
        r = httpx.post(f"{self.base_url}/api/reset",
                       headers=self.headers, timeout=self.timeout)
        r.raise_for_status()
        return r.json()

    def get_ground_truth(self) -> dict:
        r = httpx.get(f"{self.base_url}/api/ground-truth",
                      headers=self.headers, timeout=self.timeout)
        r.raise_for_status()
        return r.json()
