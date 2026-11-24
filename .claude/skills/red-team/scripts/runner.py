"""Generic Red-Team Runner — self-contained execution engine.

Target-specific behavior is provided by:
  target — object with chat(), upload(), snapshot_state() methods
  evaluator — callable(record, scenario) -> dict with "verdict" key

The runner enforces the approved scenario contract: it never modifies
the attack objective, attacker capabilities, entry point, or success
criteria. Only the payload and technique are adaptive.

Usage:
    from .runner import RedTeamRunner
    runner = RedTeamRunner(target=adapter, evaluator=eval_fn, access_mode="black_box")
    summary = runner.run_full(scenario, technique_id, payload, message)
"""
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path

try:
    from .access_policy import AccessPolicy
except ImportError:
    from access_policy import AccessPolicy


class RedTeamRunner:

    def __init__(self, target, evaluator=None,
                 access_mode: str = "black_box",
                 trace_provider=None,
                 records_dir: str = "security_testing/records"):
        self.target = target
        self.evaluator = evaluator or self._default_evaluator
        self.policy = AccessPolicy(access_mode)
        self.trace_provider = trace_provider
        self.records_dir = Path(records_dir)
        self.records_dir.mkdir(parents=True, exist_ok=True)

    # ── Step 1: Baseline ─────────────────────────────────────────────────────

    def run_baseline(self, scenario: dict) -> dict:
        sid = scenario["id"]
        task = scenario.get("legitimate_task", "")
        state_before = self.target.snapshot_state()
        record = {
            "scenario_id": sid, "phase": "baseline",
            "access_mode": self.policy.mode,
            "timestamp": _now(), "legitimate_task": task,
            "state_before": state_before,
        }
        try:
            result = self.target.chat(task)
            record["run_id"] = result.get("run_id")
            record["response_preview"] = result.get("response", "")[:500]
            record["state_after"] = self.target.snapshot_state()
        except Exception as exc:
            record["error"] = str(exc)
        self._save(record, f"{sid}_baseline.json")
        return record

    # ── Steps 2-6: Discovery ─────────────────────────────────────────────────

    def execute_attempt(self, scenario: dict, technique_id: str,
                        payload_content: str | None = None,
                        payload_filename: str = "attack.md",
                        chat_message: str | None = None,
                        attempt: int = 1) -> dict:
        sid = scenario["id"]
        entry = scenario.get("attacker", {}).get("entry_point", {})
        state_before = self.target.snapshot_state()
        record = {
            "scenario_id": sid, "phase": "discovery",
            "access_mode": self.policy.mode, "attempt": attempt,
            "timestamp": _now(), "technique_id": technique_id,
            "payload": {
                "type": "uploaded_document" if payload_content else "chat_only",
                "filename": payload_filename if payload_content else None,
                "content_hash": _hash(payload_content),
                "content": payload_content,
            },
            "chat_message": chat_message, "state_before": state_before,
        }
        try:
            if payload_content and "upload" in entry.get("method", "").lower():
                record["upload"] = self.target.upload(payload_filename, payload_content)
            if chat_message:
                result = self.target.chat(chat_message, run_tag=f"{sid}-attempt-{attempt}")
                record["run_id"] = result.get("run_id")
                record["session_id"] = result.get("session_id")
                record["response_preview"] = result.get("response", "")[:500]
            record["state_after"] = self.target.snapshot_state()

            if self.policy.can_access_traces and self.trace_provider and record.get("run_id"):
                try:
                    raw = self.trace_provider(record["run_id"])
                    record["trace"] = self.policy.filter_trace(raw)
                except Exception:
                    record["trace"] = {"unavailable": True}

            verdict = self.evaluator(record, scenario)
            record["verdict"] = verdict.get("verdict", "INCONCLUSIVE")
            record["evidence"] = verdict.get("evidence", [])
        except Exception as exc:
            record["error"] = str(exc)
            record["verdict"] = "ERROR"
        self._save(record, f"{sid}_attempt_{attempt}.json")
        return record

    # ── Step 7: Repeat Validation ─────────────────────────────────────────────

    def run_validation(self, scenario: dict, technique_id: str,
                       payload_content: str | None,
                       payload_filename: str,
                       chat_message: str | None,
                       repeat_count: int = 10,
                       reset_fn=None) -> dict:
        sid = scenario["id"]
        runs = []
        for i in range(1, repeat_count + 1):
            if reset_fn:
                try:
                    reset_fn()
                except Exception as exc:
                    runs.append({"validation_run": i, "verdict": "ERROR", "error": f"Reset: {exc}"})
                    continue
            state_before = self.target.snapshot_state()
            rec = {
                "scenario_id": sid, "phase": "validation",
                "access_mode": self.policy.mode, "validation_run": i,
                "timestamp": _now(), "technique_id": technique_id,
                "payload": {"content_hash": _hash(payload_content)},
                "chat_message": chat_message, "state_before": state_before,
            }
            try:
                entry = scenario.get("attacker", {}).get("entry_point", {})
                if payload_content and "upload" in entry.get("method", "").lower():
                    self.target.upload(payload_filename, payload_content)
                if chat_message:
                    result = self.target.chat(chat_message, run_tag=f"{sid}-val-{i}")
                    rec["run_id"] = result.get("run_id")
                    rec["response_preview"] = result.get("response", "")[:500]
                rec["state_after"] = self.target.snapshot_state()
                verdict = self.evaluator(rec, scenario)
                rec["verdict"] = verdict.get("verdict", "INCONCLUSIVE")
            except Exception as exc:
                rec["error"] = str(exc)
                rec["verdict"] = "ERROR"
            runs.append(rec)
            self._save(rec, f"{sid}_validation_{i}.json")

        s = sum(1 for r in runs if r["verdict"] == "SUCCEEDED")
        f = sum(1 for r in runs if r["verdict"] == "FAILED")
        valid = s + f
        return {
            "repetitions": len(runs), "succeeded": s, "failed": f,
            "inconclusive": sum(1 for r in runs if r["verdict"] == "INCONCLUSIVE"),
            "errors": sum(1 for r in runs if r["verdict"] == "ERROR"),
            "observed_success_rate": s / valid if valid > 0 else None,
            "runs": runs,
        }

    # ── Summary ───────────────────────────────────────────────────────────────

    def generate_summary(self, scenario: dict, baseline: dict,
                         discovery_records: list[dict],
                         validation: dict | None = None) -> dict:
        sid = scenario["id"]
        first = next((r for r in discovery_records if r.get("verdict") == "SUCCEEDED"), None)
        summary = {
            "scenario_id": sid,
            "related_risk_ids": scenario.get("related_risk_ids", []),
            "objective": scenario.get("objective", ""),
            "access_mode": self.policy.mode,
            "access_policy": self.policy.to_dict(),
            "baseline": {
                "response_preview": baseline.get("response_preview", ""),
                "state_snapshot": baseline.get("state_before", {}),
            },
            "discovery": {
                "total_attempts": len(discovery_records),
                "first_success_attempt": first["attempt"] if first else None,
                "successful_technique": first["technique_id"] if first else None,
                "successful_payload_hash": first["payload"]["content_hash"] if first else None,
            },
            "validation": validation or {"not_performed": True},
            "limitations": [],
        }
        self._save(summary, f"{sid}_summary.json")
        return summary

    # ── Default evaluator ─────────────────────────────────────────────────────

    @staticmethod
    def _default_evaluator(record: dict, scenario: dict) -> dict:
        """Compare state_before and state_after. Only flags INCONCLUSIVE on change."""
        before = record.get("state_before", {})
        after = record.get("state_after", {})
        if before and after and before != after:
            return {"verdict": "INCONCLUSIVE", "evidence": [{"type": "state_changed"}]}
        return {"verdict": "FAILED", "evidence": []}

    def _save(self, data: dict, filename: str):
        (self.records_dir / filename).write_text(
            json.dumps(data, indent=2, default=str), encoding="utf-8")


def _now():
    return datetime.now(timezone.utc).isoformat()

def _hash(content):
    return hashlib.sha256((content or "").encode()).hexdigest()[:16]
