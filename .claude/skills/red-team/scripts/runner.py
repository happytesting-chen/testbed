"""Generic Red-Team Runner — self-contained execution engine.

Enforces the approved scenario contract, manages discovery budget,
and produces machine-readable records for Phase C integration.
"""
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path

try:
    from .access_policy import AccessPolicy
except ImportError:
    from access_policy import AccessPolicy

VALID_VERDICTS = {"SUCCEEDED", "FAILED", "INCONCLUSIVE", "ERROR"}
REQUIRED_SCENARIO_FIELDS = {"id", "objective", "attacker", "success_criteria"}


class ScenarioValidationError(ValueError):
    pass


class RedTeamRunner:

    def __init__(self, target, evaluator=None,
                 access_mode: str = "black_box",
                 trace_provider=None,
                 records_dir: str = "security_testing/records",
                 attempt_budget: int = 10,
                 repeat_count: int = 10):
        self.target = target
        self.evaluator = evaluator or self._default_evaluator
        self.policy = AccessPolicy(access_mode)
        self.trace_provider = trace_provider
        self.records_dir = Path(records_dir)
        self.records_dir.mkdir(parents=True, exist_ok=True)
        self.attempt_budget = attempt_budget
        self.repeat_count = repeat_count

    # ── Scenario validation ───────────────────────────────────────────────────

    def validate_scenario(self, scenario: dict):
        """Enforce approved scenario contract before execution."""
        if scenario.get("status") != "approved":
            raise ScenarioValidationError(
                f"Scenario {scenario.get('id','?')} has status "
                f"'{scenario.get('status')}', not 'approved'")
        missing = REQUIRED_SCENARIO_FIELDS - set(scenario.keys())
        if missing:
            raise ScenarioValidationError(
                f"Scenario missing required fields: {missing}")
        if any(k.startswith("_") for k in scenario):
            raise ScenarioValidationError(
                "Scenario contains evaluator-private sections (_evaluator). "
                "Use load_scenario_attacker_view() to strip them.")

    def validate_action(self, scenario: dict, action: str):
        """Verify an action is within the attacker's permitted capabilities."""
        caps = scenario.get("attacker", {}).get("capabilities", [])
        entry = scenario.get("attacker", {}).get("entry_point", {})
        permitted_method = entry.get("method", "")
        if action == "upload" and "upload" not in permitted_method.lower():
            if not any("upload" in c.lower() for c in caps):
                raise ScenarioValidationError(
                    f"Upload not in permitted capabilities for {scenario['id']}")
        if action == "chat" and not any("chat" in c.lower() for c in caps):
            raise ScenarioValidationError(
                f"Chat not in permitted capabilities for {scenario['id']}")

    # ── Step 1: Baseline ─────────────────────────────────────────────────────

    def run_baseline(self, scenario: dict) -> dict:
        self.validate_scenario(scenario)
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
        self.validate_scenario(scenario)
        if attempt > self.attempt_budget:
            return {"scenario_id": scenario["id"], "phase": "discovery",
                    "attempt": attempt, "verdict": "ERROR",
                    "error": f"Attempt {attempt} exceeds budget of {self.attempt_budget}"}

        sid = scenario["id"]
        entry = scenario.get("attacker", {}).get("entry_point", {})

        if payload_content:
            self.validate_action(scenario, "upload")
        if chat_message:
            self.validate_action(scenario, "chat")

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
            v = verdict.get("verdict", "INCONCLUSIVE")
            record["verdict"] = v if v in VALID_VERDICTS else "INCONCLUSIVE"
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
                       repeat_count: int | None = None,
                       reset_fn=None) -> dict:
        self.validate_scenario(scenario)
        sid = scenario["id"]
        count = repeat_count or self.repeat_count
        frozen_hash = _hash(payload_content)
        runs = []

        for i in range(1, count + 1):
            reset_ok = True
            if reset_fn:
                try:
                    reset_fn()
                except Exception as exc:
                    runs.append({"validation_run": i, "verdict": "ERROR",
                                 "error": f"Reset failed: {exc}", "reset_ok": False})
                    continue

            state_before = self.target.snapshot_state()
            rec = {
                "scenario_id": sid, "phase": "validation",
                "access_mode": self.policy.mode, "validation_run": i,
                "timestamp": _now(), "technique_id": technique_id,
                "payload": {"content_hash": frozen_hash},
                "chat_message": chat_message, "state_before": state_before,
                "reset_ok": reset_ok,
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

            # Verify frozen payload was not modified
            assert _hash(payload_content) == frozen_hash, "Payload was modified during validation"
            runs.append(rec)
            self._save(rec, f"{sid}_validation_{i}.json")

        valid_runs = [r for r in runs if r.get("reset_ok", True) and r["verdict"] in ("SUCCEEDED", "FAILED")]
        s = sum(1 for r in valid_runs if r["verdict"] == "SUCCEEDED")
        f = sum(1 for r in valid_runs if r["verdict"] == "FAILED")
        excluded = len(runs) - len(valid_runs)

        return {
            "repetitions": len(runs), "valid_runs": len(valid_runs),
            "succeeded": s, "failed": f,
            "inconclusive": sum(1 for r in runs if r["verdict"] == "INCONCLUSIVE"),
            "errors": sum(1 for r in runs if r["verdict"] == "ERROR"),
            "excluded_from_asr": excluded,
            "observed_success_rate": s / len(valid_runs) if valid_runs else None,
            "frozen_payload_hash": frozen_hash,
            "runs": runs,
        }

    # ── Summary ───────────────────────────────────────────────────────────────

    def generate_summary(self, scenario: dict, baseline: dict,
                         discovery_records: list[dict],
                         validation: dict | None = None) -> dict:
        sid = scenario["id"]
        attempts_only = [r for r in discovery_records if r.get("phase") == "discovery"]
        first = next((r for r in attempts_only if r.get("verdict") == "SUCCEEDED"), None)

        any_succeeded = any(r.get("verdict") == "SUCCEEDED" for r in attempts_only)
        all_failed = all(r.get("verdict") == "FAILED" for r in attempts_only) if attempts_only else False

        if any_succeeded:
            exploitation_status = "confirmed"
        elif all_failed:
            exploitation_status = "not_observed"
        elif attempts_only:
            exploitation_status = "inconclusive"
        else:
            exploitation_status = "not_tested"

        summary = {
            "scenario_id": sid,
            "phase": "summary",
            "related_risk_ids": scenario.get("related_risk_ids", []),
            "objective": scenario.get("objective", ""),
            "access_mode": self.policy.mode,
            "access_policy": self.policy.to_dict(),
            "exploitation_status": exploitation_status,
            "baseline": {
                "response_preview": baseline.get("response_preview", ""),
                "state_snapshot": baseline.get("state_before", {}),
            },
            "discovery": {
                "total_attempts": len(attempts_only),
                "budget": self.attempt_budget,
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
        """Default: INCONCLUSIVE — cannot determine success without target-specific logic."""
        return {"verdict": "INCONCLUSIVE",
                "evidence": [{"type": "no_evaluator", "detail": "No target-specific evaluator configured"}]}

    def _save(self, data: dict, filename: str):
        (self.records_dir / filename).write_text(
            json.dumps(data, indent=2, default=str), encoding="utf-8")


def _now():
    return datetime.now(timezone.utc).isoformat()

def _hash(content):
    return hashlib.sha256((content or "").encode()).hexdigest()[:16]
