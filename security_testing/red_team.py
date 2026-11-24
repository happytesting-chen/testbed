"""Generic Red-Team Runner — execute approved scenarios against any AI target.

The runner is target-agnostic. Target-specific behavior is provided by:
- A target adapter (how to interact with the application)
- An evidence collector (how to observe outcomes)
- An evaluator function (how to check success criteria)

Usage:
    from security_testing.red_team import RedTeamRunner

    runner = RedTeamRunner(
        target=target_adapter,       # implements chat(), upload(), snapshot_state()
        evaluator=eval_fn,           # callable(record, criteria) -> verdict
        records_dir="security_testing/records",
    )
    summary = runner.run_scenario(scenario, technique_id, payload, message, budget=10)
"""
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from .access_policy import AccessPolicy


class RedTeamRunner:
    """Generic red-team execution engine."""

    def __init__(self, target, evaluator=None,
                 access_mode: str = "black_box",
                 trace_provider=None,
                 records_dir: str = "security_testing/records"):
        """
        Args:
            target: object with chat(), upload(), snapshot_state() methods
            evaluator: callable(record, criteria) -> dict with "verdict" key
                       (independent of access_mode — always has full access)
            access_mode: "black_box", "grey_box", or "white_box"
            trace_provider: callable(run_id) -> dict (raw trace); only used
                            when access_mode allows traces
            records_dir: directory for saving records
        """
        self.target = target
        self.evaluator = evaluator or self._default_evaluator
        self.policy = AccessPolicy(access_mode)
        self.trace_provider = trace_provider
        self.records_dir = Path(records_dir)
        self.records_dir.mkdir(parents=True, exist_ok=True)

    # ── Step 1: Baseline ─────────────────────────────────────────────────────

    def run_baseline(self, scenario: dict) -> dict:
        """Execute the legitimate task without malicious content."""
        sid = scenario["id"]
        task = scenario.get("legitimate_task", "")
        state_before = self.target.snapshot_state()

        record = {
            "scenario_id": sid,
            "phase": "baseline",
            "access_mode": self.policy.mode,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "legitimate_task": task,
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
                        attempt: int = 1,
                        state_before: dict | None = None) -> dict:
        """Execute a single attack attempt."""
        sid = scenario["id"]
        entry = scenario.get("attacker", {}).get("entry_point", {})
        criteria = scenario.get("success_criteria", {})

        if state_before is None:
            state_before = self.target.snapshot_state()

        record = {
            "scenario_id": sid,
            "phase": "discovery",
            "access_mode": self.policy.mode,
            "attempt": attempt,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "technique_id": technique_id,
            "payload": {
                "type": "uploaded_document" if payload_content else "chat_only",
                "filename": payload_filename if payload_content else None,
                "content_hash": hashlib.sha256(
                    (payload_content or "").encode()).hexdigest()[:16],
                "content": payload_content,
            },
            "chat_message": chat_message,
            "state_before": state_before,
        }

        try:
            if payload_content and "upload" in entry.get("method", "").lower():
                upload_result = self.target.upload(payload_filename, payload_content)
                record["upload"] = upload_result

            if chat_message:
                result = self.target.chat(
                    chat_message,
                    run_tag=f"{sid}-attempt-{attempt}")
                record["run_id"] = result.get("run_id")
                record["session_id"] = result.get("session_id")
                record["response_preview"] = result.get("response", "")[:500]

            record["state_after"] = self.target.snapshot_state()

            # Fetch trace if access mode permits and provider available
            if self.policy.can_access_traces and self.trace_provider and record.get("run_id"):
                try:
                    raw_trace = self.trace_provider(record["run_id"])
                    record["trace"] = self.policy.filter_trace(raw_trace)
                except Exception:
                    record["trace"] = {"unavailable": True}

            verdict = self.evaluator(record, criteria)
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
        """Repeat the exact successful payload to measure reproducibility."""
        sid = scenario["id"]
        criteria = scenario.get("success_criteria", {})
        results = []

        for i in range(1, repeat_count + 1):
            if reset_fn:
                try:
                    reset_fn()
                except Exception as exc:
                    results.append({"run": i, "verdict": "ERROR",
                                    "error": f"Reset failed: {exc}"})
                    continue

            state_before = self.target.snapshot_state()
            record = {
                "scenario_id": sid,
                "phase": "validation",
                "access_mode": self.policy.mode,
                "validation_run": i,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "technique_id": technique_id,
                "payload": {
                    "type": "uploaded_document" if payload_content else "chat_only",
                    "content_hash": hashlib.sha256(
                        (payload_content or "").encode()).hexdigest()[:16],
                },
                "chat_message": chat_message,
                "state_before": state_before,
            }

            try:
                if payload_content and scenario.get("attacker", {}).get(
                        "entry_point", {}).get("method", "").lower().find("upload") >= 0:
                    self.target.upload(payload_filename, payload_content)

                if chat_message:
                    result = self.target.chat(
                        chat_message,
                        run_tag=f"{sid}-validation-{i}")
                    record["run_id"] = result.get("run_id")
                    record["response_preview"] = result.get("response", "")[:500]

                record["state_after"] = self.target.snapshot_state()
                verdict = self.evaluator(record, criteria)
                record["verdict"] = verdict.get("verdict", "INCONCLUSIVE")

            except Exception as exc:
                record["error"] = str(exc)
                record["verdict"] = "ERROR"

            results.append(record)
            self._save(record, f"{sid}_validation_{i}.json")

        succeeded = sum(1 for r in results if r["verdict"] == "SUCCEEDED")
        failed = sum(1 for r in results if r["verdict"] == "FAILED")
        errors = sum(1 for r in results if r["verdict"] == "ERROR")
        inconclusive = sum(1 for r in results if r["verdict"] == "INCONCLUSIVE")
        valid = succeeded + failed

        return {
            "repetitions": len(results),
            "succeeded": succeeded,
            "failed": failed,
            "inconclusive": inconclusive,
            "errors": errors,
            "observed_success_rate": succeeded / valid if valid > 0 else None,
            "runs": results,
        }

    # ── Summary ───────────────────────────────────────────────────────────────

    def generate_summary(self, scenario: dict, baseline: dict,
                         discovery_records: list[dict],
                         validation: dict | None = None) -> dict:
        """Generate the final scenario summary."""
        sid = scenario["id"]
        first_success = next(
            (r for r in discovery_records if r.get("verdict") == "SUCCEEDED"), None)

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
                "first_success_attempt": first_success["attempt"] if first_success else None,
                "successful_technique": first_success["technique_id"] if first_success else None,
                "successful_payload_hash": (
                    first_success["payload"]["content_hash"] if first_success else None),
            },
            "validation": validation if validation else {"not_performed": True},
            "limitations": [],
        }

        self._save(summary, f"{sid}_summary.json")
        return summary

    # ── Default evaluator ─────────────────────────────────────────────────────

    @staticmethod
    def _default_evaluator(record: dict, criteria: dict) -> dict:
        """Simple evaluator: compare state_before and state_after."""
        before = record.get("state_before", {})
        after = record.get("state_after", {})
        if before and after and before != after:
            return {"verdict": "INCONCLUSIVE",
                    "evidence": [{"type": "state_changed",
                                  "detail": "Application state changed"}]}
        return {"verdict": "FAILED", "evidence": []}

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _save(self, data: dict, filename: str):
        path = self.records_dir / filename
        path.write_text(json.dumps(data, indent=2, default=str),
                        encoding="utf-8")
