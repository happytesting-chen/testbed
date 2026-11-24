"""Generic Red-Team Runner — self-contained execution engine.

Enforces the approved scenario contract, manages discovery budget,
separates attacker-visible feedback from evaluator evidence, and
produces machine-readable records for Phase C integration.
"""
import json
import hashlib
import uuid
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
        self.attempt_budget = max(1, attempt_budget)
        self.repeat_count = max(1, repeat_count)
        self._discovery_count = 0
        self._run_id = uuid.uuid4().hex[:8]

    # ── Scenario validation ───────────────────────────────────────────────────

    def validate_scenario(self, scenario: dict):
        if scenario.get("status") != "approved":
            raise ScenarioValidationError(
                f"Scenario {scenario.get('id','?')} status is "
                f"'{scenario.get('status')}', not 'approved'")
        missing = REQUIRED_SCENARIO_FIELDS - set(scenario.keys())
        if missing:
            raise ScenarioValidationError(f"Missing required fields: {missing}")
        if any(k.startswith("_") for k in scenario):
            raise ScenarioValidationError(
                "Scenario contains evaluator-private sections. "
                "Use load_scenario_attacker_view().")

    def _can_upload(self, scenario: dict) -> bool:
        caps = scenario.get("attacker", {}).get("capabilities", [])
        return any("upload" in c.lower() for c in caps)

    def _can_chat(self, scenario: dict) -> bool:
        caps = scenario.get("attacker", {}).get("capabilities", [])
        return any("chat" in c.lower() for c in caps)

    def _validate_actions(self, scenario: dict,
                          has_upload: bool, has_chat: bool):
        if has_upload and not self._can_upload(scenario):
            raise ScenarioValidationError(
                f"Upload not permitted for {scenario['id']}")
        if has_chat and not self._can_chat(scenario):
            raise ScenarioValidationError(
                f"Chat not permitted for {scenario['id']}")
        if not has_upload and not has_chat:
            raise ScenarioValidationError("No attack action specified")

    # ── Step 1: Baseline ─────────────────────────────────────────────────────

    def run_baseline(self, scenario: dict) -> dict:
        self.validate_scenario(scenario)
        sid = scenario["id"]
        task = scenario.get("legitimate_task", "")
        state_before = self.target.snapshot_state()
        record = {
            "scenario_id": sid, "phase": "baseline",
            "execution_id": self._run_id,
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
        self._save(record, f"{sid}_{self._run_id}_baseline.json")
        return record

    # ── Steps 2-6: Discovery ─────────────────────────────────────────────────

    def execute_attempt(self, scenario: dict, technique_id: str,
                        payload_content: str | None = None,
                        payload_filename: str = "attack.md",
                        chat_message: str | None = None) -> dict:
        self.validate_scenario(scenario)
        self._discovery_count += 1
        attempt = self._discovery_count

        if attempt > self.attempt_budget:
            return {"scenario_id": scenario["id"], "phase": "discovery",
                    "attempt": attempt, "verdict": "ERROR",
                    "error": f"Attempt {attempt} exceeds budget of {self.attempt_budget}"}

        sid = scenario["id"]
        self._validate_actions(scenario, bool(payload_content), bool(chat_message))

        state_before = self.target.snapshot_state()
        record = {
            "scenario_id": sid, "phase": "discovery",
            "execution_id": self._run_id,
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

        full_response = None
        try:
            # Execute upload if payload provided and permitted
            if payload_content:
                record["upload"] = self.target.upload(payload_filename, payload_content)

            # Execute chat if message provided and permitted
            if chat_message:
                result = self.target.chat(chat_message, run_tag=f"{sid}-attempt-{attempt}")
                record["run_id"] = result.get("run_id")
                record["session_id"] = result.get("session_id")
                full_response = result.get("response", "")
                record["response_preview"] = full_response[:500]

            record["state_after"] = self.target.snapshot_state()

            if self.policy.can_access_traces and self.trace_provider and record.get("run_id"):
                try:
                    raw = self.trace_provider(record["run_id"])
                    record["trace"] = self.policy.filter_trace(raw)
                except Exception:
                    record["trace"] = {"unavailable": True}

            # Evaluate — build an isolated copy for the evaluator
            eval_input = {
                "state_before": record.get("state_before"),
                "state_after": record.get("state_after"),
                "response_preview": record.get("response_preview"),
                "run_id": record.get("run_id"),
                "_full_response": full_response,
            }
            verdict = self.evaluator(eval_input, scenario)
            v = verdict.get("verdict", "INCONCLUSIVE")
            record["verdict"] = v if v in VALID_VERDICTS else "INCONCLUSIVE"
            # Only sanitized feedback reaches the attacker-visible record
            feedback = verdict.get("attacker_feedback", v)
            record["attacker_feedback"] = feedback if isinstance(feedback, str) else v
            # Evaluator evidence stored with _ prefix — stripped by _attacker_view and _save
            record["_evaluator_evidence"] = verdict.get("evidence", [])

        except Exception as exc:
            record["error"] = str(exc)
            record["verdict"] = "ERROR"

        # Save two versions: full (for reporting) and attacker-visible
        self._save(record, f"{sid}_{self._run_id}_attempt_{attempt}.json")
        return self._attacker_view(record)

    # ── Step 7: Repeat Validation ─────────────────────────────────────────────

    def run_validation(self, scenario: dict, frozen_attack: dict,
                       repeat_count: int | None = None,
                       reset_fn=None,
                       expected_state: dict | None = None) -> dict:
        """Repeat the exact frozen attack inputs.

        Args:
            frozen_attack: dict with technique_id, payload_content,
                          payload_filename, chat_message
            reset_fn: callable that restores the target to initial conditions
            expected_state: snapshot of the expected initial state; if None,
                           captured from the target before validation starts
        """
        self.validate_scenario(scenario)
        self._validate_actions(
            scenario,
            has_upload=bool(frozen_attack.get("payload_content")),
            has_chat=bool(frozen_attack.get("chat_message")),
        )
        sid = scenario["id"]
        count = repeat_count or self.repeat_count
        frozen_hash = _hash(frozen_attack.get("payload_content"))
        has_reset = reset_fn is not None

        # Capture expected initial state if not provided
        if expected_state is None:
            if reset_fn:
                try:
                    reset_fn()
                except Exception:
                    pass
            expected_state = self.target.snapshot_state()

        runs = []
        all_verified_independent = True

        for i in range(1, count + 1):
            reset_ok = False
            state_verified = False

            # Always start a fresh session if the target supports it
            if hasattr(self.target, "reset_session"):
                self.target.reset_session()

            if reset_fn:
                try:
                    reset_fn()
                    reset_ok = True
                except Exception as exc:
                    runs.append({"validation_run": i, "verdict": "ERROR",
                                 "error": f"Reset failed: {exc}",
                                 "reset_ok": False, "state_verified": False})
                    all_verified_independent = False
                    continue

                # Verify the state matches the expected baseline
                post_reset_state = self.target.snapshot_state()
                state_verified = (post_reset_state == expected_state)
                if not state_verified:
                    runs.append({"validation_run": i, "verdict": "ERROR",
                                 "error": "State not restored to expected baseline after reset",
                                 "reset_ok": True, "state_verified": False,
                                 "expected_state": expected_state,
                                 "actual_state": post_reset_state})
                    all_verified_independent = False
                    continue
            else:
                # No reset — not independent
                all_verified_independent = False

            state_before = self.target.snapshot_state()
            rec = {
                "scenario_id": sid, "phase": "validation",
                "execution_id": self._run_id,
                "access_mode": self.policy.mode, "validation_run": i,
                "timestamp": _now(),
                "technique_id": frozen_attack["technique_id"],
                "payload": {"content_hash": frozen_hash},
                "chat_message": frozen_attack.get("chat_message"),
                "state_before": state_before,
                "reset_ok": reset_ok, "state_verified": state_verified,
            }
            full_response = None
            try:
                pc = frozen_attack.get("payload_content")
                fn = frozen_attack.get("payload_filename", "attack.md")
                if pc:
                    self.target.upload(fn, pc)
                cm = frozen_attack.get("chat_message")
                if cm:
                    result = self.target.chat(cm, run_tag=f"{sid}-val-{i}")
                    rec["run_id"] = result.get("run_id")
                    full_response = result.get("response", "")
                    rec["response_preview"] = full_response[:500]
                rec["state_after"] = self.target.snapshot_state()
                eval_input = {
                    "state_before": rec.get("state_before"),
                    "state_after": rec.get("state_after"),
                    "response_preview": rec.get("response_preview"),
                    "run_id": rec.get("run_id"),
                    "_full_response": full_response,
                }
                verdict = self.evaluator(eval_input, scenario)
                rec["verdict"] = verdict.get("verdict", "INCONCLUSIVE")
            except Exception as exc:
                rec["error"] = str(exc)
                rec["verdict"] = "ERROR"

            self._save(rec, f"{sid}_{self._run_id}_validation_{i}.json")
            runs.append(self._attacker_view(rec))

        # Independent runs: reset succeeded AND state verified AND conclusive verdict
        independent_runs = [r for r in runs
                            if r.get("state_verified", False)
                            and r["verdict"] in ("SUCCEEDED", "FAILED")]
        # Observed runs (no independence requirement): any conclusive verdict
        observed_runs = [r for r in runs
                         if r.get("reset_ok", False) or not has_reset
                         if r["verdict"] in ("SUCCEEDED", "FAILED")]

        ind_s = sum(1 for r in independent_runs if r["verdict"] == "SUCCEEDED")
        obs_s = sum(1 for r in observed_runs if r["verdict"] == "SUCCEEDED")

        return {
            "repetitions": len(runs),
            "independent_runs": len(independent_runs),
            "observed_runs": len(observed_runs),
            "succeeded": obs_s,
            "failed": len(observed_runs) - obs_s,
            "inconclusive": sum(1 for r in runs if r["verdict"] == "INCONCLUSIVE"),
            "errors": sum(1 for r in runs if r["verdict"] == "ERROR"),
            "independently_validated": has_reset and all_verified_independent and len(independent_runs) > 0,
            "independent_asr": ind_s / len(independent_runs) if independent_runs else None,
            "observed_asr": obs_s / len(observed_runs) if observed_runs else None,
            "frozen_payload_hash": frozen_hash,
            "state_coverage_note": (
                "State verification depends on the target adapter's snapshot_state(). "
                "The runner also calls reset_session() (if available) for fresh sessions. "
                "Components not covered by snapshot_state (e.g., agent memory, internal caches) "
                "are not verified between runs."
            ),
            "runs": runs,
        }

    # ── Summary ───────────────────────────────────────────────────────────────

    def generate_summary(self, scenario: dict, baseline: dict,
                         discovery_records: list[dict],
                         validation: dict | None = None) -> dict:
        sid = scenario["id"]
        attempts = [r for r in discovery_records if r.get("phase") == "discovery"]
        first = next((r for r in attempts if r.get("verdict") == "SUCCEEDED"), None)
        any_ok = any(r.get("verdict") == "SUCCEEDED" for r in attempts)
        all_fail = all(r.get("verdict") == "FAILED" for r in attempts) if attempts else False

        exploitation_status = ("confirmed" if any_ok else
                               "not_observed" if all_fail else
                               "inconclusive" if attempts else "not_tested")

        summary = {
            "scenario_id": sid, "phase": "summary",
            "execution_id": self._run_id,
            "related_risk_ids": scenario.get("related_risk_ids", []),
            "objective": scenario.get("objective", ""),
            "access_mode": self.policy.mode,
            "exploitation_status": exploitation_status,
            "baseline": {
                "response_preview": baseline.get("response_preview", ""),
                "state_snapshot": baseline.get("state_before", {}),
            },
            "discovery": {
                "total_attempts": len(attempts),
                "budget": self.attempt_budget,
                "first_success_attempt": first["attempt"] if first else None,
                "successful_technique": first.get("technique_id") if first else None,
                "successful_payload_hash": first["payload"]["content_hash"] if first else None,
            },
            "validation": validation or {"not_performed": True},
            "limitations": [],
        }
        self._save(summary, f"{sid}_{self._run_id}_summary.json")
        return summary

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _default_evaluator(record: dict, scenario: dict) -> dict:
        return {"verdict": "INCONCLUSIVE",
                "evidence": [{"type": "no_evaluator"}],
                "attacker_feedback": "INCONCLUSIVE"}

    def _attacker_view(self, record: dict) -> dict:
        """Strip evaluator-private fields from the returned record."""
        return {k: v for k, v in record.items() if not k.startswith("_")}

    def _save(self, data: dict, filename: str):
        clean = {k: v for k, v in data.items() if not k.startswith("_")}
        (self.records_dir / filename).write_text(
            json.dumps(clean, indent=2, default=str), encoding="utf-8")


def _now():
    return datetime.now(timezone.utc).isoformat()

def _hash(content):
    return hashlib.sha256((content or "").encode()).hexdigest()[:16]
