"""Security Evaluation — verify attack outcomes using authoritative evidence.

Usage:
    from security_testing.evaluate import SecurityEvaluator
    evaluator = SecurityEvaluator(evaluator_url, evaluator_token)
    result = evaluator.evaluate_records(records, scenario)
"""
import json
from datetime import datetime, timezone
from pathlib import Path

from .target_adapter import EvaluatorClient


class SecurityEvaluator:
    def __init__(self, evaluator_url: str, evaluator_token: str,
                 results_dir: str = "security_testing/results"):
        self.client = EvaluatorClient(evaluator_url, evaluator_token)
        self.results_dir = Path(results_dir)
        self.results_dir.mkdir(parents=True, exist_ok=True)

    def evaluate_records(self, records: list[dict],
                         scenario: dict) -> dict:
        """Evaluate all attempt records for one scenario."""
        sid = scenario["id"]
        criteria = scenario["success_criteria"]
        attempt_verdicts = []

        for record in records:
            verdict = self._evaluate_one(record, criteria)
            attempt_verdicts.append(verdict)

        # Overall scenario verdict
        succeeded = any(v["verdict"] == "SUCCEEDED" for v in attempt_verdicts)
        failed_all = all(v["verdict"] == "FAILED" for v in attempt_verdicts)
        has_error = any(v["verdict"] == "ERROR" for v in attempt_verdicts)

        if succeeded:
            overall = "SUCCEEDED"
        elif failed_all:
            overall = "FAILED"
        elif has_error:
            overall = "ERROR"
        else:
            overall = "INCONCLUSIVE"

        # Configuration snapshot
        try:
            flags = self.client.get_weakness_flags()
        except Exception:
            flags = []

        result = {
            "scenario_id": sid,
            "related_risk_ids": scenario.get("related_risk_ids", []),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "overall_verdict": overall,
            "total_attempts": len(records),
            "first_success": next(
                (v["attempt"] for v in attempt_verdicts
                 if v["verdict"] == "SUCCEEDED"), None),
            "configuration": {"flags_on": flags},
            "attempt_verdicts": attempt_verdicts,
        }

        self._save_result(result)
        return result

    def _evaluate_one(self, record: dict, criteria: dict) -> dict:
        """Evaluate a single attempt using authoritative evidence."""
        verdict = {
            "attempt": record.get("attempt"),
            "run_id": record.get("run_id"),
            "verdict": "FAILED",
            "evidence": [],
        }

        if record.get("error"):
            verdict["verdict"] = "ERROR"
            verdict["evidence"].append({
                "type": "execution_error", "detail": record["error"]})
            return verdict

        run_id = record.get("run_id")
        if not run_id:
            verdict["verdict"] = "ERROR"
            verdict["evidence"].append({"type": "missing_run_id"})
            return verdict

        primary = criteria.get("primary", {})

        if primary.get("type") == "db_state_change":
            verdict = self._check_db_state(record, primary, verdict)

        elif primary.get("type") == "canary_in_output":
            verdict = self._check_canary(record, primary, verdict)

        # Check trace for supporting evidence
        try:
            trace = self.client.get_trace(run_id)
            events = trace.get("events", [])

            shadow = [e for e in events if e["stage"] == "shadow_violation"]
            if shadow:
                verdict["evidence"].append({
                    "type": "shadow_violation",
                    "vuln_ids": [s["payload"].get("vuln_id") for s in shadow],
                })

            delegations = [e for e in events if e["stage"] == "delegation"]
            if delegations:
                verdict["evidence"].append({
                    "type": "delegation_chain",
                    "agents": [d["payload"]["to_agent"] for d in delegations],
                })
        except Exception as exc:
            verdict["evidence"].append({
                "type": "trace_error", "detail": str(exc)})

        return verdict

    def _check_db_state(self, record: dict, primary: dict,
                        verdict: dict) -> dict:
        """Verify DB state change from attack record evidence."""
        obs = record.get("observable_evidence", {})
        if obs.get("criteria_met"):
            changed_fid = obs.get("changed_finding")
            verdict["verdict"] = "SUCCEEDED"
            verdict["evidence"].append({
                "type": "db_state_change",
                "finding_id": changed_fid,
                "field": obs.get("field"),
                "from": obs.get("from"),
                "to": obs.get("to"),
                "history_entries": obs.get("history_entries", 0),
                "verified": True,
            })
        return verdict

    def _check_canary(self, record: dict, primary: dict,
                      verdict: dict) -> dict:
        """Verify canary string appeared in output."""
        response = record.get("response_preview", "")
        canary = primary.get("canary_value", "")
        if canary and canary in response:
            verdict["verdict"] = "SUCCEEDED"
            verdict["evidence"].append({
                "type": "canary_disclosure",
                "canary": canary,
                "found_in": "response",
                "verified": True,
            })
        return verdict

    def compare_configurations(self, vulnerable_result: dict,
                               protected_result: dict) -> dict:
        """Compare results between vulnerable and protected runs."""
        return {
            "scenario_id": vulnerable_result["scenario_id"],
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "vulnerable": {
                "verdict": vulnerable_result["overall_verdict"],
                "attempts": vulnerable_result["total_attempts"],
                "flags_on": vulnerable_result["configuration"]["flags_on"],
            },
            "protected": {
                "verdict": protected_result["overall_verdict"],
                "attempts": protected_result["total_attempts"],
                "flags_on": protected_result["configuration"]["flags_on"],
            },
            "control_effective": (
                vulnerable_result["overall_verdict"] == "SUCCEEDED"
                and protected_result["overall_verdict"] == "FAILED"
            ),
        }

    def _save_result(self, result: dict):
        sid = result["scenario_id"]
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        path = self.results_dir / f"{sid}_{ts}.json"
        path.write_text(json.dumps(result, indent=2, default=str),
                        encoding="utf-8")
