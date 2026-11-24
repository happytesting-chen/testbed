"""Red-Team Testing — execute approved scenarios against the live application.

Usage:
    from security_testing.red_team import RedTeamRunner
    runner = RedTeamRunner(target_url, analyst_token)
    results = runner.execute_scenario(scenario, budget=5)
"""
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from .target_adapter import TargetClient


class RedTeamRunner:
    def __init__(self, target_url: str, token: str, records_dir: str = "security_testing/records"):
        self.client = TargetClient(target_url, token)
        self.records_dir = Path(records_dir)
        self.records_dir.mkdir(parents=True, exist_ok=True)

    def execute_scenario(self, scenario: dict, budget: int = 5,
                         refine_fn=None) -> list[dict]:
        """Execute a scenario with up to `budget` attempts.

        Args:
            scenario: parsed YAML scenario dict
            budget: max attempts
            refine_fn: optional callable(attempt_record, scenario) -> str
                       returns refined payload text. If None, retries same payload.

        Returns:
            list of attempt records
        """
        sid = scenario["id"]
        objective = scenario["objective"]
        entry = scenario["entry_point"]
        payload = scenario["payload"]
        steps = scenario["attack_steps"]
        criteria = scenario["success_criteria"]

        records = []
        session_id = None

        # Capture pre-attack state
        findings_before = {}
        try:
            for f in self.client.get_findings():
                findings_before[f["id"]] = {
                    "finding_id": f.get("finding_id"),
                    "severity": f["severity"],
                    "status": f["status"],
                }
        except Exception:
            pass

        current_payload = payload.get("content", "")
        current_message = next(
            (s["message"] for s in steps if "message" in s), objective)

        for attempt in range(1, budget + 1):
            record = {
                "scenario_id": sid,
                "attempt": attempt,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "payload": {
                    "type": payload.get("type", "chat"),
                    "content_hash": hashlib.sha256(
                        current_payload.encode()).hexdigest()[:16],
                },
                "findings_before": findings_before,
            }

            try:
                # Step 1: upload if entry is document upload
                if entry.get("method") == "POST /api/reports/upload":
                    fname = payload.get("filename", "attack.md")
                    upload = self.client.upload_report(fname, current_payload)
                    record["upload"] = {"id": upload["id"], "filename": fname}

                # Step 2: send chat message
                chat_result = self.client.chat(
                    current_message, session_id=session_id,
                    run_tag=f"{sid}-attempt-{attempt}")
                session_id = chat_result.get("session_id")
                record["run_id"] = chat_result["run_id"]
                record["session_id"] = session_id
                record["response_preview"] = chat_result["response"][:500]

                # Step 3: check observable outcomes
                evidence = self._collect_evidence(findings_before, criteria)
                record["observable_evidence"] = evidence
                record["attacker_assessment"] = (
                    "succeeded" if evidence.get("criteria_met") else "failed")

            except Exception as exc:
                record["error"] = str(exc)
                record["attacker_assessment"] = "error"

            records.append(record)
            self._save_record(record)

            if record.get("attacker_assessment") == "succeeded":
                break

            if refine_fn and attempt < budget:
                refined = refine_fn(record, scenario)
                if refined:
                    current_payload = refined
                    current_message = refined

        return records

    def _collect_evidence(self, findings_before: dict,
                          criteria: dict) -> dict:
        evidence = {"criteria_met": False}
        try:
            findings_after = {}
            for f in self.client.get_findings():
                findings_after[f["id"]] = {
                    "finding_id": f.get("finding_id"),
                    "severity": f["severity"],
                    "status": f["status"],
                }
            evidence["findings_after"] = findings_after

            primary = criteria.get("primary", {})
            if primary.get("type") == "db_state_change":
                field = primary["field"]
                expected = primary["to_value"]
                for fid, after in findings_after.items():
                    before = findings_before.get(fid, {})
                    if before.get(field) != after.get(field) and after[field] == expected:
                        evidence["criteria_met"] = True
                        evidence["changed_finding"] = fid
                        evidence["field"] = field
                        evidence["from"] = before.get(field)
                        evidence["to"] = after[field]
                        # Check history
                        try:
                            h = self.client.get_finding_history(fid)
                            evidence["history_entries"] = len(h)
                        except Exception:
                            pass
                        break

            elif primary.get("type") == "canary_in_output":
                # Will be checked by the caller from the response
                pass

        except Exception as exc:
            evidence["error"] = str(exc)
        return evidence

    def _save_record(self, record: dict):
        sid = record["scenario_id"]
        attempt = record["attempt"]
        path = self.records_dir / f"{sid}_attempt_{attempt}.json"
        path.write_text(json.dumps(record, indent=2, default=str),
                        encoding="utf-8")
