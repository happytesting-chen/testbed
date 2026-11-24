"""Red-Team Testing — execute approved scenarios against the live application.

Scenarios are technique-independent. The Red-Team Skill (or caller) provides:
- attack_technique: description of the approach
- payload_content: the actual attack content (document text or chat message)
- chat_message: the trigger message to send via chat

Usage:
    from security_testing.red_team import RedTeamRunner
    runner = RedTeamRunner(target_url, analyst_token)
    records = runner.execute_scenario(scenario, technique="...", payload="...", message="...")
"""
import json
import hashlib
from datetime import datetime, timezone
from pathlib import Path

from .target_adapter import TargetClient


class RedTeamRunner:
    def __init__(self, target_url: str, token: str,
                 records_dir: str = "security_testing/records"):
        self.client = TargetClient(target_url, token)
        self.records_dir = Path(records_dir)
        self.records_dir.mkdir(parents=True, exist_ok=True)

    def execute_scenario(self, scenario: dict,
                         technique: str,
                         payload_content: str | None = None,
                         payload_filename: str = "attack.md",
                         chat_message: str | None = None,
                         budget: int = 5) -> list[dict]:
        """Execute a scenario with a specific technique and payload.

        Args:
            scenario: parsed YAML scenario (technique-independent)
            technique: description of the attack technique being used
            payload_content: document content to upload (for C2 entry)
            payload_filename: filename for upload
            chat_message: message to send via chat API
            budget: max attempts with this technique

        Returns:
            list of attempt records
        """
        sid = scenario["id"]
        entry = scenario.get("attacker", {}).get("entry_point", {})
        criteria = scenario.get("success_criteria", {})

        records = []
        session_id = None

        findings_before = self._snapshot_findings()

        for attempt in range(1, budget + 1):
            record = {
                "scenario_id": sid,
                "attempt": attempt,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "technique": technique,
                "payload": {
                    "type": "uploaded_document" if payload_content else "chat_only",
                    "filename": payload_filename if payload_content else None,
                    "content_hash": hashlib.sha256(
                        (payload_content or "").encode()).hexdigest()[:16],
                    "content": payload_content,
                },
                "chat_message": chat_message,
                "findings_before": findings_before,
            }

            try:
                if payload_content and entry.get("method") == "POST /api/reports/upload":
                    upload = self.client.upload_report(payload_filename, payload_content)
                    record["upload"] = {"id": upload["id"], "filename": payload_filename}

                if chat_message:
                    result = self.client.chat(
                        chat_message, session_id=session_id,
                        run_tag=f"{sid}-attempt-{attempt}")
                    session_id = result.get("session_id")
                    record["run_id"] = result["run_id"]
                    record["session_id"] = session_id
                    record["response_preview"] = result["response"][:500]

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

        return records

    def _snapshot_findings(self) -> dict:
        try:
            return {f["id"]: {"finding_id": f.get("finding_id"),
                              "severity": f["severity"], "status": f["status"]}
                    for f in self.client.get_findings()}
        except Exception:
            return {}

    def _collect_evidence(self, findings_before: dict, criteria: dict) -> dict:
        evidence = {"criteria_met": False}
        try:
            findings_after = {f["id"]: {"finding_id": f.get("finding_id"),
                                        "severity": f["severity"], "status": f["status"]}
                              for f in self.client.get_findings()}
            evidence["findings_after"] = findings_after

            primary = criteria.get("primary", {})
            if primary.get("type") == "db_state_change":
                for fid, after in findings_after.items():
                    before = findings_before.get(fid, {})
                    if before.get("severity") != after.get("severity"):
                        evidence["criteria_met"] = True
                        evidence["changed_finding"] = fid
                        evidence["field"] = "severity"
                        evidence["from"] = before.get("severity")
                        evidence["to"] = after["severity"]
                        try:
                            evidence["history_entries"] = len(
                                self.client.get_finding_history(fid))
                        except Exception:
                            pass
                        break

        except Exception as exc:
            evidence["error"] = str(exc)
        return evidence

    def _save_record(self, record: dict):
        sid = record["scenario_id"]
        attempt = record["attempt"]
        path = self.records_dir / f"{sid}_attempt_{attempt}.json"
        path.write_text(json.dumps(record, indent=2, default=str),
                        encoding="utf-8")
