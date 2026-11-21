"""Coordinator Agent — orchestrates Document Reader and Findings Manager."""
import json
import uuid

from ..db import Database
from ..llm import LLMError
from ..prompts import ACTIVE_SYSTEM_PROMPT as BASE_SYSTEM_PROMPT
from .delegation import DelegationContext
from .reader import DocumentReaderAgent
from .findings_manager import FindingsManagerAgent

COORDINATOR_TOOLS = [
    {"type": "function", "function": {
        "name": "delegate_to_reader",
        "description": "Delegate a task to the Document Reader agent. Use for searching, reading and summarising uploaded assessment reports.",
        "parameters": {"type": "object", "properties": {
            "task": {"type": "string", "description": "What the Reader should do"},
            "context": {"type": "string", "description": "Supporting information for the task"}},
            "required": ["task"]}}},
    {"type": "function", "function": {
        "name": "delegate_to_findings_manager",
        "description": "Delegate a task to the Findings Manager agent. Use for retrieving, viewing or updating security findings.",
        "parameters": {"type": "object", "properties": {
            "task": {"type": "string", "description": "What the Findings Manager should do"},
            "context": {"type": "string", "description": "Supporting information for the task"}},
            "required": ["task"]}}},
]


def build_system_prompt(cfg: dict) -> str:
    return BASE_SYSTEM_PROMPT


class CoordinatorAgent:
    def __init__(self, db: Database, provider,
                 reader: DocumentReaderAgent,
                 findings_manager: FindingsManagerAgent,
                 max_steps: int = 6):
        self.db = db
        self.provider = provider
        self.reader = reader
        self.findings_manager = findings_manager
        self.max_steps = max_steps

    def _execute(self, cfg: dict, name: str, args: dict,
                 actor: str, actor_role: str,
                 session_id: str, run_id: str, log_fn) -> tuple[dict, list[str]]:
        if name == "delegate_to_reader":
            task = str(args.get("task", ""))
            context = str(args.get("context", ""))
            delegation = DelegationContext(
                msg_id=str(uuid.uuid4()),
                from_agent="coordinator", to_agent="reader",
                session_id=session_id, actor=actor, actor_role=actor_role,
                task=task, context=context,
            )
            log_fn("delegation", {"from_agent": "coordinator", "to_agent": "reader",
                                  "task": task, "context": context, "actor_role_sent": actor_role})
            result = self.reader.handle(delegation, cfg, run_id, log_fn)
            return {"reader_response": result}, []

        if name == "delegate_to_findings_manager":
            task = str(args.get("task", ""))
            context = str(args.get("context", ""))
            delegation = DelegationContext(
                msg_id=str(uuid.uuid4()),
                from_agent="coordinator", to_agent="findings_manager",
                session_id=session_id, actor=actor, actor_role=actor_role,
                task=task, context=context,
            )
            log_fn("delegation", {"from_agent": "coordinator", "to_agent": "findings_manager",
                                  "task": task, "context": context, "actor_role_sent": actor_role})
            result = self.findings_manager.handle(delegation, cfg, run_id, log_fn)
            return {"findings_manager_response": result}, []

        return {"error": f"Unknown tool: {name}"}, []

    def run(self, message: str, actor: str, actor_role: str = "",
            session_id: str | None = None, run_tag: str | None = None) -> dict:
        session_id = session_id or str(uuid.uuid4())
        history = self.db.get_history(session_id, actor)
        if history is None:
            raise PermissionError("Session belongs to another user")
        cfg = self.db.get_agent_config()
        run_id = str(uuid.uuid4())
        self.db.start_run(run_id, session_id, actor, self.provider.model, cfg, message, run_tag)
        seq = 0

        def log(stage, payload):
            nonlocal seq
            seq += 1
            if "agent" not in payload:
                payload = {**payload, "agent": "coordinator"}
            self.db.add_event(run_id, seq, stage, payload)

        log("user_input", {"message": message, "session_id": session_id,
                           "history_turns": len(history) // 2})
        messages = [{"role": "system", "content": build_system_prompt(cfg)}, *history,
                    {"role": "user", "content": message}]
        answer = None
        try:
            for step in range(1, self.max_steps + 1):
                log("llm_request", {"step": step,
                                    "body": self.provider.request_body(messages, COORDINATOR_TOOLS)})
                resp = self.provider.complete(messages, COORDINATOR_TOOLS)
                log("llm_response", {"step": step, "content": resp.content,
                                     "tool_calls": [{"id": t.id, "name": t.name, "arguments": t.arguments,
                                                     "parse_error": t.parse_error} for t in resp.tool_calls],
                                     "raw": resp.raw})
                if not resp.tool_calls:
                    answer = resp.content or ""
                    break
                messages.append({"role": "assistant", "content": resp.content,
                                 "tool_calls": [{"id": t.id, "type": "function",
                                                 "function": {"name": t.name, "arguments": t.raw_arguments}}
                                                for t in resp.tool_calls]})
                for t in resp.tool_calls:
                    log("tool_call", {"step": step, "id": t.id, "name": t.name, "arguments": t.arguments})
                    result, retrieved = self._execute(cfg, t.name, t.arguments, actor, actor_role,
                                                     session_id, run_id, log)
                    log("tool_result", {"step": step, "id": t.id, "name": t.name,
                                        "retrieved_report_ids": retrieved, "result": result})
                    messages.append({"role": "tool", "tool_call_id": t.id,
                                     "content": json.dumps(result, ensure_ascii=False)})
            else:
                answer = "I could not complete this request within the allowed number of steps."
                log("step_limit", {"max_steps": self.max_steps})
        except LLMError as exc:
            log("error", {"message": str(exc)})
            self.db.finish_run(run_id, error=str(exc))
            raise
        log("final_answer", {"answer": answer})
        self.db.finish_run(run_id, answer=answer)
        self.db.save_history(session_id, actor, history + [{"role": "user", "content": message},
                                                           {"role": "assistant", "content": answer}])
        return {"run_id": run_id, "session_id": session_id, "response": answer}
