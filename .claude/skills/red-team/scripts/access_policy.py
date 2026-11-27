"""Access policy enforcement for the Red-Team Skill.

Controls what information is available to the attack agent based on
access_mode. The evaluation function is not restricted — it always
has full access to verify outcomes.
"""

VALID_MODES = {"black_box", "grey_box", "white_box"}


class AccessPolicy:

    def __init__(self, mode: str = "black_box"):
        if mode not in VALID_MODES:
            raise ValueError(f"Invalid access_mode: {mode}. Must be one of {VALID_MODES}")
        self.mode = mode

    @property
    def can_access_traces(self) -> bool:
        return self.mode in ("grey_box", "white_box")

    @property
    def can_access_source(self) -> bool:
        return self.mode == "white_box"

    def filter_scenario(self, scenario: dict) -> dict:
        stripped = {k: v for k, v in scenario.items() if not k.startswith("_")}
        if self.mode == "black_box":
            stripped.pop("potential_weakness", None)
        return stripped

    def filter_trace(self, trace: dict) -> dict:
        if self.mode == "black_box":
            return {}

        events = trace.get("events", [])
        run = trace.get("run", {})

        if self.mode == "grey_box":
            filtered = []
            for e in events:
                stage = e.get("stage", "")
                if stage in ("tool_call", "tool_result", "delegation",
                             "final_answer", "user_input"):
                    entry = {"seq": e.get("seq"), "stage": stage, "ts": e.get("ts")}
                    p = e.get("payload", {})
                    if stage == "tool_call":
                        entry["payload"] = {"name": p.get("name"), "step": p.get("step"), "agent": p.get("agent")}
                    elif stage == "tool_result":
                        entry["payload"] = {"name": p.get("name"), "step": p.get("step"), "agent": p.get("agent")}
                    elif stage == "delegation":
                        entry["payload"] = {"to_agent": p.get("to_agent"), "task": p.get("task")}
                    elif stage == "final_answer":
                        entry["payload"] = {"answer": p.get("answer", "")[:500]}
                    elif stage == "user_input":
                        entry["payload"] = {"message": p.get("message")}
                    filtered.append(entry)
            return {"run_id": run.get("id"), "model": run.get("model"), "events": filtered}

        if self.mode == "white_box":
            filtered = [
                {"seq": e.get("seq"), "stage": e.get("stage"), "ts": e.get("ts"), "payload": e.get("payload", {})}
                for e in events
                if e.get("stage") not in ("shadow_violation", "scope_request", "scope_grant")
            ]
            return {"run": {k: v for k, v in run.items() if k != "agent_config"}, "events": filtered}

        return {}

    def to_dict(self) -> dict:
        return {"mode": self.mode, "traces_available": self.can_access_traces, "source_available": self.can_access_source}
