"""Access policy enforcement for the Red-Team Skill.

Controls what information is available to the attack agent based on the
configured access_mode. The evaluation component is not restricted by
this policy — it always has full access to verify outcomes.

Modes:
  black_box — only application responses and attacker-observable state
  grey_box  — adds permitted runtime traces for analysis and refinement
  white_box — adds authorized source code and architecture details

All modes strip _evaluator scenario metadata and protect secrets.
"""

VALID_MODES = {"black_box", "grey_box", "white_box"}


class AccessPolicy:
    """Enforces information access restrictions for the attack agent."""

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
        """Strip evaluator-private sections regardless of mode."""
        return {k: v for k, v in scenario.items() if not k.startswith("_")}

    def filter_trace(self, trace: dict) -> dict:
        """Filter trace data according to access mode.

        Black-box: no trace access (returns empty).
        Grey-box: tool calls and delegations, no system prompts or raw LLM bodies.
        White-box: full trace minus secrets and evaluator ground truth.
        """
        if self.mode == "black_box":
            return {}

        events = trace.get("events", [])
        run = trace.get("run", {})

        if self.mode == "grey_box":
            filtered_events = []
            for e in events:
                stage = e.get("stage", "")
                if stage in ("tool_call", "tool_result", "delegation",
                             "final_answer", "user_input"):
                    entry = {"seq": e.get("seq"), "stage": stage, "ts": e.get("ts")}
                    payload = e.get("payload", {})
                    if stage == "tool_call":
                        entry["payload"] = {"name": payload.get("name"),
                                            "step": payload.get("step"),
                                            "agent": payload.get("agent")}
                    elif stage == "tool_result":
                        entry["payload"] = {"name": payload.get("name"),
                                            "step": payload.get("step"),
                                            "agent": payload.get("agent")}
                    elif stage == "delegation":
                        entry["payload"] = {"to_agent": payload.get("to_agent"),
                                            "task": payload.get("task")}
                    elif stage == "final_answer":
                        entry["payload"] = {"answer": payload.get("answer", "")[:500]}
                    elif stage == "user_input":
                        entry["payload"] = {"message": payload.get("message")}
                    filtered_events.append(entry)
            return {
                "run_id": run.get("id"),
                "model": run.get("model"),
                "events": filtered_events,
            }

        if self.mode == "white_box":
            filtered_events = []
            for e in events:
                stage = e.get("stage", "")
                if stage in ("shadow_violation", "scope_request", "scope_grant"):
                    continue
                entry = {"seq": e.get("seq"), "stage": stage,
                         "ts": e.get("ts"), "payload": e.get("payload", {})}
                filtered_events.append(entry)
            return {
                "run": {k: v for k, v in run.items()
                        if k not in ("agent_config",)},
                "events": filtered_events,
            }

        return {}

    def to_dict(self) -> dict:
        return {
            "mode": self.mode,
            "traces_available": self.can_access_traces,
            "source_available": self.can_access_source,
        }
