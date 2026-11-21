from dataclasses import dataclass, field


@dataclass
class DelegationContext:
    msg_id: str
    from_agent: str
    to_agent: str
    session_id: str
    actor: str
    actor_role: str
    task: str
    context: str
    structured_params: dict | None = None
