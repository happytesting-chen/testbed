# Reference: Document Assistant Testbed

This file provides target-specific guidance for running the Threat Modeling Skill against the Multi-Agent Document Assistant.

## Target application files

- `app/agents/coordinator.py` — Coordinator agent, system prompt, delegation tools
- `app/agents/reader.py` — Document Reader agent, report processing, content wrapping
- `app/agents/findings_manager.py` — Findings Manager agent, authorization checks
- `app/agents/delegation.py` — DelegationContext dataclass
- `app/auth_service.py` — Scope request/grant/approval workflow
- `app/main.py` — API endpoints, authentication, role separation
- `app/db.py` — Database schema, finding history, scope grants
- `app/prompts.py` — System prompt versions

## Threat scope

Use the bundled default taxonomy (`references/agentic_ai_threat_taxonomy.yaml`).

For testbed-specific weakness flag mappings and implementation status, see:
- `app/weakness_registry.py` — 24 weakness definitions with implementation status and flag keys (testbed-specific, not part of the generic Skill)

For design context:
- `requests/DocAssist_Multi_Agent_Testbed_Design.md` — Architecture and weakness design
- `requests/Attack_Scenarios_and_Batch_Roadmap.md` — Scenario definitions and batch mapping

## Existing outputs

- `security_testing/tra/tra_document_assistant.yaml` — Current TRA
- `security_testing/scenarios/S1-RP1-001.yaml` — First test scenario
