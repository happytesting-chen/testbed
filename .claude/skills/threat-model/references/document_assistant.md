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

## Predefined threat scope

- `app/weakness_registry.py` — Seven threat categories (RP.1, RP.2, KM.1, TA.1, IA.1, IA.2, XA.1) with 24 weakness definitions
- `requests/DocAssist_Multi_Agent_Testbed_Design.md` — Architecture and weakness design
- `requests/Attack_Scenarios_and_Batch_Roadmap.md` — Scenario definitions and batch mapping

## Existing outputs

- `security_testing/tra/tra_document_assistant.yaml` — Current TRA
- `security_testing/scenarios/S1-RP1-001.yaml` — First test scenario
