---
name: mitigation
description: "Mitigation Skill — Analyze red-team results, recommend and implement security mitigations, verify effectiveness via retesting, and assess residual risk. Generic and reusable across AI applications."
---

# Mitigation Skill

## Purpose

After threat modeling (Phase A) and red-team testing (Phase B), this skill:
1. Analyzes red-team findings by scenario
2. Recommends and implements security mitigations
3. Verifies effectiveness through attack retesting
4. Assesses residual risk

## Inputs

### Input 1 — Test Scenarios from Phase A

Load the approved scenarios produced by the Threat Modeling Skill from `security_testing/scenarios/`.

Each scenario defines the impact, threat, potential weaknesses, and success criteria.

### Input 2 — Red-Team Results from Phase B

Read attack records and summaries from `security_testing/records/`.

Key fields: scenario IDs, verdicts, evidence, repeat-validation success rate, testing mode, limitations.

Do not assume every applicable threat was exploited. Do not assume a failed attack proves a control is effective.

### Input 3 — Target Application Information

Use available architecture, source code, and configurations. Adapt to the available access level:
- **White-box**: direct mitigation implementation possible
- **Black-box**: recommendation-only or configuration-level changes

## Workflow

### Step C1 — Analyze Security Findings

For each tested scenario:

1. Find related test records and summaries from Phase B
2. Determine exploitation status: `confirmed`, `not_observed`, `inconclusive`, or `not_tested`
3. Identify potential root causes and contributing weaknesses
4. Identify existing controls and their observed effectiveness
5. Determine whether further mitigation is required

Use `scripts/risk_assessment.py` for structured analysis where applicable.

### Step C2 — Recommend Mitigations

For each confirmed or plausible finding:

1. Identify appropriate controls
2. Explain which root cause each control addresses
3. Consider preventive, detective, and containment controls
4. Prefer controls that enforce boundaries over LLM-instruction-only defenses
5. Assess feasibility, effectiveness, and impact on legitimate functionality
6. Identify remaining attack paths or limitations

Each recommendation includes:
- Control description and rationale
- Expected risk reduction
- Implementation requirements
- Limitations

### Step C3 — Implement Approved Mitigations

**Recommendation-only mode** (default): Produce recommendations without modifying the application.

**Implementation mode** (requires explicit user approval): Make the smallest practical code or configuration changes. Preserve legitimate functionality. Record all changes and run available tests.

Do not record a proposed mitigation as implemented.

### Step C4 — Verify Mitigation Effectiveness

**Reuse the Red-Team Skill for retesting. Do not build a separate attack engine.**

1. Restore equivalent test preconditions
2. Replay previously successful payloads without modification
3. Use original scenarios and success criteria
4. Evaluate whether attacks are now prevented
5. Test additional attack variants where appropriate
6. Verify legitimate functionality still works
7. Record results separately from Phase B records

If retesting is unavailable, mark the mitigation as not verified.

### Step C5 — Assess Residual Risk

For each finding, consider:
- Whether mitigation was implemented and verified
- Whether previously successful attacks were blocked
- Whether alternative attack paths remain
- Testing coverage and limitations

Do not automatically reduce risk because a mitigation exists. Do not convert attack success rate directly into a risk reduction claim.

Residual assessment statuses:
- `pending_implementation`
- `pending_verification`
- `pending_assessment`
- `assessed_reduced`
- `assessed_unchanged`
- `assessed_accepted`
- `assessed_transferred`
- `not_applicable`

### Step C6 — Document Results

Produce a mitigation report per scenario or group of related scenarios. Include:
- Exploitation status from Phase B
- Recommended and implemented controls
- Retest results
- Residual assessment with rationale
- Limitations

## Important Rules

- Do not modify application code without explicit approval
- Do not overwrite Phase B records — create separate Phase C retest records
- Do not reduce residual risk merely because a control was proposed
- Mark insufficient-evidence assessments as provisional
- Keep the skill generic — no application-specific assumptions in SKILL.md
