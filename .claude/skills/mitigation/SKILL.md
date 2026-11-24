---
name: mitigation
description: "Mitigation Skill — Security Control Implementation and Residual Risk Assessment. Analyze red-team results, recommend and implement mitigations, verify effectiveness via retesting, assess residual risk, and update the existing TRA. Generic and reusable across AI applications."
---

# Mitigation Skill

## Purpose

After threat modeling (Phase A) and red-team testing (Phase B), this skill:
1. Analyzes risks and red-team findings
2. Recommends and implements security mitigations
3. Verifies effectiveness through attack retesting
4. Assesses residual risk
5. Updates the existing TRA with Phase B and Phase C results

## Inputs

### Input 1 — Existing TRA from Phase A

Load the TRA produced by the Threat Modeling Skill (`security_testing/tra/tra_<target>.yaml`).

Preserve the original preliminary assessment when updating.

### Input 2 — Red-Team Results from Phase B

Read attack records and summaries from `security_testing/records/`.

Key fields: scenario IDs, related risk IDs, verdicts, evidence, repeat-validation success rate, testing mode, limitations.

Do not assume every applicable threat was exploited. Do not assume a failed attack proves a risk doesn't exist.

### Input 3 — Target Application Information

Use available architecture, source code, and configurations. Adapt to the available access level:
- **White-box**: direct mitigation implementation possible
- **Black-box**: recommendation-only or configuration-level changes

### Input 4 — Risk Assessment Methodology

Use the same methodology applied in Phase A. If provisional, retain it and label assessments accordingly.

## Workflow

### Step C1 — Analyze Risks and Security Findings

For each Risk ID in the TRA:

1. Find related test scenarios and their results from Phase B
2. Determine exploitation status: `confirmed`, `not_observed`, `inconclusive`, or `not_tested`
3. Identify potential root causes and contributing weaknesses
4. Identify existing controls and their observed effectiveness
5. Determine whether further mitigation is required

Use `scripts/risk_assessment.py` for structured analysis:
```python
from scripts.risk_assessment import analyze_risk, RiskAnalysis
analysis = analyze_risk(risk_entry, test_results)
```

### Step C2 — Recommend Mitigations

For each risk requiring treatment:

1. Identify appropriate controls from `references/mitigation_guidance.yaml`
2. Explain which root cause each control addresses
3. Consider preventive, detective, and containment controls
4. Prefer controls that enforce boundaries over LLM-instruction-only defenses
5. Assess feasibility, effectiveness, and impact on legitimate functionality
6. Identify remaining attack paths or limitations

Produce a mitigation plan mapped to Risk IDs. Each recommendation includes:
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

For each Risk ID, using `scripts/risk_assessment.py`:

```python
from scripts.risk_assessment import assess_residual_risk
residual = assess_residual_risk(risk_entry, mitigations, retest_results)
```

Consider:
- Whether mitigation was implemented and verified
- Whether previously successful attacks were blocked
- Whether alternative attack paths remain
- Testing coverage and limitations

Do not automatically reduce risk because a mitigation exists. Do not convert attack success rate directly into risk likelihood.

Residual assessment statuses:
- `pending_implementation`
- `pending_verification`
- `pending_assessment`
- `assessed_reduced`
- `assessed_unchanged`
- `assessed_accepted`
- `assessed_transferred`
- `not_applicable`

### Step C6 — Update the Existing TRA

Add Phase B testing and Phase C mitigation fields to each Risk ID in the existing TRA. Do not create a separate risk register.

Preserve all original fields. Add:

```yaml
testing:
  scenario_ids: []
  status: completed | not_tested
  exploitation_status: confirmed | not_observed | inconclusive | not_tested
  evidence_refs: []

mitigation:
  recommended_controls: []
  implemented_controls: []
  implementation_status: proposed | implemented | partial
  retest_status: not_started | completed | not_available
  retest_evidence: []

residual_assessment:
  status: pending_assessment
  likelihood: null
  impact: null
  risk_rating: null
  risk_level: null
  rationale: null
  limitations: []

risk_disposition:
  status: open | mitigated | accepted | transferred
```

Save the updated TRA to the same file, preserving the original structure.

## Important Rules

- Assess residual risk per Risk ID, not per threat category or payload
- Do not modify application code without explicit approval
- Do not overwrite Phase B records — create separate Phase C retest records
- Do not reduce residual risk merely because a control was proposed
- Use the same risk matrix as the preliminary assessment
- Mark insufficient-evidence assessments as provisional
- Keep the skill generic — no application-specific assumptions in SKILL.md
