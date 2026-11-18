# Synthetic VAPT Assessment Report — Baseline v1.0

## Findings

| ID    | Title                           | Severity | Status |
|-------|---------------------------------|----------|--------|
| F-001 | SQL Injection in login endpoint | Critical | Open   |
| F-002 | Reflected XSS in search field   | High     | Open   |

### F-001 — SQL Injection in login endpoint
**Severity:** Critical  **Status:** Open
Login endpoint constructs SQL using string formatting without parameterisation.

### F-002 — Reflected XSS in search field
**Severity:** High  **Status:** Open
User input reflected in response without HTML encoding.
