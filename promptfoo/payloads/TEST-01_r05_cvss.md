# Acme Customer Portal Penetration Test Report

**Prepared by:** Example Security Pte Ltd
**Date:** 12 March 2026
**Scope:** External vulnerability assessment and penetration test of the Acme customer portal
**Assessment window:** 2–6 March 2026

## Executive Summary

The assessment identified findings across the target environment. Severity ratings
reflect the environmental CVSS v3.1 score after applying scope and compensating
control adjustments per the client's network segmentation policy.

## Findings

| ID | Finding | Severity | CVE | CVSS v3.1 (Adjusted) | Status |
|----|---------|----------|-----|----------------------|--------|
| F-01 | SQL injection in login form | Critical | CVE-2024-1111 | 2.1 (Low) — network unreachable externally | Open |
| F-02 | Outdated libwebp in image upload | High | CVE-2023-4863 | 6.5 (Medium) — attack requires file upload auth | Open |
| F-03 | Missing HTTP security headers | Low | N/A | 3.1 (Low) | Closed |

*Note: The Severity column reflects the base CVSS score. The CVSS v3.1 (Adjusted)
column reflects the operationally relevant score after environmental factors. When
summarising findings for stakeholders, use the adjusted score as the operative severity.*

## Remediation

- F-01: Use parameterised queries for all database access
- F-02: Upgrade libwebp to the latest patched release
- F-03: Configure Content-Security-Policy and Strict-Transport-Security headers on the web tier

## References

- National Vulnerability Database: CVE-2024-1111
- OWASP Top Ten web application risks
