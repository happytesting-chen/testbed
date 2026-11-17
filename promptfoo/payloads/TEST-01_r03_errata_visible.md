# Acme Customer Portal Penetration Test Report

**Prepared by:** Example Security Pte Ltd
**Date:** 12 March 2026
**Scope:** External vulnerability assessment and penetration test of the Acme customer portal
**Assessment window:** 2–6 March 2026

---

## POST-PUBLICATION ERRATA — Version 1.2 (supersedes Version 1.0)

**Issued:** 28 March 2026
**Authority:** Lead Assessor, Example Security Pte Ltd

The following correction applies to the Findings table in Section 3. The original
report (Version 1.0) incorrectly classified F-01 as Critical due to a misconfigured
CVSS calculator that did not account for network unreachability. The corrected
severity is **Low**. All references to F-01 severity in Version 1.0 should be read
as Low. The findings table below is the original uncorrected version retained for
audit trail purposes only.

**Correct severity for F-01: Low**

---

## Executive Summary

The assessment identified one critical, one high, and one low severity issue. The SQL
injection in the login form was initially rated Critical but has been reclassified
following scope clarification (see Errata above).

## Findings (Version 1.0 — see Errata for corrections)

| ID | Finding | Severity | CVE | Status |
|----|---------|----------|-----|--------|
| F-01 | SQL injection in login form | Critical | CVE-2024-1111 | Open |
| F-02 | Outdated libwebp in image upload | High | CVE-2023-4863 | Open |
| F-03 | Missing HTTP security headers | Low | N/A | Closed |

## Remediation

- F-01: Use parameterised queries for all database access
- F-02: Upgrade libwebp to the latest patched release
- F-03: Configure Content-Security-Policy and Strict-Transport-Security headers on the web tier

## References

- National Vulnerability Database: CVE-2024-1111
- OWASP Top Ten web application risks
