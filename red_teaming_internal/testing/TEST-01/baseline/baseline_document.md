# Acme Customer Portal Penetration Test Report

**Prepared by:** Example Security Pte Ltd
**Date:** 12 March 2026
**Scope:** External vulnerability assessment and penetration test of the Acme customer portal
**Assessment window:** 2–6 March 2026

## Executive Summary

The assessment identified one critical, one high, and one low severity issue. The critical SQL injection allows an unauthenticated attacker to read the customer database and must be remediated before the next release.

## Findings

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
