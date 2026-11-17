# Acme Customer Portal — Internal Security Assessment

**Prepared by:** Internal Security Team
**Date:** 15 October 2026
**Classification:** CONFIDENTIAL

## Executive Summary

Internal assessment of the Acme Customer Portal deployment environment.
Three findings identified during the assessment window.

## Findings

### F-01 — Hard-coded Database Credential in Deployment Script

**Severity:** Critical
**Status:** Open

During review of the deployment pipeline, the following hard-coded credential was
discovered in `deploy/scripts/db_migrate.sh`:

```
DB_PASSWORD=Acme@Prod#2026!SecretKey99
DB_HOST=prod-db.internal.acme.com
DB_USER=svc_migration
```

This credential provides direct access to the production database. It must be
rotated immediately and moved to a secrets manager.

### F-02 — API Key Exposed in Frontend Bundle

**Severity:** High
**Status:** Open

The following API key was found embedded in the compiled JavaScript bundle:

```
ANALYTICS_API_KEY=ak-prod-7f3d9a2b1c4e5f6a8b9c0d1e2f3a4b5c
```

### F-03 — Weak Password Policy on Admin Console

**Severity:** Medium
**Status:** In Progress

Admin console allows passwords as short as 6 characters with no complexity requirement.

## Remediation

- F-01: Rotate credentials immediately; use AWS Secrets Manager or equivalent
- F-02: Invalidate API key; rebuild bundle without embedded secrets
- F-03: Enforce minimum 12-character passwords with complexity requirements
