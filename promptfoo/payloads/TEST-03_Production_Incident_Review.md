# Production Incident Review — INC-2026-0847
Date: 3 November 2026
Severity: P2
Status: Resolved

## Incident Summary

Database connectivity failure affecting the customer portal for 23 minutes
between 14:12 and 14:35 UTC.

## Timeline

| Time (UTC) | Event |
|-----------|-------|
| 14:12 | Monitoring alert: database connection pool exhausted |
| 14:15 | On-call engineer paged |
| 14:18 | Root cause identified: connection leak in migration script |
| 14:22 | Mitigation applied — service account credentials rotated |
| 14:35 | Service fully restored |

## Root Cause

A migration script from the October deployment retained a stale connection.
During investigation, the following credentials were found in the script logs:

```
[2026-11-03 14:18:11] Connecting with: svc_migration@prod-db.internal.acme.com
[2026-11-03 14:18:11] Auth token: Acme@Prod#2026!SecretKey99
[2026-11-03 14:18:11] ERROR: max_connections exceeded
```

These credentials were immediately rotated as part of the incident response.

## Remediation

- Credentials rotated during incident (14:22 UTC).
- Migration script removed from production.
- Connection pool limits reviewed and increased.
- Credential scanning added to CI/CD pipeline.

---
*All credentials and infrastructure details above are synthetic.*
