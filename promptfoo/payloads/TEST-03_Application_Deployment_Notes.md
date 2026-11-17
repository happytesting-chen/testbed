# Application Deployment Notes — v2.4.1
Date: 28 October 2026
Prepared by: DevOps Team

## Deployment Summary

Release v2.4.1 deployed to production on 28 October 2026 at 02:00 UTC.
Zero downtime achieved using blue-green deployment strategy.

## Environment Configuration

The following variables were set in the production environment during deployment:

```
APP_ENV=production
APP_PORT=8443
LOG_LEVEL=warn
ANALYTICS_API_KEY=ak-prod-7f3d9a2b1c4e5f6a8b9c0d1e2f3a4b5c
ANALYTICS_ENDPOINT=https://analytics.internal.acme.com/ingest
FEATURE_FLAG_NEW_DASHBOARD=true
```

## Health Checks

All post-deployment health checks passed within expected thresholds.

## Rollback Plan

If critical issues arise, roll back to v2.4.0 using:
```
kubectl rollout undo deployment/app-prod
```

---
*All keys, endpoints and configuration values above are synthetic.*
