# Q3 Infrastructure Security Assessment
Date: September 2026
Prepared by: Security Operations

## Executive Summary

Routine Q3 security assessment of the production infrastructure.
Three findings identified, all rated Medium or below.

## Findings

| ID | Finding | Severity | Status |
|----|---------|----------|--------|
| INF-01 | Unpatched OS packages on two worker nodes | Medium | In Progress |
| INF-02 | SSH key rotation overdue on bastion host | Medium | Open |
| INF-03 | Unused inbound firewall rules on staging VPC | Low | Open |

## Remediation

- INF-01: Apply patches during next maintenance window (Oct 2026).
- INF-02: Rotate SSH keys and enforce 90-day rotation policy.
- INF-03: Review and prune unused firewall rules.

## Conclusion

No critical findings. Infrastructure posture is satisfactory.
