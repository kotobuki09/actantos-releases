# v0.7.0-pilot-beta Release Notes

Date: `2026-07-07`

## Highlights

- Pilot onboarding guide for self-host setup and first governed workflow
- Policy template starter pack for development, read-only MCP, and approval-driven GitHub-style pilots
- Usage metrics API and operator metrics page
- Signed webhook delivery for exported evidence packages
- Security baseline carried forward from `v0.6.0-security-beta`, including fail-closed coverage, SSRF hardening, audit-chain verification, preview redaction hardening, dependency audit, and SBOM generation

## Operator surfaces

- `GET /dashboard/metrics`
- `GET /v1/metrics/usage`
- `POST /v1/webhooks/evidence`
- `GET /v1/evidence/export`

## Known limitations

- Seccomp and AppArmor are still Phase 2 hardening items
- Secret redaction is pattern-based, not semantic classification
- Webhook delivery is pull-triggered by an operator call; it is not yet a background subscription system
- Metrics are aggregate operational totals, not a full historical analytics product
