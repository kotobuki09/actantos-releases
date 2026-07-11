# Stage 3 Hosted / Production Prerequisites

Stage 2 Compose remains the baseline self-host path. Stage 3 hardened mode adds:

## Required roles and database

- Application role: `actantos_app` (no BYPASSRLS)
- Maintenance role: `actantos_maintenance` (BYPASSRLS for migrations only)
- Migrations: `sql/migrations/001`…`008_tenant_rls.sql`
- Unit tests use `migrateDatabaseForUnitTests` (skips RLS on pg-mem)

## Isolation

- Runtime: `runsc` only in hardened mode (never silent Docker fallback)
- Pinned image digest (`sha256:…`)
- Seccomp + AppArmor profiles present
- Egress only via allowlisted proxy

## Credentials

- AWS STS AssumeRole via credential broker
- Secrets injected to owner-only tmpfs paths
- Lease metadata stores hashes only

## Evidence

- S3 bucket with Object Lock **COMPLIANCE**, versioning, SSE-KMS
- Default retention 365 days (30 days–7 years)
- Post-upload signature verification before `complete`

## SIEM

- Tenant connector configs (webhook + Splunk HEC)
- At-least-once outbox delivery with dead-letter and replay
- HTTPS public endpoints only; private/metadata blocked

## Readiness

`GET /health/ready` reports Stage 2 flags plus Stage 3 subsystem readiness when configured.

## Upgrade

1. Backup Postgres
2. Run migrations through `008_tenant_rls.sql`
3. Configure OIDC JWKS (or `ACTANTOS_OIDC_ALLOW_HS256=true` for dev only)
4. Enable hardened isolation only after runsc preflight passes
5. Flip capability ledger entries to `done` only with evidence (`npm run stage3:validate`)
