# Stage 3 Operator Runbook

## Preflight

```bash
npm run stage3:preflight          # offline fixtures
npm run stage3:preflight:optional # probe optional cloud deps
npm run stage3:preflight:required # fail if hardened deps missing
npm run stage3:validate
npm test
npm run typecheck
```

## Rollback

1. Disable hardened isolation (`provider=docker` development only)
2. Pause SIEM connectors
3. Restore Postgres from pre-migration snapshot
4. Redeploy previous package artifact

## Restore

1. Restore Postgres
2. Re-run migrations if schema lagging
3. Verify audit chain per tenant
4. Replay dead-letter outbox items after root-cause fix

## Security incidents

- Unresolved credential cleanup: treat as Sev-1; revoke IAM role sessions
- Object Lock delete failures are expected under COMPLIANCE retention
- Cross-tenant 403 spikes: inspect OIDC memberships and `x-actantos-tenant`
