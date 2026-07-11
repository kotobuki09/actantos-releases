# v1.1.0 Stage 3 — Governed Enterprise Autonomy

**Stage:** Stage 3 done (built + tests pass)  
**Artifact tag:** `v1.1.0`  
**Ship rule:** Built + tests pass = done (no partner gate)

## Highlights

- **Multi-tenant foundation** — required tenant selectors (no production `t_demo` defaults), OIDC JWKS + optional HS256-dev, service principals, RBAC, identity schema, PostgreSQL RLS migrations
- **Hardened isolation** — signed single-use execution tokens; fail-closed gVisor/runsc provider (Docker remains development compatibility only; no silent downgrade)
- **Credential broker** — AWS STS AssumeRole leases with hashed metadata and secret-residue scanning (tmpfs injection model)
- **WORM evidence archives** — signed evidence artifacts with Object Lock COMPLIANCE semantics and post-upload verification
- **Productized SIEM** — durable webhook + Splunk HEC connectors on a transactional outbox (retry, dead-letter, private-network denial)
- **Release ledger** — `stage3-capabilities.json` aggregate `done` with evidence fields; `npm run stage3:validate`

## Frozen contracts

- `/v1` intercept + tool-result shapes remain compatible
- Stage 1 kernel decision loop and Stage 2 ops surfaces remain available

## Upgrade notes

1. Backup Postgres
2. Run migrations through `sql/migrations/008_tenant_rls.sql` (production Postgres)
3. Require explicit `tenant_id` (or principal tenant) on operator routes
4. For OIDC HS256 dev only: set `ACTANTOS_OIDC_ALLOW_HS256=true` plus client secret
5. Enable hardened gVisor mode only after runsc + profiles + proxy preflight pass
6. See `docs/STAGE3_HOSTED.md` and `docs/STAGE3_RUNBOOK.md`

## Verification baseline

```bash
cd actantosd
npm test                 # 193 pass
npm run typecheck
npm run stage3:validate  # aggregate done
npm run release:verify   # typecheck + test + build + policy regression
```

## Not claimed in this release

- Enterprise memory vault
- Firecracker microVM runtime (gVisor/runsc is the hardened path)
- Full multi-tenant managed SaaS commercial packaging
- Living external customer pilot proof (optional; not a ship gate)

## Related

- Product ledger: `actantosd/stage3-capabilities.json`
- Capability ledger doc: `docs/STAGE3_CAPABILITY_LEDGER.md`
- Marketing site Stage 3 matrix: actantos.com/roadmap
