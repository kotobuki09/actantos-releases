# v0.1.0 Release Notes (superseded naming)

> **Superseded for public tagging.** Use **`v1.0.0` Quiet Open-Core** (`release-notes-v1.0.0.md`).  
> This file is retained so older artifact paths that referenced `v0.1.0` remain understandable.

## Highlights

- frozen `/v1` API contract for runtime, operator, and MCP gateway integrations
- verified upgrade path from `v0.7.0-pilot-beta` to `v0.1.0` (now published as `v1.0.0`)
- release checklist, artifact manifest, and release packaging workflow
- expanded policy template pack to five starter templates
- stable MCP gateway client guidance for operators

## Upgrade notes

- run `npm run db:migrate` before starting the upgraded service
- the demo tenant policy bundle is backfilled from the old placeholder policy text to the checked-in Cedar source
- `db:seed-demo` remains optional and is only for local demo fixtures

## Verification baseline

- `typecheck`
- `test`
- `build`
- `policy:regression`
- `smoke:fresh-install`

## Known limits

- this is a first public test release — API contracts may still evolve in minor ways
- Firecracker / gVisor sandboxing, full OIDC/SCIM, and multi-tenant SaaS are not in scope for v0.1.0
