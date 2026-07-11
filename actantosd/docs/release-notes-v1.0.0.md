# v1.0.0 Quiet Open-Core Release Notes

**Stage:** Open-Core / Design Partner (quiet publish — no launch campaign)  
**Artifact tag:** `v1.0.0`  
**Not claimed:** living-customer battle-tested production proof (see Proven Claim Gate)

## Highlights

- frozen `/v1` API contract for runtime, operator, and MCP gateway integrations
- verified upgrade path from `v0.7.0-pilot-beta` to `v1.0.0`
- production release checklist, artifact manifest, and release packaging workflow
- starter policy template pack (coding pilots should default to **Balanced** posture; **Strict** opt-in)
- stable MCP gateway client guidance (**supported; optional** for Design Partner Pilot success — Pi Primary Path is pilot-gating)
- self-host free surface: enforcement kernel, web approval, basic operator console, optional Slack connector

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

- Quiet Open-Core: public tag and install docs; no marketing launch required
- Proven Claim Gate still requires a living Design Partner Pilot (coding / Pi, unaided) — lab `pilot-evidence-*.md` fixtures are not sufficient
- Firecracker / gVisor, full OIDC/SCIM, credential broker, and multi-tenant SaaS remain out of scope (Pilot Freeze / later paid platform)
- Image signing may be deferred if tooling is unavailable; document residual risk

## Related plans

- `v1.0.0_plan.md` — tag and claim hygiene
- `design_partner_window_plan.md` — living pilots
- `docs/go-no-go-v1.md` — gate table
