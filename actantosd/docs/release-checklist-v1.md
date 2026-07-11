# Quiet Open-Core v1.0.0 Release Checklist

> Stage language: **Open-Core / Design Partner** — not proven-customer production claims.  
> See plan: `v1.0.0_plan.md`, ADR `0003-v1-tag-vs-proven-claims.md`.

## Required verification

- `npm run typecheck`
- `npm test`
- `npm run build`
- `npm run policy:regression`
- `npm run smoke:fresh-install`
- `npm run release:artifacts`

Prefer: `npm run release:verify` when available.

## Artifact set

- Docker image: `actantosd:v1.0.0` (or equivalent digest-pinned image)
- npm tarball: generated under `artifacts/npm/`
- release manifest: `artifacts/release-manifest.json`
- release notes: `docs/release-notes-v1.0.0.md` (Quiet Open-Core naming inside)

## Upgrade evidence

- `docs/upgrade-v0.7-to-v1.md`
- `src/migration-compatibility.test.ts`

## Security evidence

- `docs/threat-model.md`
- `docs/security-hardening.md`
- `docs/security-review-checklist.md`
- `docs/security-sbom.cdx.json`
- `src/audit-chain-verifier.test.ts`
- `src/fail-closed.test.ts`
- `src/url-target-guard.test.ts`
- `src/tool-result-service.test.ts`

## Operator docs

- `docs/api-v1-contract.md`
- `docs/mcp-gateway-stable.md` (MCP Optional Path for pilots)
- `docs/pilot-policy-templates.md` (Balanced default / Strict opt-in)
- `docs/support-runbook.md`
- `docs/go-no-go-v1.md`

## Claim hygiene (required before public announce)

- [x] README / release notes do not claim living-customer battle-tested proof
- [x] Stage described as Quiet Open-Core / Design Partner (`docs/open-core-surface.md`)
- [x] `pilot-evidence-*.md` labeled lab/fixture unless re-run by living partner
- [x] Git tag is **`v1.0.0`** (not `v0.1.0`) — create via Quiet Open-Core publish (#7)
- [x] Quiet publish only (no launch campaign required)

## Residual publish risks

- [x] **Docker smoke** verified 2026-07-09 (`smoke:fresh-install` 35/35) — re-check if environment drifts
- [ ] **Image signing** deferred if cosign/notary tooling is unavailable — note on release surface if skipped
- [x] **GitHub release / tag** — ticket #7

## Proven Claim Gate (not required for tag)

Tracked in plan `design_partner_window_plan.md` and [`design-partner-kit.md`](./design-partner-kit.md):

- [ ] Living Pilot #1 Pilot Done (Unaided) — coding / Pi
- [ ] Clone Pilot #2 before strong repeatability claims
