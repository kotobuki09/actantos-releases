# Production v1 Release Checklist

## Required verification

- `npm run typecheck`
- `npm test`
- `npm run build`
- `npm run policy:regression`
- `npm run smoke:fresh-install`
- `npm run release:artifacts`

## Artifact set

- Docker image: `actantosd:v1.0.0-production`
- npm tarball: generated under `artifacts/npm/`
- release manifest: `artifacts/release-manifest.json`
- release notes: `docs/release-notes-v1.0.0-production.md`

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
- `docs/mcp-gateway-stable.md`
- `docs/pilot-policy-templates.md`
- `docs/support-runbook.md`
