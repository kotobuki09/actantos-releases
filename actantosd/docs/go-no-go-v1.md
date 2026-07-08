# Production v1 Go/No-Go

## Local release verdict

`Go` for the code and release package.

Verified on `2026-07-08` with:

- `npm run release:verify`
- `npm run smoke:fresh-install`
- `npm run release:artifacts`

Observed release evidence:

- `release:verify` passed with `145` tests green, build green, and `policy:regression` green
- `smoke:fresh-install` passed the compose-backed demo flow with `35 passed, 0 failed`
- release artifacts were regenerated under `artifacts/`

The repository now contains:

- a frozen `/v1` contract
- a tested `v0.7` to `v1` migration path
- security regression evidence
- production installation, upgrade, backup, and MCP gateway docs
- release artifact generation and checklist documentation

## External release gate still required

The final public production announcement is still blocked on two external items that cannot be generated inside this workspace:

- completion evidence for two real pilot workflows
- the actual GitHub release publication step

## Ship criteria for the operator

Before publishing:

1. confirm the pilot evidence package is attached
2. run the release checklist in `docs/release-checklist-v1.md`
3. publish the Git tag `v0.1.0`
4. upload the npm tarball and release notes to the final release surface
