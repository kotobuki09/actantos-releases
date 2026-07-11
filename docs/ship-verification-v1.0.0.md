# Ship seam verification log — v1.0.0

**Date:** 2026-07-09  
**Tickets:** #5 (ship seam), #7 (public Quiet Open-Core publish)

## Commands

| Command | Result | Notes |
| --- | --- | --- |
| `npm run release:verify` | **PASS** | typecheck + full test suite + build + policy:regression |
| `npm run release:artifacts` | **PASS** | `actantosd-1.0.0.tgz`, manifest `release_version: v1.0.0`, stage `quiet-open-core` |
| `npm run policy:regression` | **PASS** | 5/5 including git push `approval_required` |
| `npm run smoke:fresh-install` | **PASS** | Docker Server Version 29.6.1; demo **35 passed, 0 failed** |

## Artifact identity

```json
{
  "release_version": "v1.0.0",
  "stage": "quiet-open-core",
  "npm_package": { "file": "npm/actantosd-1.0.0.tgz" },
  "docker_image": { "image": "actantosd:v1.0.0" },
  "github_release": { "tag": "v1.0.0" }
}
```

## Residual risks for public publish

1. **Image signing** not performed in this verification pass (document on release if skipped).
2. **Proven Claim Gate** still blocked until living Pilot Done (Unaided) — tag is Quiet Open-Core only.

## Verdict

| Criterion | Status |
| --- | --- |
| release:verify | Met |
| smoke:fresh-install | Met (35/35) |
| artifacts v1.0.0 | Met |
| checklist v1.0.0 naming | Met |
| residual risks documented | Met |

**Ship gate: Go for Quiet Open-Core public tag `v1.0.0`.**
