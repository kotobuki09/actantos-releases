# Release and Maturity Truth Source

**Milestone:** A-01  
**Authoritative file:** [`../release-maturity-truth.json`](../release-maturity-truth.json)

## Purpose

One machine-readable source defines Mode A public package identity, maturity labels, claim levels, supported deployments, and deferred/unsupported claims.

Semantic version tags are **not** production qualification. Never encode maturity as `v1.0.0-production`.

## Schema (schema_version 1)

| Field | Type | Notes |
|---|---|---|
| `schema_version` | number | Currently `1` |
| `package_version` | string | npm semver without `v` (must match `package.json`) |
| `release_tag` | string | Git/release tag, normally `v` + package_version |
| `maturity_label` | enum | See allowed maturity labels |
| `validation_class` | enum | Overall product validation class (claim-level vocabulary) |
| `supported_deployments` | string[] | Deployment forms currently supported |
| `evidence_date` | string | ISO date (`YYYY-MM-DD`) for the truth snapshot |
| `public_artifact_urls` | string[] | Public release/install references |
| `claim_entries` | object[] | Individual claims with levels |
| `repository_relationship` | object | How related trees map to this baseline |
| `forbidden_maturity_encodings` | string[] | Banned semver-as-maturity strings |
| `precedence` | object | Conflict-resolution rule |

### Allowed `maturity_label` values

- `quiet-open-core`
- `design-partner-window`
- `production-qualified` (only with validation_class `production-qualified` and Mode B evidence)

### Allowed claim / validation labels

Aligned to overview §6:

- `claimed`
- `implemented`
- `locally-verified`
- `integration-verified`
- `release-verified`
- `production-qualified`
- `unsupported`
- `planned`
- `conditional`
- `deprecated`

## Precedence

1. **`release-maturity-truth.json`** — Mode A public identity, maturity, claim levels  
2. **`package.json`** — must match `package_version` and `actantos.stage` ↔ `maturity_label`  
3. **`artifacts/release-manifest.json`** — generated output; must match package identity  
4. **Docs / website** — consumers; may not exceed the truth source  

During transition, if docs disagree, this file wins. Do not leave two active truth sources.

## Consumers

| Consumer | Path | Behavior on drift |
|---|---|---|
| Validator | `scripts/validate-release-maturity-truth.mjs` | Exit non-zero |
| Kernel tests | `scripts/validate-release-maturity-truth.test.mjs` | Fail CI/local test |
| Release verify | `npm run release:verify` | Chains maturity validation |
| Artifact builder | `scripts/build-release-artifacts.mjs` | Asserts package identity matches truth before pack |
| Website (out of tree) | `web/actantos` via `ACTANTOS_TRUTH_PATH` or sibling check | Claim tests must not encode Stage 3 / v1.1.0 as Mode A public baseline |

## Fail-closed release paths

Publication-oriented paths that depend on this check:

- `npm run maturity:validate`
- `npm run release:verify`
- `npm run release:artifacts` (refuses to pack when identity drifts)

A failed check must block treating the tree as a publishable Mode A release.

## Mode A baseline (current)

- Package: `1.0.0`
- Tag: `v1.0.0`
- Maturity: `quiet-open-core`
- Overall validation class: `locally-verified`
- Not claimed: Stage 3 / v1.1.0 as Mode A public baseline; production-qualified platform; living pilot proof

## Deferred claim owners

| Claim cluster | Owner milestone |
|---|---|
| Authoritative fail-closed evaluator | A-04 |
| Egress destination enforcement claims | A-05 |
| Multi-repo status/doc reconciliation | A-06 |
| Production-qualified multi-tenant platform | Mode B (PQ-*) |
