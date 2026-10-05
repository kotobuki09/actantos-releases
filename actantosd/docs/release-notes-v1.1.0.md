# ActantOS v1.1.0 Release Notes

**Date:** 2026-07-12
**Stage:** Quiet Open-Core / Design Partner

## Overview

`v1.1.0` closes Enterprise Tracks A through D on top of the `v1.0.0` frozen enforcement kernel.
It adds the operator-facing surfaces those tracks needed — policy bundles, role separation, SSO,
and an SDK — together with the hardening and correctness fixes found by the independent
qualification passes.

Every item below corresponds to a commit in the range `v1.0.0..v1.1.0`. Nothing here is
projected work.

> **Note on this file.** It was previously named `release-notes-v1.1.0.md` while still carrying
> the `v1.0.1` heading and body, and `package.json` pointed at a `release-notes-v1.0.1.md` that
> does not exist. Both defects are now fixed and guarded; see the last section.

## Carried forward from v1.0.1

* **MCP tenant spoofing:** `mcp-gateway` rejects identity and tenancy headers
  (`x-actantos-tenant-id` and similar) on unauthenticated requests, locking context to safe
  defaults unless explicitly opted in or validated with an API key.
* **HMAC secret enforcement:** the daemon refuses to start in `production` evaluator mode when
  `ACTANTOS_HMAC_SECRET` is unset or equals the insecure `"actantos-dev-secret"` default.
* **gVisor downgrade warning:** when `ACTANTOS_USE_GVISOR=true`, the daemon probes for `runsc` at
  startup and warns rather than silently falling back to standard Docker.
* **Preflight CLI:** `npm run preflight` checks Node, Docker, the Cedar CLI, and required
  environment variables before installation.

## Enterprise tracks

### Track A — integrity and claim honesty

* **Authoritative evaluator guard (A-04):** `ACTANTOS_EVALUATOR_MODE=production` and
  `ACTANTOS_REQUIRE_CEDAR=1` now refuse to fall back to `FakeCedarProvider`. If the Cedar CLI is
  unavailable in production mode, startup fails.
* **Egress claim integrity (A-05):** the release-maturity truth file records that
  `network_mode=egress_proxy` selects a Docker bridge network only, and that the SSRF guard is
  application-level. The claim is marked `unsupported` rather than left implied.
* **Repository reconciliation (A-06):** release identity is single-sourced in
  `release-maturity-truth.json`, which wins over `package.json`, the generated manifest, and
  human documentation when they disagree.

### Track B — qualification

* **Operational resilience (PQ-05)** and **independent production qualification (PQ-06)**:
  documented resilience and qualification passes against the deployed topology.

### Enterprise foundation

* **Enterprise identity, managed deployment, evidence signing, and MCP context.**
* **SQL injection fix:** tenant identifiers are validated against `^[a-zA-Z0-9_-]+$` before being
  interpolated into `SET LOCAL actantos.tenant_id`.

### Operator surfaces

* **OIDC SSO for the dashboard (PQ-07).**
* **Control-plane and data-plane role separation (PQ-08).** The daemon takes a `serviceRole` and
  exposes control-plane and data-plane routes accordingly.
* **Policy bundles with hot reloading (PQ-09).**
* **ActantOS SDK and tool wrapper (PQ-10).**
* **Actionable reason codes and a policy simulation API.**

## Upgrade path

Compatible with `v1.0.0` environments. The one behavioural break: in production evaluator mode
the daemon now **refuses to start** rather than silently substituting `FakeCedarProvider`. Ensure
`ACTANTOS_HMAC_SECRET` is set and the Cedar binary is present before upgrading.

## Known residuals

* WORM evidence storage remains deferred.
* `network_mode=egress_proxy` is network selection, not an authenticated destination-enforcing
  proxy. It is recorded as `unsupported` in the release-maturity truth file.
* No external living-pilot proof and no production-qualified multi-tenant platform claim. Both are
  recorded as `unsupported` / `conditional` in the truth file.

## Release-identity defect fixed here

`package.json` declared `actantos.releaseNotesFile` as `docs/release-notes-v1.0.1.md`, a file
that does not exist, and `build-release-artifacts.mjs` copied that value into the release
manifest without checking it. The pointer now names `docs/release-notes-v1.1.0.md`, which matches
`release_tag: "v1.1.0"` in `release-maturity-truth.json`. `build-release-artifacts.mjs` now
fails closed when the declared notes file is missing, and `security-docs-consistency.test.mjs`
asserts the pointer matches the governed version.