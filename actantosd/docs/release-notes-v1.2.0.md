# ActantOS v1.2.0 Release Notes

**Date:** 2026-10-06
**Stage:** Quiet Open-Core
**Validation class:** `locally-verified` — every claim below was measured on one host; nothing here is projected work, and nothing here is production-qualified.

## Overview

`v1.2.0` is the quiet-open-core build that carries the **v2 agent security fabric** on top of the
frozen `/v1` enforcement kernel. The fabric's premise: the LLM and the agent process may become
fully compromised, and the surrounding system must still constrain what the compromised agent can
access, communicate, delegate, and cause in the real world.

The frozen `/v1` intercept API remains compatible. The previous Stage 3 v1.1.0 lineage stays
published at tag `v1.1.0` and its GitHub release; this tree does not include it.

## What is new in v1.2.0

### The v2 security fabric (S1–S14)

Fourteen invariants define what a compromised agent still cannot do. Twelve are **HELD** —
demonstrated by an executable test that shows both the allow path and the deny path and then
checks resulting external state. **S4 (per-agent short-lived workload identity) is PARTIAL** and
is reported as such.

- Production credentials never enter model or agent context; mediation happens outside the
  process the agent could compromise (S1).
- Delegation may narrow but never increase authority, and trust is never implicitly transitive
  (S5, S6).
- Authorization is bound to the exact canonical action; changing target or parameters afterwards
  invalidates it (S7, S8); tokens are short-lived, single-use and nonce-bound (S9).
- Higher-sensitivity data may not flow into a lower-clearance sink (S10).
- Local enforcement continues without a control-plane round-trip, expires fail-closed, and the
  LLM may advise but is never the final authority (S11, S12, S14).

### Measurement, not intention

- **1007 unit tests** — 915 passing, 0 failing, 92 skipped (skips are the gated database,
  Docker, SPIRE, gVisor and substrate-flag suites).
- **135 gated substrate tests** run against a real Docker daemon, a real PostgreSQL server and a
  real gVisor (runsc) runtime, including the Tetragon emitted-policy suite.
- **Security bench: 28/28** — 26 attacks blocked, 2 allow-path controls, **0 prohibited external
  effects**.
- Every enforcement control is **mutation-checked**: the flag, check or trigger it depends on is
  removed, and the specific test that must fail is confirmed to fail while the rest stay green.

### Release governance and evidence tooling

- `release-maturity-truth.json` is the fail-closed claim source; the artifact builder refuses to
  pack when package identity and truth drift.
- Documentation-consistency guards fail the suite if a document claims something the tests do not
  demonstrate, including a reproducible probe for the confidential-computing waiver
  (`npm run confidential:probe`).
- Machine-readable fabric state with a check mode: `npm run security:state`,
  `npm run security:state:check`.
- `npm run release:verify` (typecheck + tests + build + policy regression + security bench +
  state check) and `npm run test:substrate` for the gated suites.

## Explicitly not claimed

- **Not production-qualified.** Locally verified on one host is not a claim about any other host.
- **Confidential computing is not implemented.** The itemized waiver `W-001` in
  `docs/OPEN_WAIVERS.md` is unsigned.
- **No protection against a compromised host.** The fabric defends against a compromised agent,
  not against root or a hostile kernel.
- No SOC 2 / ISO 27001 / FedRAMP certification is claimed.

## Upgrade notes

From the v1.0.x quiet-open-core line: the `/v1` API is unchanged; new surfaces are additive.
From the Stage 3 `v1.1.0` tag: that lineage remains at its tag — this tree is a different
lineage, and its multi-tenant, credential-broker and WORM features are not in `v1.2.0`.
