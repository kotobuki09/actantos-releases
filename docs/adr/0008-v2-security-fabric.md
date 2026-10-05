# ADR-0008: ActantOS v2 Agent Security Fabric

Status: accepted
Date: 2026-10-03
Supersedes: nothing
Relates to: `docs/THREAT_MODEL.md`, `docs/SECURITY_INVARIANTS.md`, ADR-0005

> Numbering note: this file is `0008-`, following the existing `0001`–`0007` convention in
> this directory rather than the `001-` name used in the original v2 request.

## Context

The v2 request was written on the premise that a substantial v1 control plane already
exists to be preserved and extended: Cedar policies, approval workflows, kill switch,
budget and rate limiting, audit/evidence, tenant concepts, an MCP gateway, gVisor support,
credential/STS work, and a `/v1` compatibility surface.

Repository reconnaissance on 2026-10-03 (`actantos-plan` at `a22faf0`, `actantosd/`,
97 source files, 46 test files) confirms **part** of that premise and refutes the rest.

### What v1 genuinely has and keeps

- Cedar policy engine with an explicit refusal to fall back to a fake evaluator
  (`src/cedar-provider.ts`, `cedar-cli-provider.ts`).
- MCP gateway with manifest guarding and tool-version pinning (`src/mcp-gateway.ts`).
- Hardened container execution (`src/docker-executor.ts`) and opt-in gVisor.
- Tamper-evident audit chain and offline-capable evidence export.
- Approval workflow, kill switch, budget and rate limiting, risk engine.
- Multi-tenant model with Postgres row-level security (`sql/migrations/009_pq02_tenant_rls.sql`).
- A release-provenance discipline (ADR-0005) with cosign keyless signing for release assets.

### What v1 does not have

A keyword search across `actantosd/src` and `actantosd/policies` returns **no match** for
`delegation`, `delegate`, `grant`, `effect_permit`, `network_rules`, `tool_manifest`,
`agent_profile`, `data_clearance`, `risk_profile`, `trusted_issuers`, `workload_identity`,
or `spiffe`. The v2 security fabric is greenfield. There is no v1 sidecar, capability
broker, network cell, workload identity, effect permit, IFC label engine, or
`security-bench` to extend.

Two further facts change the security posture materially:

1. **Policy bundles are unsigned.** `policy_bundles` carries `source_hash` (SHA-256) and an
   `active` flag. A hash detects corruption, not forgery.
2. **The authoritative Cedar evaluator was never executed on the build host.** No `cedar`
   binary is on PATH. The 17 passing `cedar-provider.test.ts` tests inject `probeBinary`,
   so they exercise plumbing and fail-closed behaviour, not Cedar evaluation semantics.

## Decision

### 1. Keep the existing control plane. Do not rewrite it.

v1 keeps its public `/v1` surface, Cedar model, approval and audit paths. v2 is additive and
lives beside it. Where v1 already enforces an invariant, v2 reuses the mechanism rather
than replacing it.

### 2. Signed policy bundles are the first change.

This is the only change that is both (a) a genuine security gap in v1 and (b) a hard
prerequisite for the rest of v2. Without authentic bundles there is no trustworthy local
lease (S11), and therefore no local enforcement (S11 is the foundation of the entire v2
model).

Implementation constraints:

- Use an existing, well-tested primitive. Node `crypto` Ed25519 via
  `generateKeyPair`/`sign`/`verify`. **No new cryptographic primitive is invented.**
- Put the algorithm behind a `SignatureAlgorithm` interface so ML-DSA or a PQ scheme can
  be added later without changing bundle consumers.
- Sign a canonical serialization of the bundle body, not the transport envelope.
- Keep `source_hash` for change detection. It is not a substitute for the signature and must
  not be described as one (consistent with ADR-0005 §2).

### 3. The sidecar speaks a versioned protocol, not an SDK.

The protected agent talks to the local sidecar over a Unix domain socket using an explicit
versioned protocol (`CheckAction`, `CheckMessage`, `ResolveGrant`, `RequestEffectPermit`,
`CommitEffect`, `GetSecurityContext`). The agent SDK depends on that protocol, never on
sidecar internals, so the sidecar can be replaced or moved without breaking agents.

### 4. Fail closed, including for optional hardening.

`ACTANTOS_USE_GVISOR=true` without `runsc` refuses the execution instead of continuing on the
weaker runtime. The refusal is a typed `SandboxRuntimeUnavailableError` raised before the
Docker network is created and before the image is pulled, so a request that will be refused
costs no host mutation. In strict mode — `ACTANTOS_GVISOR_STRICT=true`, or `NODE_ENV=production`
— the server refuses to start at all, so it never accepts traffic it cannot enforce.

This is decided by `src/sandbox-runtime.ts`, which the executor, the startup path, and the
preflight check all call. They previously disagreed: preflight failed hard, startup and the
executor warned and carried on. One module, one rule.

The remaining honest limit is that the decision is still made from an environment variable
rather than from signed policy. Making it a signed-bundle field is the correct end state and
is recorded as future work; the fail-closed behaviour above is the part that had to be true
today.

### 5. Honest status over aspirational status.

ADR-0005 established the rule that the repo must not describe digests as signatures or
describe unimplemented behaviour as shipped. That rule extends to v2:

- No security property is claimed until an adversarial test demonstrates the deny path and
  the external state is checked.
- Unverifiable on the current build host means **unverified**, not **assumed correct**.

## Consequences

**Positive**

- v1 behaviour and the `/v1` surface are preserved; `/v1` regression remains the gate.
- Signed bundles make the local lease — and therefore local enforcement — achievable.
- The protocol boundary keeps the agent untrusted by construction.

**Negative / accepted cost**

- v2 is a larger build than "extend the existing fabric" implied. Most of Phases 2–10 of
  the v2 request are new systems, not modifications.
- Signing key management (rotation, revocation, tenant binding, offline root) is real work
  and is not solved by adopting Ed25519.
- Adding a real `cedar` binary to the build and CI environment is required before any claim
  about authoritative Cedar evaluation can be made.

**Risks**

- A compromised control plane holding the signing key can publish a malicious bundle.
  Mitigated by key separation, issuer allow-lists, short expiry, and cross-tenant
  signature binding. Not eliminated. See Threat Model A8.
- Host root/kernel compromise defeats all userspace enforcement. Explicitly out of scope
  until Confidential Mode. See Threat Model A9.

## Validation

This ADR is validated by, in order:

1. `docs/SECURITY_INVARIANTS.md` status column reflecting inspected v1 reality.
2. Executable conformance tests for signed bundles: valid bundle accepted; tampered body,
   wrong tenant, wrong version, expired, untrusted issuer, and replayed bundle all refused.
3. The v1 `/v1` regression suite continuing to pass.