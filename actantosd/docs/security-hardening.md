# Security Hardening Guide

Last updated: `2026-07-07`

This guide captures the Milestone 5 security baseline for `actantosd`. It is the operator-facing companion to the STRIDE threat model in [`docs/threat-model.md`](./threat-model.md).

## What is verified now

The current release baseline has executable coverage for these controls:

- Fail-closed runtime behavior when policy, risk, approval, or result-recording dependencies fail
- Decision-token verification on both `/v1/tool-result` and the Docker execution path
- Approval replay denial after an approval is already decided
- SSRF blocking for localhost, RFC1918, metadata, link-local, and private IPv6 targets
- Per-tenant audit-chain verification with tamper detection
- Preview redaction for env-style secrets, GitHub tokens, bearer tokens, AWS access-key IDs, and PEM private keys
- Docker sandbox flags for non-root execution, read-only FS, capability drop, no-new-privileges, memory/CPU/PID limits, and explicit network mode selection

Primary verification commands:

```bash
npm test
npm run build
npm run policy:regression
npm audit --omit=dev
```

## Docker sandbox baseline

The guarded Docker execution path currently enforces:

- `--user 1001:1001`
- `--read-only`
- `--tmpfs /tmp:size=64m`
- `--cap-drop ALL`
- `--security-opt no-new-privileges`
- `--memory 512m`
- `--cpus 0.5`
- `--pids-limit 64`
- `--network none` by default, or `actantos_egress` for the explicit egress-proxy mode

These invariants are exercised in `src/docker-executor.test.ts`.

## Audit-chain verification

Use `verifyTenantAuditChain(...)` from `src/audit-chain-verifier.ts` to recompute the tenant chain from `audit_events` and `audit_chain_state`.

It detects:

- `prev_hash_mismatch`
- `event_hash_mismatch`
- `chain_state_mismatch`

This gives us a direct tamper check over the persisted audit trail instead of trusting only the write path.

## Dependency and SBOM evidence

The dependency scan run on `2026-07-07` reported:

- production vulnerabilities: `0`
- critical vulnerabilities: `0`
- total production dependencies scanned: `149`

The generated CycloneDX SBOM lives at [`docs/security-sbom.cdx.json`](./security-sbom.cdx.json).

## Phase 2 hardening plan

Milestone 5 establishes the portable baseline. The next hardening layer should add host-specific isolation that we can stage safely:

1. Add a dedicated seccomp profile that permits the current `alpine` and `alpine/git` execution paths, then wire it through `docker run --security-opt seccomp=...`.
2. Add an AppArmor profile for the sandbox container and validate it in Linux CI or a documented local verification path.
3. Move the container root filesystem and workspace mount policy toward `noexec`/reduced-write semantics where tool compatibility allows.
4. Evaluate gVisor for single-tenant hosted deployments and Firecracker for higher-isolation multi-tenant plans.

Until seccomp/AppArmor land, the current sandbox should be treated as a strong default container boundary, not a final high-risk multi-tenant isolation story.
