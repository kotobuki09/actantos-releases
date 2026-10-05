# Migrating from ActantOS v1 to v2

## What actually changed

v1 is not removed. v2 is added alongside it, and no existing public or production behaviour
changed. This document describes what is new, what now runs it, and what stays where it is.

| Area | v1 | v2 | Can you turn v2 off? |
| --- | --- | --- | --- |
| Policy storage | DB row: `source_hash` (SHA-256) + `active` flag | signed bundle: Ed25519 signature over a canonical body | yes — v1 path untouched |
| Policy evaluation | central policy API over HTTP | sidecar, local, holds a signed lease | yes |
| Network guard | `src/url-target-guard.ts`, SSRF **blocklist** | `src/v2/network-target-guard.ts`, destination **allowlist** | yes — different modules |
| Tool execution | intercept service + HMAC decision token | effect gateway + `EffectPermit` | yes |
| Identity | user OIDC (`oidc-routes.ts`) | workload identity, SPIFFE-form | yes — different subject |
| Audit | chain verifier + export, no identity links | hash-chained, per-record signed, offline verifiable | yes |

## Entry points

| Command | What it does |
| --- | --- |
| `npm run demo:v2` | The §21 narrative end to end. Six attacks, a control-plane outage, offline evidence verification. Exits non-zero if any attack lands. |
| `npm run bench:v2` | p50/p95/p99 on the enforcement path. |
| `npm run evidence:verify <bundle> --keys <keys>` | Offline evidence verification. Needs no database or service. |
| `npm run tetragon:emit <bundle> <deployment>` | Compiles a signed bundle into Tetragon TracingPolicy YAML. |
| `npm run bench` | security-bench: 26 attacks + 2 controls. |

## Why the URL guard was not replaced

v1 has `src/url-target-guard.ts`, which blocks SSRF targets. It is a **blocklist**: it knows the
destinations that are forbidden and allows everything else. The v2 guard is an **allowlist**: it
knows the destinations that are permitted and refuses everything else.

They are not the same control and both are wanted:

- The v1 blocklist is defence in depth on the v1 HTTP path. A blocklist is the right shape
  there, because v1 callers are ordinary application code and an allowlist would be a breaking
  change to their behaviour.
- The v2 allowlist is what S3 requires. "Cannot bypass policy via curl, sockets, Node, shell,
  child processes, raw MCP, IPv6 or alternate DNS" is a statement about the destination, and a
  blocklist cannot answer it — every new destination is a hole until someone remembers to add
  it.

The v2 module is therefore named `network-target-guard.ts` rather than `target-guard.ts`, and
its header documents the relationship, so the two are not mistaken for duplicates.

## Policy authoring

There is no second policy language. The Tetragon YAML in Phase 5 is a **compiler output**: every
port and allowlist host comes from the signed bundle's `network_rules`. Only binary paths and
write paths come from a deployment file, because a binary path cannot be derived from a logical
tool name without inventing a mapping table — and that mapping table would be a second policy
language.

## Deploying the Tetragon policy

```bash
npm run tetragon:emit signed-bundle.json deployment.json > /tmp/emitted.yaml
tetra tracingpolicy add /tmp/emitted.yaml
```

```json
{
  "policyName": "actant-agent-reviewer",
  "deniedBinaries": ["/usr/bin/curl", "/usr/bin/wget", "/usr/bin/nc"],
  "deniedWritePaths": ["/etc/shadow"],
  "mode": "observe"
}
```

`mode` defaults to `observe`. Set `enforce` only where the BPF enforcer has been shown to work,
because an enforcement action that misfires takes down legitimate work. **On the substrate
measured here, no kprobe event was ever observed from a workload container — read
`SECURITY_TEST_MATRIX.md` before switching to `enforce`.**

`emit-tetragon` compiles whatever bundle it is given and does **not** verify the signature. Feed
it a bundle `verifyPolicyBundle` has already accepted; the output is only as trustworthy as its
input.

## What to read before trusting any of it

- `docs/SECURITY_INVARIANTS.md` — per-invariant status and what is NOT demonstrated.
- `docs/SECURITY_TEST_MATRIX.md` — every measurement, including the failures.
- `docs/ARCHITECTURE_V2.md` — the shape, and what the design explicitly does not claim.

## Scope limit that does not change with the version

Baseline v2 does not claim protection after host-kernel or root compromise. Every control runs
as an ordinary process; root can read the sidecar's memory and ptrace the broker. This is the
same limit v1 had. Confidential computing is the future mitigation.