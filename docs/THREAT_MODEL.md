# ActantOS v2 Threat Model

Status: draft for v2 security fabric
Date: 2026-10-03
Scope: Agent Security Fabric (local boundary + distributed enforcement)

## 1. Core security assumption

ActantOS v2 assumes the LLM and the agent process are fully compromised.

The design question is not "how do we stop a misbehaving model?" It is:

> When the model and its process are under attacker control, what can the surrounding
> system still prevent?

The answer must not depend on the agent cooperating. Any control that the protected
agent can disable, rewrite, or route around is not a security control.

## 2. Adversary classes

Each class is listed with what v2 must contain, and what v2 explicitly does not claim.

### A1. Compromised LLM

The model emits malicious instructions, or follows an injected instruction.

Contains: the model has no authority. It cannot mint credentials, mint permits, mark a
permit consumed, alter policy, or reach the network directly. It can only *request*
actions through the local boundary, and every request is evaluated independently (S6, S14).

Does not contain: a compromised model with valid, already-authorized capability can still
perform that capability's actions. v2 limits blast radius through narrow scope, short
expiry, and single-use permits; it does not make an authorized action "safe".

### A2. Compromised agent process

Full local code execution inside the agent container: arbitrary languages, arbitrary
binaries, child processes, raw syscalls.

Contains: the OS/network layer denies direct egress (S2, S3). The process holds only a
short-lived workload identity (S4), and that identity is bound to the execution scope.
A compromised process can attempt anything reachable; the boundary decides what succeeds.

Does not contain: a fully compromised agent process can still read anything the identity
is entitled to read, and can still make noise or consume quota.

### A3. Malicious peer agent

Another agent in the mesh behaves maliciously, or relays a forged claim.

Contains: trust is never transitive (S5). Every A→B hop authorizes independently against
its own policy. A peer cannot assert authority it does not hold.

Does not contain: v2 cannot prevent a peer that is legitimately entitled to a capability
from using it. It prevents *escalation* and *impersonation*, not legitimate peer use.

### A4. Prompt injection

Untrusted content (web page, tool output, repository file, email) instructs the agent to
exfiltrate data or perform a privileged action.

Contains: injection is treated as attacker-controlled input, not as a policy change.
Sinks are gated by data label and by permit, not by the model's judgment (S7, S10). The
injection payload has no path to a credential because no credential exists in context (S1).

Does not contain: injection can still cause the agent to *request* many permitted actions,
or to make poor decisions within its granted scope. Rate and budget limits bound volume.

### A5. Malicious tool or MCP server output

A tool or MCP server returns content crafted to subvert the agent, or leaks data it holds.

Contains: tool responses are labeled at ingestion (S10). MCP servers are sinks with
declared clearance. A tool cannot widen the agent's scope by asserting a new capability.

Does not contain: a malicious tool that lies about the *content* of data it returns. v2
protects the label and the boundary, not the truth of the payload.

### A6. Network attacker

On-path attacker: TLS interception, DNS poisoning, ARP spoofing, rogue proxy.

Contains: egress is proxied through a controlled gateway, not directly dialed. DNS is
not freely resolvable (S2, S3). Transport is mTLS with mutual authentication.

Does not contain: v2 does not claim protection against an attacker who fully controls the
host network stack or has a trusted CA installed.

### A7. Stolen or replayed authorization

An attacker captures a decision token, permit, or identity assertion and replays it.

Contains: permits are nonce-bound, single-use, and short-lived (S9). Decision tokens are
HMAC-bound and short-lived. Revocation is checked.

Does not contain: within its validity window, a valid permit is usable. The window is the
security parameter; single-use and expiry bound it.

### A8. Compromised control plane

The central ActantOS control plane is compromised, or the attacker controls it.

Contains: the sidecar keeps enforcing from the last valid signed policy lease during a
control-plane outage (S11). The control plane cannot forge a workload identity, and cannot
make the sidecar accept an unverifiable bundle (S12).

Does not contain: a compromised control plane **can** publish a maliciously signed policy
bundle if it holds the signing key. v2 mitigates this with key separation, issuer
allow-lists, short bundle expiry, and cross-tenant signature binding. Full protection
requires an external HSM-held or quorum-signed key, which is not implemented.

### A9. Compromised host, root, or kernel

Attacker has root on the host or a compromised kernel.

**v2 baseline explicitly does NOT claim protection against this threat.**

An attacker with root can patch the sidecar, replace the verifier, forge workload identity,
and read memory. No userspace security boundary survives that.

Future mitigation is Confidential Mode: AMD SEV-SNP or Intel TDX confidential VMs, later
confidential GPU attestation. See ADR-0008 §7 and v2.1 item D.

This limitation must appear in any security-facing surface that describes v2. It is a
correctness-of-claims requirement, not a marketing caveat.

## 3. Trust boundaries

| Boundary | Enforced by | Trust assumption |
|---|---|---|
| LLM context | Capability broker; no raw credentials issued | Model is untrusted |
| Agent process → Internet | OS network cell; egress gateway only | Process is untrusted |
| Agent process → sidecar | Unix domain socket; versioned protocol | Process is untrusted; peer authenticated |
| Sidecar → control plane | Signed policy bundles; lease-based | Network untrusted; bundle cryptographically verified |
| Agent A → Agent B | Mutual workload identity; per-hop authorization | No transitive trust |
| Effect permit → effect gateway | Exact-action permit; nonce; single-use | Agent cannot self-authorize |
| Evidence sink | Hash-chained, signed records | Agent cannot rewrite history |

## 4. Current v1 state relevant to this model

Verified by inspection of `actantosd/` at commit a22faf0 (2026-10-03):

- **Container isolation is real but partial.** `src/docker-executor.ts` applies
  `--read-only`, `--cap-drop ALL`, `--security-opt no-new-privileges`, `--user 1001:1001`,
  `--pids-limit`, memory/CPU caps, and `--network none` (or `egress_proxy`). This is a
  genuine boundary for the containerized tool-execution path.
- **gVisor is opt-in and fails closed.** `ACTANTOS_USE_GVISOR=true` with `runsc` absent
  **refuses the execution** rather than falling back to the default runtime; in strict mode
  (`ACTANTOS_GVISOR_STRICT=true` or `NODE_ENV=production`) the server refuses to start. The
  check runs before the network is created and before the image is pulled, so a refused
  request costs no host mutation. Resolved in `src/sandbox-runtime.ts`, shared by the
  executor, the startup path, and the preflight check so the three cannot disagree.
- **gVisor adds a userspace kernel but does not change the compromise model.**
  `runsc` is installed and the sandbox is measured working: under `runc`, `dmesg` is refused
  against the host kernel; under `runsc` it returns gVisor's own kernel boot log. This narrows
  what a kernel exploit reaches, but the host-kernel/root exclusion below still holds. gVisor is
  a hardening layer, not a substitute for the sidecar or the network cell.
- **Policy bundles are not signed.** `policy_bundles` rows carry `source_hash` (SHA-256)
  and an `active` flag. A hash detects accidental change; it provides no authenticity.
  Anyone able to write the row or serve the bundle can recompute it. This contradicts S11
  and is the first v2 fix.
- **No asymmetric signing exists at runtime.** The only MAC is HMAC-SHA256
  (`src/hash.ts`, used for decision tokens, webhooks, evidence export). These are
  symmetric shared-secret constructions, not signatures, and they cannot support a
  control-plane-issued bundle that a sidecar verifies without a shared secret.
- **The authoritative Cedar evaluator was not executed.** No `cedar` binary is present on
  the build host. `src/cedar-provider.test.ts` injects `probeBinary`, so the 17 passing
  tests exercise plumbing and fail-closed logic, **not** real Cedar evaluation semantics.
- **Tenant RLS is unverified here.** `src/tenant-isolation.test.ts` skips all 4 tests
  without `DATABASE_URL`.

## 5. Out of scope for v2 baseline

- Host root / kernel compromise (A9).
- Physical or supply-chain compromise of the build pipeline.
- Side-channel and timing attacks on cryptographic primitives.
- Malicious *operator* with legitimate authority to publish policy.