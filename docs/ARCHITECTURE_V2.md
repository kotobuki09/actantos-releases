# ActantOS v2 — Agent Security Fabric: Architecture

## The assumption this design starts from

The LLM and the agent process may become fully compromised. The surrounding system must still
constrain what the compromised agent can access, communicate, delegate, and cause in the real
world.

That assumption is not rhetorical. Every design decision below exists because a control that
lives *inside* the agent process is a control the compromised agent owns. v1's shape was:

```
agent  ──►  central policy API  ──►  tool
```

If the agent is compromised, the agent decides which tool to call, and the central API is a
remote procedure call the agent can simply not make. Enforcing anything at the API means the
enforcer is reachable, and reachability is what the attacker has.

v2's shape is:

```
agent  ──►  local security boundary  ──►  controlled process / network / effect plane
```

The boundary is the thing that holds authority. The agent does not hold the credential, does
not hold the permit, and does not get to decide whether the call happens.

## Components

```
                        ┌───────────────────────────────────────────────┐
                        │                 control plane                │
                        │   policy source · identity service · issuer   │
                        └───────┬────────────────────────┬──────────────┘
                     signed bundle│              short-lived identity│
                                ▼                                ▼
  ┌──────────────────────────────────────────────────────────────────────┐
  │                        agent container                               │
  │                                                                       │
  │   ┌──────────┐   request    ┌───────────────────────────────────────┐ │
  │   │  LLM /   │─────────────►│  sidecar (the security boundary)      │ │
  │   │  agent   │◄─────────────│                                        │ │
  │   └──────────┘  allow/deny  │  · policy lease (signed, S11)          │ │
  │                             │  · tool manifest check                 │ │
  │   no credential             │  · network destination allowlist (S3) │ │
  │   ever enters               │  · delegation scope algebra (S5, S6)   │ │
  │   this box                  │  · permit issuance (S7–S9)             │ │
  │                             └───────┬───────────────────┬────────────┘ │
  └─────────────────────────────────────│───────────────────│──────────────┘
                                        │ execute           │ execute
                                        ▼                   ▼
                          ┌───────────────────┐   ┌────────────────────────┐
                          │  capability       │   │  effect gateway        │
                          │  broker           │   │  · permit verify        │
                          │  holds the        │   │  · nonce consume (S9)   │
                          │  credential       │   │  · action digest (S8)  │
                          │  (S1)             │   │  · label check (S10)   │
                          └───────────────────┘   │  · evidence first(S13) │
                                                └───┴────────────────────┘
                                                        │
                                                        ▼
                                          ┌──────────────────────────┐
                                          │  evidence chain          │
                                          │  hash-chained, signed,   │
                                          │  verifiable offline      │
                                          └──────────────────────────┘
```

### Signed policy bundle

The unit of local enforcement state. Carries an Ed25519 signature over a canonical
serialization of the body, so a sidecar can distinguish an authentic bundle from a forged one
without a database round-trip. `version` is a strictly increasing integer per tenant, which
makes rollback to a previously valid bundle detectable — a signature alone does not catch that.

This is the piece v1 lacked. v1 stored bundles as a database row with `source_hash` and an
`active` flag. A hash detects corruption; it does not establish authenticity, because anyone
who can write the row can recompute the digest.

### Signature algorithm registry

Every signed document — bundle, revocation snapshot, security context envelope, effect permit —
resolves its algorithm through `getSignatureAlgorithm` before verifying anything. The registry
holds exactly one entry, `ed25519`. An unrecognised name is `unsupported_algorithm`, never a
fallback.

The registry exists so a second algorithm could be added without touching call sites, and Phase P
measured what that would cost without adding one. A test scans `src/` and fails if any file calls
`registerSignatureAlgorithm`: widening what the enforcement path accepts is a decision that has
to be visible in review, not a side effect of a measurement. See "Post-quantum signatures" below.

### Sidecar

The security boundary. Holds the signed policy lease, so it keeps enforcing when the control
plane is unreachable (S11). Checks, in order: tenant, issuer trust, signature, expiry, version
monotonicity; then tool manifest, then delegation scope; then network destination allowlist;
then effect permit issuance.

Every rejection is fail-closed. An unparseable bundle, an untrusted issuer, an expired lease —
all refuse, none degrade.

### Capability broker

The only component that holds a downstream credential. The agent sends a grant; the broker
exchanges it for a short-lived credential, uses it, and returns **data only**. The broker
independently checks the returned value for credential-shaped keys before handing it back.

The distinction that matters: the agent can request `grant://github/org/repo/issues/read`, and
what comes back is issues. What does not come back is the token that would let the agent do
that itself.

### Effect gateway

The point where something real happens in the world — a file write, an HTTP call, a merge.
Every such effect needs a permit bound to a digest of the exact canonical action (S7). Changing
the tool, resource, or any argument value changes the digest, and the permit stops verifying
(S8). Permits are single-use, nonce-bound, and short-lived (S9).

Authorization is written to the evidence chain **before** the effect runs. If the evidence
cannot be recorded, the effect does not happen. An unrecorded effect is worse than a denied
one, because it cannot be audited.

### Evidence chain

Hash-chained, per-record-signed, with an offline verifier (`actant verify`). A record's payload
is redacted before hashing: `redactSensitive` matches property *names* against a credential
pattern and replaces matching values. Note the limit this implies — a credential embedded in a
free-text string, such as a bearer token inside a command line, is not caught by name matching
alone. The Tetragon adapter handles that case by recording a digest of the command line rather
than the command line itself.

## Where enforcement lives, per invariant

| Invariant | Enforced by | Verified by |
| --- | --- | --- |
| S1 credentials out of context | capability broker, `assertNoCredentialsInResult` | `capability-broker.test.ts`, `demo.test.ts` |
| S2 no unrestricted egress | network cell (network namespace) | Docker `--network none` → `ENETUNREACH` (measured) |
| S3 no policy bypass via alternate transport | sidecar destination allowlist | `network-target-guard.test.ts`, bench scenarios 5–6 |
| S4 distinct short-lived identity | signed workload identity; SPIFFE JWT-SVID when attested | `identity-delegation.test.ts`, `workload-identity-provider.test.ts`, `spire-identity-runtime.test.ts` |
| S5 no implicit transitive trust | per-hop delegation resolution | `identity-delegation.test.ts` |
| S6 delegation narrows only | scope algebra | `identity-delegation.test.ts` |
| S7 authorization bound to action | effect permit digest | `effect-permit.test.ts` |
| S8 mutation invalidates authorization | action digest comparison | `effect-permit.test.ts` |
| S9 single-use, nonce-bound | `NonceStore.consume`; signed revocation snapshots with anti-rollback versions | `effect-permit.test.ts`, `failure-semantics.test.ts`, `revocation-snapshot.test.ts`, `revocation-runtime.test.ts` |
| S10 no flow to lower-clearance sink | boundary IFC | `ifc` cases in `capability-broker.test.ts`, bench scenario 22 |
| S11 local enforcement without round-trip | signed policy lease | `failure-semantics.test.ts` |
| S12 fail closed | every verification path | `failure-semantics.test.ts`, `signed-policy-bundle.test.ts` |
| S13 verifiable evidence | evidence chain + offline verifier | `cli-verify-evidence.test.ts`, `demo.test.ts` |
| S14 LLM is a signal, not authority | no LLM output is read by any enforcement path | architectural; stated below |

### On S14 specifically

No enforcement path in this codebase reads a model output. The risk signals that exist —
`risk_profile.requires_effect_permit` in the bundle, for instance — come from the signed policy
bundle, which an LLM cannot write. The model may propose; the bundle decides.

This is no longer left to inspection. `src/v2/llm-authority.test.ts` (9 tests) sends the sidecar
every advisory field a model-backed classifier might plausibly emit — `model_approved`,
`model_risk_score`, `model_confidence`, `model_rationale`, `llm_verdict`, `semantic_class`,
`human_reviewed` — and asserts the decision is identical to the decision made without them, across
five deny paths: out-of-scope tool, missing workload identity, expired bundle, missing effect
permit, and a network target outside the bundle. Two further tests pin why: the request schema is
a closed Zod object, so unknown keys are stripped before any decision code runs, and no v2
enforcement module imports a model client.

The point is not that the model is untrustworthy. The point is that its output is structurally
incapable of being authority.

## Measured substrate behaviour

Everything below was measured on this host, not inferred. Reproduce with
`docs/SECURITY_TEST_MATRIX.md`.

### Network cell — VERIFIED

| Configuration | Result |
| --- | --- |
| Default bridge, `wget https://example.com` | `EGRESS_ALLOWED` |
| `--network none`, `wget https://example.com` | `EGRESS_BLOCKED` |
| `--network none`, raw Node TCP socket to `93.184.216.34:443` | `CONNECT_ERROR:ENETUNREACH` |
| internal cell network, `wget https://example.com` | `EGRESS_BLOCKED` |
| internal cell network, raw socket to `93.184.216.34:443` | `EGRESS_BLOCKED` |
| internal cell network, raw socket to `169.254.169.254:80` | `EGRESS_BLOCKED` |
| internal cell network, `nslookup example.com` | `SERVFAIL` |
| internal cell network, `wget http://<peer>:8080/` | reaches the peer |

The last four rows are asserted by `src/v2/egress-proxy-topology.test.ts` against real containers,
so the cell's central claim is a test result rather than a paragraph. The default bridge provides
**no** isolation. The block is kernel-level, not application-level: a raw socket cannot route
around it.

### Controlled egress cell — `ACTANTOS_EGRESS_CELL`

Three operator-scoped modes, parsed strictly at startup; an unrecognised value throws rather than
falling back, because the default is `none` and a typo would otherwise run no cell while looking
configured.

```
                  ┌──────────────────────── actantos_egress_cell (--internal) ─────┐
                  │                                                              │
  workload ───────┤  agent workload, --read-only, cap-drop ALL, --network <cell>  │
                  │        │                                                     │
                  │        │ CONNECT host:port  +  Proxy-Authorization: <ticket>  │
                  │        ▼                                                     │
                  │  egress proxy  ── resolve ──►  deny if not public+allowlisted  │
                  │        │                                                     │
                  └────────┼─────────────────────────────────────────────────────┘
                           │ second network interface (the only way out)
                           ▼
                    default bridge ──► internet
```

| Mode | Workload network | A network-capable call |
| --- | --- | --- |
| `none` | `--network none` | Fails at connect time inside the workload |
| `broker_only` | `--network none` | Denied at decision time, `egress_broker_required` |
| `egress_proxy` | internal cell network | Allowed through the proxy; destination enforced at connect time |

The proxy must be the only member of the cell network besides the workloads, and must be attached
to a second network that has a route out. **That is a deployment property and nothing in the test
suite asserts it** — the topology tests prove the cell network blocks egress and that a peer is
reachable; they do not prove which container that peer is. A workload that could reach another
peer on the cell network could reach whatever that peer can reach.

The four checks the proxy applies, in order, all of which deny:

1. **Ticket.** Signed, single-use, expiring, and naming this exact destination.
2. **Host.** In the ticket's destination set *and* in the cell allowlist.
3. **Address.** Every address the host resolves to is public and allowlisted; the connection is
   pinned to one that passed. The proxy resolves the name itself, so `http://2852039166/`,
   `::ffff:169.254.169.254` and a rebinding to `169.254.169.254` all arrive as the same address and
   are all refused.
4. **Port.** One the cell permits.

A resolver failure denies. So does an unreachable replay store, under a distinct reason code from a
policy denial, because "the database is down" and "this permit was already used" are different
incidents and an operator must not have to guess which one they are looking at. `runsc` (gVisor) is now installed and the gVisor cell is
**VERIFIED** through the real executor: `dmesg` under the default runtime is refused against the
host kernel, while under `--runtime runsc` it returns gVisor's own userspace kernel boot log, and
egress remains blocked. Details and provisioning notes are in `docs/SECURITY_TEST_MATRIX.md`.

### Workload identity — `ACTANTOS_FABRIC_IDENTITY_SOURCE`

```
   control plane                                  sidecar
   ─────────────                                  ───────
   ACTANTOS_FABRIC_IDENTITY_SOURCE
     ├── local_key (default)
     │     sign with ACTANTOS_FABRIC_IDENTITY_KEY ──────────▶ verify against
     │                                                          trusted issuer keys
     └── spire
           GET /workload-api/jwt-svid?spiffe_id=…
                 │
                 ▼
           spire-agent  ──attests──▶  spire-server
                                        │
                 ◀──── JWT-SVID, signed by the trust domain
           verify against the trust domain's JWKS
           (fail closed on any mismatch)
                 │
                 └── the verified JWT itself ──────────────▶ verifyIdentityToken:
                                                             re-derive the identity from
                                                             those bytes, bind the tenant,
                                                             apply both revocation lists
```

The sidecar holds `spire: { keys, trustDomain, audience }` as configuration and verifies on its own.
It does not ask the control plane whether an SVID is good: that would put the control plane back on
the request path, which is the round trip the signed policy lease exists to remove (S11).

**Why only the token crosses the wire.** `createSpireIdentityProvider` returns
`{ token, identity }`, and only `token` is sent. The sidecar re-derives the identity from those
exact bytes. Sending the parsed identity instead would mean the object being asserted is not the
object that was signed, and the signature would be verifying nothing.

**Why `local_key` remains the default.** It is the only mode that works without SPIRE deployed, so
making `spire` the default would break every existing deployment on upgrade. It is documented as
weaker, not presented as equivalent: with a local key the signature proves only that the caller
held the key, which is also what an attacker reading the environment variable can prove. An
unrecognised value throws at startup rather than falling back, because the fallback is the weaker
mode.

### Revocation — signed, versioned, local

```
   control plane                       sidecar (RevocationStore)
   ────────────                       ─────────────────────────
   signs snapshot v=N
   { snapshot_id, tenant_id, version,
     issued_at, expires_at,
     entries: [ {agent_id|nonce|permit_id,
                  reason, revoked_at} ] }
          │
          ▼
   offer() ─────────────────────────▶ verify signature, issuer,
                                       tenant, window, and
                                       version > highest applied
                                          │
                    ┌─────────────────────┴─────────────────────┐
                    │ refused: keep the previous snapshot      │ accepted: replace
                    └───────────────────────────────────────────┘

   read path, per request:
     verify identity  →  isAgentRevoked / isNonceRevoked  →  deny("identity_revoked")
```

Three properties the shape exists to provide:

* **Attributable absence.** A `ReadonlySet` handed in by a caller proves nothing about what was
  *not* revoked. A signature over the document is what makes "this agent is not on the list" a
  statement rather than an assumption.
* **Refusal never clears.** A rejected push leaves the previous snapshot enforced. Clearing on
  error is how a corrupted or forged push becomes a mass un-revocation.
* **Expired is not empty.** An expired snapshot's entries are still denied. Empty means nothing is
  known; expired means what was signed still holds. Collapsing them would turn a control-plane
  outage into an un-revocation.

There is no un-revoke operation. An entry stops applying when a **higher version** omits it;
replaying an older one is refused as `version_rollback`.

`propagationAgeMs()` reports how long since the last accepted snapshot. This is the SLO instrument:
an enforcement point can be enforcing correctly and still be unable to accept *new* revocations,
which `state()` alone does not reveal.

### Credential mediation — the broker is the only holder

```
   agent (untrusted)                 broker                        vendor
   ────────────────                 ──────                        ──────
   grant://github/org/repo/
       issues/read
          │
          │  1. verify workload identity      (phases H, I)
          │  2. resolve grant, find provider
          │  3. grant ⊆ authority in signed bundle
          ▼
   CapabilityBroker ──── obtain(grant, {tenant, agent}) ───▶ GitHub App: RS256 JWT
          │                                               → installation token (1 h)
          │                                               AWS STS: SigV4 AssumeRole
          │                                                 → session named for the agent
          │                                               Vault: AppRole → lease
          │  4. refuse an already-expired or undatable credential
          │  5. provider.execute(credential) ─────────────▶ real API call
          │  6. field-name check  AND  value-echo check    ◀── result only
          │  7. destroy(credential) ─────────────────────▶ revoke the exact lease
          ▼
   result  ──▶ agent            credential never crosses back
```

The load-bearing line is step 6. The broker is holding the credential, so it does not have to infer
whether the result is safe from the *shape* of the result — it compares against the exact value it
issued. A provider returning `{ data: "<token>" }` passes every field-name pattern; it cannot pass
this.

`obtain()` receives the verified identity because a credential that is not bound to a caller cannot
be attributed to one. An AWS session named from a constant records that "actant" happened, which is
not the same statement as "reviewer-1 happened".

### Security context envelope — signed, nonce-bound, narrowing only

```
   control plane                        agent                        enforcement point
   ────────────                        ─────                        ─────────────────
   signs envelope v=N
   { envelope_id, tenant_id, spiffe_id,
     nonce,                 ◀── the per-execution nonce
     version, issued_at,           from phase H
     expires_at,
     context: { clearance, grants,
       tools, hosts, depth } }
          │
          ▼
   ┌────────────┐   presents envelope    ┌──────────────┐
   │  agent     │─── + identity ────────▶│  verify:     │
   │            │                       │  signature   │
   └────────────┘                       │  tenant      │
                                        │  subject     │
                                        │  nonce       │  ← same execution only
                                        │  window      │
                                        │  version     │  ← anti-rollback
                                        └──────┬───────┘
                                               │ signature says the control plane
                                               │ issued *something*
                                               ▼
                                        ┌──────────────┐
                                        │  narrow:     │
                                        │  grants ⊆    │
                                        │  tools ⊆     │
                                        │  hosts ⊆     │
                                        │  clearance ≤ │  ← ceiling read from the
                                        │  depth ≤     │     signed policy bundle
                                        └──────────────┘
```

The two boxes are separate on purpose. The first answers "did the control plane issue this?"; the
second answers "is it still inside what the policy in force allows?". Only the first is a signature
check, and only the first is satisfied by every genuinely issued envelope — including a stale one
issued under a wider bundle. Without the second, narrowing policy would be revocable by waiting.

### Post-quantum signatures — MEASURED, NOT ADOPTED

Phase P measured ML-DSA-44, ML-DSA-65 and SLH-DSA-SHA2-128s against Ed25519 through `node:crypto`
on this runtime. Verification is not the obstacle: ML-DSA verifies faster than Ed25519 here,
because the fabric signs canonical JSON of a few kilobytes rather than a pre-computed digest. The
obstacle is key generation — `generateKeyPairSync("ML-DSA-44")` throws on this Node, so a lattice
migration would have to source issuer keys from the `openssl` CLI or a pre-shipped PEM. SLH-DSA
generates keys natively but its signature is 7,856 bytes, which lands on the security context
envelope and the effect permit, both per-execution.

Nothing was registered. The tests build documents carrying cryptographically valid ML-DSA and
SLH-DSA signatures and assert they are refused.

### WASI as a containment substrate — MEASURED, NOT ADOPTED

A real `wasm32-wasip1` guest (`experiments/wasi-guest`) probed its own boundary under Node's WASI.
The containment is genuine and it is not the containment this design needs. Traversal out of a
preopen is `ENOTCAPABLE`; there are no socket syscalls; the environment is empty unless passed. But
the same module reads different files under different preopens, because every one of those
properties belongs to the import object the host chose. WASI contains a guest from its host, and
this design assumes the host is already compromised. Node's WASI is also in-process, so a
compromised host does not escape it — it picks a different preopen. WASI additionally provides no
workload identity and so cannot carry S4.

### Confidential computing — NOT RUN

No code, no test, no hardware. SEV-SNP needs an AMD EPYC 9004 and TDX needs Intel Sapphire Rapids;
this machine is an Intel Core i7-12700K on Windows and has neither. This is the only technology
that would change the scope statement in "What this design does not claim".

### Tetragon runtime layer — VERIFIED

Load-time behaviour on Tetragon v1.1.2:

- The TracingPolicy emitted by `buildTracingPolicy` — `security_bprm_check`/`Mask`,
  `tcp_connect`/`DPort`, `security_file_permission`/`Equal`+`Mask`, no `labels` — imports and
  reports `enabled` with a loaded sensor. Its BPF maps load successfully. **VERIFIED.**
- `labels` is rejected at kprobe level (YAML/CRD parse error) and at policy level
  (`json: unknown field "labels"`). A policy with no `labels` loads. **VERIFIED.**
- `sys_enter_execve` cannot be attached through `tetra tracingpolicy add`:
  `kprobe spec pre-validation failed: call "sys_enter_execve" type name sys_enter_execve: not
  found`. **VERIFIED.**
- A built-in base sensor fails to load on this kernel:
  `detect modify return syscall ... __x64_sys_getcpu() is not modifiable`. **VERIFIED.**
- `procfs does not appear to be host procfs` is a **false positive on Docker Desktop**: Tetragon
  expects inode `4026531836`, a constant for a bare-metal host init namespace. Measured directly,
  `/host/proc/1/ns/pid` and `/proc/1/ns/pid` were both `pid:[4026532291]`. **VERIFIED as benign
  here; not investigated on bare metal.**

Runtime behaviour — **VERIFIED**. The earlier "observes nothing" conclusion was wrong. The agent
had been started with only `/sys/kernel/tracing` mounted, no host `/proc` bind, no `--procfs`, and
its own PID namespace. Corrected to `--pid=host`, `-v /proc:/host/proc:ro`, and
`tetra run --procfs /host/proc`, the built-in sensor observes processes inside workload containers
— 36/36 forked children in a measured run, each event carrying the container's ID.

A second earlier conclusion — that a container's own PID 1 and any process started by `docker
exec` leave no event — was **also wrong, and is retracted**. Re-measured on a fresh container with
the reader attached *before* the workload runs, PID 1 is observed 1/1 and `docker exec` targets
5/5, each carrying the container ID. The false negative was an artifact of the measurement:
`tetra getevents` reads a ring buffer of roughly 120–210 events that turns over in seconds under
ambient container churn, and every earlier probe ran first and read afterwards.

The eBPF layer therefore provides full `process_exec` attribution for workload containers on this
substrate. It remains a **detection and evidence** layer rather than an enforcement control: no
invariant in this design depends on it. S3 is carried by the sidecar decision layer and the
evidence chain, both verified by executable tests. The reproducible checks — including the
`--entrypoint` override needed to keep a `curlimages/curl` probe alive, and the requirement to
attach the reader first — are in `docs/SECURITY_TEST_MATRIX.md`.

## What this design does not claim

**That any vendor accepts these requests.** The GitHub App, AWS STS and Vault providers speak the
documented protocols over real sockets with real signatures — the SigV4 implementation is pinned to
AWS's published known-answer vector and the documented key-derivation chain, so it is conformant
rather than merely self-consistent. But every test points at a loopback server. Vendor acceptance,
App key provisioning and IAM trust-policy correctness are NOT RUN, and a deployment that has not
exercised them against the real service has not verified them.

**Credentials are released, not erased.** A Vault lease is revoked and the call ends; nothing here
zeroes a credential out of memory afterwards. Node strings are immutable, so "release" is the
honest word and "erasure" would be a claim the runtime cannot support.

**Host-kernel compromise.** Baseline v2 does not claim protection after an attacker has root on
the host kernel. Every control here runs as an ordinary process; root can read the sidecar's
memory, forge its clock, and ptrace the broker. Confidential computing — an attested
enclave with a measured launch — is the future mitigation, and it is the only thing that
actually closes this.

**Bare hostnames in free-form arguments.** The sidecar guard recognises URLs, IPv4 literals,
and bracketed IPv6 literals. A bare hostname in a sentence is not treated as a target, because
guessing would deny legitimate arguments. The network cell is the backstop, and only the
network cell can cover that case completely.

**Shell execution through `@actantos/pi-adapter`.** The security properties in this document are
carried by `actantosd`. `packages/pi-adapter/src/shell_executor.ts` is a divergent fork of
`actantosd/src/docker-executor.ts` that does not bind the command into its decision token, does
not check token expiry, and has no gVisor integration — so S8 and S9 do not hold on that path.
It is reachable from the package entry point. See "An unmet prerequisite, recorded rather than
fixed" in `docs/SECURITY_INVARIANTS.md` for the detail. A deployment routing shell execution
through that package is outside the fabric.

**Unbounded request arguments.** The decision-layer target guard walks the request value under a
fixed node budget (`MAX_TARGET_WALK_NODES`, 10,000 values). A value larger than that is refused as
uninspectable rather than inspected partially — the guard fails closed on its own budget, because
the alternative is deciding on the prefix that happened to be visited while the attacker chooses
where the unvisited tail is. The guard also treats a value that throws on property access (a
`Proxy` trap) as uninspectable. Both are deliberate: `request.args` is written by the agent, and
the guard is on the path where a crash is a denial of service rather than a denial of a request.

**Redirects inside an established tunnel.** The cell constrains where a connection is *opened*, not
where it ends. A CONNECT tunnel is opaque: if the workload fetches an allowlisted URL and that page
302s elsewhere, the proxy is carrying bytes it cannot read. Closing this needs TLS interception with
a proxy-trusted CA inside the workload, which is a larger change with its own key-distribution
problem. Policy that needs the stronger property belongs in the decision-layer allowlist, which
sees the URL before the connection is made.

**Plain HTTP through the proxy.** Only `CONNECT` is supported; an absolute-URI request is refused
with 405 rather than rewritten. Rewriting it correctly is a second protocol implementation with its
own smuggling surface, and every HTTPS-capable client uses CONNECT anyway.

**The proxy is not yet a deployed service.** `src/v2/egress-proxy.ts` is a working, tested
enforcement point, but nothing in `index.ts` starts it and no deployment manifest attaches it to
both networks. Until that exists, `ACTANTOS_EGRESS_CELL=egress_proxy` gives the workload a correct
cell with no proxy in it — which denies everything rather than leaking, so it fails closed, but it
is not yet a usable configuration.

**The JWKS URI is a trust anchor, and nothing here pins it.** Verifying an SVID against
`ACTANTOS_SPIRE_JWKS_URI` proves the trust domain signed it — and only if that URI actually serves
the trust domain's keys. This is the bootstrap problem: nothing in the client establishes who vouches
for the vouches. An operator must pin the URI, or the bundle, out of band. Without pinning, the
client trusts whatever the configured URL serves, and an attacker who can redirect it can mint
SVIDs the fabric will accept. The client verifies the signature and refuses every mismatch; it does
not and cannot verify the source.

**Node attestation is untested on real infrastructure.** `src/v2/spire-substrate.test.ts` holds four
tests that run against a live SPIRE trust domain. All four skip on this host, because neither
`spire-server` nor `spire-agent` is installed. Every SVID in the passing suite is signed by a key
the test itself generated, so the suite demonstrates this client's verification and the sidecar's
enforcement of it — not that SPIRE issues SVIDs it accepts, and not that one workload is prevented
from obtaining another's identity. S4 is recorded as PARTIAL for that reason.

**Only JWT-SVIDs.** X.509-SVIDs are not supported. Node has no X.509 chain-building API, so
supporting the certificate form would mean hand-rolling chain validation — the one thing this
codebase must never do. JWT-SVIDs are a standard JWS that `node:crypto` verifies directly against a
published JWKS, and nothing about the envelope format here is invented.

**The revocation list does not compact.** A long-running sidecar accumulates entries until the
snapshot is replaced; there is no compaction scheme here. The `ReadonlySet` views handed to the
existing verifier options are also built per request rather than cached — correct, because a stale
cache is an un-revocation, but not free. If either becomes a problem the answer is a different data
structure, not a cache.

**Enforcement via logs.** Nothing in this design treats a log line as enforcement. The Tetragon
adapter writes signed evidence; it stops nothing, and its module comment says so.

## Performance

Measured in-process, 2000 iterations, no transport, UDS round-trip excluded. These catch
structural regressions, not noise.

| Operation | p50 ms | p95 ms | p99 ms |
| --- | --- | --- | --- |
| Sidecar decision (allow) | 0.097 | 0.122 | 0.181 |
| Sidecar decision (deny) | 0.093 | 0.104 | 0.153 |
| Workload identity verify | 0.090 | 0.104 | 0.190 |
| Effect permit issuance | 0.082 | 0.126 | 0.178 |
| Evidence append | 0.081 | 0.148 | 0.269 |
| Capability broker grant | 0.175 | 0.196 | 0.300 |
| Effect through gateway | 0.454 | 0.805 | 1.236 |

Reproduce with `npm run bench:v2`.

## Reference demo

`npm run demo:v2` runs the whole §21 narrative end to end with fixed timestamps: an
Orchestrator delegates a narrowed grant to a Reviewer, the Reviewer performs legitimate work,
six attacks are attempted, the control plane then goes away, and the evidence bundle is
verified offline. It exits non-zero if any attack succeeds, if a credential reaches the agent,
or if the evidence fails to verify.