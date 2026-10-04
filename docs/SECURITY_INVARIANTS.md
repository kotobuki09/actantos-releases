# ActantOS v2 Security Invariants

Status: v2 security fabric implemented; v1 paths unchanged
Date: 2026-10-03
Rule: an invariant is not satisfied until an executable test demonstrates both the allow
path and the deny/bypass path, and the resulting external state is checked.

Evidence lives in `docs/SECURITY_TEST_MATRIX.md`, which records every measurement including
the ones that failed. Anything not demonstrated there is reported as NOT_RUN, not as held.

## Status legend

| Symbol | Meaning |
|---|---|
| **HELD** | Enforced and demonstrated by a passing executable test, allow path and deny path |
| **VERIFIED** | Demonstrated by measurement on a real substrate; not itself an invariant |
| **PARTIAL** | Mechanism exists with a demonstrated gap |
| **NOT RUN** | Specified and implemented, but not exercised on the available substrate |
| **ABSENT** | No mechanism exists |

Twelve of the fourteen invariants are **HELD**. **S4 is `PARTIAL`** and says so in the table
below; every other status is **HELD**. The two rows at the foot of that table are not invariants:
they are extra layers, and they are recorded because they were measured, not because any
invariant depends on them.

## Invariant matrix — v2 status

| ID | Invariant | v1 | v2 status | Enforcement point | Evidence |
|---|---|---|---|---|---|
| S1 | Production credentials never enter LLM/agent reasoning context | ABSENT | **HELD** | capability broker: field-name check *and* a value-echo check against the credential the broker is holding; real GitHub App / AWS STS / Vault providers | `capability-broker.test.ts` (17), `demo.test.ts`, `provider-signing.test.ts` (13), `providers-production.test.ts` (26) |
| S2 | Agent workloads have no unrestricted network egress | PARTIAL | **HELD** | internal Docker cell network plus a connect-time egress proxy | `docker-executor.test.ts` (30), `egress-cell.test.ts` (23), `egress-proxy.test.ts` (24), `egress-cell-runtime.test.ts` (5), `egress-proxy-topology.test.ts` (4, real Docker), `docker-executor-substrate.test.ts` (the cell itself: the executor provisions `actantos_egress_cell`, the daemon reports `Internal: true`, and a workload on it cannot resolve a name — mutation-checked by dropping `--internal`, which let a container resolve `example.com`) |
| S3 | Cannot bypass policy via curl/socket/node/shell/child/MCP/IPv6/DNS | PARTIAL | **HELD** | sidecar destination allowlist, plus the cell for anything it cannot see | `network-target-guard.test.ts` (26), `egress-proxy-topology.test.ts` (raw socket and metadata probes), bench 5–6, 7–10 |
| S4 | Every agent has a distinct short-lived workload identity | ABSENT | **PARTIAL** | signed workload identity, and the JWT-SVID path is now proven against a live SPIRE 1.15.3 trust domain: this project's own gRPC client obtains an SVID and the trust domain refuses to issue for a workload with no entry for it | `identity-delegation.test.ts` (31), `workload-identity-provider.test.ts` (73), `spiffe-workload-api.test.ts` (13), `spire-identity-runtime.test.ts` (8), `spire-substrate.test.ts` (11, gated on a trust domain whose Workload API socket exists; **11 of 11 run** against a live SPIRE 1.15.3 trust domain in WSL2). Downgrade explained by the registered substrate `spire-workload-identity`, level REAL_SUBSTRATE |
| S5 | Agent-to-agent trust is never implicitly transitive | ABSENT | **HELD** | per-hop delegation resolution | `identity-delegation.test.ts` |
| S6 | Delegation may narrow but never increase authority | ABSENT | **HELD** | scope algebra, plus a narrowing-only envelope check against the signed lease | `identity-delegation.test.ts`, `security-context-envelope.test.ts` (29) |
| S7 | Sensitive effects require authorization bound to the exact canonical action | PARTIAL | **HELD** | effect permit action digest; Ed25519 decision tokens, so the verifier cannot also be the issuer | `effect-permit.test.ts` (30), `decision-token-signature.test.ts` (12), `docker-executor.test.ts` S7 cases (3), `shell_executor.test.ts` S7 cases (4), `docker-executor-substrate.test.ts` (the Ed25519 path against real containers: an asymmetric token starts one, an HMAC token under the same verifier is refused, and a well-formed token signed by an untrusted key is refused — mutation-checked by removing the signature check, which ran a container for the forgery) |
| S8 | Changing target or parameters after authorization invalidates it | PARTIAL | **HELD** | action digest comparison; `command_hash` on both shell executors | `effect-permit.test.ts`, bench 12–13, `decision-command.test.ts`, `docker-executor.test.ts`, `shell_executor.test.ts` |
| S9 | Authorization is short-lived, single-use, nonce-bound, replay-resistant | ABSENT | **HELD** | `ReplayStore.consume` (durable); `InMemoryDecisionNonceStore` on the executor path (per-process); signed revocation snapshots with anti-rollback versions | `effect-permit.test.ts`, `replay-store.test.ts` (17), `effect-gateway-replay.test.ts` (7), `decision-nonce-store.test.ts` (9), `revocation-snapshot.test.ts` (31), `revocation-runtime.test.ts` (8), bench 11, 14–16 |
| S10 | Higher-sensitivity data may not flow into a lower-clearance sink | ABSENT | **HELD** | boundary IFC; an envelope cannot raise its own clearance | `capability-broker.test.ts`, `security-context-envelope.test.ts` (29), bench 20 |
| S11 | Local enforcement continues without a control-plane round-trip | ABSENT | **HELD** | signed policy lease, enforced in a separate process behind a local socket, consulted by the live server | `failure-semantics.test.ts` (8), `sidecar-server.test.ts` (11), `fabric.test.ts` (18), `fabric-runtime.test.ts` (9), bench 22 |
| S12 | Expired or unverifiable security state fails closed | PARTIAL | **HELD** | every verification path | `failure-semantics.test.ts` (4 named S12, 8 total), `signed-policy-bundle.test.ts` (15), `sidecar-server.test.ts` (6 transport), `fabric.test.ts` (9), `fabric-runtime.test.ts` (4), `fail-closed.test.ts` (4), `sandbox-runtime.test.ts` (13) |
| S13 | Every important effect produces verifiable evidence | PARTIAL | **HELD** | hash-chained signed evidence, durable append-only store, commit protocol journal | `cli-verify-evidence.test.ts` (8), `audit-chain-verifier.test.ts` (2), `evidence-store.test.ts` (13 pure + 14 on PostgreSQL), `effect-commit.test.ts` (17 pure + 10 on PostgreSQL), bench 26 |
| S14 | The LLM may give semantic signals but is never final authority | PARTIAL | **HELD** | closed request schema | `llm-authority.test.ts` (9) — new; was previously architectural only |
| — | Tetragon runtime observation as a second detection layer | ABSENT | **VERIFIED** (detection, not enforcement) | eBPF kprobes | policy loads; PID 1, `docker exec`, and in-container forks all observed — see matrix |
| — | gVisor userspace-kernel sandbox as a second barrier | ABSENT | **HELD** (hardening, not an invariant) | `runsc` runtime | the same image and daemon run on two different kernels depending only on the runtime flag, and `dmesg` returns gVisor's own boot log where the host ring buffer is refused. **Egress is not claimed from this host**: its bridge has no external route for *either* runtime, so blocked egress there cannot be attributed to gVisor's netstack |

## What the four "PARTIAL → HELD" changes actually were

### S1 — the credential-key coverage was an illusion, and was fixed

`assertNoCredentialsInResult` guards S1 by refusing any result object whose keys match
`/pass|secret|token|api[_-]?key|private[_-]?key|authorization|credential|bearer|session[_-]?key/`.

Mutation testing found that **deleting the standalone `credential` alternative from that pattern
left all 14 broker tests passing.** The two deny tests used `access_token` and `api_key`, and both
are still caught by the `token` and `api_key` alternatives. The `credential` branch had never been
exercised. The invariant was real; the evidence for it was not.

Three tests were added. One enumerates every alternative in the pattern plus realistic variants
(`AWS_SECRET_ACCESS_KEY`, `refreshToken`, `x-api-key`) and asserts each is refused. One checks the
guard fires at any nesting depth, including inside arrays. One drives a provider that leaks through
a `credential` key all the way through the broker. Removing the `credential` alternative now fails
all three. `capability-broker.test.ts` is 17 tests.

This is the second time in this project that mutation testing found a passing test that proved
nothing. The first was a Tetragon measurement error; this one was a coverage illusion. Both were
invisible to a green suite.

### S6 — a mixed scope list silently granted authority, and was fixed

`scopeIsNarrowerThan` refuses a parent scope when *any* entry fails to parse:

```ts
if (parsedParent.length !== parent.length) {
  return false
}
```

Mutation testing found that **removing that guard changed no test in the project.** The reason is
that the guard is invisible to the obvious test. When the parent list is *entirely* unparseable,
`parsedParent` becomes empty and the later `.some()` is already false — the denial comes from the
fallback, not the guard. So the existing test "an unparseable parent pattern grants nothing" passed
with or without the line.

The guard only decides the outcome when a list **mixes** a valid grant with a malformed one:

```
parent = ["grant://github/org/repo/**", "not-a-grant"]
child  = ["grant://github/org/repo/issues/read"]

with the guard     -> false   (fail closed)
without the guard  -> true    (authority derived from a scope entry that was never a valid grant)
```

Measured directly against both versions of the function. No existing test covered the mixed case, so
the fail-closed behaviour of the whole list was unverified while appearing verified.

Two regression tests were added: one asserting a malformed entry poisons an otherwise-valid parent
scope, and one covering every malformed-parent shape (`not-a-grant`, `grant://`, an https URI
mixed with a grant, an empty string, and a bare `**`). Removing the guard now fails both.

**Why this matters more than the S1 finding.** The S1 gap meant a pattern branch was never
exercised. This one meant a *deny* could become an *allow*. `authorityFor` returns a
`readonly string[]` assembled by the control plane, so a single malformed entry in a stored scope
would have been silently dropped while the rest of the scope still granted access.

### S11 — bundles are now signed

v1 stored `source_text`, `source_hash` (SHA-256), `active`. A hash detects corruption, not
forgery: anyone who can write the row recomputes the digest. A sidecar therefore could not
distinguish an authentic bundle from a forged one, and the local enforcement lease was not
buildable on v1 data.

v2 adds an Ed25519 signature over the canonical serialization of the bundle body, using Node's
`crypto` behind a swappable algorithm interface. No new cryptographic primitive. `version` is a
strictly increasing integer per tenant, so rollback to a previously valid bundle is detectable —
which a signature alone does not catch.

### S3 — the network guard is an allowlist, not a blocklist

v1's `src/url-target-guard.ts` blocks RFC1918, loopback, link-local, cloud metadata and private
IPv6. That is correct SSRF hygiene at request time, and it stays. It cannot satisfy S3, because
S3 is a statement about the destination: with a blocklist, every destination not yet listed is
a hole.

v2's `src/v2/network-target-guard.ts` collects the network targets a request names — URLs, IPv4
literals, IPv6 literals, wherever they appear — and requires each to be covered by a
`network_rules` entry from the signed bundle. One rule of any host denies the request, so a
payload that names one good host and one bad host is refused.

Honest limit: a bare hostname in free-form prose is not treated as a target, because guessing
would deny legitimate arguments. The network cell is the backstop for that case, and only the
cell covers it completely.

### S7/S8/S9 — permits, not tokens

v1's `signDecisionToken` / `verifyDecisionToken` in `src/hash.ts` use HMAC-SHA256 over a
base64url payload. That authenticates the token to a shared secret but does not bind a canonical
action, carries no nonce, and has no single-use state — replay inside the validity window works.

v2's `EffectPermit` binds `action_digest`, a SHA-256 over the canonical action. A digest rather
than a reference is deliberate: a reference would let the caller swap the target afterwards, and
any change to tool, resource or any argument value produces a different digest. Permits carry a
nonce consumed exactly once, so two concurrent uses of one permit cannot both succeed.

The first implementation consumed that nonce in a process-memory `NonceStore`. That made "cannot
be used twice" true only inside one running process: a restart forgot every consumption, and a
second gateway replica had never heard of the first. The invariant as written says
*authorization is single-use*, with no qualifier about the process that grants it, so the
in-memory set was not a sufficient enforcement.

`ReplayStore` replaces it. First use is claimed with a single
`INSERT ... ON CONFLICT DO NOTHING RETURNING 1` against a table with two unique constraints —
primary key `(tenant_id, nonce)` and unique `(tenant_id, permit_id)`. The database, not the
application, decides the winner, so the guarantee survives a restart and holds across replicas
without coordination. `ON CONFLICT DO NOTHING` is load-bearing rather than stylistic: under
`READ COMMITTED` a read-then-write lets two writers both observe an absent row and both insert.
Applying that mutation made three tests fail, which is how the suite is known to be testing
atomicity rather than merely testing the happy path.

When a `ReplayStore` is configured it is the **only** first-use authority; the in-memory set is
not consulted as a second opinion, because a check that can disagree with the authority is a
second source of truth about whether an effect already happened. If the store is unreachable the
gateway refuses the effect (`replay_store_unavailable`) rather than proceeding on the assumption
that an unreachable store means an unused permit.

### S12 — evidence is written before the effect

A hole found and closed during v2 work: the effect gateway originally executed the effect and
recorded evidence afterwards. A failing evidence sink therefore produced an unrecorded effect,
which is worse than a denied one because it cannot be audited.

The authorization record is now appended before `executor` is called, and a sink failure returns
`evidence_unavailable` without performing the effect.

## Phase F — the fabric is now on the live request path

Until this phase, every v2 module was a correct library that nothing called. The sidecar ran, the
policy lease was honoured, the network guard scanned — and the production server dispatched tool
calls without consulting any of it. The modules were the *fabric*; they were not yet *on*.

### The mode cannot be agent-controlled

v1 already has a request-level `decision_mode` that the caller sets, and its `dry_run` value
suppresses enforcement. That is the correct shape for a v1 compatibility knob and exactly the
wrong shape for the fabric: a knob the agent's own request can set is not a security control,
because the agent's premise is that it is fully compromised. `ACTANTOS_FABRIC_MODE` is read once
from the environment at startup. An unrecognised value **throws and exits** rather than defaulting
to `v1_compat`; a typo in `ACTANTOS_FABRIC_MODE=v2_enforc` silently disabling enforcement is the
single most damaging thing this code could do, and the test for it asserts the throw.

### One gate, one decision function

`src/v2/fabric.ts` exposes `createFabricGate` and `fabricDenial`. The gate is attached in
`src/intercept-service.ts`, immediately after the v1 URL guard — the single point both the HTTP
gateway and the MCP gateway already traverse, so no route can bypass it by choosing a different
entry. The important structural property is that **there is exactly one function that turns an
assessment into a denial.** A caller cannot hold a fabric verdict and quietly act on it, because
`fabricDenial` is what the caller is given, and it returns `null` for `v1_compat` and for every
outcome in `v2_observe` structurally, not by convention.

### Fail-closed has two distinct failures, and they are not the same

`v2_enforce` denies on both a policy denial and an unreachable fabric, but it reports them under
different reason codes — `fabric.network_rule_denied` versus `fabric.unavailable`. An operator who
sees a spike of `fabric.unavailable` is looking at a sidecar outage, not an attack, and collapsing
the two would make the first incident invisible. `fabricDenial` also copies any human-readable
detail from the sidecar into the prose `reason` and keeps `reasonCode` a stable machine token, so
a log pipeline keyed on the code does not break when a message changes.

### The evidence for this phase is mutation, not inspection

None of the three rules above was verified by reading the code. Each was broken deliberately and
the suite was re-run:

| Mutation | Result |
| --- | --- |
| Gate constructed but never consulted (`if (false && …)`) | 4 enforcement tests fail |
| Unreachable fabric fails **open** (`unavailable` → `null`) | 4 tests fail |
| `v2_observe` starts governing (`!==` → `===` in the mode check) | 5 tests fail |

`fabric-runtime.test.ts` drives a real Fastify server against a real sidecar over a real local
socket, with a policy bundle that permits exactly one host. It asserts that `v1_compat` and
`v2_observe` both **allow** a call the fabric denies and that `v2_enforce` **denies** it, and that
`v2_enforce` denies when the sidecar process is simply not there. The observe path is tested by
requiring it to allow, which is the only direction in which an accidental promotion to enforcing
shows up as a failure.

## Phase G — the egress cell was not a cell

### What the name was hiding

`constraints.network_mode` had two values. `none` put the workload on Docker's `--network none`,
which blocks a raw socket at the kernel and was measured doing so. `egress_proxy` selected a plain
user-defined bridge called `actantos_egress`: no proxy process on it, no `--internal` flag, no
firewall, no destination check. Anything on that network could reach anything.

So `egress_proxy` was not a weaker form of containment. It was the **absence** of containment,
under a name that read as its presence. `milestones/A-05-egress-claim-integrity.md` had already
narrowed the written claim to match the code; the code was the problem, and the narrowed claim
still left an operator believing something the deployment did not do.

### What replaced it

`egress_proxy` now selects `actantos_egress_cell`, created with `--internal`. The workload's only
reachable peer is the egress proxy, which authenticates the connection, resolves the destination
itself, refuses any address that is not public and allowlisted, and pins its outbound socket to
the address it just validated.

The topology is asserted against real containers in `egress-proxy-topology.test.ts`, not described
in prose: no HTTPS egress, no raw-socket egress to a public IP, no route to `169.254.169.254`,
`SERVFAIL` from the embedded resolver for any name the cell does not host, and a peer still
reachable by name and by IP so the blocked cases are not merely a dead network.

### Why the proxy resolves the name itself

Because the proxy resolves, the address it validates is the address it connects to. That makes the
whole family of textual tricks irrelevant in one step. `http://2852039166/`,
`http://0177.0.0.1/`, `http://[::ffff:169.254.169.254]/` and a hostname that resolves to
`169.254.169.254` all arrive at the same function as the string `169.254.169.254`, and all four
are refused. A blocklist of encodings would be a list of the encodings somebody thought of.

`64:ff9b::/96` is in the same category: a NAT64 prefix turns any IPv4 literal into a valid IPv6
destination, and a check that only understood `::1` and `fe80::/10` would miss it. So would
`::ffff:0:0/96`. Both are handled by unwrapping the embedded IPv4 and applying the IPv4 rules, so a
public address written in either form is still allowed and a private one is still denied.

### A Node defect found while writing this, and the failure it would have caused

`BlockList.addSubnet("::ffff:0:0", 96, "ipv6")` makes **every** IPv4 check in the same BlockList
return true. Measured on Node v26.4.0:

```
const b = new BlockList()
b.addSubnet("10.0.0.0", 8, "ipv4")
b.check("8.8.8.8", "ipv4")   // false
b.addSubnet("::ffff:0:0", 96, "ipv6")
b.check("8.8.8.8", "ipv4")   // true   <-- every public address now denied
```

`64:ff9b::/96` and `fe80::/10` do not trigger it; the IPv4-mapped prefix specifically does.

The failure direction is the one that would have gone unnoticed. A deny list that has quietly become
a deny-everything list denies the entire internet including the destinations the allowlist permits,
and the symptom is a broken cell rather than an open one — so it would be shipped, and then worked
around by turning the cell off. `egress-cell.ts` keeps the two families in separate BlockLists, and
`egress-cell.test.ts` reproduces the defect and asserts that the split design does not have it, so a
future refactor to a single list fails a test rather than silently breaking every deployment.

### `broker_only` exists so an operator can tell two failures apart

Under `none` a network-capable call is already impossible. It fails inside the workload with
`ENETUNREACH`, which the agent sees and the operator does not — indistinguishable from a bug.
Under `broker_only` the same call is denied at decision time with `egress_broker_required`. The
workload has no network either way; the difference is that one of them is countable.

### The evidence for this phase is mutation, not inspection

| Mutation | Result |
| --- | --- |
| Address check made advisory (log and continue) | 4 tests fail |
| Resolver failure falls through to the raw host | 2 tests fail |
| Ticket no longer binds the destination | 2 tests fail |
| Unrecognised cell mode falls back to the default | 1 test fails |
| `broker_only` check never reached | 1 test fails |

### A second defect found by writing a test rather than by reading code

The executor decided whether an existing cell network was internal by matching the text
`"Internal": true` in `docker network inspect` output. `docker` pretty-prints, and its exact
spacing is not a contract — so the check failed open on any reformatting, which for a security
property means it silently stops checking. It is parsed now, and unparseable output is treated as
"not internal", because the two ways to be wrong are not symmetric: a false refusal costs an
operator one `docker network rm`, and a false accept is an open cell.

## Limits that remain

**S2 / S3 kernel layer.** The sidecar allowlist is a decision-layer control: it constrains
requests that pass through the sidecar. A workload that never speaks to the sidecar is bounded
only by the network cell. Docker `--network none` was measured to block a raw socket at the
kernel level (`ENETUNREACH`). gVisor `runsc` is now installed and the stronger cell is
**VERIFIED**: through the real executor, `dmesg` under `runc` is refused against the host kernel,
while under `runsc` it returns gVisor's own userspace kernel boot log. This is a second
independent barrier, not a replacement for the network cell, and it does not narrow the
host-compound-compromise exclusion below.

**Tetragon.** The generated policy imports and enables on Tetragon v1.1.2. After the agent was
corrected to share the host PID namespace and mount host procfs (`--pid=host`,
`-v /proc:/host/proc:ro`, `--procfs /host/proc`), the built-in sensor observes workload
containers: 36/36 forked processes in a measured run, each event carrying the container's ID.

An earlier revision of this document reported a remaining gap — that a container's own PID 1 and
any process started by `docker exec` left no event. **That claim was false and is retracted.**
Re-measured on a fresh container, PID 1 is observed 1/1 and `docker exec` targets 5/5, each with
the container ID attached. The false negative came from the measurement, not the substrate:
`tetra getevents` returns a *ring buffer* holding roughly 120–210 events on this host, and every
earlier probe ran the workload first and attached a reader afterwards, so the target event had
already rotated out. Attaching the reader first catches the same probes every time. Full
reproduction and the four measurement mistakes are in `docs/SECURITY_TEST_MATRIX.md`.

Tetragon is a **detection and evidence** layer. No invariant depends on it, and it is not an
enforcement control.

**S14 is a property of the protocol, not of a code review.** `src/v2/llm-authority.test.ts`
(9 tests) sends the sidecar every advisory field a model-backed classifier might plausibly emit —
`model_approved`, `model_risk_score`, `model_confidence`, `model_rationale`, `llm_verdict`,
`semantic_class`, `human_reviewed` — and asserts the decision is byte-identical to the decision
made without them, across six deny paths: out-of-scope tool, missing workload identity, expired
bundle, missing effect permit, a credential-labelled message to another agent, and a network
target outside the bundle.

Three further tests pin the structural reason this holds: the request schema is a closed Zod
object, so unknown keys are stripped by `safeParse` before any decision code runs; no v2
enforcement module imports a model client; and the scanner that enforces the last point is itself
tested against every client it claims to detect, plus the near-misses that must not trip it
(`model_provider` as an IFC sink name, and prose mentions).

The point is not that the model is untrustworthy. The point is that its output is structurally
incapable of being authority.

**Deny reasons are asserted, not just "denied".** Two of these six tests originally passed for the
wrong reason: both sent a request that failed schema validation, so the sidecar refused it as
`protocol_version_unsupported` before ever reaching the security check the test claimed to
exercise. They passed while proving nothing. Each now asserts the specific reason
(`identity_invalid`, `ifc_violation`, and explicitly *not* `protocol_version_unsupported` on the
others), so a malformed request can no longer satisfy a deny-path test. All six were then
mutation-tested: injecting `if (raw.model_approved === true) return allow` into `sidecar.ts` fails
all six. A test that cannot fail is not evidence.

**S12 and S13 scope.** Both are HELD for every path v2 introduces, demonstrated by named tests:
S12 by 4 S12-named cases in `failure-semantics.test.ts` plus `signed-policy-bundle.test.ts` (15),
`sidecar-server.test.ts` (6 transport-level), `fail-closed.test.ts` (4), and
`sandbox-runtime.test.ts` (7); S13 by `cli-verify-evidence.test.ts`
(8), `audit-chain-verifier.test.ts` (2), `evidence-store.test.ts` (13 pure, 14 more on real
PostgreSQL), and `effect-commit.test.ts` (25 pure, 10 more on real PostgreSQL). The v1 column remains PARTIAL because the v1 paths are
unchanged by design, not because a v2 mechanism is missing. **No v2 path is exempted.**

**S11 — a class that runs in your own process was never a boundary.** Every sidecar test until
phase E called `handle` directly, in the same process, as the same user. An agent in that
arrangement is not prevented from calling the effect gateway directly; nothing about it stops
one. `sidecar-server.ts` moves enforcement behind a real socket — a Unix domain socket on POSIX, a
named pipe on Windows, because `node:net` refuses filesystem socket paths there. The last test
starts a second process and asserts a decision that came from the *other* process's policy state,
which is the only arrangement in which the claim means anything.

Three transport rules are asserted rather than assumed, and each is a denial:

* A frame that is not JSON is denied. Silence is not an option: an agent that gets no answer will
  eventually find a way to act anyway.
* A frame larger than `MAX_FRAME_BYTES` is denied and the connection closes. A peer that never
  sends a newline must not grow the server's buffer until it dies.
* The sidecar refuses to serve over a socket path that already exists. A leftover socket file is
  the hijack condition: serving over it sends real requests to whoever bound it first.

**A third availability defect, found by the size-limit test rather than by inspection.** The
frame cap passed, the transport passed, and one test still timed out at 69 seconds. The cause was
one layer down: `checkNetworkTargets` in `network-target-guard.ts` was **quadratic in argument
size**. The URL pattern `(?:[a-zA-Z][a-zA-Z0-9+.-]*:)?\/\/(...)` has an optional greedy scheme
group, so the engine retries the match at every start position and backtracks across the whole
remaining run each time. Measured in isolation: 1.8 s at 64 KB, 7.5 s at 128 KB, **31 s at
256 KB** — every one of those frames inside `MAX_FRAME_BYTES`.

This is a denial of service on the boundary, delivered by one well-formed request from one agent
against every other agent sharing the single-threaded sidecar, and it defeats the availability
property the frame cap exists to provide. The fix anchors the pattern with `y` at a `//` located
by a native `indexOf` scan, so there is one match attempt instead of a search: **256 KB now scans
in 0.33 ms**. Two smaller quadratic paths in the same function were fixed at the same time —
`Array.includes` de-duplication (now a `Set`) and three unanchored patterns now guarded by an
`includes` prefilter.

Reverting the scan to its previous shape fails three tests, two on timing and one on correctness:
`"a permitted URL in front of a denied one does not hide it"`. That last one is a real bypass the
old code had — it read only the *first* URL in a string, so `https://allowed.example` placed in
front of `https://evil.example` satisfied the allowlist. `collectNetworkTargets` now checks every
`//`. The 17 pre-existing S3 tests pass under both implementations, which is what establishes
that the rewrite preserved the original semantics rather than redefining them.

**S13 durability — the in-memory chain was not enough.** `EvidenceChain` signed and linked every
record, but it held them in a process array. A restart lost the history, so "every important
effect produces verifiable evidence" was only true until the next deploy. `PostgreSQLEvidenceStore`
moves the chain to a table with `(tenant_id, seq)` as primary key and one row per append, and the
`EffectGateway` now writes there by default.

Three properties had to be earned rather than assumed, and each is mutation-tested:

* **Append order is a security property.** Record N+1's `prev_hash` is record N's hash, so two
  writers appending one tenant concurrently would each build a valid but *different* chain, and
  neither would know. `pg_advisory_xact_lock(hashtext(tenant_id))` serialises them per tenant.
  Removing the lock fails 2 tests.
* **History is unrewritable.** `BEFORE UPDATE OR DELETE` raises. This is a trigger and not a
  `REVOKE` because `FORCE ROW LEVEL SECURITY` closes the table-owner exemption but not the
  superuser exemption, and the migrating role is a superuser — so a `REVOKE` would protect
  against nobody here. Turning the trigger into `RETURN NEW` fails 2 tests.
* **Nothing is silently skipped.** An `unavailable` store or a detected fork makes
  `EffectGateway.#record` throw, so an effect whose evidence did not land does not land either.
  A gateway constructed with neither a chain nor a store refuses to exist at all.

The store also writes checkpoints, which is what lets `auditEvidenceChain` distinguish "this chain
was rewritten from seq 4" from "this chain is genuinely short". Offline verification is unchanged
and still works with no service running: exporting a bundle and calling `verifyEvidenceBundle`
needs only the issuer public key.

**S13 crash accountability — the evidence chain could not say what happened.** Recording the
authorization before the effect and the outcome after it leaves a gap: a process that dies between
the executor returning and the outcome being written leaves an authorization with no execution,
which is indistinguishable from a refusal. The permit is spent either way, so nothing is retried
and nothing is lost — but an operator cannot tell a crash from a refusal, and the journal cannot
say whether the effect reached the real world.

`v2_effect_journal` closes that window with five states: `prepared`, `executing`, `committed`,
`failed`, `uncertain`. `uncertain` is the reason the module exists. Collapsing it into `failed`
invites a retry, and retrying an effect that actually succeeded applies it twice; collapsing it into
`committed` asserts a result nobody observed. Both errors are worse than recorded ignorance, so
recovery resolves every unfinished entry to `uncertain`, signs a receipt, and offers **no retry
action at all** — whether an unknown-outcome effect should be tried again is a decision for someone
who can look at the external system.

The transition table is enforced twice. In application code, because that is where a caller can be
mistaken. In the database, as `BEFORE UPDATE` triggers, because application code is the thing that
crashed. Three mutations confirm the second line is real rather than decorative: allowing every
transition fails 2 tests, dropping the terminal-outcome check fails 1, and widening the RLS policy
fails 1. The last of these also caught a genuine gap during development — a same-state `UPDATE`
could rewrite `result_digest` on an already-committed row, which would have let the journal
disagree with the world it describes.

**gVisor fail-open — RESOLVED.** This was previously listed as a remaining S12 gap: the
executor warned and continued on the default runtime when `runsc` was missing, and the startup
path did the same while preflight failed hard. Now `src/sandbox-runtime.ts` owns the decision
and all three call it. A required-but-missing runtime raises `SandboxRuntimeUnavailableError`
before the Docker network is created and before the image is pulled; in strict mode
(`ACTANTOS_GVISOR_STRICT=true` or `NODE_ENV=production`) the server exits rather than listening.
The old message claimed containers "will fall back" to `runc` — which never happened, since
`--runtime runsc` was still passed and Docker failed later. That text is gone, and a test
asserts it does not come back.

Covered by `src/sandbox-runtime.test.ts` (7), `src/docker-executor.test.ts` (15), and
`src/server-startup-sandbox.test.ts` (4), the last of which runs the real entry point as a
subprocess and asserts on the exit code.

**Host-kernel compromise.** Not claimed by either version. Every control runs as an ordinary
process; root can read the sidecar's memory and ptrace the broker.

## Phase H — S4 was the one invariant the local key could not carry

### Why a signed identity was not enough

Phases A–G signed a workload identity with an Ed25519 key the daemon read from
`ACTANTOS_FABRIC_IDENTITY_KEY`. The signature is real and the token is real, and the property it
establishes is narrow: **somebody holding this key issued this token**. That is also what an
attacker who has read the environment variable can establish, and it cannot distinguish agent A from
agent B, or an agent from the control plane itself.

S4 asks for a *distinct* identity per agent execution. Distinctness has to come from somewhere the
agent does not control, or it is a claim rather than a property. A key the process holds cannot be
that somewhere.

### What replaced it

`ACTANTOS_FABRIC_IDENTITY_SOURCE` selects between two modes, and an unrecognised value **throws at
startup** for the same reason `ACTANTOS_FABRIC_MODE` does: the default is the weaker mode, so a
typo falling back to it would remove attestation while an operator believed it was in force.

* `local_key` (default) — unchanged. It keeps working without SPIRE, and it is documented as the
  weaker option rather than presented as equivalent.
* `spire` — the workload asks the SPIFFE Workload API for a JWT-SVID. The workload never holds a
  signing key and cannot obtain an SVID for a different workload, because the trust domain decides.
  The SVID is verified against the trust domain's published JWKS **twice**: once by the control
  plane before it is used, and again by the sidecar, which does not take the control plane's word
  for it.

### Why the sidecar verifies the SVID itself

The obvious shortcut is to let the control plane verify the SVID and hand the sidecar a parsed
identity. That would make the signature verify nothing: the object being asserted would not be the
bytes that were signed. So the provider returns `{ token, identity }`, only `token` crosses the
wire, and `verifyIdentityToken` in the sidecar re-derives the identity from those exact bytes —
including tenant binding and both revocation lists.

A deployment with no SPIRE keys refuses a JWT-SVID outright rather than falling back to the
envelope path. "Not configured" must never mean "trusted".

### Two real defects this phase found

**Node has no `createVerify("Ed25519")`.** Ed25519 is not a digest; `createVerify` throws
`Invalid digest`. The first implementation mapped the JWS `alg` to a digest name and Ed25519
verification silently never worked — every Ed25519 token was refused as `signature_invalid`, which
is at least fail-closed, but the mode was non-functional while looking correct. The RS256 path
passed throughout, which is exactly the kind of partial green that hides a broken branch.

**An unsupported algorithm reported the wrong reason.** `HS256` fell through the key lookup and was
refused as `signature_invalid`, telling an operator their trust domain published a bad key when the
real answer was that the caller asked for an algorithm SPIFFE does not issue. The whitelist is now
checked before the key is looked up.

### Where S4 stands now

The verification and enforcement path is verified: 61 tests, real `node:crypto`, a real sidecar on a
real socket, a real HTTP Workload API, and 11 mutations each of which produced failing tests. Three
mutations initially survived — the ones at the sidecar's own verifier — which is why
`verifyIdentityToken` is now tested directly instead of only through a client that had already
verified the same token.

### Four more defects, found by running it against a real trust domain

Every SVID in the suite above is signed by a key the test generated, so it stands in for the wire
format, not for the attestation. A SPIRE 1.15.3 trust domain was stood up inside WSL2 — a real
server, a join-token-attested agent, a registration entry for `t_spire/pi_demo`, and a bundle
endpoint publishing the trust domain's JWKS — and the same file was pointed at it. It could not
interoperate with SPIRE at all. Four independent defects, each measured rather than inferred:

1. **Transport.** The Workload API is gRPC over a Unix socket. The exact
   `GET /workload-api/jwt-svid?spiffe_id=…` that `requestSvid` performed got the connection reset;
   no SPIRE version serves it, and `fetch` cannot open a Unix socket at all.
2. **Algorithm.** SPIRE signs JWT-SVIDs with **ES256**. The whitelist held `Ed25519` and `RS256`
   only, so a genuine SVID was refused as `unsupported_algorithm` before its signature was examined.
3. **Issuer.** SPIRE emits **no `iss` claim**. Requiring `iss` to equal `spiffe://<trust domain>`
   meant that fixing (2) alone would have moved the refusal to `wrong_trust_domain`.
4. **ECDSA encoding.** JWS specifies a raw `R‖S` signature; `node:crypto`'s `verify` accepts only
   DER. The same signature verifies as DER and is rejected raw, so whitelisting ES256 would not
   have been sufficient on its own.

The signature was genuine throughout — it verified against the trust domain's own published key — so
none of this is a forgery finding. It is a client that had only ever been proven against a stub.

All four are now fixed. `src/v2/spiffe-workload-api.ts` speaks the agent's actual gRPC: method
`/SpiffeWorkloadAPI/FetchJWTSVID`, the header `workload.spiffe.io: true`, and `JWTSVIDRequest` field
numbers 1 (`audience`) and 2 (`spiffe_id`), each taken from the agent rather than from the proto
documentation. That last point is not pedantic: a wrong field number is answered with a
plausible-looking "invalid requested SPIFFE ID" error rather than a parse error, so the first
attempt got a real-looking answer to the wrong question. `rawEcdsaToDer` re-encodes the signature
before handing it to `node:crypto`, with both branches of its leading-zero rule tested
deterministically rather than by a sampling loop. The trust domain is read from the subject SPIFFE
ID, which is where SPIRE puts it, and a disagreeing `iss` is still refused — so not requiring a
claim SPIRE does not send did not mean trusting an unchecked subject.

Adding ES256 is conformance to the SPIFFE JWT-SVID profile, not a widening of what verifies: it is
pinned to `kty: EC` and `crv: P-256`, which is the only curve `ES256` names, and no other ECDSA
curve is accepted.

### Where S4 stands now

`src/v2/spire-substrate.test.ts` runs **eleven of eleven, skipped zero, against a live trust
domain**. One obtains an SVID through this project's own gRPC client rather than through
`spire-agent api fetch` — the CLI would prove something about SPIRE, not about the code under test.
One verifies it against the trust domain's published key. One asserts SPIRE still signs ES256 with
no `iss`, so a change in either is reported rather than absorbed. One proves the raw signature does
*not* verify unconverted while this project's conversion does. One issues a real identity through
the provider. Two assert that the trust domain refuses an SVID for a workload with no entry for it
and refuses a foreign SPIFFE ID — that pair is the S4 claim itself. One asserts this client's SVID
names the same subject and audience as SPIRE's own client's. `spire-workload-identity` is
therefore **REAL_SUBSTRATE**.

**What is still not claimed.** The Workload API is gRPC over a Unix domain socket, so on a Windows
host those eleven tests skip whatever is installed; the run was done inside WSL2, and
`substrate_run` reports the socket separately from the binaries so that skip is not read as "SPIRE
missing". One mutation is **not** caught by the gated file: removing the subject trust-domain check
entirely leaves all eleven green, because a well-behaved authority only ever issues for its own
trust domain. A foreign-domain token has to be synthetic, so that property is asserted in
`workload-identity-provider.test.ts` instead, including the prefix-confusion case
(`actantos.local.evil.example`). S4 stays **PARTIAL** rather than HELD: the attestation authority
is now exercised on real infrastructure, but X.509-SVIDs are not supported at all and the
un-skipping of this group is a platform property, not a decision.

Two further limits are recorded in `ARCHITECTURE_V2.md`: the JWKS URI is a trust anchor that must
be pinned out of band, and only JWT-SVIDs are supported — X.509-SVIDs are not, because Node has no
chain-building API and hand-rolling one is the one thing this codebase must never do.

## Phase I — revocation was a set the caller filled in

### The defect in the shape, not in the values

Revocation existed as `ReadonlySet<string>` passed to each verifier by its caller. The values were
right. The *shape* was the problem, and it only shows up in a real deployment: a set has no
identity. Whoever fills it decides what it contains, so a compromised caller can pass an empty set
and receive "nothing is revoked" — which is an allow. The enforcement point has no way to tell a
real empty set from a lie, and no way to know whether the set it is checking is the one the control
plane published.

This is the same mistake the policy bundle fixed in phase A, in the other direction. A bundle needed
a signature to establish authenticity. Revocation needed one to establish **absence**: a signature
over the document is what makes "this agent is not on the list" mean anything, because it is the
only thing that makes the list itself attributable.

### What replaced it

`RevocationStore` holds a signed, versioned, expiring snapshot, and refuses any candidate whose
signature, issuer, tenant, validity window or version does not check out. A refusal **leaves the
previous snapshot in place** — clearing on error is precisely how a corrupted push becomes an
un-revocation, and that mutation is one of the six the tests kill.

Entries revoke an `agent_id`, a single `nonce`, or a `permit_id`. Nonce revocation is the narrow
one: revoking one execution rather than every future execution of that agent.

### Expired is not the same as empty

An expired snapshot is a distinct state from an empty store, and the difference decides an outcome.
Empty means nothing is known, so nothing is enforced. Expired means the entries are **still
enforced** — a revocation the control plane signed must not stop applying because the control plane
went away. Collapsing the two states would turn every outage into a mass un-revocation. A test
asserts both states and the decision that differs between them.

### Lifting a revocation is a signed decision, not a deletion

There is no un-revoke operation. An entry stops applying when the control plane publishes a **higher
version** that does not list it. Replaying version 2 after version 5 is refused as `version_rollback`,
which is the same anti-rollback property the policy bundle has and for the same reason: a genuinely
signed older document is exactly what an attacker needs.

The runtime tests run the attacks in the direction that matters. A forged snapshot at version 99
with the entry removed must not restore a revoked agent; nor must a replay of an older genuine one.
Both are asserted against a real sidecar while the agent holds a valid policy and a valid signature,
so nothing else can be doing the denying.

### The propagation SLO is an instrument, not a promise

`propagationAgeMs()` reports how long the enforcement point has been without a fresh snapshot. The
point of exposing it is that an enforcement point can be **enforcing correctly and still unable to
accept new revocations** — a state that `state()` alone does not show, and that an operator has to
be able to alert on. Exceeding the interval is not a security failure; it is a stated availability
trade, and it is visible rather than silent.

### What is not claimed

A revocation list that grows without bound is not modelled. A long-running sidecar accumulates
entries until the snapshot is replaced, and no compaction scheme exists here. That belongs with
the key lifecycle work in phase O. The sets handed to the existing `ReadonlySet` verifier options
are built per request rather than cached, which is correct but is not free — the fix if that ever
becomes a problem is a different data structure, not a cache, because a stale cache is an
un-revocation.

## Phase J — the boundary checked names, not values

S1 was already marked HELD. It was not. The claim was that production credentials never enter
LLM reasoning context, and the enforcement was `assertNoCredentialsInResult`, which inspects
**field names** in a provider's return value. That catches a provider that hands back a field
called `access_token`. It does not catch a provider that returns `{ data: "<the token>" }`, and it
cannot: the broker was holding the exact value it had issued and never compared against it.

### Three defects, measured before fixing

None of these were found by reading. Each was reproduced against the previous code, and the
observed behaviour is what the test now pins.

**The boundary had a hole.** `assertNoCredentialsInResult({ data: SECRET })` returned cleanly. A
provider under misconfiguration or compromise can return the credential it was handed under any
key it likes. The fix is not a better name pattern — it is to check the **value the broker is
holding** against every string in the result, including keys. Because a JSON credential carries
its secrets as components, the marker set is the whole blob plus each component, so returning one
field out of the credential is caught too. A length floor keeps a component like a username from
matching unrelated response text; without it the control would refuse legitimate work, which is how
a security control gets switched off.

**A credential provider was never told who was asking.** `obtain()` received only the grant, so an
AWS session had to be named from a constant. Every agent in every tenant produced the literal
`actant-broker`, which means a CloudTrail entry could not say which agent caused an effect — the
attribution that phases H and I exist to establish. `obtain()` now receives the verified identity
the broker already has. Session names are sanitised to STS's `[\w+=,.@-]` limit with a digest
suffix on truncation; underscore is inside `\w` and must survive, or `t_demo` and `t-demo` collapse
onto one name.

**A lease was revoked against the wrong credential.** `createVaultCredentialProvider` held one
`activeLeaseId`. Two concurrent grants overwrote it, so destroying the first credential revoked the
**second's still-in-use** lease while the first's lease survived unrevoked to its full TTL. The
measured result of handing it the first credential was `revoked: ['lease-2']`. Leases are now held
per credential handle, and the entry is removed *before* the revoke is awaited so a retry cannot
hit a lease that has since been reassigned.

### Two more defects, in the code this phase added

The value-echo check would have been pointless if the credential itself were wrong, so the signing
is pinned to an **external** known-answer vector rather than to itself: AWS's published
`get-vanilla` signature, plus the documented `kDate`/`kRegion`/`kService`/`kSigning` derivation.
That vector immediately caught a real bug — `toISOString()` already ends in `Z` and the signer
appended a second one, so every request carried `...Z Z`. The signature was well-formed and the
timestamp was not, and only the external vector could tell. Two more followed: `readJson` rejected
any response that was not an object, which broke GitHub's issue listing (a top-level array); and
the session-name charset omitted `_`.

### The expiry a vendor grants is the expiry that counts

Vault can grant a shorter TTL than requested — a policy cap, or a database engine whose own
credential lifetime binds. Using the requested TTL would hand the broker an expiry later than the
truth, and the broker would report a dead credential as valid. The broker now also refuses a
credential that is already expired or whose expiry cannot be parsed, and never reaches the provider
with one. An unusable `expiresAt` is a failure, not an unlimited lease.

### What is not claimed

None of this ran against github.com, AWS or Vault. The sockets, the HTTP, the RSA and HMAC
signatures and the request formats are real; the far end is a loopback server in the test file. So
what is demonstrated is that each provider speaks the vendor's protocol correctly and that a
credential cannot escape through the broker — not that any vendor accepts these requests, that an
App key is correctly provisioned, or that an IAM trust policy permits the assumed role. Those need
a real account and are NOT RUN. The registry entry is `production-credential-providers`,
INTEGRATION, not REAL_SUBSTRATE.

The STS response parser handles the one flat document `AssumeRole` produces and fails closed on
anything else, because no XML parser is vendored here and one was not added for the sake of one
call. A response with a nested structure is refused rather than misread.

Strings in Node are immutable, so nothing here zeroes a credential out of memory after use. Release
means the lease is revoked or the call is over — not that the bytes are gone.

## Phase K — the one document the agent is allowed to believe

Everything else in the fabric tells the *enforcement point* what an agent may do. Nothing told
the *agent*. Its picture of its own authority was ambient text — a prompt line, a tool
description, conversation history — written by something the agent does not control and cannot
audit. For a fabric whose premise is that the agent is compromised, that is the wrong shape: a
compromised agent believes what it is told, so a description of authority is only worth carrying
if it is signed by something the agent does not control.

### A valid signature is necessary and not sufficient

The obvious implementation is "sign the agent's context and check the signature". That is half of
it, and the half that is easy. The tests in this phase hold the **same key pair the policy bundle
is signed with**, so every widening case below is a document the control plane genuinely issued.
All five pass a signature check.

They are refused anyway, by a second step: every grant, tool, host, clearance and delegation depth
in the envelope is compared against the authority in the signed lease. An envelope may narrow; it
may not widen. This is invariant S6 in the same form the delegation chain enforces, applied to a
different artefact.

Without that step, policy narrowing would be revocable by waiting. An envelope issued ten minutes
ago under a wider bundle is genuinely signed and genuinely stale — "the control plane said this" is
not the same statement as "this is still allowed".

### Bound to the execution, not just the agent

The envelope carries the nonce of the workload identity it was issued against. Phase H made that
nonce per-execution, so the interesting attack is not cross-agent theft but **cross-execution
reuse**: the same agent presenting an envelope from a previous run of itself. Same identity, so
the spiffe check passes; different nonce, so it is refused. A stolen envelope also expires.

`version` is strictly increasing per agent, so a genuinely signed *older* envelope — the one a
rollback attacker actually holds — cannot be replayed over a newer narrowing. The tracker is kept
separate from the policy lease on purpose: folding them into one counter would let an envelope
advance the policy version, or a policy bundle retire an envelope.

### The ceiling is read from the bundle, never from the envelope

`authorityFromBundle` reads `allowed_tools` only when the bundle names the agent asking. A bundle
is a single document, and reading its tool list regardless of the subject would hand one agent
another agent's tools — the same mistake as trusting a caller-supplied revocation set in phase I.
The ceiling has to come from somewhere the constrained party does not control.

### What is not claimed

Nothing enforces the envelope yet. It verifies, it binds, and it narrows, and there are tests for
each. No request path currently requires one, and no control plane issues them — that is wiring
that has not been done, so the property is "a presented envelope cannot widen authority", not "the
agent cannot act outside its envelope".

## Phase N — the property I had to weaken was the one that was wrong

Property-based fuzzing of every verifier between the network and an allow, with a fixed seed so a
failure reproduces. The first version asserted "no single mutation of a signed document is ever
accepted", and three of thirteen properties failed.

Both causes were in the test, not the product, and both are worth stating because the second one
is a property of the whole design rather than a detail:

**The mutation was a no-op.** The reported mutation inserted a key into the *string*
`"allow_via_egress_gateway"`. `applyMutation` guards on `typeof parent === "object"`, so it
skipped the insert and returned an untouched clone — the verifier accepted the authentic document,
correctly. The mutator now only offers `insert` at paths whose container is an object.

**Zod strips unknown keys before the signature is checked.** Every verifier parses with a schema
*first* and hashes the parsed result. An unknown key therefore never reaches the canonical bytes,
so inserting one leaves the signed bytes identical and acceptance is correct. Refusing it would
be a bug, not a defence.

So the property was false by construction. The restated one is stronger in the direction that
matters: **acceptance is a pure function of the canonical bytes.** A mutation that changes those
bytes must be refused; one that leaves them unchanged must be accepted. The second half matters
because a verifier that refused everything would otherwise pass the test, and the file already
asserts the control case for exactly that reason.

Checked by mutation rather than by inspection: changing the bundle verifier to sign-check the raw
candidate instead of the parsed body — which would make an unknown-key insert significant — is
caught by the fuzzer.

### A denial the attacker could turn into a crash

The fuzzer also reached `checkNetworkTargets`, which is the only verifier that takes raw `unknown`
with **no schema at all**. Its traversal recursed without a bound, and `request.args` is written by
the agent — the component this system assumes may be fully compromised. Five thousand levels of
nesting raised a `RangeError` out of `checkNetworkTargets`; `handle()` does not catch, so the
sidecar died rather than denying. A `Proxy` whose `ownKeys` trap throws escaped the same way.

Fixed by walking with an explicit stack under a node budget, and by treating a throwing property
accessor as uninspectable. **A value too large to inspect is denied, not partially decided** — a
permitted host in the visited prefix must not buy an allow when the unvisited tail is unknown,
because the attacker chooses where that tail is. Both halves are pinned by tests that fail when
the budget or the accessor guard is removed.

## Phase O — an issuer could not rotate its key at all

Every verifier in the fabric took `trustedIssuerKeys: ReadonlyMap<string, string>`. One issuer id,
one PEM. No key id, no validity window, no way to hold two keys at once, and the map was captured
at construction and never reassigned.

That is not a missing convenience. It means **rotation was impossible**, and both ways of failing
looked identical:

- Keep the old key, and every document signed after the rotation is refused as `invalid_signature`.
- Swap the map, and every document signed before the rotation stops verifying.

There was no overlap, so there was no window in which neither side was broken. And because the
issuer id is configuration rather than something derived from the key, "the control plane
rotated" and "someone forged this" were the same event with the same log line.

### What was added

A keyring: issuer id to several keys, each with an optional `notBefore` and `notAfter`. During a
rotation both keys are present; when the old one retires, its documents stop verifying. A
fingerprint (SHA-256 over the DER SPKI, so PEM rewrapping does not read as a rotation) makes the
change visible to an operator.

The plain `Map<issuerId, pem>` is still accepted everywhere, unchanged. This is a superset, not a
replacement — the candidate loop is the same shape `verifyJwtSvid` already used for `kid`, so
there is one mechanism in the codebase rather than two.

### The two things rotation must not break

Both are load-bearing and both are tested, because both fail in the direction of *less* safety:

**A running lease keeps its anti-rollback floor.** Before, the only way to change keys was to
construct a new `PolicyLease`, which reset the highest activated version to zero and re-opened the
replay of an older but genuinely signed bundle. `setTrustedKeys` replaces the keys without
touching that counter.

**Withdrawing every key does not tear down an active lease or clear a revocation list.** This one
is a judgement call, and it is worth being explicit about which way it goes. Refusing to enforce
because a key was withdrawn would let anyone who can push a key update deny service to a sidecar
that is otherwise enforcing correctly — a stronger attack than the withdrawal prevents. An
applied revocation list going empty on a key update would be worse still: that is a rotation
turned into a mass un-revocation. So the bound is the signed document's own expiry, which is a
property of what the control plane signed rather than of local key state.

### Compaction: bounded, but deliberately not by age

The obvious fix for a growing revocation list is to prune entries older than some window. That is
not implemented, and the reason is the same un-revocation rule as above: `revoked_at` is
informational and never read, so nothing here knows when a revoked nonce's identity window has
passed. Pruning by age would drop entries that are still the only record of a revocation.

What is bounded instead is the size. `MAX_REVOCATION_ENTRIES` refuses an oversized snapshot as
`too_many_entries`. Before this, the same document arrived as a frame-decoder `overflowed` — a
symptom that says the transport gave up, not which document was at fault. The supported remedy
for an oversized list is a higher signed version that omits stale entries, which is the same
mechanism un-revocation already uses.

### What is not claimed

There is no key hierarchy: no root, no cross-signature, no chain. A key is trusted because an
operator put it in the map. There is also still **no private-key storage abstraction** — a signing
key arrives as a PEM in an environment variable, and rotating it means restarting with a different
variable. The rotation *mechanism* is done; the operator tooling and a real key vault are not, and
no deployment has rotated a key through this path.

## Sequencing used

1. **S11** signed bundles — without authentic bundles no local lease is possible.
2. **S12** fail closed — required for the lease to be trustworthy.
3. **S1** broker.
4. **S4/S5/S6** identity and delegation.
5. **S7/S8/S9** effect permits.
6. **S10** IFC.
7. **S3** adversarial network suite.
8. **S13** evidence.

All eight were implemented. The result is 249 v2 tests, 28/28 bench scenarios with zero
prohibited external effects, and an end-to-end demo that exits non-zero if any attack lands. The
authoritative, machine-derived counts live in `docs/security-fabric-current-state.json`; the
numbers in prose are refreshed by hand and are not guarded.
## An unmet prerequisite, recorded rather than fixed

Everything above describes `actantosd`. One enforcement path outside it does not meet the bar,
and it is the most serious gap found in this work. It is recorded here rather than patched,
because patching it means changing a package that has its own tests and its own release
cadence, and because the right fix is a decision rather than a diff.

### `packages/pi-adapter/src/shell_executor.ts`

This section previously described `shell_executor.ts` as a fork that left S8 and S9 unmet, and
stated that the canonical `docker-executor.ts` was unaffected because S8 was carried by
`effect-permit.ts`.

**Both claims were wrong.** `effect-permit.ts` is a separate mechanism and is not on this path.
And the canonical executor did not bind the command either: `constraints_hash` covers only the
envelope (`network_mode`, `timeout_ms`, `max_output_bytes`), and `scope_hash` covers `resource` and
the `normalized` block, which carries `command_family` and `subcommand` but **not the arguments**.

Measured against the unmodified code on both executors, with a token minted for `printf hello`,
substituting `rm -rf /workspace/important` was **accepted and executed on both**. So S8 was unmet
on the canonical path as well, not only on the fork.

| | `docker-executor.ts` | `shell_executor.ts` |
|---|---|---|
| `exp` checked | yes | **was absent** |
| `constraints_hash` checked | yes | **was absent** |
| The command bound into the token | **was absent** | **was absent** |
| The token is single-use | **was absent** | **was absent** |
| gVisor / `runsc` sandbox | present | **was absent** |
| Egress network | internal cell | **plain bridge, no proxy** |

### What was fixed

- `actantosd/src/decision-command.ts` mints a `command_hash` over the ordered argv plus the host
  workspace, derived from the same interception request the policy engine evaluated.
- **Both executors verify it** before any spawn, alongside expiry and the envelope check.
- `shell_executor.ts` resolves gVisor through the canonical rule (run under gVisor or refuse) and
  attaches to `actantos_egress_cell` rather than creating a plain bridge called
  `actantos_egress`, which had no proxy on it and no `--internal` flag.
- `createDecisionToken` mints a unique `nonce` per token, and **both executors claim it before
  spawning**. The store is a required dependency, so an executor configured without one does not
  start rather than silently accepting a replayable token. A token with no nonce claim is refused
  as malformed rather than treated as exempt, because exempting it would be a bypass an attacker
  could mint deliberately.

Tests in `decision-command.test.ts`, `docker-executor.test.ts`,
`decision-nonce-store.test.ts` and `packages/pi-adapter/src/shell_executor.test.ts`. Each was
mutation-verified: disabling the command check fails 4 tests on each path; removing `--internal`,
or the gVisor refusal, each fail their test; disabling the nonce consume, or keeping the consume
but discarding its result, each fail 2 tests on each path. The pi-adapter drift guards import the
actantosd implementations and assert the restated digests match, so the two copies cannot diverge
silently.

### What remains on this path

- **The nonce store is per-process.** `InMemoryDecisionNonceStore` does not survive an executor
  restart, so a captured token becomes replayable again within its TTL after a restart. The
  durable `ReplayStore` used by the effect gateway closes this; it is not wired to this path. A
  test asserts the limitation rather than documenting it only.
- **Ed25519 decision tokens are implemented but not enabled by default.** The executors now accept
  `tokenVerification: { kind: "ed25519", publicKeyPem }`, which makes them verifiers that cannot
  mint. HMAC remains the default because switching the default silently would be a behaviour change
  on a path with no production caller; the asymmetry is opt-in and tested, not assumed.
- **This proves the public-key holder cannot forge, not that the private key is kept off the
  adapter's host.** Where the private key lives is a deployment property a signature format cannot
  demonstrate.
- **The workspace is now visible to policy, but the shipped policy does not constrain it.** The
  Cedar resource entity carries `workspace_path`, derived through `commandFromRequest` so it is the
  same value the command digest binds. A policy *can* refuse an out-of-root workspace. What is
  **not** demonstrated is a Cedar-level enforcement: that test needs the `cedar` binary, which is
  absent here, so it skips and runs only in CI. The entity attribute reaching the policy input is a
  weaker claim than a policy acting on it, and the two are not reported interchangeably.
- **The pi-adapter executor now has its own real-container tests**
  (`shell_executor_substrate.test.ts`, 8 gated tests), which is why its state entry moved from
  `SIMULATED` to `REAL_SUBSTRATE`. Both executors are exercised against a live Docker daemon, not
  just one — two implementations agreeing on recorded argv can still disagree about what Docker
  receives.
- **A real container is not a real sandbox.** The substrate tests stub `checkRunsc`, so gVisor
  stays `SIMULATED` and nothing in them observes runsc.
- **The two executors still exist.** Their enforcement now agrees, and drift is guarded, but there
  is one behaviour, written twice.

## Phase P — what was measured rather than changed

Phase P added three experiments and no invariants. None of them changed what the fabric accepts, and
that is the point of writing them down as measurements.

**Post-quantum signatures.** Every signed document in the fabric uses Ed25519, which is broken by a
large enough quantum computer. `signature.ts` was written with a registry so another algorithm
could be added without touching call sites, and Phase P measured what adding one would cost.
Verification is not the obstacle: ML-DSA verifies *faster* than Ed25519 on the multi-kilobyte
canonical JSON this fabric signs. The obstacle is key generation — `node:crypto` on this runtime
cannot generate an ML-DSA key at all, so a lattice migration is blocked on where the issuer key
comes from, while the hash-based family (SLH-DSA, FIPS 205) has a complete path today.

Nothing was registered. A test scans the source tree and fails if any file calls
`registerSignatureAlgorithm`, because registering an algorithm is a silent widening of what the
enforcement path accepts, and it must be a reviewed decision rather than a side effect of a
measurement. The tests build policy bundles and revocation snapshots carrying **cryptographically
valid** ML-DSA and SLH-DSA signatures and assert they are refused as `unsupported_algorithm`.

**WASI.** Measured against a real `wasm32-wasip1` guest, WASI's containment is genuine: traversal
out of a preopened directory is refused as `ENOTCAPABLE`, host absolute paths do not exist in the
guest's namespace, there are no socket syscalls, and the environment is empty unless the host
passes it. Two weakenings are asserted rather than discovered later — Node's WASI has no read-only
preopen, and `fd_readdir` is unimplemented.

It was not adopted, and the reason is directional rather than a matter of quality. Every one of
those properties is a property of *the import object the host chose*: the same module reads
different files under different preopens. WASI contains a guest from its host. This project's
premise is that the host is already compromised, so the boundary WASI enforces is not the one that
matters — and WASI provides no workload identity, so it cannot satisfy **S4** on its own.

**Confidential computing: NOT RUN.** Nothing was measured; there is no code and no hardware. The
machine is an Intel Core i7-12700K, which predates TDX, and neither SEV-SNP nor TDX is reachable
from Windows. This is the only technology that would change the scope statement in "An unmet
prerequisite": until it exists, the fabric does not claim protection after host-kernel or root
compromise.

**A test double that was more permissive than production.** Seven v1 suites authorize through
`FakeCedarProvider`, which permits anything that is not a credential access, and each builds an
"allow" as a precondition for asserting something else about it. Five of those fixtures asserted
an allow that `policies/default.cedar` **denies**, because `commandFromRequest` derives the
workspace as `dirname(resource.path)` and no shipped policy permits the result. They passed only
because the fake is more permissive than the policy engine — so a suite could certify "an allowed
tool call is audited" on the strength of an authorization production cannot issue. The fixtures
now live in one module and `cedar-fixture-parity.test.ts` evaluates them against the real
`cedar-policy-cli`. One divergence was open and was asserted as open: `src/mcp-gateway.ts`
derives a resource path under `/mcp/<server>/tools/`, which no shipped policy permitted, so the MCP
gateway could not obtain an allow in production. This bore on **S7**: authorization was being
demonstrated for requests the authorizer did not actually admit. **Closed in `8bfc7fb`.** The
gateway's derived path is exactly what `policies/default.cedar` confines to the approved
workspace, so denying by default was correct and is now asserted as such rather than worked
around; opening MCP is an explicit `CEDAR_POLICY_PATH` choice, not the shipped default. Closing
it also surfaced `policies/templates/mcp-readonly.cedar`, which shipped inert gating on two
actions the gateway never emits and could not express read-only-ness at all. Both are fixed, and
the default still refuses all five MCP shapes.

**A defect found on the way.** Phase O's 5,000-entry snapshot ceiling turned the revocation lookup
into a linear scan on the per-request path: 20,000 worst-case lookups cost 363 ms. `RevocationStore`
now derives its lookup tables when a snapshot is accepted, and the same loop costs 6 ms. The
interesting part is not the speed — it is that the index is replaced together with the signed body
it came from, in one statement, so there is no window in which a snapshot and its index disagree.

## A note on measurement

The pattern across these phases is consistent enough to be worth naming. Every real defect found
in this work — the S1 boundary that checked field names, the Vault lease revoked against the
wrong credential, the `Z` doubled in an AWS timestamp, the unbounded recursion in the egress
guard — was found by a check that compared an *expected specific outcome* against reality: a known
answer vector, an independent recomputation, a deliberately hostile input. None was found by
reading the code, and several were in code that had already been reviewed. The tests that did not
catch these were the ones asserting a weaker property than the one that mattered.
