# ActantOS v2 — Agent Security Fabric: implementation report

**Date:** 2026-10-04
**Scope of this report:** phases J through P of the security fabric roadmap.
**Maturity label:** `quiet-open-core` / `implemented` / `locally-verified`.

This document is a report, not a claim of production qualification. The conditions for that claim
are in "What is not claimed" and are not met.

---

## 1. What this work did

The premise, unchanged throughout: **the LLM and the agent process may become fully compromised.
The surrounding system must still constrain what the compromised agent can access, communicate,
delegate, and cause in the real world.**

Fourteen invariants (S1–S14) define what that means. Each phase below took the invariant that was
weakest and found the specific way it was weak.

| Phase | Commit | The finding |
|---|---|---|
| I | `53a6e34` | Revocation was a `Set` the caller filled in — it proved nothing about what was *not* revoked |
| J | `189526a` | The S1 credential boundary checked field *names*, so `{ data: "<token>" }` sailed through |
| K | `2ff0036` | A valid signature is necessary and not sufficient; policy narrowing was revocable by waiting |
| N | `04b810b` | The egress guard recursed without bound — a compromised agent could crash the enforcement path |
| O | `49eb58a` | An issuer could not rotate its key at all, and a rotation was indistinguishable from a forgery |
| P | `97638ff` | Phase O's own size ceiling made revocation lookup linear per request; the two experiments that followed changed nothing about what the fabric accepts |

### Phase J — the boundary checked names, not values

S1 was already marked HELD and was not. The broker's credential-leak check inspected result keys
for names like `token` and `password`. A provider returning `{ data: "<the actual token>" }`
produced no flagged key name and passed.

Four defects, all measured rather than reasoned about:

- **The boundary checked names.** Fixed with `assertCredentialNotEchoed`, which scans values for
  the exact credential the broker issued.
- **A credential provider was never told who was asking.** Every AWS session was named
  `actant-broker`, destroying CloudTrail attribution. Fixed by adding `CredentialRequestContext`.
- **A Vault lease was revoked against the wrong credential.** The provider held one `activeLeaseId`
  for the whole process; destroying credential A revoked B's live lease and left A's unrevoked to
  full TTL. Fixed with a per-handle map.
- **Two defects in my own new signing code**, caught by a known-answer test rather than by review:
  a doubled `Z` in the SigV4 timestamp (my signer produced `c46f6468…`, AWS publishes
  `5fa00fa3…`), and an STS response parser that rejected the top-level array GitHub returns.

### Phase K — a valid signature is necessary and not sufficient

The security context envelope is the one document the *agent* is allowed to believe. The obvious
implementation — sign it, check the signature — is half of it.

The tests hold **the same key pair the policy bundle is signed with**, so every widening case is a
document the control plane genuinely issued. All five pass a signature check and are refused by a
second step: grants, tools, hosts, clearance and delegation depth are each compared against the
authority in the signed lease. An envelope may narrow; it may not widen.

Without that step, policy narrowing would be revocable by waiting — an envelope issued ten minutes
ago under a wider bundle is genuinely signed and genuinely stale.

### Phase N — a denial the attacker could turn into a crash

Property-based fuzzing of every verifier, fixed seed. The first property asserted "no single
mutation of a signed document is ever accepted" and three of thirteen failed.

**Both causes were in the test.** The reported mutation inserted a key into the string
`"allow_via_egress_gateway"` — the mutator guards on `typeof parent === "object"`, so it was a
no-op and the verifier correctly accepted an untouched document. And because Zod strips unknown
keys and every verifier parses *before* hashing, an unknown-key insert never reaches the signed
bytes, so acceptance was correct.

The property was false by construction. Restated as something stronger in the direction that
matters: **acceptance is a pure function of the canonical bytes, in both directions** — a
byte-changing mutation must be refused *and* an invisible one must be accepted. The second half is
what stops a verifier that refuses everything from passing.

The fuzzer also reached `checkNetworkTargets`, the only verifier taking raw `unknown` with no schema
at all. Its traversal recursed without bound, and `request.args` is written by the agent: 5,000
levels of nesting raised a `RangeError`, and `handle()` does not catch, so the sidecar died rather
than denying. Fixed with an explicit stack under a node budget. **A value too large to inspect is
denied, not partially decided** — a permitted host in the visited prefix must not buy an allow when
the unvisited tail is unknown, because the attacker chooses where that tail is.

### Phase O — an issuer could not rotate its key at all

Every verifier took `trustedIssuerKeys: ReadonlyMap<string, string>`: one issuer id, one PEM, no key
id, no validity window, captured at construction and never reassigned.

Rotation was therefore impossible, and both failure modes were indistinguishable from each other
and from a forgery — each surfaced as `invalid_signature` under one unchanging issuer id. Keeping
the old key refused every new document; swapping the map broke every old one. There was no overlap,
so no window in which neither side was broken.

Added a keyring with per-key validity windows and an operator-visible fingerprint, plus
`setTrustedKeys` on the two long-lived holders. Two properties are load-bearing and both are tested
because both fail toward *less* safety:

- **A running lease keeps its anti-rollback floor.** Changing keys previously meant constructing a
  new lease, which reset the highest activated version to zero and re-opened replay of an older but
  genuinely signed bundle.
- **Withdrawing every key neither tears down an active lease nor clears a revocation list.**
  Refusing to enforce on a withdrawal would let anyone who can push a key update deny service to a
  correctly-enforcing sidecar; a revocation list going empty would be a rotation turned into a mass
  un-revocation. The bound is the signed document's own expiry.

Revocation lists are bounded by size (`MAX_REVOCATION_ENTRIES` → `too_many_entries`) and
deliberately **not** by age: `revoked_at` is informational and never read, so nothing knows when a
revoked nonce's identity window has passed, and age-based pruning would drop entries that are still
the only record of a revocation.

### Phase P — three experiments, and one defect found on the way

Phase O introduced a cost it did not mean to introduce. Bounding a revocation snapshot at 5,000
entries turned the lookup path into a measured expense: every action a sidecar decides makes up to
three revocation lookups, and each one scanned the whole entry array. Twenty thousand worst-case
lookups cost **363 ms**. `RevocationStore` now derives lookup tables when a snapshot is accepted —
never lazily, never per question — so a snapshot and its index are replaced together in one
statement and there is no window in which they disagree. First-wins on a duplicated id matches what
`Array.prototype.find` returned, so the index cannot change a decision that was already being made.
The same loop now costs **6 ms**, and the regression floor sits at 150 ms, between the two.

The three experiments that followed are measurements, not migrations. None of them changed what the
fabric accepts.

**P1 — post-quantum signatures.** Node 26.4.0 / OpenSSL 3.5.7, 2 KiB message:

| | Ed25519 | ML-DSA-44 | ML-DSA-65 | SLH-DSA-SHA2-128s |
|---|---|---|---|---|
| public key (DER SPKI) | 44 B | 1,334 B | 1,974 B | 50 B |
| signature | 64 B | 2,420 B | 3,309 B | 7,856 B |
| sign | 0.04 ms | 0.37 ms | 0.52 ms | 268 ms |
| verify | 0.09 ms | 0.08 ms | 0.11 ms | 0.28 ms |
| keygen in `node:crypto` | yes | **no** | **no** | yes |

Two results matter. **Latency is not the obstacle** — verification is *faster* than Ed25519 for both
ML-DSA variants, because the fabric signs canonical JSON of a few kilobytes rather than a
pre-computed digest. And **the lattice family is blocked on the runtime, not on the cryptography**:
ML-DSA is the algorithm everyone means by "post-quantum signatures", and it is the one this Node
cannot generate a key for. Keys would have to arrive from the `openssl` CLI, a pre-shipped PEM, or a
Node upgrade. The hash-based family has a complete path today.

The experiment deliberately did **not** register anything. `registerSignatureAlgorithm` is called
from nowhere in `src/`, and a test enforces that by scanning the source tree — registering ML-DSA
would be a silent widening of what the fabric accepts on the path that decides whether an agent may
act. The tests instead build policy bundles and revocation snapshots carrying **cryptographically
valid** ML-DSA-44 and SLH-DSA signatures and assert they are refused as `unsupported_algorithm`,
with an Ed25519 control over the same body proving the refusal is about the algorithm and not about
a verifier that refuses everything.

**P2 — WASI as a containment substrate.** `experiments/wasi-guest` is a Rust program compiled to
`wasm32-wasip1` whose only purpose is to probe its own boundary. What it found:

- Traversal out of a preopened directory is refused as `ENOTCAPABLE`, and this is *distinguishable*
  from `ENOENT` — a missing name gives errno 44, a traversal gives errno 76. The refusal does not
  depend on the target existing: WASI rejects `..` by inspecting the path.
- There are no socket syscalls at all, so there is no socket policy to get wrong.
- The environment is empty unless the host passes it.
- Two weakenings, found and asserted rather than discovered later: Node's WASI has **no read-only
  preopen**, so a preopened directory is writable; and `fd_readdir` is unimplemented, so a guest
  can only read names it was already told.

The conclusion is directional, and it is the reason WASI was not adopted. WASI contains a guest from
its host: identical module bytes read different files under different preopens, because every
property above is a property of *the import object the host chose*, not of WASI or of the guest.
That is WASI working exactly as specified. But this project's premise is that the host is already
compromised, so the boundary WASI enforces is not the one that matters, and Node's WASI is
additionally an in-process library — a compromised host does not escape it, it simply picks a
different preopen. WASI also provides no workload identity, so it cannot satisfy S4 on its own. It
remains a reasonable way to run third-party tool code *inside* a cell, and a poor replacement for the
sidecar, the network cell, or SPIRE.

**P3 — confidential computing: NOT RUN.** There is nothing in this repository for SEV-SNP or TDX, and
nothing was measured. What it would take: an AMD EPYC 9004 (Milan, SEV-SNP) or Intel Sapphire
Rapids (TDX); a confidential VM whose owner policy is attested before any guest code runs; a
measurement value bound to that policy; and an attestation client verifying the chain to a vendor
root of trust. This machine is an Intel Core i7-12700K, which predates TDX, and neither technology
is reachable from Windows in any case. Until that exists, §5's scope statement applies unchanged —
baseline v2 does not claim protection after host-kernel or root compromise — and confidential
computing is the only thing that would change that sentence.

**What Phase P did not settle.** Hybrid construction (Ed25519 + ML-DSA concatenated), key agility
for an issuer that must rotate a PQ key on a schedule it cannot yet meet, whether a hash-based
security assumption fits this threat model, and the roughly 16 KB an SLH-DSA signature adds to every
security context envelope and effect permit. Those are decisions, not measurements.

---

## 2. Security guarantee matrix

Levels are the project's own taxonomy and are machine-derived in
`docs/security-fabric-current-state.json`.

| Substrate | Level | What the tests actually prove |
|---|---|---|
| `cedar-pdp` | REAL_SUBSTRATE | Real Cedar policy evaluation |
| `docker-internal-cell-network` | REAL_SUBSTRATE | Real containers on a real network with no egress route |
| `postgres-replay-guard` | REAL_SUBSTRATE | Replay refused against a real database |
| `postgres-evidence-store` | REAL_SUBSTRATE | Evidence persisted and verified against a real database |
| `postgres-effect-journal` | REAL_SUBSTRATE | Effect journal against a real database |
| `spire-workload-identity` | REAL_SUBSTRATE | Eleven gated tests against a live SPIRE 1.15.3 trust domain. Four client defects were measured there and all four are fixed; this project's own gRPC client now obtains an SVID from the agent and verifies it. One mutation is not caught by the gated file and is recorded in the state file |
| `property-based-fuzzing` | REAL_SUBSTRATE | Every verifier, fixed seed, reproducible |
| `key-rotation` | REAL_SUBSTRATE | Overlap window, retirement, rollback floor preserved |
| `post-quantum-signatures` | REAL_SUBSTRATE | ML-DSA and SLH-DSA measured; **both refused** by the live verifiers |
| `wasi-containment` | REAL_SUBSTRATE | A real `wasm32-wasip1` guest against Node's real WASI |
| `postgres-tenant-rls` | INTEGRATION | RLS exercised against a real database |
| `sidecar-local-socket` | INTEGRATION | Real socket, real sidecar process |
| `fabric-runtime-wiring` | INTEGRATION | The fabric on the live request path |
| `production-credential-providers` | INTEGRATION | Real protocols and signatures; **not** real vendors |
| `jwt-svid-verification` | INTEGRATION | Real SVID verification; **not** real SPIRE issuance |
| `gvisor-sandbox` | REAL_SUBSTRATE | Real containers under `runsc` on a daemon in WSL2 that registers it: same image and daemon, two different kernels depending only on the runtime flag. Egress is **not** claimed — that daemon's bridge blocks both runtimes |
| `docker-executor` | REAL_SUBSTRATE | Was SIMULATED with three items of residue itemised. All three are now closed: each resource flag is read back from inside a real container with a control that removes it, output truncation and redaction and the timeout run against a real process, and the `--runtime runsc` flag is proved end to end in `gvisor-sandbox` with the executor's own probe deciding it |
| `decision-execution` | INTEGRATION | The production caller: reads a stored allow, spends the token through the real executor with a durable nonce and an Ed25519 verifier |
| `docker-container-execution` | REAL_SUBSTRATE | The same binding with real containers running |
| `pi-adapter-shell-executor` | REAL_SUBSTRATE | The same binding, exercised against real containers on this path too |
| `tetragon-runtime` | REAL_SUBSTRATE | Five gated tests against a live Tetragon v1.7.1 loading the policy this repository emits. Two defects fixed: the emitter used a `Mask` selector that v1.7.1 refuses to load, and the adapter modelled only `process_exec`, so it dropped its own policy's events. **No** detection claim is needed: no invariant depends on this layer |
| `cedar-fake-provider` | SIMULATED | A stand-in used for tests that need a provider. **It was found permitting requests the shipped policy denies**; five fixtures were corrected and a parity guard now checks every one against the real `cedar-policy-cli`. One real divergence remains open — see §1 |
| `confidential-computing` | NOT_IMPLEMENTED | **No code, no test, no hardware.** See §1, Phase P |

**Invariant citation check:** 14 declared, 0 cited without a test file that exists and contains
tests. This is enforced by `scripts/security-docs-consistency.test.mjs`.

---

## 3. Architecture

```
                    ┌──────────────────────────────────────────────┐
                    │           control plane (trusted)            │
                    │  signs bundles, envelopes, revocations,      │
                    │  evidence, permits.  Holds private keys.     │
                    └───────────────────┬──────────────────────────┘
                                        │ signed documents
                    ┌───────────────────▼──────────────────────────┐
                    │              sidecar process                  │
                    │                                              │
                    │  verify identity ──▶ revocation ──▶ policy   │
                    │  lease (fail closed)      store      bundle   │
                    │                                              │
                    │  ┌────────────────────────────────────────┐  │
                    │  │ capability broker                      │  │
                    │  │ holds NO credential material            │  │
                    │  │ injects at the call boundary           │  │
                    │  └────────────────────────────────────────┘  │
                    │  ┌────────────────────────────────────────┐  │
                    │  │ target guard (bounded walk, fail closed)│ │
                    │  └────────────────────────────────────────┘  │
                    └───────────────────┬──────────────────────────┘
                                        │ local UDS
                    ┌───────────────────▼──────────────────────────┐
                    │   egress cell / gVisor / docker executor     │
                    │   network namespace with no route out        │
                    └──────────────────────────────────────────────┘

  compromised agent ──► can call any tool, hold any token, hold any
                        identity.  It cannot: reach an unlisted host,
                        obtain a credential, widen a signed envelope,
                        replay a permit, or act on an expired lease.
```

---

## 4. Verification evidence

**VERIFIED** — `actantosd`, this machine, 2026-10-04:

| Check | Result |
|---|---|
| `npm test` | 1007 tests, **915 pass, 0 fail**, 92 skipped |
| `npm run typecheck` | clean |
| `npm run release:verify` | passes; "security fabric state is current" |
| Security bench | 28/28 (26 attacks blocked, 2 controls), **0 prohibited external effects** |
| Suite composition | `src/` 328 + `src/v2/` 629 + `scripts/` 46 = 1003 |

The composition above is a static count, and it is four below what the runner reports (1007). A `test(`
inside a `for` body registers once per element while the static count sees it once; that is exactly
one file, `src/v2/security-fuzz.test.ts`, with two such sites in a three-element loop. The state
file publishes the difference as `runner_overcount`, and a guard compares
`static + overcount` against a real `node --test` run of each affected file rather than against a
transcribed total.

**Not all 92 skips are covered by the substrate job**, and saying otherwise would overstate what
CI proves. Measured, not assumed — the counts are the skip reasons the runner actually emitted:

| Skipped because | Count | Un-skipped by `npm run test:substrate`? |
|---|---|---|
| `DATABASE_URL` not set | 43 | yes |
| no working Docker daemon | 17 | yes |
| no SPIRE Workload API socket | 11 | **no** — gRPC over a Unix socket, so it cannot exist on Windows |
| no `ACTANTOS_GVISOR_DOCKER_HOST` | 6 | yes |
| substrate flag not set | 5 | partly — three run, the two Tetragon ones do not |

The runner executes eight files and sets only `ACTANTOS_SUBSTRATE_TESTS` and `DATABASE_URL`.
`src/v2/spire-substrate.test.ts` is not among them. It was run separately inside WSL2 against a
live SPIRE 1.15.3 trust domain, where the Workload API's Unix socket exists. Where a
trust domain exists they run in the ordinary suite, because their gate is a capability check
rather than the substrate flag.

**The three Cedar skips are gone.** `cedar-policy-cli` 4.13.0 was installed from the upstream
release and its SHA-256 verified against the published checksum, so the four Cedar-gated tests now
execute instead of skipping. Running them exposed a defect that skipping had been hiding; §5
records it.

The substrate job was run for this report rather than quoted: **126 tests, 126 pass, 0 fail, 0
skipped** against a real Docker 29.6.2 daemon and a real PostgreSQL 16.

**Evidence standard used throughout:** mutation testing, not inspection. Each of the five phases
was verified by breaking the product and confirming the suite notices:

| Mutation | Caught by |
|---|---|
| Disable the network-guard walk budget | 2 tests fail |
| Remove the network-guard `Proxy` accessor guard | 1 test fails |
| Sign-check the raw candidate instead of the parsed body | fuzzer fails |
| Ignore key validity windows in the keyring | 4 tests fail |
| Use only the first key per issuer | 8 tests fail |

A separate known-answer test pins the SigV4 signer against AWS's published `get-vanilla` vector
and the documented key-derivation chain, so the signer is conformant rather than merely
self-consistent. The production-provider tests rebuild each signature from the bytes received
rather than trusting the signer.

**NOT_RUN** — unchanged by this work and still not run: github.com, AWS and Vault were never
contacted (vendor acceptance, App key provisioning and IAM trust-policy correctness are
unverified); no Tetragon detection is claimed; the docker executor is SIMULATED; the security

**Tetragon was installed, run, and found two defects — both of them in this repository.** Earlier
revisions of this report claimed it emitted no events on this kernel, for four separately
measured reasons, and itemised them as host limitations. That was wrong, and the cause was
ours: **Tetragon exports events to `/var/log/tetragon/tetragon.log` and writes nothing
event-shaped to stdout.** The probe was reading the agent's own log. Reading the exporter shows
`security_bprm_check` events in the hundreds and `security_file_permission` events in the
thousands. The "no LSM is registered here" and "a `tcp_connect` kprobe emits nothing" reasons
were both artifacts of that one mistake, and a wrong-stream negative is worse than an admitted
unknown, because itemising it makes it look settled.

**Defect one: the emitted policy could not be loaded at all.** Running the policy this repository
*emits* — `toTracingPolicyYaml(buildTracingPolicy(...))`, written straight to disk — against a
live v1.7.1 was refused with `writeMatchValues error: MatchArgs type linux_binprm unsupported`,
and the file hook the same way. `operator: Mask` is not a loadable selector on those argument
types, so the binary-deny probe could not be installed on any current agent. The fix is
`operator: Equal`, which loads, is exact, and is what `deniedBinaries` means anyway: an absolute
path, not a mask. It loads, and three `touch` runs now produce exactly three events against 130
for the same policy with no selector.

**Defect two: the adapter could not read its own policy's events.** `runtime-events.ts` modelled
only `process_exec`, which is emitted by the built-in base sensor — and that sensor does fail to
load on this kernel with `__x64_sys_getcpu() is not modifiable`. Every `security_bprm_check`
line the policy selects was therefore classified `unmodelled` and dropped: the evidence path
could not consume the events it generated. `process_kprobe` is now parsed, and
`security_bprm_check` classified, using the kernel-reported `linux_binprm_arg.path` rather than
the cached `process.binary` — the hook exists precisely because the cached value can be stale.
The real captured event shapes are pinned in `runtime-events.test.ts`.

`src/v2/tetragon-substrate.test.ts` now runs **five of five, skipped zero** against a live
Tetragon v1.7.1. It loads this repository's own output rather than a hand-written policy, and
asserts the kernel-side selector discriminates — three `touch` runs and three `ls` runs yield
exactly three events — so the classification tests cannot be satisfied by an adapter filtering a
stream the kernel never filtered. What remains unclaimed is narrow and stated: the
`process_exec` stream is not observed on this kernel, and `deniedWritePaths` has no runtime
signal path at all, because `security_file_permission` events are parsed but deliberately not
classified.
**SPIRE was installed, run, and refused — four times over.** A real SPIRE 1.15.3 trust domain now
runs in the WSL2 distro: `spire-server` with a disk key manager, an agent attested with a join
token, a registration entry for `t_spire/pi_demo` selected on `unix:uid`, and a SPIFFE bundle
endpoint publishing the trust domain's JWKS. The JWKS is genuinely fetched and parsed — HTTP 200,
two EC P-256 keys — and a genuine ES256 SVID issued over SPIRE's own gRPC API is genuinely
rejected by this client. The signature is real: it verifies against the trust domain's own
published key once encoded as DER. Nothing here is a forgery finding.

Four independent defects stop the integration, each measured rather than inferred:

1. **Transport.** The Workload API is gRPC over a Unix socket and does not answer HTTP/1.1.
   Writing the exact request `requestSvid` performs down that socket gets the connection reset, and
   `fetch` cannot open a Unix socket at all. No `workloadApi` value reaches an agent.
2. **Algorithm.** SPIRE signs JWT-SVIDs with ES256. `VERIFY_ALGORITHMS` whitelists `Ed25519` and
   `RS256`, so a genuine SVID is refused as `unsupported_algorithm` before its signature is read.
3. **Issuer.** SPIRE emits no `iss` claim. `verifyJwtSvid` requires one equal to
   `spiffe://<trust domain>`, so fixing (2) alone would move the refusal to `wrong_trust_domain`.
4. **ECDSA encoding.** JWS specifies a raw `R||S` signature; `node:crypto`'s `verify` accepts only
   DER. Whitelisting ES256 would not by itself be sufficient.

None is fixed here. Interoperating needs a gRPC client, and widening the algorithm table is a
security decision; both are product changes rather than test fixes. What changes is the claim:
`spire-workload-identity` moves from `REAL_SUBSTRATE` to `SIMULATED`, and S4's evidence cell now
says plainly that no SPIFFE SVID is accepted in practice. The identity a deployment runs is the
locally-signed `local_key` envelope, documented as the weaker of the two — the process that
asserts an identity is the process that holds the key.

> **Superseded — do not read the paragraph above as current.** Commit `8bfc7fb` fixed all four
> defects: a gRPC Workload API client, ES256 whitelisted, the missing `iss` derived from the
> trust domain, and DER conversion on the verify path. `spire-workload-identity` is
> `REAL_SUBSTRATE` again, and eleven gated tests pass against a live SPIRE 1.15.3 trust domain
> with zero skipped. The paragraph is kept because the downgrade was a real and correctly
> recorded finding; what it recorded has since been repaired.

**The FakeCedar provider was permitting requests the shipped policy denies.** The registry
described `FakeCedarProvider` as permitting "everything except credential_access" and said that a
pass "proves nothing about Cedar authorization semantics". Every clause was true, and it still let
a real defect through. Seven v1 suites use the fake to build an **allow** as a precondition, then
assert something unrelated to Cedar about it — that the audit chain links, that the budget check
short-circuits, that the tool result is recorded. That is safe only while the fixture's allow is
one the real policy would also issue. It was not:

```
resource.path="/workspace"           real cedar=forbid   fake=permit
resource.path="hello.txt"            real cedar=forbid   fake=permit
resource.path="/workspace/README.md" real cedar=permit   fake=permit
```

`commandFromRequest` derives the workspace as `dirname(resource.path)`, so `"/workspace"` derives
the workspace `"/"`, and `policies/default.cedar` permits only `resource.path == "" ||
resource.workspace_path == "/workspace"`. Five fixtures — `audit-chain-verifier`,
`tool-result-service`, `policy-bundle-hot-reload`, `mcp-gateway`, and partially
`postgres-repository` — sat on an allow production refuses. The consequence is not a noisy false
alarm; it is a suite certifying "an allowed tool call is audited" on the strength of an
authorization that cannot occur.

Fixed by declaring `host_workspace_path`, and the fixtures moved into one module
(`src/fake-cedar-fixtures.ts`) so they cannot drift apart again. The guard that keeps them honest
is `src/cedar-fixture-parity.test.ts`, which evaluates the **imported** fixtures against the real
`cedar-policy-cli`. The first version of that guard re-declared the shapes inline and was
worthless — deleting `host_workspace_path` from the real fixture left it green, because it was
checking its own copy. That is why the fixtures are exported rather than written twice.

**One real divergence was open, and it is not a fixture.** *(Superseded in `8bfc7fb`: the gap is
closed. The gateway's derived path is what `policies/default.cedar` confines to the approved
workspace, so the fail-closed default is correct and is now asserted as such; a second,
`policies/templates/mcp-readonly.cedar`, shipped inert because it gated on actions the gateway
never emits, and was fixed to gate on the real action plus `mutation == false &&
destructive == false`. The default still refuses all five MCP shapes. The paragraph below records
what was true when the phase closed.)* `src/mcp-gateway.ts` derives
`resource.path` as `/mcp/<server>/tools/<tool>` in production code and sets no
`host_workspace_path`, so the derived workspace is the `tools` directory and the shipped policy
denies **every** MCP tool call. `mcp-gateway.test.ts` passes because the fake permits it. In
production the MCP gateway cannot obtain an allow at all. This is a product gap: either the
gateway must declare a workspace, or a shipped policy must cover MCP resources.
`cedar-fixture-parity.test.ts` asserts the divergence **still exists**, so that fixing it fails a
test and forces the registry note to change in the same commit. It is not counted as verified.

**The `docker-executor` SIMULATED label was hiding two unbacked claims.** The note said argv was
asserted against a recorded command, which is true and understated the problem: S2 (egress
isolation) and S7 (the Ed25519 verifier) had **no** live-container coverage anywhere. Both are
now covered in `docker-executor-substrate.test.ts` and both were mutation-checked. Dropping
`--internal` from the egress cell made a workload resolve `example.com` to a real address —
`104.20.23.154` — which is the property, demonstrated by breaking it. Removing the signature check
ran a real container for a token signed by an untrusted key.

That left a residue, enumerated rather than summarised: the argv strings for `--cap-drop ALL`,
`--security-opt no-new-privileges`, `--memory`, `--cpus`, `--pids-limit` and `--tmpfs`, whose
effects inside a container were unobserved; output truncation, redaction and the timeout path,
asserted against a fabricated stdout; and the gVisor flag plumbing. **All three items are now
closed, and `docker-executor` is `REAL_SUBSTRATE`.** Nine tests run each flag on a real container
and read the consequence from inside it — the bounding set and `NoNewPrivs` in
`/proc/self/status`, the cgroup's `cpu.max`, the fork limit, `ENOSPC` on the `/tmp` tmpfs, and the
OOM killer at exit 137 — each with a control that removes exactly that flag and asserts the effect
is gone. Three details were wrong in the first attempt and are worth recording. `CapEff` cannot
carry the capability assertion, because the executor also sets `--user 1001:1001` and a non-root
user has an empty effective set regardless; only `CapBnd` is attributable to `--cap-drop ALL`. The
memory probe cannot write to the filesystem, because a cgroup limit is charged on pages *held* and
file-backed page cache is reclaimable — a container limited to 512 MB writes 200 MB to disk and
exits 0. And the `/tmp` probe has to assert `ENOSPC` rather than merely a failure, or the
read-only root filesystem would satisfy it while the tmpfs size limit went unexercised. Deleting
any flag, or disabling truncation, redaction or the timeout kill, fails exactly one of the
twenty-six and leaves the rest green.

**`confidential-computing` stays NOT_IMPLEMENTED and cannot be closed here.** The hardware claim
was an assertion — "an i7-12700K predates TDX" — until it was read out of CPUID, and it turned out
to be weaker as an assertion than as a measurement. `cpuid` on this host reports leaf 7 subleaf 0
ECX = `0x00400784`, so **TDX (bit 20) = 0 and TME (bit 5) = 0**; TME is what Intel TDX is built on,
so the substrate feature is not implemented on this part at all, rather than merely arriving a
generation too late. The AMD leaf `0x8000001F` is unsupported outright (max extended leaf
`0x80000008`), and VT-x is not exposed to the OS at all. There is nothing to configure. The tree is
separately confirmed to hold no SEV, TDX or attestation code, test or configuration; the only
matches for those terms are this documentation and unrelated `CONFIDENTIAL` `data_clearance` values.

This is the one entry in the state file that no test on any host reachable from here can close, so
it is the one that needs a decision rather than more work. An itemized waiver — what is not
claimed, the measured capability table, the five things that would close it, and a signature block
— is drafted in **`docs/OPEN_WAIVERS.md`**. It is unsigned, and unsigned means open.

The gate that let the SPIRE finding sit is itself a defect worth recording. The group claimed
`REAL_SUBSTRATE`
while every one of its tests skipped, because the gate probed `spire-server version` — not a
subcommand, and it exits 127 even when SPIRE is installed and healthy. A level with no execution
behind it. The probe is `--version` now, and all eleven tests assert measured outcomes instead of
skipping silently: they would fail loudly if the client started interoperating without anyone
updating the record. Two guards moved with it. A `SIMULATED` group may now carry gated tests, since
a simulated integration is exactly what a substrate test is for, and both guards apply the
"report your gated tests as unavailable" rule to it rather than exempting it.

context envelope is not yet enforced on any request path.

**gVisor moved from SIMULATED to NOT_RUN, and the move found a defect.** The availability gate
asked whether the `runsc` *binary* was on PATH and treated that as the runtime being usable. Those
are independent: a host can have gVisor installed and be talking to a daemon that was never
configured to offer it, which is the stock state. The gate passed, the executor emitted
`--runtime=runsc`, and the refusal arrived from Docker as `unknown or invalid runtime name`
instead of from the gate, where the message can name the missing piece. The gate now also reads
the daemon's own runtime registry and requires a `runsc` key there, and the refusal names which
precondition failed — *install gVisor* and *register it in `daemon.json`* are different fixes.

**gVisor then moved from NOT_RUN to REAL_SUBSTRATE, because NOT_RUN was wrong about the machine.**
The gate asks whichever daemon `DOCKER_HOST` names. Docker Desktop's daemon registers only
`io.containerd.runc.v2`, `nvidia` and `runc`, so probing it answered honestly and concluded gVisor
was absent. But a second isolated `dockerd` inside the WSL2 `Ubuntu-24.04` distro has `runsc
release-20260928.0` registered and has been running on this host all along. The level described
Docker Desktop's daemon and generalised it into a property of the host, which it never was.

`src/gvisor-sandbox-substrate.test.ts` now starts real containers there. The discriminator is
kernel identity, because it is the one thing that cannot be faked by an ignored flag: the same
image on the same daemon reads `6.18.33.2-microsoft-standard-WSL2` from `/proc/version` under the
default runtime and `4.19.0-gvisor` under `runsc`, and `dmesg` returns gVisor's own boot log
exactly where the host ring buffer is refused with `Operation not permitted`. The executor's real
spawn path is covered too, by reading the container's `/proc/version` back out through the bind
mount — so dropping `--runtime runsc` fails the test instead of quietly passing it. That path was
mutation-checked: reverting `resolveSandboxRuntimeFlags` to return no flags turns two of the six
red.

The one seam left was narrower than it looked. The gate was injected as `checkRunsc: () => true`
because `runsc` lives in the WSL2 distro and not on the Windows client, so every test above proved
the *argv* rather than the *wiring*: nothing showed that the executor's own `which runsc` is what
turns the flag on. `gvisor-sandbox-substrate.test.ts` now runs on both hosts, and one test passes
no `checkRunsc` at all. Run inside WSL2, production code makes that decision, the flag appears, and
the container's `/proc/version` still reads `4.19.0-gvisor`. Mutation-checked: with
`resolveSandboxRuntimeFlags` returning no flags, that test fails and the other five still pass.

Two limits are recorded rather than papered over. **Egress is not claimed**: that daemon's bridge
has no external route for *either* runtime, so blocked egress there cannot be attributed to
gVisor's netstack and is not evidence of anything. And the client-side binary probe is injected in
five of the seven tests, because `runsc` lives in the WSL2 distro and not on the Windows client —
the probe that decides usability, the daemon registry, is the real one against the live daemon in
all of them, and the seventh leaves the binary probe un-injected too, which is why it runs under
WSL2 and skips on Windows rather than the other way round.

**`packages/pi-adapter` on this machine: 73 tests, 64 pass, 0 fail, 9 skipped.** The ninth skip is
`Given a symlink to a credential file when guardedRead runs`, which fails at `symlinkSync` with
`EPERM`: a Windows capability limit — creating a file symlink needs Developer Mode or elevation —
not a property of the code under test. It is now gated on a **probed capability** rather than
skipped or deleted: the test creates a real symlink in a temp directory and, only if the OS
refuses, skips with a message naming the limit. The probe is specific — directory junctions still
work on this machine — so a Windows host with Developer Mode on still runs the test. It is
recorded as a skip, not as a pass, because the symlink-resolution path really is unexercised here
and no other test covers it.

---

## 5. The shell command was unbound on both executors (fixed)

This section previously described the pi-adapter `shell_executor.ts` as a divergent fork that
left S8 and S9 unmet *on that path only*, and stated that the `actantosd` executor was unaffected
because S8 was carried by `effect-permit.ts`.

**That was wrong, and the error mattered.** Re-tested directly, the canonical executor was
missing the same binding. `constraints_hash` covers only the execution envelope
(`network_mode`, `timeout_ms`, `max_output_bytes`); `scope_hash` covers `resource` and the
`normalized` block, which carries `command_family` and `subcommand` but not the arguments. Nothing
on either path bound the argv.

Measured against the unmodified code, on both executors, with a token minted for `printf hello`:

| Tamper after authorization | `docker-executor` | `shell_executor` |
| --- | --- | --- |
| Substitute `rm -rf /workspace/important` | **ACCEPTED, command ran** | **ACCEPTED, command ran** |
| Raise `max_output_bytes` to 10 MB | rejected | **ACCEPTED** |
| Escalate `network_mode` to `egress_proxy` | n/a (hashed) | **ACCEPTED** |
| Remount `/etc` as the workspace | **ACCEPTED** | **ACCEPTED** |
| Expired token | rejected | **ACCEPTED** |

So the previous claim — that this weakened only pi-adapter — understated it. Authorization on
this path bound *who asked* and *the envelope*, never *what ran*. A token granted for a read
command authorised an arbitrary destructive one, which is the S8 failure the invariant exists to
prevent.

### What changed

- **`actantosd/src/decision-command.ts` (new).** `canonicalCommandHash(argv, workspacePath)` —
  a digest over the ordered argv plus the host workspace that will be mounted. It reuses the
  existing `canonicalHash`; no new policy language, no new primitive.
- **The server mints `command_hash`** from `commandFromRequest(request)`, derived from the same
  interception request the policy engine evaluated, so the token cannot describe a different
  command than the one authorized.
- **Both executors verify it** before any spawn, alongside expiry and `constraints_hash`.
  `docker-executor` already had expiry and the envelope check; `shell_executor` had neither and
  now has both.
- **`shell_executor` additionally** resolves gVisor through a `resolveSandboxRuntimeFlags` port
  of the canonical rule (run under gVisor or refuse; never degrade), and attaches to
  `actantos_egress_cell` — the internal cell — instead of creating and joining a plain bridge
  called `actantos_egress`, which had no proxy on it and no `--internal` flag.

### Evidence

14 new tests in `packages/pi-adapter/src/shell_executor.test.ts` and `src/decision-command.test.ts`,
plus 6 in `src/docker-executor.test.ts`. Each was mutation-verified: disabling the command check
fails 4 tests on each path; removing `--internal` fails the S2 test; removing the gVisor refusal
fails both the behaviour test and the drift guard. The drift guards import the *actantosd*
implementations and assert the restated digests match, so the two copies cannot diverge silently.

**The binding was then re-verified against real containers.** A recorded argv proves the executor
*decided* to refuse; it does not show that a running container is subject to that decision.
`src/docker-executor-substrate.test.ts` (12 tests, `docker-container-execution`, REAL_SUBSTRATE)
runs actual containers: the authorized command executes and its output is observed, a substituted
`sh -c` command is refused with Docker live behind it, `--network none` leaves no name resolution,
the container runs as a non-root uid with an unwritable root filesystem, and a forged signature is
refused. Disabling the command check fails 2 of these against the live daemon.

**The decision token is now single-use on this path too.** Before this, a captured token could be
replayed for the whole of its remaining TTL — the expiry check bounded the window but did not close
it. `createDecisionToken` mints a unique nonce per token, and both executors claim it before
spawning. The store is a *required* dependency rather than an optional one: an executor configured
without it throws at startup rather than quietly accepting replayable tokens. A token with no nonce
claim is refused as malformed rather than exempted, because exempting it would hand an attacker a
way to mint replayable tokens on purpose.

Proven at three levels. Unit tests in `decision-nonce-store.test.ts` cover the store itself,
including that `isConsumed` does not consume and that a restart clears it. The executor tests
assert the exact refusal reason — `decision token already used`, distinct from `decision token
command mismatch` and `decision token expired` — so a passing test cannot be explained by a
different check firing first. And `docker-executor-substrate.test.ts` closes the loop with a live
daemon: one token produces exactly one container, and the replay is refused in well under the
one-second image-inspect timeout, which is what distinguishes "refused before starting anything"
from "refused slowly". The control test issues two independent tokens for the same command and
sees both run, so single-use has not degenerated into "this command may run once, ever".

Mutation-verified by disabling the consume, and separately by keeping the consume but discarding
its result (`&& false`). Each fails 2 tests on each executor.

### The Cedar CLI was never actually asked, and it disagreed with us about denying

The three Cedar tests skipped on every previous run of this suite, so nothing in this repository
had ever executed Cedar. Installing `cedar-policy-cli` 4.13.0 (SHA-256 verified against the
upstream release checksum) turned a `NOT_RUN` into a result, and the first result was a failure.

**Cedar exits 2 to say Deny.** Measured directly:

| Outcome | Exit code | stdout | stderr |
|---|---|---|---|
| Allow | 0 | `ALLOW` | empty |
| **Deny** | **2** | `DENY` | empty |
| Policy parse error | 1 | `× failed to parse policy set` | empty |
| Missing policy file | 1 | `× failed to open policy set file` | empty |

`#runAuthorize` treated *any* non-zero exit as an evaluator failure and threw before reaching
`parseAuthorizeDecision`, which already knew how to read `DENY`. Every policy denial that reached
the CLI therefore surfaced as an exception. The production caller catches that and fails closed, so
no request was wrongly allowed — but the decision was reported as
`dependency_failure.policy_evaluation`, an infrastructure fault, rather than the policy's own
refusal, and the policy's reason code was lost from the audit record.

This never surfaced because `evaluateBuiltInPolicy` answers the three known policies in-process, so
the shipped policy never reached the CLI to be denied.

An existing test asserted the opposite behaviour *by name* — "rejects non-zero Cedar exits even when
stdout begins with DENY" — on a fixture pairing exit 2 with an error string. That fixture is not a
shape the real CLI produces: a diagnostic comes with exit 1. The test encoded an assumption about a
substrate that had never run, and would have kept a denial-as-exception bug in place. It is kept,
with its premise corrected: a bare `DENY` is now a decision, and a `DENY` carrying a diagnostic is
still a failure, so the retryable recursion case it was written for keeps working.

### The shipped policy now constrains the workspace, and two evaluators must agree

`policies/default.cedar` was `resource.credential_access == false` and nothing else — the
`workspace_path` attribute added in `5678af8` was visible to policy and ignored by it. It now
constrains file operations to `/workspace`.

Two things had to change with it, and both were found by running tests rather than by reading:

**The workspace fallback was wrong.** With no declared `host_workspace_path`, `commandFromRequest`
fell back to the whole resource *path*, so `/workspace/README.md` was offered to policy as a
workspace. A file is not a directory. It now falls back to the containing directory, in
`commandFromRequest` itself so the value the command digest binds and the value policy sees stay
the same value — splitting them is the defect `5678af8` was written to remove.

**The constraint does not apply to network calls.** Scoping it to every resource denied 14
v2 runtime tests, because their fixtures are `resource: { url: ... }` with no path, so the
workspace was empty and the equality failed. A filesystem boundary is not the right test for an
outbound HTTP call. The shipped policy therefore reads
`resource.path == "" || resource.workspace_path == "/workspace"` — verified against the real CLI
across six shapes: file in workspace allows, `/etc` workspace denies, nested workspace denies,
credential file denies, and both network-call shapes allow.

`evaluateBuiltInPolicy` is a second implementation of the same decision, kept so the daemon works
without the binary installed. Two implementations that can drift is precisely how a host with no
Cedar would quietly enforce something other than the policy it ships, so
`the built-in evaluator and the real cedar CLI never disagree` runs the same contexts through both
and fails on any difference. Mutation-verified: making the built-in evaluator ignore the workspace
fails that test.

**What this still does not establish.** The policy constrains the *workspace*, not the resource
path relative to it: an agent declaring `/workspace` is still permitted to name `/etc/shadow`,
because this CLI build exposes no string extensions (`startsWith` is rejected at parse time) and an
exact-equality policy cannot express "under this directory". The containment for that is the target
guard and the command digest, not this policy, and the two claims are recorded separately.

### What this does not establish

The digest binds the host workspace **consistently**, not by policy. `host_workspace_path` is
declared by the caller and the policy engine does not evaluate it, so this stops the executed
command from diverging from the authorized one; it does not make the workspace an authorization
input.

The nonce store is **per-process**. `InMemoryDecisionNonceStore` holds consumed nonces in a `Set`,
so an executor restart makes every previously-used token usable again for whatever remains of its
TTL. The durable `ReplayStore` used by the effect gateway closes this and is not wired here; the
reason is timing and coupling, since the executor must decide before it spawns and
`ReplayStore.consume` is async and backed by PostgreSQL. A test asserts this limitation rather
than leaving it in prose only.

`pi-adapter-shell-executor` is now **REAL_SUBSTRATE** too:
`packages/pi-adapter/src/shell_executor_substrate.test.ts` (8 tests) starts real containers on the
fork. Running both executors against a live daemon is the point — two implementations agreeing on
recorded argv can still disagree about what Docker actually receives. `docker-executor` remains
`SIMULATED` as an entry because the REAL_SUBSTRATE claim for that code path belongs to
`docker-container-execution`.

Writing that test surfaced a false green worth recording. Both substrate suites asserted a
read-only root filesystem by attempting a write and checking it failed. The actantosd version
wrote to `/root` and the pi-adapter version to `/`. Both fail for a non-root user whether or not
`--read-only` is set, so both were really re-asserting `--user`; **deleting `--read-only` from the
executors left both suites green.** `/tmp` is no better, since the executors mount a writable tmpfs
there and the write always succeeds. The tests now write to `/etc` and assert the *reason* —
`Read-only file system` with the flag, `Permission denied` without it. Both are `rc=1`, so only the
message distinguishes them, and removing the flag now fails both suites.

That second fix needed a third correction. The rewritten test asserted the reason string against
`stdout`, but the executor captures `stderr` separately, so `touch` wrote the message to a stream
the assertion never saw — the tests failed for a reason that had nothing to do with the flag under
test. `2>&1` inside the container command is what makes the assertion able to see it. The mutation
was re-run only after that was fixed; the first result was not evidence of anything.

The symmetric HMAC is still the default scheme, so a secret holder can mint tokens — but both
executors now also accept Ed25519 (`src/decision-token-signature.ts`), which closes that. The
algorithm is bound into the token envelope and checked against a fixed expectation rather than used
to dispatch, so a token cannot select its own verifier; the downgrade test asserts that an
Ed25519-configured executor refuses an HMAC token. Ed25519 reuses the existing `ed25519` wrapper in
`v2/signature.ts` rather than adding a second implementation, and pi-adapter's restated copy is
guarded by tests that mint with the actantosd implementation and verify through the pi-adapter one.

`effect-permit.ts` is a separate mechanism and is **not** on this path. gVisor is
unchanged and still `SIMULATED`: the substrate tests stub `checkRunsc`, so they say nothing about
runsc.

---

## 6. Limitations

1. **Baseline v2 does not claim protection after host-kernel or root compromise.** Every control
   runs as an ordinary process. Confidential computing is the only thing that actually closes this.
2. **Credentials are released, not erased.** A Vault lease is revoked and the call ends; Node
   strings are immutable, so erasure is a claim the runtime cannot support.
3. **No private-key storage abstraction.** A signing key arrives as a PEM in an environment
   variable. The rotation *mechanism* is done; operator tooling and a real key vault are not, and
   no deployment has rotated a key through this path.
4. **No key hierarchy.** No root, no cross-signature, no chain. A key is trusted because an
   operator put it in the map.
5. **The envelope is not enforced.** It verifies, binds and narrows, with tests for each, but no
   request path requires one and no control plane issues them.
6. **A bare hostname in free-form arguments is not a target.** Recognised are URLs, IPv4, and
   bracketed IPv6. The network cell is the backstop.
7. **Redirects inside an established tunnel are not constrained.** The cell constrains where a
   connection opens, not where it ends.
8. **The egress guard has a node budget.** A value above `MAX_TARGET_WALK_NODES` is refused as
   uninspectable rather than inspected partially.

### 5a. The authorization ended in a database column

**The gap.** `executeDockerCommand` had no non-test caller anywhere in the repository. The control
plane minted a signed decision token, returned it in the interception response, stored it, and
re-verified it on the `/v1/tool-result` callback — and then nothing ever handed it to an executor.
The signed-authorization chain terminated in a column. Every test that exercised the executor
injected its own nonce store and its own spawn stub, so a reader could reasonably conclude the
executor was load-bearing while the product had no way to reach it. `ReplayStoreDecisionNonceStore`
and `PostgreSQLReplayStore` were constructed only in test files.

That is also why last milestone's note declined to build a durable nonce store: it would have been
an abstraction without a consumer. The consumer was the missing piece, so the store was the wrong
thing to build and was not built.

**The fix.** `src/decision-execution.ts` looks the stored authorization back out of the tables the
control plane wrote, refuses anything that is not a live `allow`, and spends the token through the
real executor. `src/execution-routes.ts` exposes it at `POST /v1/executions`.

**Identity comes from the record, not from the caller.** `assertClaimsMatch` compares the token's
claims against the request: tenant, agent, session, scope hash, expiry, and the hashes binding the
command and the constraints. Copying those fields out of the token would make the check compare the
token against itself, so they are read back from PostgreSQL instead — `agents` and `sessions` are
joined for their `external_id`, because the UUID is not what the token is signed over. The caller
supplies only `argv` and `workspacePath`, which is exactly the S8 surface: a swapped binary, an
appended argument or a different directory all leave `command_hash` unmatched, and the test asserts
that **nothing is spawned**, not merely that an error was raised.

**Durability.** The executor consumes its nonce in PostgreSQL, so a captured token stays spent
across a restart. `index.ts` refuses to start if `DATABASE_URL` is absent rather than falling back
to a `Set` — there is no in-memory fallback that would not silently downgrade S9.

**Ed25519 is enforced here, offered elsewhere.** The service throws at construction if handed an
HMAC verifier, because a verifier holding the signing key can also mint, which is what S7 forbids.
A stored HMAC token is refused at execution time by name (`token_not_ed25519`), which is the
fail-closed outcome; the alternative would be a fallback to HMAC verification, i.e. the exact
property this work exists to remove.

**Constraints come from the record too.** `network_mode`, `timeout_ms` and `max_output_bytes` are
read from the stored decision, and `constraints_hash` binds them, so a tampered row cannot widen
egress — there is a test that sets the row to `egress_proxy` against a token signed for `none` and
asserts the refusal.

**Not enabled by default.** The route is registered only under `ACTANTOS_DECISION_EXECUTION=1` and
never on a control plane. A build without the flag has no `/v1/executions` handler at all, so a
deployment that never opted in is unaffected rather than newly refusing traffic it never handled —
asserted by a test that injects the request and requires a 404.

**What this does not prove.** That a container started through this path is genuinely isolated, and
that the Ed25519 private key stays off the executor host. The first needs the real-container
substrate tests; the second is a deployment property no signature format can demonstrate.

---

## 7. Next milestone

**P — WASI, PQC and confidential-computing experiments.** Explicitly last: the roadmap requires
A–N to be trustworthy first, and they now are, with every one of the five phases verified by
mutation rather than inspection.

The most valuable immediate work was reconciling `shell_executor.ts` with
`docker-executor.ts`, because until that is done the fabric does not cover a path that ships.
That is now done (section 5), and it turned out to cover a defect the `actantosd` executor had
too.

**What remains, in order of value:**

1. ~~**Real container execution.**~~ Done on both paths: `docker-container-execution` runs 26 gated
   tests against a live daemon, and `pi-adapter-shell-executor` is itself REAL_SUBSTRATE with 8
   more (section 5).
2. ~~**Nonce consumption on the executor path.**~~ Done, including the part that was left open
   last time. Both executors require a nonce store and claim the token before spawning, and
   `ReplayStoreDecisionNonceStore` now wraps the same PostgreSQL `ReplayStore` the effect gateway
   uses, so single use survives an executor restart rather than resetting with the process. That
   store was previously unbuilt on the grounds that `executeDockerCommand` and `executeShellCommand`
   have no production caller and a durable store for them would be an abstraction without a
   consumer. The caller now exists — see section 5a — so the store has one.
3. ~~**Asymmetric token signatures.**~~ Implemented and now enforced on the path that executes.
   Both executors accept `tokenVerification: { kind: "ed25519", publicKeyPem }`, which makes the
   verifier unable to mint. On the execution path this is no longer a choice: the service refuses to
   construct with an HMAC verifier and refuses an HMAC token at execution time, so a token minted
   before Ed25519 was configured is unexecutable rather than quietly verified the weak way. HMAC
   remains the default everywhere else — changing it silently on the rest of the surface would be a
   behaviour change nobody asked for. What remains is deployment: proving the private key stays on
   the control plane is a property of the deployment, not of the signature format.
4. ~~**The workspace as a policy input.**~~ Done, and it found two defects on the way. The Cedar
   resource entity carries `workspace_path`, derived through `commandFromRequest` so policy sees
   the same value the command digest binds, and `policies/default.cedar` now *acts* on it: file
   operations are confined to `/workspace`, and a guard fails if the in-process built-in evaluator
   and the real CLI ever disagree about a request. Installing `cedar-policy-cli` turned the
   `NOT_RUN` into a run, and the first run failed — Cedar exits 2 to say Deny, which the provider
   was treating as an evaluator failure. Section 5 has the measurements. What is *not* claimed:
   the policy constrains the workspace, not the path beneath it, because this CLI build has no
   string extensions.

---

## 8. A note on how these defects were found

Every real defect in this work was found by a check that compared an **expected specific outcome**
against reality — a known-answer vector, an independent recomputation, a deliberately hostile
input, or a mutation. None was found by reading the code, and several were in code that had
already been reviewed and marked complete.

The pattern worth carrying forward: a test asserting a weaker property than the one that matters
is worse than no test, because it is indistinguishable from one that is working. Two of the three
failures in Phase N were tests asserting something false, and the honest response was to work out
which — the test, the product, the assumption, or the substrate — was wrong before changing
anything.
