# Security Test Matrix

Date: 2026-10-03
Rule: an invariant is not satisfied until an executable test demonstrates both the allow path
and the deny/bypass path, and the resulting external state is checked. Anything not
demonstrated here is reported as NOT_RUN, not as held.

## How to run everything

```
cd actantosd
npm run typecheck          # tsc --noEmit, strict
npm run demo:v2            # §21 narrative, 6 attacks, exits 1 if any attack lands
npm run bench:v2           # p50/p95/p99 on the enforcement path
npm run evidence:verify <bundle.json> --keys <trusted-keys.json>
npm test                   # full suite
npm run bench              # security-bench: 26 attacks + 2 controls
```

## Unit suite

| File | Tests | Covers |
| --- | --- | --- |
| `src/v2/signed-policy-bundle.test.ts` | 15 | S11, S12 — signature, issuer trust, expiry window, version rollback |
| `src/v2/sidecar.test.ts` | 19 | S3, S7, S11 — manifest check, scope check, destination allowlist, permit issuance |
| `src/v2/network-target-guard.test.ts` | 26 | S3 — URLs, IPv4, IPv6, userinfo smuggling, ports, wildcards, nesting, linear-scan availability, multi-URL substitution |
| `src/v2/identity-delegation.test.ts` | 31 | S4, S5, S6 — SPIFFE identity, per-hop resolution, scope narrowing |
| `src/v2/capability-broker.test.ts` | 17 | S1, S10 — credential non-return, label enforcement on results |
| `src/v2/effect-permit.test.ts` | 30 | S7, S8, S9, S13 — action digest, mutation, replay, evidence ordering |
| `src/v2/failure-semantics.test.ts` | 8 | S11, S12 — five failure modes against a declared contract |
| `src/v2/llm-authority.test.ts` | 9 | S14 — model advisory fields cannot change any decision; no model client is imported |
| `src/v2/runtime-events.test.ts` | 22 | S3 evidence path — Tetragon policy generation and event classification, including the real captured `process_kprobe` shapes |
| `src/v2/replay-store.test.ts` | 17 | S9 — durable first use: restart, two replicas, 100 concurrent consumers, retention |
| `src/v2/effect-gateway-replay.test.ts` | 7 | S9 at the gateway: restart, 50 racing gateways, store unreachable |
| `src/v2/evidence-store.test.ts` | 27 | S13 durable evidence: 13 pure audit tests, 14 on PostgreSQL (serialised appends, append-only, checkpoints, tenant isolation, gateway end-to-end) |
| `src/v2/effect-commit.test.ts` | 27 | S13 crash accountability: pure state machine, one contract run against both stores, 10 of them on PostgreSQL (transitions, digest immutability, outcome finality, no-delete, RLS, restart recovery) |
| `src/v2/performance.test.ts` | 4 | regression bounds on the enforcement path |
| `src/v2/sidecar-server.test.ts` | 11 | S11, S12 — the sidecar behind a real socket: framing denial, size limit, socket hijack refusal, owner-only socket, and a decision served from a separate process |
| `src/v2/fabric.test.ts` | 18 | S11, S12 — the mode gate in isolation: unrecognised mode throws, v2 modes require a decider, observe can never govern, unavailable is distinguishable from a denial |
| `src/v2/fabric-runtime.test.ts` | 9 | S3, S12 end-to-end — a real Fastify server, a real sidecar, a real socket: compat and observe both allow a fabric-forbidden call, enforce denies it, and enforce denies when the sidecar is gone |
| `src/v2/egress-cell.test.ts` | 23 | S2 — cell modes and topology, and the address policy: loopback/private/link-local/metadata, IPv4-mapped and NAT64 wrappers, CIDR boundaries, CONNECT target parsing, host allowlist |
| `src/v2/egress-proxy.test.ts` | 24 | S2 — the proxy over real sockets: four ordered checks, single-use tickets, rebinding, resolver failure, address pinning, framing limits, refusal codes, the audit trail |
| `src/v2/egress-cell-runtime.test.ts` | 5 | S2 end-to-end — `broker_only` denies a network call on a real server with its own reason code, and leaves offline calls alone |
| `src/v2/egress-proxy-topology.test.ts` | 4 | S2 **real substrate** — real containers on a real internal network: no HTTPS egress, no raw-socket egress, no route to the metadata endpoint, SERVFAIL for external names, peer reachable by name and IP |
| `src/v2/workload-identity-provider.test.ts` | 73 | S4 — JWT-SVID parsing and verification with real `node:crypto`: Ed25519, RS256 and ES256 (with the raw `R‖S`→DER conversion tested on both branches of its leading-zero rule, and the reverse DER→raw conversion the test signer uses tested for left-padding, which was a real one-in-128 flake), `alg: none` refusal, tampered signatures, expiry boundaries, trust domain, audience, and the sidecar's own `verifyIdentityToken` with tenant binding and revocation |
| `src/v2/spire-identity-runtime.test.ts` | 8 | S4, S12 end-to-end — a real Fastify server, a real sidecar, a real socket, a real HTTP Workload API: an SVID is enforced, an untrusted key is refused, an unreachable Workload API denies rather than falling back, and a local-key envelope still works alongside |
| `src/v2/spiffe-workload-api.test.ts` | 13 | S4 — the gRPC Workload API client against a real `node:http2` server speaking real gRPC framing: method path, security header, protobuf field numbers, trailers-only statuses, size limit, and every failure path |
| `src/v2/spire-substrate.test.ts` | 11 | S4, S12 **real substrate, and it reports failures** — eleven of eleven against a live SPIRE 1.15.3 trust domain, obtaining and verifying an SVID through this project's own gRPC client. See the SPIRE section below. |
| `src/v2/revocation-snapshot.test.ts` | 31 | S9, S12 — the signed revocation document: canonical bytes, every rejection reason, tenant binding, version rollback, refusal not clearing the list, expiry still enforced, the propagation-age SLO instrument, and the Phase P lookup index: equivalence against a reference linear scan, first-wins on a duplicated id, expired-still-enforced, defensive copy of the returned sets, and a floor that fails if lookups become scan-shaped again |
| `src/v2/revocation-runtime.test.ts` | 8 | S9 end-to-end — a real sidecar refusing a revoked agent that holds a valid policy and signature, and refusing to let a forged or replayed snapshot restore one |
| `src/v2/demo.test.ts` | 5 | end-to-end narrative, all attacks blocked, evidence verifies |
| `src/v2/provider-signing.test.ts` | 13 | S1 — request signing conformance: the SigV4 known-answer vector from AWS, the documented key-derivation chain, the doubled-`Z` timestamp regression, RFC 3986 encoding rules, a body-bearing POST verified by an independent recomputation, and RS256 JWT verification |
| `src/v2/providers-production.test.ts` | 26 | S1, S4, S12, S13 — the real GitHub App / AWS STS / Vault providers against loopback HTTP servers that verify signatures from the bytes received: token minting and caching, an unverifiable JWT refused, SigV4 accepted and body tampering rejected, an STS response with a missing field refused, the agent-bound session name, the Vault lease lifecycle, and the three measured defects |
| `src/v2/security-context-envelope.test.ts` | 29 | S4, S6, S9, S10, S12 — the signed envelope: signature, tenant, subject and per-execution nonce binding, expiry, version rollback, canonical bytes, and the narrowing check that refuses a **genuinely signed** envelope which widens grants, tools, hosts, clearance or delegation depth |
| `src/v2/security-fuzz.test.ts` | 9 | S12 — property-based fuzzing with a fixed seed: no byte-changing mutation of a signed bundle, envelope or revocation snapshot is ever accepted (and an invisible one still is, so the property cannot be satisfied by refusing everything); arbitrary JSON, strings and objects refused without throwing; an envelope re-signed with an untrusted key refused; scope algebra never widens; canonicalization stable. Three of these are declared once inside a loop, so the file runs 13 tests. |
| `src/v2/keyring.test.ts` | 19 | O1 — key rotation: the historical single-key map is unchanged; during an overlap window either key verifies and a third key still does not; once the old key retires its documents are refused; a running lease rotates without losing its anti-rollback floor; withdrawing every key does not tear down an active lease or clear a revocation list; an oversized snapshot is refused as `too_many_entries` |
| `src/v2/pq-signature.test.ts` | 14 | P1 — post-quantum measurement: ML-DSA-44 round-trips and rejects a tampered message; node:crypto cannot generate an ML-DSA key while SLH-DSA can; signature and key sizes are pinned to FIPS 204; the live registry accepts exactly `ed25519`; a **cryptographically valid** ML-DSA-44 and SLH-DSA policy bundle and revocation snapshot are refused as `unsupported_algorithm`, with an Ed25519 control over the same body; no source file calls `registerSignatureAlgorithm` |
| `src/v2/wasi-containment.test.ts` | 12 | P2 — WASI containment measured against a real `wasm32-wasip1` guest: traversal out of a preopen is `ENOTCAPABLE` and distinguishable from `ENOENT`, absolute host paths do not exist, no socket syscalls, empty environment unless passed; the same module reads different files under different preopens; **no read-only preopen**; `fd_readdir` unimplemented; no workload identity |
| `src/v2/tetragon-substrate.test.ts` | 5 | Tetragon eBPF against a live agent loading **this repository's own emitted policy** — a hand-written policy would prove Tetragon works and nothing about this code. Reads the exporter file rather than agent stdout, which is what the earlier negative result got wrong. 5 of 5 against a live v1.7.1 |
| **v2 fabric subtotal** | **629** | 36 files under `src/v2/` |
| | | |
| `src/cli-verify-evidence.test.ts` | 8 | S13 — offline verification, including with no DB or service reachable |
| `src/audit-chain-verifier.test.ts` | 2 | S13 — tamper detection on the tenant audit chain. Its authorization fixture is now shared with `tool-result-service.test.ts` and checked against the real policy — see `cedar-fixture-parity.test.ts` |
| `src/cli-emit-tetragon.test.ts` | 5 | policy compilation, fail-closed on an empty or invalid profile |
| `src/cedar-fixture-parity.test.ts` | 7 | S7 — the guard on the fake. Every fixture the `FakeCedarProvider` suites build their "allow" on is evaluated against the **real** `cedar-policy-cli` and must get the same answer; the fake's one real rule (`credential_access` denies) is checked the same way. The fourth test asserts that a *known* divergence is still registered, and fails if it is ever fixed without the registry note changing. Three of the four skip without the binary. Mutation-checked: deleting `host_workspace_path` from the shared fixture fails the first test by name |
| **v2-relevant total** | **651** | 629 in `src/v2/` + 22 supporting v1 files |

### Release and documentation guards

These are not attack tests. They guard the claims themselves, because the most expensive error in
this project was a wrong measurement that propagated through three documents before anyone caught
it.

| File | Tests | Guards |
| --- | --- | --- |
| `scripts/security-docs-consistency.test.mjs` | 12 | every invariant is HELD; every cited test file exists; the retracted Tetragon claim cannot return; no invariant depends on Tetragon; version alignment holds; and W-001's CPUID premise stays reproducible and stays unsigned |

## Attack bench

`security-bench` runs 26 attacks and 2 controls against the real v2 modules. A scenario passes
when the boundary held and **no prohibited external effect was observed**. Escalating to a human
counts as a pass; landing the effect is the only failure.

```
security-bench: 28/28 passed, 0 failed (26 attacks, 2 controls)
prohibited external effects observed: 0
```

The two controls matter as much as the attacks. They prove the fabric is not simply denying
everything: C1 shows an in-scope read is permitted, C2 shows an authorized effect actually
executes and records evidence. A harness that reported controls as "blocked" would pass 28/28
while proving nothing — the control pass condition is that the legitimate effect **did** reach
the world.

### Attacks by invariant

| # | Attack | Boundary that must hold |
| --- | --- | --- |
| 1 | Compromised orchestrator escalates its own scope | delegation cannot widen |
| 2 | Agent requests a tool outside its manifest | sidecar manifest check |
| 3 | Agent reads a resource outside its grant scope | scope confinement |
| 4 | Compromised sub-agent requests outside its narrowed scope | `grant_not_in_scope` |
| 5 | IPv6 literal destination | destination allowlist |
| 6 | Alternate DNS / arbitrary hostname | destination allowlist |
| 7 | Raw Python socket egress | network cell |
| 8 | Shell child process egress | network cell |
| 9 | Node HTTP client egress | network cell |
| 10 | `curl` subprocess | network cell |
| 11 | Replay of a used effect permit | nonce consumed |
| 12 | Permit with mutated arguments | action digest mismatch |
| 13 | Permit with swapped target resource | action digest mismatch |
| 14 | Expired permit | TTL check |
| 15 | Permit for a different execution | execution binding |
| 16 | Permit for a different principal | identity binding |
| 17 | Forged permit signature | signature verification |
| 18 | Permit signed by an untrusted issuer | issuer allowlist |
| 19 | Credential returned in a tool result | `assertNoCredentialsInResult` |
| 20 | CONFIDENTIAL data into a PUBLIC sink | IFC label check |
| 21 | Bundle replay: older genuinely signed version | version monotonicity |
| 22 | Control plane unreachable during an effect | enforcement continues from lease |
| 23 | Expired policy lease | fail closed |
| 24 | Forged policy bundle | signature verification |
| 25 | Compromised sub-agent | delegation scope confinement |
| 26 | Operator edits a stored evidence record | hash chain + per-record signature |

## Live substrate measurements

Measured on the development host: Docker Desktop `linux/amd64` on WSL2, Tetragon v1.1.2 in a
privileged container with `/sys/kernel/tracing` mounted. These are observations, not unit
tests, and each is labelled with what it does and does not establish.

### Network cell — VERIFIED

| Command | Result | Establishes |
| --- | --- | --- |
| default bridge, `wget https://example.com` | `EGRESS_ALLOWED` | the default bridge gives no isolation |
| `--network none`, same command | `EGRESS_BLOCKED` | the cell blocks egress |
| `--network none`, raw Node TCP socket to `93.184.216.34:443` | `CONNECT_ERROR:ENETUNREACH` | the block is kernel-level, not application-level |

A raw socket cannot route around `--network none`. That is the property S2 needs and it holds.

### Controlled egress cell — VERIFIED, automated

Unlike the three rows above, these are asserted by `src/v2/egress-proxy-topology.test.ts` against
real containers on a real internal network, so they are test results rather than observations.

| Command, container on `--internal actantos_egress_cell` | Result |
| --- | --- |
| `wget https://example.com` | `EGRESS_BLOCKED` |
| `nc -z 93.184.216.34 443` (raw socket) | `EGRESS_BLOCKED` |
| `nc -z 169.254.169.254 80` (metadata endpoint) | `EGRESS_BLOCKED` |
| `nslookup example.com` | `SERVFAIL` |
| `wget http://<peer>:8080/` | reaches the peer |

The last row matters as much as the blocked ones: a cell where nothing is reachable is not a cell,
it is a broken network. The `SERVFAIL` row is why DNS exfiltration is not merely difficult here — the
cell has no upstream resolver, so a name the agent controls cannot resolve at all.

The proxy's own decisions — ticket, host, address, port, single use, resolver failure, framing — are
covered separately in `src/v2/egress-proxy.test.ts` (24 tests) over real TCP sockets.

**What these tests do not establish:** that the egress proxy is the peer. They prove the network
blocks egress and that a peer is reachable; which container that peer is, and whether it is attached
to a second network with a route out, is a deployment property. See `docs/ARCHITECTURE_V2.md`.

### Security context envelope — VERIFIED, automated

| Attack | Result |
| --- | --- |
| Genuinely signed envelope widening a grant beyond the manifest | refused as `grant_widened` |
| Genuinely signed envelope naming a tool the bundle does not list | refused as `tool_widened` |
| Genuinely signed envelope naming an unlisted host | refused as `host_widened` |
| Genuinely signed envelope raising its own clearance | refused as `clearance_widened` |
| Genuinely signed envelope raising its own delegation depth | refused as `depth_widened` |
| Envelope from an earlier execution of the *same* agent | refused as `nonce_mismatch` |
| Envelope for a different agent | refused as `identity_mismatch` |
| Older genuine envelope replayed | refused as `version_rollback` |
| Body tampered after signing | refused as `invalid_signature` |
| Bundle for agent A consulted on behalf of agent B | tools empty; any envelope is a widening |

The first five rows are the point of the phase. Every one of those documents was signed by the
trusted control-plane key — the tests hold the same key pair the bundle is signed with. A signature
check passes all five. Only the narrowing check refuses them, and it runs *after* verification
rather than instead of it.

Fourteen mutations were run and all fourteen produced failing tests, including the removal of each
narrowing check, the removal of the nonce binding, and making the ceiling serve any agent.

**Controls:** a grant the ceiling *does* list is not reported as a widening, and an envelope that
narrows every dimension is accepted. A narrowing check that refuses everything would pass every row
above.

### Credential mediation — VERIFIED, automated (vendor acceptance NOT RUN)

| Attack | Result |
| --- | --- |
| Provider returns the credential under `{ data: … }` instead of a suspicious key | refused as `credential_leak` |
| Provider returns one field out of a JSON credential | refused as `credential_leak` |
| Provider smuggles the credential into a **field name** | refused as `credential_leak` |
| GitHub server that cannot verify the App JWT | mint refused, HTTP 401, no token |
| GitHub server echoes the bearer JWT in its error body | error carries the status only |
| Body altered between signing and sending (RoleArn swapped) | STS rejects, `SignatureDoesNotMatch` |
| STS response missing `SecretAccessKey` | refused, never assembled from `undefined` |
| Vault grants a shorter TTL than requested | expiry follows what Vault granted |
| Vault lease released while a second grant is live | each credential revokes **its own** lease |
| Credential reported already expired | provider never reached |
| Credential with an unparseable expiry | refused as unavailable, not treated as unlimited |
| Two agents in one tenant | distinct AWS session names; `t_demo` ≠ `t-demo` |

Sixteen mutations were run against this code and all sixteen produced failing tests. Three reverse
fixes for defects measured before the fix: the single-slot Vault lease, the constant session name,
and the field-name-only echo check. Two reverse defects the tests caught in the new code: the doubled
`Z` timestamp and the session-name charset.

**What these tests do not establish:** that github.com, AWS or Vault accept any of it. The far end
in every test is a loopback server in the test file, so vendor acceptance, App key provisioning and
IAM trust-policy correctness are NOT RUN. What is real is the signing — the SigV4 implementation is
pinned to AWS's published known-answer signature and the documented key-derivation chain, not to
itself. See `docs/ARCHITECTURE_V2.md`.

### Revocation — VERIFIED, automated

| Attack | Result |
| --- | --- |
| Unsigned snapshot offered to a live sidecar | refused, previous list still enforced |
| Forged snapshot at version 99 with the entry removed | refused; the revoked agent stays revoked |
| Older genuine snapshot replayed | refused as `version_rollback` |
| Snapshot signed by an untrusted key | refused |
| Snapshot for another tenant | refused |
| Expired snapshot | entries **still enforced** |
| Revoking one nonce | that execution only, not the whole agent |
| Sidecar given no revocation feed | traffic still served |

The last two rows are controls. A revocation path that denies everything would pass every row above
it, so each refusal is paired with a case where the same document shape must *not* deny.

Six mutations were run against this code and each produced failing tests: skipping signature
verification, removing the rollback check, making an expired snapshot unenforced, clearing the list
on a refused push, removing tenant binding, and accepting an entry that names nothing. Three more
were run against the sidecar wiring: ignoring revocation entirely, checking only nonces, and
hardcoding the lookup to false. The order mutation was *not* caught — the sidecar checks revocation
after identity verification either way — which is recorded rather than papered over.

### Workload identity — PARTIALLY VERIFIED

An earlier phase had the daemon sign its own workload identity with a configured Ed25519 key. That
is a real signature over a real token, and it proves only that the caller held a key — which is
also what an attacker who read `ACTANTOS_FABRIC_IDENTITY_KEY` holds. It cannot tell one agent from
another. Phase H adds SPIFFE/SPIRE: the workload asks the Workload API for a JWT-SVID, and both the
control plane and the sidecar verify it against the trust domain's published keys.

| Property | Verified by | What actually ran |
| --- | --- | --- |
| JWS parsing, three base64url segments | `workload-identity-provider.test.ts` | real tokens, real rejections |
| Ed25519 and RS256 verification | same | `node:crypto` against generated key pairs |
| `alg: none` and unknown algorithms refused | same | asserted as `unsupported_algorithm` |
| Expiry, `nbf`, trust domain, audience | same | each with its own reason code |
| Sidecar accepts an SVID and enforces policy | `spire-identity-runtime.test.ts` | real server, real sidecar, real socket |
| Sidecar refuses an SVID when it holds no SPIRE keys | same | denied as `identity_invalid` |
| Cross-tenant SVID refused at the sidecar | `workload-identity-provider.test.ts` | tenant binding asserted both ways |
| Revocation by agent id and by nonce | same | allow and deny asserted on the same token |
| **Node attestation: one workload cannot obtain another's identity** | `spire-substrate.test.ts` | **VERIFIED** — a live SPIRE 1.15.3 trust domain refuses to issue an SVID for a workload with no entry for it, and refuses a foreign SPIFFE ID |
| **A real trust domain's JWKS is fetched and parsed** | `spire-substrate.test.ts` | **VERIFIED** — HTTP 200 from a live SPIRE bundle endpoint, EC P-256 key |
| **A genuine SVID verifies against the trust domain's own key** | `spire-substrate.test.ts` | **VERIFIED** — and it does not verify without the DER conversion, which is asserted too |
| **This client obtains and accepts that SVID** | `spire-substrate.test.ts` | **VERIFIED** — through this project's own gRPC client, not `spire-agent api fetch` |
| **The gRPC Workload API client** | `spiffe-workload-api.test.ts` | 13 tests against a real `node:http2` server speaking real gRPC framing, including trailers-only statuses |

Eleven mutations were run against this code and every one produced failing tests: dropping the
algorithm whitelist, ignoring the signature result, removing the expiry check, removing the trust
domain check, removing the audience check, removing the attestation binding, removing the SVID
subject binding, accepting an SVID with no keys configured, removing tenant binding, and removing
each of the two revocation checks. The first pass of this suite did **not** catch three of them —
the ones at the sidecar's own verifier — which is why `verifyIdentityToken` is now tested directly
rather than only through a client that already verified the same token.

**What the stub suite alone does not establish:** that node attestation works. Every SVID in it is
signed by a key the test generated, so what it proves is this client's verification and the
sidecar's enforcement of it. That is what the gated file below is for.

**What running the same file against a live SPIRE 1.15.3 trust domain established** — a real
server, a join-token-attested agent, a registration entry for `t_spire/pi_demo`, and a bundle
endpoint publishing the trust domain's JWKS — is that **this client could not interoperate with
SPIRE at all**. Four independent defects, each measured rather than inferred:

1. **Transport.** The Workload API is gRPC over a Unix socket. Writing the exact
   `GET /workload-api/jwt-svid?spiffe_id=…` request that `requestSvid` performed down that socket
   got the connection reset; no SPIRE version serves it. `fetch` cannot open a Unix socket either,
   so `requestSvid` could not reach an agent at all.
2. **Algorithm.** SPIRE signs JWT-SVIDs with **ES256**. `VERIFY_ALGORITHMS` whitelisted `Ed25519`
   and `RS256` only, so a genuine SVID was refused as `unsupported_algorithm` before its signature
   was examined.
3. **Issuer.** SPIRE emits **no `iss` claim**. `verifyJwtSvid` required `iss` to equal
   `spiffe://<trust domain>`, so fixing (2) alone would have moved the refusal to
   `wrong_trust_domain`.
4. **ECDSA encoding.** JWS specifies a raw `R‖S` signature; `node:crypto`'s `verify` accepts only
   DER. The same signature that verifies as DER is rejected raw, so whitelisting ES256 would not
   have been sufficient on its own.

**All four are now fixed and the fixes are measured against the live trust domain, not a stub.**
`src/v2/spiffe-workload-api.ts` speaks the agent's actual gRPC — method
`/SpiffeWorkloadAPI/FetchJWTSVID`, the header `workload.spiffe.io: true`, `JWTSVIDRequest` field
numbers 1 (`audience`) and 2 (`spiffe_id`) — each taken from the agent, because a wrong field number
is answered with a plausible-looking SPIFFE ID error rather than a parse error, which is how the
first attempt got a wrong answer that looked like a real one. `rawEcdsaToDer` re-encodes the
signature before handing it to `node:crypto`, with both branches of the leading-zero rule tested
deterministically. The trust domain is now read from the subject SPIFFE ID, which is where SPIRE
puts it; a disagreeing `iss` is still refused, so requiring an `iss` that SPIRE does not send no
longer means trusting an unchecked subject.

The gated file now runs **eleven of eleven, skipped zero, against a live trust domain**. One
obtains an SVID through this project's own gRPC client rather than through `spire-agent api fetch` —
using the CLI would prove something about SPIRE, not about the code under test — and asserts it is
the identity that was asked for. One verifies it against the trust domain's published key. One
asserts SPIRE still signs ES256 with no `iss`, so a change in either is reported rather than
absorbed. One proves the raw JWS signature does *not* verify unconverted while this project's own
conversion does, so the DER step cannot quietly become a pass-through. One issues a real identity
through the provider. One asserts the trust domain refuses an SVID for a workload with no entry for
it, and one that it refuses a foreign SPIFFE ID — that pair is the **S4** claim itself. One asserts
this client's SVID names the same subject and audience as SPIRE's own client's. One asserts
HTTP/1.1 is still not served, so the old path cannot quietly come back.

`spire-workload-identity` is therefore reported as **REAL_SUBSTRATE**.

**Two limits, recorded rather than absorbed.** First, the Workload API is gRPC over a Unix domain
socket, so on a Windows host these eleven tests skip no matter what is installed — the socket cannot
exist there. The run was done inside WSL2 against a live trust domain; `substrate_run` reports the
socket separately so the skip is not confused with "SPIRE missing". Second, one mutation of the
gated file is **not** caught: removing the subject trust-domain check entirely leaves all eleven
green, because a well-behaved authority only ever issues for its own trust domain — a
foreign-domain token has to be synthetic, so it is asserted in
`workload-identity-provider.test.ts` instead (including prefix confusion, `actantos.local.evil.example`).

Two further limits are recorded in `docs/ARCHITECTURE_V2.md`: the JWKS URI is a trust anchor that
must be pinned out of band, and X.509-SVIDs are not supported at all.

### gVisor cell — VERIFIED, and reproduced by the suite

`src/gvisor-sandbox-substrate.test.ts` starts real containers under `runsc` on a second isolated
`dockerd` inside the WSL2 `Ubuntu-24.04` distro, where `runsc release-20260928.0` is registered.
Run it with `ACTANTOS_SUBSTRATE_TESTS=1` and `ACTANTOS_GVISOR_DOCKER_HOST` naming that daemon;
otherwise it skips.

The discriminator is kernel identity, because an ignored flag cannot fake it. Same image, same
daemon, same command, differing only in the runtime:

| Cell | Runtime | Result |
| --- | --- | --- |
| `cat /proc/version` | default (runc) | `6.18.33.2-microsoft-standard-WSL2` — the **host** kernel |
| `cat /proc/version` | `--runtime runsc` | `4.19.0-gvisor` — the **sandbox** kernel |
| `dmesg` | default (runc) | `dmesg: klogctl: Operation not permitted` — host ring buffer refused |
| `dmesg` | `--runtime runsc` | gVisor's own kernel boot log |

The executor's real spawn path is covered too. It runs a container through `runsc` and reads that
container's `/proc/version` back out through the bind mount, so silently dropping `--runtime
runsc` fails the test rather than passing it. Mutation-checked: making `resolveSandboxRuntimeFlags`
return no flags turns two of the six red.

**Egress is not claimed from this host.** The gVisor daemon's bridge has no external route for
*either* runtime, so `nslookup` returns `Network unreachable` under `runsc` and under the default
runtime alike. Blocked egress there is a property of the daemon's networking, not evidence about
gVisor's netstack. Network isolation is proved separately, in `egress-proxy-topology.test.ts`,
against real containers on a real internal network.

Independently, the control daemon (which has **no** `runsc` registered) refuses the same flag:
`unknown or invalid runtime name: runsc`, exit 125. So the executor does not assume gVisor; it
passes `--runtime runsc` only when policy asked for it.

Under `runsc`, `dmesg` returns the sandbox's own userspace kernel rather than the host's:

```
[   0.000000] Starting gVisor...
[   0.509491] Deleting VFS and rebuilding it from scratch...
[   1.476131] Feeding the init monster...
[   2.791849] Ready!
```

#### How gVisor was provisioned

The development host is Docker Desktop on WSL2. Docker Desktop's daemon was **not** modified,
because restarting it would take down the user's running stack. Instead a second, isolated
`dockerd` runs inside the `Ubuntu-24.04` distro on its own socket, data-root, and `vfs`
storage driver, with `runsc` registered:

```json
{ "runtimes": { "runsc": { "path": "/usr/local/bin/runsc" } },
  "data-root": "/var/lib/gvisor-test", "exec-root": "/run/gvisor-test",
  "pidfile": "/run/gvisor-test/docker.pid", "iptables": false, "bridge": "none",
  "storage-driver": "vfs" }
```

```
docker run -d --name tetragon-fixed --pid=host --privileged \
  -v /sys/kernel/tracing:/sys/kernel/tracing -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
  -v /etc/os-release:/etc/os-release-host:ro -v /proc:/host/proc:ro \
  quay.io/cilium/tetragon:v1.1.2 tetra run --procfs /host/proc
```

Install notes that cost time and are recorded so they are not repeated:

- The gVisor archive is `gvisor.tar.zstd` from
  `https://storage.googleapis.com/gvisor/releases/release/latest/x86_64/`. There is **no
  standalone `runsc` URL**; `.../x86_64/runsc` returns 404.
- Installing only the `runsc` binary is **not enough**. The runtime also needs
  `gvisor_sentry` (and `checkpointgofer`, `runsc-metric-server`, `runsc-fd-parking`,
  `gvisor-sentry-prewarmer`) from the archive's `gvisor-bin/` directory, and it resolves them
  relative to its own path, i.e. `/usr/local/bin/gvisor-bin/gvisor_sentry`. Without them:
  `sidecar "gvisor_sentry" not usable (stat ...: no such file or directory) and
  --sidecar-usage-policy is set to STRICT`.
- `docker-ce` in the WSL distro auto-enables a `docker.service` that takes over
  `/var/run/docker.sock`. That displaced Docker Desktop's socket and was immediately stopped and
  disabled again; the user's 9 `scienzaos-local` containers stayed up throughout.

**Limitation of this cell.** The executor's `runsc` availability probe runs **client-side**
`execFileSync("runsc", ["--version"])`) while the runtime lives on the **daemon** host. The cell
therefore injects `checkRunsc: () => true`. The refusing path is covered separately and does not
depend on this: `docker-executor.test.ts` asserts `spawnCalls` is empty when the probe fails, and
`server-startup-sandbox.test.ts` asserts exit 1 in strict mode. A deployment where the executor
and the runtime are on the same host needs no injection.

**That limitation is now closed, and the fix found a real defect.** `resolveSandboxRuntimeFlags`
now probes the daemon as well as PATH: it asks the daemon for its own runtime registry
(`docker info --format "{{json .Runtimes}}"`) and requires a key named `runsc` there, which is the
registry the daemon resolves `--runtime=runsc` against.

The old single probe answered a question nobody was asking. It reported whether *a binary* was
installed, not whether the runtime could be used — and those are independent. A host can have
gVisor installed and be talking to a daemon that was never configured to offer it, which is the
stock state. In that case the old gate passed, the executor emitted `--runtime=runsc`, and the
refusal arrived from the daemon as `unknown or invalid runtime name` instead of from the gate,
where the message can say what is actually wrong and where to fix it. The outcome was never an
unisolated execution — Docker rejects an unknown runtime name — but it was a refusal at the wrong
layer with a message pointing at the command rather than at the daemon configuration.

The refusal now names which precondition failed, because the two have entirely different fixes:
*install gVisor* versus *register the runtime in `daemon.json` and restart Docker*.

**What is not claimed, and why.** The gVisor evidence is gathered against the second isolated
`dockerd` in the WSL2 distro. Docker Desktop's own daemon still registers no `runsc` and still
refuses the flag with `unknown or invalid runtime name: runsc`, exit 125 — so the executor does not
assume gVisor, and passes `--runtime runsc` only when policy asked for it. Two things are
explicitly **not** claimed: egress isolation, because that daemon's bridge blocks external names
for *both* runtimes and so cannot attribute the block to gVisor; and the client-side binary probe,
which is injected in these tests because `runsc` lives in the WSL2 distro rather than on the
Windows client. The probe that decides usability — the daemon registry — is the real one.

### Tetragon runtime layer — load VERIFIED, container visibility VERIFIED

Load-time, **VERIFIED**:

```
tracing policy "/tmp/emitted.yaml" added
ID   NAME                       STATE    SENSORS
8    actant-agent-reviewer      enabled  gkp-sensor-8
```

The YAML above was produced by `npm run tetragon:emit` from a signed bundle, not hand-written,
so what loaded is exactly what the generator emits. Also verified:

- `labels` rejected at kprobe level and at policy level (`json: unknown field "labels"`).
- `sys_enter_execve` unattachedable via the CLI:
  `kprobe spec pre-validation failed: call "sys_enter_execve" type name sys_enter_execve: not found`.
- Base sensor load failure on this kernel:
  `detect modify return syscall ... __x64_sys_getcpu() is not modifiable`, and a
  `procfs does not appear to be host procfs` warning.

Runtime, **VERIFIED**. In-container forks, the container's own PID 1, and processes created by
`docker exec` are all observed with the container ID attached.

The earlier conclusion here — that the built-in sensor never reaches workload containers — was
**wrong, and the cause was a misconfigured agent**, not a substrate limit. The original container
ran with only `/sys/kernel/tracing` mounted, no host `/proc` bind, no `--procfs`, and its own PID
namespace. With `--pid=host`, `-v /proc:/host/proc:ro`, and `tetra run --procfs /host/proc`, the
same workload becomes visible:

| Probe | Before | After |
| --- | --- | --- |
| `curlimages/curl` running `sleep 1` in a loop | 0 events | 36 events, all with `"docker"` set to the container ID |

A record from the fixed configuration, showing the `docker` field and a busybox `cwd`:

```json
{"process_exec":{"process":{"pid":14117,"cwd":"/home/curl_user","binary":"/bin/sleep",
 "arguments":"1","flags":"execve","docker":"7ee4033051e4c1882da67e5d769d3a5"}}}
```

**The earlier "gap" was also a measurement error, and it is retracted.** This project previously
recorded that the execve of the *outermost* process of a container is not observed — neither the
container's own PID 1 nor any `docker exec` process. That conclusion is **false**. Both are
observed. Re-measured on a fresh container with collection running concurrently:

| Process | Previously claimed | Measured |
| --- | --- | --- |
| container PID 1 (`docker run`) | not observed | **observed**, 1/1, `"flags":"execve"` |
| `docker exec -d` target process | not observed | **observed**, 5/5 trials |
| `sleep 1` forked by PID 1 | observed | observed, 36/36 |

The `docker exec` records, taken from five consecutive trials (`DET1CANARY`…`DET5CANARY`), each
carried the container ID in `process.docker`:

```json
{"process_exec":{"process":{"pid":25787,"uid":100,"cwd":"/home/curl_user","binary":"/bin/busybox",
 "arguments":"sh -c \"exec -a FOREGROUNDCANARY sleep 60\"","flags":"execve",
 "docker":"5d08eaa7125af40b23266e94d1a9457","parent":{"pid":23692,"binary":"[ssl_client]",
 "flags":"procFS"}}}}
```

**Root cause of the false negative: the event backlog rotates.** `tetra getevents` returns a
*ring buffer*, not a durable log. On this host the buffer holds roughly 120–210 `process_exec`
events and turns over in seconds under the ambient container churn. Every earlier probe ran the
workload, **waited, and only then attached** a reader — so the target event had already been
evicted before it was read. Once collection is attached *before* the workload runs, the same
probes are caught every time:

| Probe pattern | Delayed read | Concurrent collection |
| --- | --- | --- |
| `docker exec -d`, one at a time | 0 / 8 | **5 / 5** |
| `docker exec`, foreground | 1 / 1 | **1 / 1** |
| container PID 1 at `docker run` | 0 / 2 | **1 / 1** |

The result is 5/5, not a coincidence of one lucky read: the trial that did land on a delayed read
is explained by the event happening to still be resident when the reader attached.

**Consequence.** There is no Tetragon visibility gap on this substrate. Tetragon remains a
**detection and evidence** layer and is not an enforcement control: nothing in the invariant set
depends on it. S3 rests on the sidecar decision layer and the evidence chain, which are verified by
executable tests. A `runsc` container adds a second, independent barrier.

Six earlier mistakes in this project are recorded so they are not repeated:

1. `tetra getevents --since` **does not exist** in v1.1.2. Every "no events observed" result
   obtained with it was a flag error, not an empty stream.
2. `tetra getevents -o clear` **does not exist** in v1.1.2 either. Attempts to "clear" the backlog
   before a probe printed `Error: invalid value for "output" flag: clear` and cleared nothing, so
   the following probe inherited the previous probe's backlog.
3. The real `process_exec` payload nests its fields under `process_exec.process`, not flat. A
   first version of the adapter matched zero real events because of this.
4. `procfs does not appear to be host procfs` is a **false positive on Docker Desktop**. Tetragon
   expects inode `4026531836`, a constant for a bare-metal host init namespace. Measured inside
   the corrected container, `/host/proc/1/ns/pid` and `/proc/1/ns/pid` are both `pid:[4026532291]`
   — the mount was correct all along. Do not chase this warning on Docker Desktop.

5. Tetragon **exports to a file, not to stdout.** The agent logs `Exporter configuration
   enabled=true fileName=/var/log/tetragon/tetragon.log` and writes no event-shaped line to
   stdout. A probe that greps the agent's own log concludes the kernel emitted nothing, and did
   so for several iterations — which is how `tetragon-runtime` came to be reported `NOT_RUN`
   with an itemised list of four "measured reasons" that were all artifacts of reading the wrong
   stream. Reading the exporter showed `security_bprm_check` events in the hundreds and
   `security_file_permission` events in the thousands.

6. A DER integer shorter than 32 bytes is a real shape, not a rounding error. The test signer that
   converts `node:crypto`'s DER ECDSA output into the raw `R‖S` a JWS carries stripped the sign
   padding byte but never left-padded. DER encodes an integer as the shortest string reading back
   as the same number, so it *also* drops leading zeros outright — which happens to roughly one
   signature in 128. Those tokens carried a 63-byte signature, the verifier correctly refused them
   as `signature_invalid`, and whichever of the 73 tests happened to draw one failed for a reason
   that had nothing to do with what it was asserting. Measured: 21 of 4000 signatures came out
   short, and the failure reproduced in 1 isolated run in 3.

   The verifier was never wrong — `rawEcdsaToDer` requires exactly 64 bytes and handles both the
   sign pad and the stripped zero. Only the test helper was. The fix is in the helper, and two
   tests were added: one over a hand-built encoding, one asserting that 1000 tokens signed by the
   real signer all come out 64 bytes wide. Reverting the padding makes both fail, so the branch is
   now covered on every run instead of one run in 128. The general lesson is the one the product's
   own doc comment already stated for the forward direction and the test helper ignored for the
   reverse: **a branch that only a random input reaches must not be left to chance.**

The general lesson, which is the reason the false negative survived so long: **a negative result
from a rotating buffer is not evidence of absence.** Attach the reader first. The corollary,
learned the hard way here: **a negative result from the wrong stream is not a measurement at
all**, and itemising it as one makes it much harder to revisit than a bare "unknown" would.

The adapter was fixed against a recorded 114-line capture and now parses 101 of 114 lines,
produces 19 evidence records, and the bundle verifies offline.

### Reproducing the substrate check

Attach the reader **before** the workload, or the backlog will have rotated past it:

```
tetra tracingpolicy add /tmp/emitted.yaml
tetra getevents -o json > /tmp/before.json &      # attach first
docker run -d --name probe --entrypoint /bin/sh curlimages/curl:latest -c 'while true; do sleep 1; done'
sleep 8
docker exec -d probe /bin/busybox sh -c 'exec -a MARKER /bin/busybox sleep 300'
sleep 5
kill %1
grep -c MARKER /tmp/before.json                   # expect >= 1
```

A count of zero after attaching the reader first means the agent is not reaching workload
containers. Note the `--entrypoint` override: `curlimages/curl` declares
`ENTRYPOINT ["/entrypoint.sh"]`, so a bare `docker run … sleep 300` is interpreted by that
entrypoint and the container exits almost immediately, which silently invalidates the probe.

To check whether the agent itself is correctly configured:

```
docker inspect <container> --format '{{.HostConfig.PidMode}} {{range .Mounts}}{{.Source}}->{{.Destination}} {{end}}'
```

`PidMode` empty with no `/host/proc` in the mounts is the misconfiguration found here.

## Mutation testing — what a green suite did not prove

A passing test proves nothing unless it can fail. Each core enforcement mechanism was deliberately
broken and the suite re-run. Every mutation was reverted afterwards; no production code changed.

| Property | Mutation applied | Before the fix | After the fix |
| --- | --- | --- | --- |
| **S6 scope list** | delete the unparseable-parent guard in `scopeIsNarrowerThan` | **48/48 still passed** | **2 tests fail** |
| **S1 credential guard** | delete the `credential` alternative from `CREDENTIAL_KEY` | **14/14 still passed** | **3 tests fail** |
| S14 deny paths | `if (raw.model_approved === true) return allow` in `sidecar.ts` | 2 passed for the wrong reason | **6/6 tests fail** |
| S3 network allowlist | force `checkNetworkTargets` to allow every target | — | **10 tests fail** |
| S12 lease expiry | neuter the `kind: "expired"` branch in `PolicyLease.state` | — | **6 tests fail** |
| S10 IFC rank | invert `LABEL_RANK[a] <= LABEL_RANK[sink]` to `>=` | — | **5 tests fail** |
| S8 action digest | drop `args` from `canonicalActionDigest` | — | **3 tests fail** |
| S11 signature | short-circuit `signatureValid` to true | — | **3 tests fail** |
| S6 wildcard | disable the `**` parent branch in `grantSubsumes` | — | **6 tests fail** |
| S9 nonce replay | delete the `#consumed.has(nonce)` check | — | **1 test fails** |
| S9 durable atomicity | replace `INSERT ... ON CONFLICT DO NOTHING` with `SELECT` then `INSERT` | — | **3 tests fail** |
| S13 append serialisation | remove `pg_advisory_xact_lock` from `PostgreSQLEvidenceStore.append` | — | **2 tests fail** |
| S13 append-only | turn `v2_evidence_append_only()` into `RETURN NEW` | — | **2 tests fail** |
| S13 commit protocol | allow every transition in `v2_effect_journal_transition()` | — | **2 tests fail** |
| S13 outcome finality | drop the terminal-outcome check from the transition trigger | — | **1 test fails** |
| S13 tenant isolation | widen the journal RLS policy to `USING (true)` | — | **1 test fails** |
| S14 schema strip | `.passthrough()` on the request schemas | — | **1 test fails** |
| Docs guard | flip S14 back to PARTIAL in the invariant matrix | — | **1 test fails** |
| Docs guard | re-assert the retracted Tetragon claim | — | **1 test fails** |
| Docs guard | make S3 cite Tetragon | — | **1 test fails** |

5. **The atomicity mutation was caught by 3 of 4 concurrent tests.** Replacing the single-statement
   insert with the textbook read-then-write failed the restart test, the two-replica test and the
   100-consumer test. The 50-gateway test still passed: with a ten-connection pool the interleaving
   that exposes the race did not occur on that run. It is reported as a weaker check, not as a
   fourth confirmation.

Four results are worth reading twice.

1. **The two "before" columns are the findings.** Both describe tests that passed while proving
   nothing. In the S6 case a *deny* could silently become an *allow*. Details are in
   `docs/SECURITY_INVARIANTS.md`.
2. **Two S14 tests initially passed for the wrong reason.** Both sent a malformed request, so the
   sidecar refused it as `protocol_version_unsupported` before reaching the security check the
   test claimed to exercise. Each now asserts the specific deny reason.
3. **A redundant-looking guard can still be load-bearing.** The S6 guard looks dead because an
   entirely-unparseable parent list is already denied by the fallback. It only decides the outcome
   when a list *mixes* valid and malformed entries — the untested case.
4. **Mutation anchors must be verified.** Several early mutations silently failed to apply and
   looked like "no coverage". The mutation helper now asserts its anchor exists before writing.

The rules this produced: a deny-path test must assert *why* it was denied; a pattern-based guard
needs a test per alternative; and a guard that fails closed must be tested on the *mixed* input,
not only the fully-degenerate one.

## Coverage gaps, stated rather than hidden

| Area | State |
| --- | --- |
| gVisor network cell | **VERIFIED** — real containers under `runsc` on a WSL2 daemon that registers it; same image and daemon run on two different kernels (`6.18.33.2-microsoft-standard-WSL2` vs `4.19.0-gvisor`). Egress is **not** claimed from that daemon — see the cell above |
| Tetragon runtime events | **VERIFIED** — in-container forks, container PID 1, and `docker exec` targets all observed with container-ID attribution, and now also five gated tests proving the emitted policy loads on a live agent and its `security_bprm_check` events classify as S3 signals |
| Host-kernel / root compromise | **OUT OF SCOPE** — not claimed; see `ARCHITECTURE_V2.md` |
| Bare hostnames in free-form arguments | Not treated as targets; the network cell is the backstop |
| SPIRE node attestation | **VERIFIED** — a live SPIRE 1.15.3 trust domain refuses to issue an SVID for a workload with no entry for it, and refuses a foreign SPIFFE ID. Eleven gated tests run against it. The limit is the platform: the Workload API is a Unix socket, so on Windows they skip |
| Transport round-trip latency | Not measured — all figures are in-process, UDS excluded |

## Full suite regression

```
node --experimental-strip-types --test src/*.test.ts src/v2/*.test.ts scripts/*.test.mjs
tests 1007   pass 915   fail 0   skipped 92   duration ~27s
```

These numbers are not transcribed. `docs/security-fabric-current-state.json` is generated from the
test files themselves by `npm run security:state`, and `scripts/security-fabric-state.test.mjs`
re-derives it on every run and fails if the committed file is stale. An earlier revision of this
document said `378 / 372 / 6` while `node --test` reported `401 / 395 / 6`, and the commit
message said 401; nothing reconciled them. That is why the derivation exists.

The suite decomposes as `src/` 328 + `src/v2/` 629 + `scripts/` 46 = 1003, which is four below what
the runner reports (1007): a `test(` inside a `for` body is counted once statically and registers
once per element. The state file publishes that difference as `runner_overcount`, and a guard
compares `static + overcount` against a real `node --test` run. The earlier `378` counted only
part of `src/`, which is how a per-file table can be internally consistent and still describe the
wrong total.

### The 92 skipped tests, named

Every group below skips because this host lacks the dependency, and none of them is a passing
test. Counting them as coverage would be the error. The per-file counts were measured, not
carried forward.

* **`src/cedar-provider.test.ts` — no longer skips.** `cedar-policy-cli` 4.13.0 was installed
  from the upstream release with its SHA-256 verified, so the four Cedar-gated tests execute.
  Running them exposed that Cedar exits 2 to say Deny, which the provider treated as an evaluator
  failure: every policy denial reaching the CLI threw instead of returning a decision. That was
  invisible while the tests skipped.
* **`src/tenant-isolation.test.ts` — 4 skipped**, and
* **`src/v2/replay-store.test.ts` (11) + `src/v2/effect-gateway-replay.test.ts` (4) — 15 skipped**,
  and
* **`src/v2/evidence-store.test.ts` — 14 skipped**, and
* **`src/v2/effect-commit.test.ts` — 10 skipped**, all four groups with reason
  `DATABASE_URL not set, or run \`npm run test:substrate\``. Together, 43.
* **`src/docker-executor-substrate.test.ts` — 26 skipped**, reason `run \`npm run test:substrate\`
  on a host with a working Docker daemon`. These drive real containers. Four were added when the
  `docker-executor` entry was audited: the Ed25519 verifier end to end (accept, HMAC-downgrade
  refusal, untrusted-key refusal) and the internal egress cell. All four were mutation-checked —
  dropping `--internal` from the cell made a workload resolve `example.com` to a real address, and
  removing the signature check ran a container for a forged token.

  Nine more were added when the entry was found to be `SIMULATED` with its residue itemised. These
  are the ones that turn each flag from a string into an observation, and they close that residue:

  | Test | Reads back from inside the container | Control |
  |---|---|---|
  | `--cap-drop ALL` | `CapBnd` in `/proc/self/status` is `0000000000000000` | same non-root user, flag absent: `CapBnd` stays `a80425fb` |
  | `--security-opt no-new-privileges` | `NoNewPrivs: 1` | flag absent: `0` |
  | `--cpus 0.5` | `/sys/fs/cgroup/cpu.max` is `50000 100000` | flag absent: `max 100000` |
  | `--pids-limit 64` | 200 forks, container exits 2 on `can't fork` | flag absent: `forked=200` |
  | `--tmpfs /tmp:size=64m` | 128 MB write fails `ENOSPC`, not `EROFS` | flag absent: `128+0 records out` |
  | `--memory 512m` | holding 700 MB is OOM-killed, exit 137 | flag absent: `held=700000000` |
  | output truncation | 40 KB emitted, 4000-byte budget, full stream still hashed | — |
  | secret redaction | preview carries `[REDACTED_GITHUB_TOKEN]`, not the value | — |
  | timeout | `sleep 120` under a signed 3 s budget reports `timeout` | — |

  Three details are worth stating, because each was wrong in the first version of these tests.
  The capability control cannot assert `CapEff`: the executor also sets `--user 1001:1001`, and a
  non-root user has an empty effective set on its own, so `CapEff` is zero either way — only the
  *bounding* set is attributable to `--cap-drop ALL`. The memory probe cannot write to the
  filesystem, because a cgroup limit is charged on pages *held* and file-backed page cache is
  reclaimable: a container limited to 512 MB writes 200 MB to disk and exits 0. And the `/tmp`
  probe has to assert `ENOSPC` rather than merely a failure, or a read-only root filesystem would
  satisfy it while the tmpfs size limit went unexercised.

  All nine were mutation-checked. Deleting each flag, or disabling truncation, redaction or the
  timeout kill, fails exactly one test and leaves the other twenty-five green.
* **`src/cedar-fixture-parity.test.ts` — no longer skips.** Measured directly: 7 tests, 7 pass,
  0 skipped, because `cedar-policy-cli` 4.13.0 is on this machine's PATH. The four that used to
  skip here are the same four that were corrected when the CLI's exit-2-means-Deny behaviour was
  found; they now run against the real binary and are part of the 92-skips accounting only on a
  host without it.
* **`src/v2/tetragon-substrate.test.ts` — 5 skipped**, reason `needs ACTANTOS_SUBSTRATE_TESTS=1`.
  Run inside WSL2 against a live Tetragon v1.7.1, **five of five pass**. This entry was `NOT_RUN`
  with four itemised "measured reasons"; all four were artifacts of grepping the agent's stdout
  instead of the exporter file, and the real reason it could not load was a defect in our own
  emitter. See the Tetragon section above.
* **`src/v2/spire-substrate.test.ts` — 11 skipped**, reason `SPIRE is not available`. **This is the
  gap that matters most in this list.** The other 69 skipped tests skip a *storage*, *container*
  backend whose logic is exercised elsewhere against a stand-in; these eleven skip the *attestation
  authority* itself, and node attestation cannot be stood in for.

  This group is the one that changed most. It was reported as `REAL_SUBSTRATE` while all four of
  its tests skipped, because the gate probed `spire-server version` — not a subcommand, exit 127 —
  so it skipped even where SPIRE was installed. Run inside WSL2 against a live SPIRE 1.15.3 trust
  domain, the tests execute and four client defects surfaced; those are listed in the SPIRE section
  above. All four are now fixed and the file is back to **eleven of eleven, skipped zero**. The
  group is `REAL_SUBSTRATE` and it reports *failures* rather than skips, which is the useful
  outcome — a substrate test that can only skip tells you nothing about the substrate.

  It still skips in the default suite on this host, and now for a different and better reason: the
  Workload API is gRPC over a Unix domain socket, so on Windows it cannot exist whatever is
  installed. `substrate_run` reports the socket separately from the binaries so that skip is not
  read as "SPIRE missing".

A separate `packages/pi-adapter` suite adds 8 more Docker-gated skips of its own. It is a
different package and is not part of the 92.

The 92 decompose by measured skip reason, not by guesswork: 43 for `DATABASE_URL`, 26 for a
working Docker daemon, 11 for the SPIRE Workload API socket, 7 for `ACTANTOS_GVISOR_DOCKER_HOST`,
and 5 for the substrate flag. **69 of the 92 are un-skipped by `npm run test:substrate`** — the 43
database-backed and 26 container-backed. All 26 tests in `docker-executor-substrate.test.ts` are
ow gated; the other three container files behind the same gate carry the rest. The eleven SPIRE
tests are not among them: the runner executes
eight named files and sets only `ACTANTOS_SUBSTRATE_TESTS` and `DATABASE_URL`, so it never reaches
that file. They were run separately, against a trust domain stood up inside WSL2, where the
Workload API socket can exist at all.

The five substrate-flag skips are the three database-backed ones the runner does not reach plus
the two `tetragon-substrate.test.ts` tests this document counts separately. The Tetragon file is
gated on a substrate the runner does not start either: it needs a Tetragon agent inside WSL2 on a
kernel where this repository's emitted policy loads, and both were arranged by hand rather than by
`npm run test:substrate`.

The four Cedar-gated tests no longer skip here. `cedar-policy-cli` 4.13.0 is on this machine's
PATH, so they execute — and running them exposed a defect that the skip had been hiding.

All six groups are registered in `SUBSTRATE_REQUIREMENTS`, and
`security-fabric-state.test.mjs`
fails if a skip appears that nobody registered, or if a registered count no longer matches the
skip sites actually present in the file.

### Running the database tests

`npm run test:substrate` runs eight named files against a real PostgreSQL server and a real Docker
daemon — **126 tests, 126 pass, 0 fail, 0 skipped** as measured for this document. That covers the
43 database-backed tests and the 13 container-backed ones, plus the ungated tests in those same
files and this guard suite. Two things about it are not obvious:

* It is **opt-in** (`ACTANTOS_SUBSTRATE_TESTS=1`) and **serial** (`--test-concurrency=1`). Several
  test files migrate and seed the same database. Node runs files concurrently, so a plain
  `npm test` with `DATABASE_URL` exported deadlocks on DDL locks — which is exactly what happened
  the first time the substrate was enabled. The opt-in makes that failure mode unreachable rather
  than leaving it for the next person to rediscover.
* It **refuses to start without `DATABASE_URL`**. A substrate pass that silently skips everything
  would report green while proving nothing.

The PostgreSQL substrate is verified, not assumed: `collectSubstrates` opens a connection and asks
for `version()`, so `postgres_integration` in the state file means a server answered, not that an
environment variable was set.

Both groups are registered in `SUBSTRATE_REQUIREMENTS`, and `security-fabric-state.test.mjs`
fails if a skip appears that nobody registered, or if a registered count no longer matches the
skip sites actually present in the file.

`npm run typecheck`, `npm run build`, `npm run policy:regression` (5/5), `npm run demo:v2`, and
`npm run bench` (28/28, 0 prohibited external effects) all exit 0.

### Simulated versus real substrate

Most substrate-related tests in this repository do not touch a substrate. They inject a fake and
assert the surrounding wiring. `SUBSTRATE_REQUIREMENTS` in `scripts/security-fabric-state.mjs`
classifies every one of them, and the classification is asserted, not merely documented.

| Group | Level | Meaning |
| --- | --- | --- |
| `cedar-pdp` | `REAL_SUBSTRATE` | the real `cedar` CLI parses and evaluates. 4 tests, gated on the binary being present. |
| `postgres-tenant-rls` | `INTEGRATION` | real Postgres applies real row security. 4 tests, gated on `DATABASE_URL`. |
| `postgres-replay-guard` | `REAL_SUBSTRATE` | real Postgres makes the first use exclusive. 15 tests, gated on `DATABASE_URL`. |
| `postgres-evidence-store` | `REAL_SUBSTRATE` | real Postgres provides append serialisation, append-only triggers and enforced RLS. 14 tests, gated on `DATABASE_URL`. |
| `postgres-effect-journal` | `REAL_SUBSTRATE` | real Postgres enforces the commit state machine as triggers, independently of the application code that crashed. 10 tests, gated on `DATABASE_URL`. |
| `cedar-fake-provider` | `SIMULATED` | `FakeCedarProvider` is substituted across 7 v1 files. Proves wiring, not Cedar semantics. |
| `gvisor-sandbox` | `REAL_SUBSTRATE` | `gvisor-sandbox-substrate.test.ts` starts real containers under `runsc` and proves kernel identity, not just argv. Gated on `ACTANTOS_GVISOR_DOCKER_HOST` naming a daemon that registers `runsc`. Egress is not claimed: that daemon blocks it for both runtimes. |
| `docker-executor` | `REAL_SUBSTRATE` | The three files listed still assert argv against a recorded command, which is the right check for the decision logic. The live counterpart is `docker-executor-substrate.test.ts`: every resource limit is now read back from inside a real container with a control that removes the flag, and output truncation, redaction and the timeout run against a real process. The `--runtime runsc` flag is proved end to end in `gvisor-sandbox`. What is **not** claimed: that these limits hold on a daemon that ignores them. |
| `tetragon-runtime` | `REAL_SUBSTRATE` | five gated tests against a live Tetragon v1.7.1 loading the unmodified policy this repository emits. Two defects fixed: the emitter used a `Mask` selector no current agent can load, and the adapter modelled only `process_exec` so it dropped its own policy's events. |
| `spire-workload-identity` | `REAL_SUBSTRATE` | eleven gated tests against a live SPIRE 1.15.3 trust domain; this project's own gRPC client obtains an SVID from the agent and verifies it against the trust domain's published key. One mutation is not caught by the gated file and is recorded in the state file. |
| `confidential-computing` | `NOT_IMPLEMENTED` | **No code, no test, no configuration, and no hardware.** Measured rather than inferred: `cpuid` on this host reports TDX = 0 *and* TME = 0, and the AMD SEV leaf unsupported, so the capability is absent rather than merely unavailable to configure. This is the one entry no test on any reachable host can close. An itemized, unsigned waiver is drafted in `docs/OPEN_WAIVERS.md` as W-001. |

`postgres-tenant-rls` is `INTEGRATION` while `postgres-replay-guard` and
`postgres-evidence-store` are `REAL_SUBSTRATE` even though all three use the same server. The difference is what each group actually proves. Atomic first
use depends on PostgreSQL's `INSERT ... ON CONFLICT DO NOTHING`, and that really runs. The RLS
tests had to be repaired before they proved anything at all: they ran every query over the
migration superuser connection, and a superuser bypasses row-level security entirely, so tenant A
could see tenant B's rows and the test would have passed for the wrong reason once its seed data
was valid. They now `SET LOCAL ROLE` to an ordinary role first. The seed itself was also missing
the `users` rows that the `agents.owner_user_id` foreign key requires — `pg-mem` never enforced
that constraint, which is how the gap survived.

The evidence store needs the real server for three separate reasons, and each has a mutation
behind it. `pg_advisory_xact_lock` is what makes two writers appending the same tenant serial;
without it `100 concurrent appends produce one gapless chain` and `two stores for one tenant
interleave without forking` both fail. The `BEFORE UPDATE OR DELETE` trigger is what makes the
history unrewritable; with it turned into a no-op, `evidence cannot be deleted or edited` and
`checkpoint cannot be moved once written` both fail. Append-only is enforced by trigger rather
than by `REVOKE` precisely because `FORCE ROW LEVEL SECURITY` closes the table-owner exemption
but not the superuser exemption, and the migrating role is a superuser.

The `VERIFIED` Tetragon row carries two claims of different strength, and this paragraph used to
describe only the weaker one. **Container visibility** — in-container forks, container PID 1, and
`docker exec` targets observed with container-ID attribution — is still a **manual probe**, run
interactively against Tetragon v1.1.2 and recorded here with its method and its two measurement
errors. No test reproduces it. **Emitted-policy loading** is the opposite: five gated tests in
`src/v2/tetragon-substrate.test.ts` load this repository's unmodified emitted policy on a live
v1.7.1 agent and assert that its `security_bprm_check` events classify as S3 signals. While the row
was wholly manual, both sentences here were true of it.

The gVisor cell above is automated, and `npm test` reproduces it whenever
`ACTANTOS_GVISOR_DOCKER_HOST` names a gVisor-capable daemon.

### Two unrelated defects found while re-running — both now fixed

Both were outside the v2 security fabric, and both are **fixed**.

1. **`src/sse-routes.test.ts` could never finish** and hung the whole run (it blocked for 900 s
   and was only killed by an external timeout). The route handler awaits a promise that settles
   only on socket close and holds a 30 s heartbeat interval; under `server.inject()` neither ever
   fires, so the timer kept the event loop alive forever. The file even declared an unused
   `AbortController`, showing a real request was intended. It now makes a real request to an
   ephemeral port, aborts it, and asserts status `200`, `content-type: text/event-stream`, and the
   initial heartbeat — a stronger test than the one it replaces. This is a **test-only** change;
   `src/sse-routes.ts` is untouched. **VERIFIED**: 2/2 pass in 335 ms.

2. **`scripts/*.test.mjs` failed on a version guard**, `release maturity truth package_version
   1.1.0 != package.json 1.2.0`. The authoritative version is **1.1.0**, decided on two
   independent pieces of evidence rather than preference:

   - `release-maturity-truth.json` pins `package_version: "1.1.0"`, `release_tag: "v1.1.0"`, and
     `maturity_label: "quiet-open-core"`. Its own `precedence.rule` states that when surfaces
     disagree during transition, this file **wins** for maturity, claim levels, and Mode A public
     identity, and that `package.json` must match `package_version` and `maturity_label`.
   - The repo's own `scripts/build-release-artifacts.test.mjs` hardcodes the expectation with
     `assert.equal(packageJson.version, "1.1.0")`. A release pipeline that fails its own test is
     the loudest possible statement of intent.

   `package.json` and `package-lock.json` were therefore aligned **down** to 1.1.0. The guard then
   tripped a second, unrelated bug: `scripts/build-release-artifacts.test.mjs` invoked
   `execFileSync("tar", ["-tzf", tarballPath])`, and GNU tar parses a Windows `D:\…` argument as
   `host:path` and fails with `Cannot connect to D: resolve failed`. Both `tar` call sites now
   pipe the archive over **stdin** (`["-tzf", "-"]`), which is correct on Windows, Linux, and BSD
   tar alike. No production code was touched — both changes are confined to the test file and the
   two version strings.

3. **`actantos.releaseNotesFile` pointed at a file that does not exist.** `package.json` named
   `docs/release-notes-v1.0.1.md`; no such file exists, and `build-release-artifacts.mjs` copied
   the value into the release manifest without ever checking it, so the bad reference shipped
   silently.

   Resolved from repository governance rather than by inventing release notes.
   `release-maturity-truth.json` pins `package_version: "1.1.0"` and `release_tag: "v1.1.0"`, and
   its own `precedence.rule` states that this file wins when surfaces disagree. The
   version-derived filename is therefore `docs/release-notes-v1.1.0.md`, and that file does exist.
   The pointer was corrected to it.

   A second defect surfaced underneath: `release-notes-v1.1.0.md` *itself* began with the heading
   `# ActantOS v1.0.1 Release Notes` and described v1.0.1 content. The file was renamed during the
   1.1.0 bump while its contents were left behind. The heading was corrected to match the release
   the file documents.

   This is now enforced rather than merely fixed: `build-release-artifacts.mjs` fails closed when
   the declared notes file is missing, and `security-docs-consistency.test.mjs` asserts the
   pointer matches the version in `release-maturity-truth.json`.

The complete suite, `scripts/` included, now runs green. These are the counts **as of this fix**; the
v2 fabric grew after it, so the current totals are in `docs/PHASE_REPORT.md`.

```
node --experimental-strip-types --test src/*.test.ts src/v2/*.test.ts scripts/*.test.mjs
tests 491   pass 446   fail 0   skipped 45   duration ~18s
```