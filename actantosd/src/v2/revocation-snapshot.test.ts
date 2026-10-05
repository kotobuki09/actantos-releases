import assert from "node:assert/strict"
import test from "node:test"

import { ed25519 } from "./signature.ts"
import {
  MAX_REVOCATION_ENTRIES,
  REVOCATION_REASONS,
  RevocationStore,
  canonicalRevocationBytes,
  signRevocationSnapshot,
  verifyRevocationSnapshot,
  type RevocationSnapshotBody,
  type SignedRevocationSnapshot,
} from "./revocation-snapshot.ts"

/**
 * Signed revocation snapshots (invariants S9, S12).
 *
 * The central question these tests answer is not "does a revoked agent get refused" — that was
 * already true of a `ReadonlySet`. It is "can an attacker who controls the process remove a
 * revocation". Every mutation below is an attempt at exactly that, in the shapes it could take:
 * a forged document, a replayed older one, a stale one, an empty one presented as truth.
 */

const ISSUER = "issuer-revocation"
const OTHER_ISSUER = "issuer-other"
const keyPair = ed25519.generateKeyPair()
const otherKeyPair = ed25519.generateKeyPair()
const trustedIssuerKeys = new Map([[ISSUER, keyPair.publicKeyPem]])

const TENANT = "t_revocation"
const HOUR_MS = 60 * 60 * 1000
const NOW = new Date("2026-10-04T12:00:00.000Z")

const body = (overrides: Partial<RevocationSnapshotBody> = {}): RevocationSnapshotBody => ({
  snapshot_id: "snap-1",
  tenant_id: TENANT,
  version: 1,
  issued_at: new Date(NOW.getTime() - HOUR_MS).toISOString(),
  expires_at: new Date(NOW.getTime() + 24 * HOUR_MS).toISOString(),
  entries: [
    { agent_id: "planner", reason: "credential_compromised", revoked_at: NOW.toISOString() },
  ],
  ...overrides,
})

const signed = (
  overrides: Partial<RevocationSnapshotBody> = {},
  key = keyPair,
  issuer = ISSUER,
): SignedRevocationSnapshot =>
  signRevocationSnapshot(body(overrides), { algorithm: "ed25519", issuer_id: issuer, value: "" }, key)

const verify = (candidate: unknown, options: Record<string, unknown> = {}) =>
  verifyRevocationSnapshot(candidate, {
    expectedTenantId: TENANT,
    trustedIssuerKeys,
    now: NOW,
    ...options,
  })

/* ------------------------------------------------------------------------- signing and shape */

test("a signed snapshot verifies, and canonical bytes are stable under key reordering", () => {
  const result = verify(signed())

  assert.equal(result.accepted, true)

  // Same content, different property order. The signature is over canonical bytes, so it must
  // verify either way — a signature scheme that depended on insertion order would be signing the
  // JSON writer's mood.
  const reordered: RevocationSnapshotBody = {
    entries: body().entries,
    expires_at: body().expires_at,
    issued_at: body().issued_at,
    version: 1,
    tenant_id: TENANT,
    snapshot_id: "snap-1",
  }

  assert.deepEqual(
    Buffer.from(canonicalRevocationBytes(reordered)),
    Buffer.from(canonicalRevocationBytes(body())),
  )
  assert.equal(verify(signRevocationSnapshot(reordered, { algorithm: "ed25519", issuer_id: ISSUER, value: "" }, keyPair)).accepted, true)
})

test("an entry that names nothing to revoke is refused at the schema", () => {
  const result = verify(
    signed({
      entries: [{ reason: "policy_violation", revoked_at: NOW.toISOString() }],
    } as Partial<RevocationSnapshotBody>),
  )

  // An entry with no target would verify, occupy a version, and do nothing. It would also read as
  // an intentional "nothing revoked here" marker to anyone inspecting the snapshot later.
  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "malformed_snapshot")
})

test("an unrecognised revocation reason is refused", () => {
  const result = verify(
    signed({
      entries: [{ agent_id: "planner", reason: "because_i_said_so", revoked_at: NOW.toISOString() }],
    } as unknown as Partial<RevocationSnapshotBody>),
  )

  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "malformed_snapshot")
})

test("every declared reason is accepted", () => {
  for (const reason of REVOCATION_REASONS) {
    const result = verify(
      signed({
        entries: [{ agent_id: "planner", reason, revoked_at: NOW.toISOString() }],
      } as Partial<RevocationSnapshotBody>),
    )

    assert.equal(result.accepted, true, `reason ${reason} was refused`)
  }
})

/* ------------------------------------------------------- every refusal has its own reason */

test("a snapshot signed by an untrusted issuer is refused", () => {
  const result = verify(signed({}, otherKeyPair, OTHER_ISSUER))

  assert.equal(result.accepted === false && result.reason, "untrusted_issuer")
})

test("a snapshot whose signature does not verify is refused", () => {
  const tampered = signed()
  // Change the entry after signing. This is the exact shape of an attacker editing the list.
  tampered.body.entries = [{ agent_id: "exfiltrator", reason: "policy_violation", revoked_at: NOW.toISOString() }]

  const result = verify(tampered)

  assert.equal(result.accepted === false && result.reason, "invalid_signature")
})

test("a snapshot for another tenant is refused", () => {
  const result = verify(signed({ tenant_id: "someone-else" }))

  // Cross-tenant matters more here than for policy: a snapshot from tenant B must not be able to
  // revoke tenant A's agents, and tenant A's must not be read as clearing them.
  assert.equal(result.accepted === false && result.reason, "tenant_mismatch")
})

test("an expired snapshot is refused", () => {
  const result = verify(
    signed({
      issued_at: new Date(NOW.getTime() - 2 * HOUR_MS).toISOString(),
      expires_at: new Date(NOW.getTime() - HOUR_MS).toISOString(),
    }),
  )

  assert.equal(result.accepted === false && result.reason, "expired")
})

test("a snapshot expiring exactly now is expired", () => {
  const result = verify(
    signed({
      issued_at: new Date(NOW.getTime() - 2 * HOUR_MS).toISOString(),
      expires_at: NOW.toISOString(),
    }),
  )

  assert.equal(result.accepted === false && result.reason, "expired")
})

test("a snapshot that is not yet valid is refused", () => {
  const result = verify(signed({ issued_at: new Date(NOW.getTime() + HOUR_MS).toISOString() }))

  assert.equal(result.accepted === false && result.reason, "not_yet_valid")
})

test("a snapshot whose window runs backwards is refused", () => {
  const result = verify(
    signed({
      issued_at: new Date(NOW.getTime() + HOUR_MS).toISOString(),
      expires_at: NOW.toISOString(),
    }),
  )

  assert.equal(result.accepted === false && result.reason, "invalid_expiry_window")
})

test("a version at or below the highest applied is refused as a rollback", () => {
  const result = verify(signed({ version: 3 }), { minimumVersion: 3 })

  // Replaying an older, genuinely signed snapshot is how an attacker un-revokes: it is a valid
  // document, from the right issuer, that simply predates the decision.
  assert.equal(result.accepted === false && result.reason, "version_rollback")
})

test("a higher version is accepted over a lower one", () => {
  const result = verify(signed({ version: 4 }), { minimumVersion: 3 })

  assert.equal(result.accepted, true)
})

/* ------------------------------------------------------------------------------ the store */

test("the store reports what the control plane actually revoked", () => {
  const store = new RevocationStore({ tenantId: TENANT, trustedIssuerKeys })

  store.offer(
    signed({
      entries: [
        { agent_id: "planner", reason: "credential_compromised", revoked_at: NOW.toISOString() },
        { nonce: "nonce-abc", reason: "session_terminated", revoked_at: NOW.toISOString() },
        { permit_id: "permit-xyz", reason: "policy_violation", revoked_at: NOW.toISOString() },
      ],
    } as Partial<RevocationSnapshotBody>),
    NOW,
  )

  assert.equal(store.isAgentRevoked("planner", NOW).revoked, true)
  assert.equal(store.isAgentRevoked("planner", NOW).reason, "credential_compromised")
  assert.equal(store.isNonceRevoked("nonce-abc", NOW).revoked, true)
  assert.equal(store.isPermitRevoked("permit-xyz", NOW).revoked, true)

  assert.equal(store.isAgentRevoked("someone-else", NOW).revoked, false)
  assert.equal(store.isNonceRevoked("nonce-other", NOW).revoked, false)
})

test("an empty store revokes nothing and says so", () => {
  const store = new RevocationStore({ tenantId: TENANT, trustedIssuerKeys })

  assert.deepEqual(store.state(NOW), { kind: "empty" })
  // A freshly started sidecar must serve traffic; answering "unknown" here would deny everything.
  assert.equal(store.isAgentRevoked("planner", NOW).revoked, false)
  assert.equal(store.propagationAgeMs(NOW), undefined)
})

test("an unsigned snapshot is refused and does not clear what is already applied", () => {
  // The central anti-tampering property. A compromised caller that can reach `offer` must not be
  // able to replace a real list with an empty one.
  const store = new RevocationStore({ tenantId: TENANT, trustedIssuerKeys })

  assert.equal(store.offer(signed(), NOW).accepted, true)
  assert.equal(store.isAgentRevoked("planner", NOW).revoked, true)

  const forged = { body: body({ version: 2, entries: [] }), signature: { algorithm: "ed25519", issuer_id: ISSUER, value: "AAAA" } }

  assert.equal(store.offer(forged, NOW).accepted, false)
  // Still revoked. Clearing on error is how a corrupted push becomes an un-revocation.
  assert.equal(store.isAgentRevoked("planner", NOW).revoked, true)
  assert.equal(store.appliedVersion, 1)
})

test("an expired snapshot is still enforced", () => {
  const store = new RevocationStore({ tenantId: TENANT, trustedIssuerKeys })

  store.offer(
    signed({
      issued_at: new Date(NOW.getTime() - 2 * HOUR_MS).toISOString(),
      expires_at: new Date(NOW.getTime() + HOUR_MS).toISOString(),
    }),
    NOW,
  )

  const later = new Date(NOW.getTime() + 2 * HOUR_MS)

  assert.equal(store.state(later).kind, "expired")
  // The distinction that matters: an entry the control plane signed must not stop applying because
  // the control plane went away. Dropping it would turn an outage into an un-revocation.
  assert.equal(store.isAgentRevoked("planner", later).revoked, true)
})

test("a rollback attempt does not replace the current snapshot", () => {
  const store = new RevocationStore({ tenantId: TENANT, trustedIssuerKeys })

  store.offer(signed({ version: 5 }), NOW)
  assert.equal(store.offer(signed({ version: 2, entries: [] }), NOW).accepted, false)
  assert.equal(store.appliedVersion, 5)
  assert.equal(store.isAgentRevoked("planner", NOW).revoked, true)
})

test("a higher version replaces the list, which is how an entry is lifted", () => {
  const store = new RevocationStore({ tenantId: TENANT, trustedIssuerKeys })

  store.offer(signed({ version: 1 }), NOW)
  assert.equal(store.isAgentRevoked("planner", NOW).revoked, true)

  // Lifting a revocation is a signed decision at a higher version, not a deletion an attacker can
  // perform. That is the whole reason this is a snapshot and not a mutable set.
  store.offer(signed({ version: 2, entries: [] }), NOW)

  assert.equal(store.isAgentRevoked("planner", NOW).revoked, false)
  assert.equal(store.appliedVersion, 2)
})

test("sets for the existing verifier options carry exactly the revoked ids", () => {
  const store = new RevocationStore({ tenantId: TENANT, trustedIssuerKeys })

  store.offer(
    signed({
      entries: [
        { agent_id: "planner", reason: "operator_request", revoked_at: NOW.toISOString() },
        { agent_id: "coder", reason: "operator_request", revoked_at: NOW.toISOString() },
        { nonce: "nonce-abc", reason: "operator_request", revoked_at: NOW.toISOString() },
      ],
    } as Partial<RevocationSnapshotBody>),
    NOW,
  )

  assert.deepEqual([...store.agentIdSet(NOW)].sort(), ["coder", "planner"])
  assert.deepEqual([...store.nonceSet(NOW)], ["nonce-abc"])
  // An entry with no permit must not put `undefined` in the set, which a `.has()` would miss.
  assert.deepEqual([...store.permitIdSet(NOW)], [])
})

/* ----------------------------------------------------------- the propagation SLO instrument */

test("propagation age is measured from when the control plane issued the snapshot", () => {
  const store = new RevocationStore({ tenantId: TENANT, trustedIssuerKeys })
  const issuedAt = new Date(NOW.getTime() - 5 * 60 * 1000)

  store.offer(
    signed({ issued_at: issuedAt.toISOString() }),
    NOW,
  )

  assert.equal(store.propagationAgeMs(NOW), 5 * 60 * 1000)
})

test("propagation age keeps growing while no new snapshot arrives, and the entries still apply", () => {
  // This is the SLO's whole purpose: an enforcement point can be enforcing correctly and still be
  // unable to accept new revocations. That is not visible from `state()` alone, and it is exactly
  // what an operator needs to alert on.
  const store = new RevocationStore({ tenantId: TENANT, trustedIssuerKeys })

  store.offer(signed({ issued_at: NOW.toISOString() }), NOW)

  const tenMinutesLater = new Date(NOW.getTime() + 10 * 60 * 1000)

  assert.equal(store.propagationAgeMs(NOW), 0)
  assert.equal(store.propagationAgeMs(tenMinutesLater), 10 * 60 * 1000)
  // Enforcing is not the same as receiving. Both are true at once and the operator needs to see
  // the second one.
  assert.equal(store.isAgentRevoked("planner", tenMinutesLater).revoked, true)
})

test("a fresh snapshot resets the propagation age", () => {
  const store = new RevocationStore({ tenantId: TENANT, trustedIssuerKeys })

  store.offer(signed({ version: 1, issued_at: NOW.toISOString() }), NOW)
  assert.equal(store.propagationAgeMs(new Date(NOW.getTime() + 10 * 60 * 1000)), 10 * 60 * 1000)

  const refreshed = new Date(NOW.getTime() + 10 * 60 * 1000)

  store.offer(
    signed({ version: 2, issued_at: refreshed.toISOString() }),
    refreshed,
  )

  assert.equal(store.propagationAgeMs(refreshed), 0)
})

/* ------------------------------------------------------------- Phase P: the revocation index */

/**
 * The lookup index (S9, S12).
 *
 * `RevocationStore` answers per request, up to three times per action, and it used to scan the
 * whole entry array each time. Phase O raised the ceiling on that array to 5,000 entries, which
 * turned a linear scan into a measured cost on the enforcement path rather than a theoretical one.
 *
 * So these tests are mostly equivalence tests. A faster lookup that answers a slightly different
 * question is worse than the scan, so the index is pinned against a reference implementation of
 * the behaviour it replaced, including the one place the two could plausibly diverge: a duplicated
 * id, where `Array.prototype.find` returns the earliest entry's reason.
 */

type LookupKey = "agent_id" | "nonce" | "permit_id"

/** The pre-index behaviour, written out here so it cannot drift with the product code. */
const linearLookup = (
  entries: RevocationSnapshotBody["entries"],
  key: LookupKey,
  id: string,
): { revoked: boolean; reason?: string } => {
  const found = entries.find((entry) => entry[key] === id)
  return found === undefined ? { revoked: false } : { revoked: true, reason: found.reason }
}

test("Phase P: the index answers exactly what the linear scan answered", () => {
  const entries: RevocationSnapshotBody["entries"] = [
    { agent_id: "planner", reason: "credential_compromised", revoked_at: NOW.toISOString() },
    { nonce: "nonce-abc", reason: "policy_violation", revoked_at: NOW.toISOString() },
    { permit_id: "permit-1", reason: "session_terminated", revoked_at: NOW.toISOString() },
    // An entry that revokes two things at once. The schema allows it, so the index has to agree
    // about both halves rather than assuming one target per entry.
    { agent_id: "coder", nonce: "nonce-def", reason: "operator_request", revoked_at: NOW.toISOString() },
  ]

  const store = new RevocationStore({ tenantId: TENANT, trustedIssuerKeys })
  const result = store.offer(signed({ entries } as Partial<RevocationSnapshotBody>), NOW)
  assert.equal(result.accepted, true)

  const probes = ["planner", "coder", "absent-agent", "", "Nonce-ABC"]
  const nonceProbes = ["nonce-abc", "nonce-def", "absent-nonce", ""]
  const permitProbes = ["permit-1", "absent-permit", ""]

  for (const id of probes) {
    assert.deepEqual(
      store.isAgentRevoked(id, NOW),
      linearLookup(entries, "agent_id", id),
      `agent_id ${JSON.stringify(id)}`,
    )
  }
  for (const id of nonceProbes) {
    assert.deepEqual(
      store.isNonceRevoked(id, NOW),
      linearLookup(entries, "nonce", id),
      `nonce ${JSON.stringify(id)}`,
    )
  }
  for (const id of permitProbes) {
    assert.deepEqual(
      store.isPermitRevoked(id, NOW),
      linearLookup(entries, "permit_id", id),
      `permit_id ${JSON.stringify(id)}`,
    )
  }

  // The empty-string probe above matters because `Array.prototype.find` compares against
  // `undefined`-absent fields too; an id that no entry names must be "not revoked", never a
  // crash and never a match on some entry's missing field.
  assert.equal(store.isAgentRevoked("", NOW).revoked, false)
})

test("Phase P: a duplicated id keeps the reason from the earliest entry", () => {
  const entries: RevocationSnapshotBody["entries"] = [
    { agent_id: "planner", reason: "credential_compromised", revoked_at: NOW.toISOString() },
    { agent_id: "planner", reason: "operator_request", revoked_at: NOW.toISOString() },
  ]

  const store = new RevocationStore({ tenantId: TENANT, trustedIssuerKeys })
  store.offer(signed({ entries } as Partial<RevocationSnapshotBody>), NOW)

  // First wins, because that is what `.find` did. This is deliberately *not* "the most severe
  // reason" and *not* "the most recent": either would change an existing decision based on a
  // re-ordered but equally valid snapshot.
  assert.equal(store.isAgentRevoked("planner", NOW).reason, "credential_compromised")
  assert.deepEqual(store.isAgentRevoked("planner", NOW), linearLookup(entries, "agent_id", "planner"))
})

test("Phase P: an expired snapshot is still answered from the index", () => {
  const store = new RevocationStore({ tenantId: TENANT, trustedIssuerKeys })

  store.offer(
    signed({
      entries: [{ nonce: "nonce-abc", reason: "session_terminated", revoked_at: NOW.toISOString() }],
      issued_at: new Date(NOW.getTime() - 2 * HOUR_MS).toISOString(),
      expires_at: new Date(NOW.getTime() + HOUR_MS).toISOString(),
    } as Partial<RevocationSnapshotBody>),
    NOW,
  )

  const later = new Date(NOW.getTime() + 2 * HOUR_MS)
  assert.equal(store.state(later).kind, "expired")
  assert.equal(store.isNonceRevoked("nonce-abc", later).revoked, true)

  // And the set accessors behave the same way. An index that expired with the snapshot would turn
  // a control-plane outage into a mass un-revocation.
  assert.deepEqual([...store.nonceSet(later)], ["nonce-abc"])
})

test("Phase P: an empty store answers nothing from an empty index", () => {
  const store = new RevocationStore({ tenantId: TENANT, trustedIssuerKeys })

  assert.equal(store.state(NOW).kind, "empty")
  assert.deepEqual(store.isAgentRevoked("planner", NOW), { revoked: false })
  assert.deepEqual(store.isNonceRevoked("nonce-abc", NOW), { revoked: false })
  assert.deepEqual(store.isPermitRevoked("permit-1", NOW), { revoked: false })
  assert.deepEqual([...store.agentIdSet(NOW)], [])
})

test("Phase P: a refused snapshot leaves the previous index untouched", () => {
  const store = new RevocationStore({ tenantId: TENANT, trustedIssuerKeys })

  store.offer(signed({ version: 4, entries: [{ agent_id: "planner", reason: "agent_disabled", revoked_at: NOW.toISOString() }] } as Partial<RevocationSnapshotBody>), NOW)

  // A rollback, a forgery, and an oversized list are all refusals. If any of them cleared or
  // replaced the index, the attacker's move would be to *offer* something invalid.
  assert.equal(store.offer(signed({ version: 2, entries: [] } as Partial<RevocationSnapshotBody>), NOW).accepted, false)
  assert.equal(store.isAgentRevoked("planner", NOW).revoked, true)
  assert.equal(store.isAgentRevoked("planner", NOW).reason, "agent_disabled")
})

test("Phase P: a new snapshot's index replaces the old one atomically", () => {
  const store = new RevocationStore({ tenantId: TENANT, trustedIssuerKeys })

  store.offer(signed({ version: 1, entries: [{ agent_id: "planner", reason: "agent_disabled", revoked_at: NOW.toISOString() }] } as Partial<RevocationSnapshotBody>), NOW)
  store.offer(signed({ version: 2, entries: [{ agent_id: "coder", reason: "operator_request", revoked_at: NOW.toISOString() }] } as Partial<RevocationSnapshotBody>), NOW)

  // Neither the old body nor the new index survives in a mixture. A partially-updated pair here
  // would show up as "planner is gone but coder was never indexed".
  assert.equal(store.isAgentRevoked("planner", NOW).revoked, false)
  assert.equal(store.isAgentRevoked("coder", NOW).reason, "operator_request")
  assert.deepEqual([...store.agentIdSet(NOW)], ["coder"])
})

test("Phase P: the set accessors hand back a copy, not the store's own index", () => {
  const store = new RevocationStore({ tenantId: TENANT, trustedIssuerKeys })

  store.offer(signed({ entries: [{ agent_id: "planner", reason: "agent_disabled", revoked_at: NOW.toISOString() }] } as Partial<RevocationSnapshotBody>), NOW)

  const first = store.agentIdSet(NOW) as Set<string>
  first.add("smuggled")

  // `ReadonlySet` is compile-time only. If the caller can reach the internal set, a single `.add()`
  // would put an id into every future revocation answer that the control plane never signed.
  assert.equal(store.isAgentRevoked("smuggled", NOW).revoked, false)
  assert.deepEqual([...store.agentIdSet(NOW)], ["planner"])
})

test("Phase P: at the 5,000-entry ceiling a lookup is not a scan", () => {
  const entries: RevocationSnapshotBody["entries"] = Array.from(
    { length: MAX_REVOCATION_ENTRIES },
    (_unused, index) => ({
      agent_id: `agent-${index}`,
      reason: "operator_request" as const,
      revoked_at: NOW.toISOString(),
    }),
  )

  const store = new RevocationStore({ tenantId: TENANT, trustedIssuerKeys })
  assert.equal(store.offer(signed({ entries } as Partial<RevocationSnapshotBody>), NOW).accepted, true)

  // Worst case for a linear scan: the id being asked about is the last entry.
  const started = process.hrtime.bigint()
  const iterations = 20_000
  let revokedCount = 0

  for (let i = 0; i < iterations; i += 1) {
    if (store.isAgentRevoked(`agent-${MAX_REVOCATION_ENTRIES - 1}`, NOW).revoked) revokedCount += 1
  }

  const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6

  assert.equal(revokedCount, iterations)

  // Not a benchmark, a regression floor that sits between the two implementations. Measured on the
  // development machine, this loop costs ~6ms indexed and ~363ms as a `.find()` scan — so 150ms is
  // 25x of headroom above the index and still well under the scan it is meant to catch. The claim
  // being defended is "a lookup does not depend on how many entries the snapshot holds", and the
  // way to lose it is to rebuild or scan the table per question.
  assert.ok(
    elapsedMs < 150,
    `20,000 lookups over ${MAX_REVOCATION_ENTRIES} entries took ${elapsedMs.toFixed(1)}ms, which is scan-shaped`,
  )
})

