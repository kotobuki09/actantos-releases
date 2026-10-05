import assert from "node:assert/strict"
import test from "node:test"

import {
  InMemoryDecisionNonceStore,
  ReplayStoreDecisionNonceStore,
  type DecisionNonceEntry,
} from "./decision-nonce-store.ts"
import type { ReplayConsumeOutcome, ReplayStore } from "./v2/replay-store.ts"

const entry = (nonce: string, overrides: Partial<DecisionNonceEntry> = {}): DecisionNonceEntry => ({
  tenantId: "t_demo",
  permitId: "dec_00000001",
  nonce,
  expiresAt: new Date("2030-01-01T00:00:00.000Z"),
  ...overrides,
})

test("S9: a nonce is consumable exactly once", async () => {
  const store = new InMemoryDecisionNonceStore()

  assert.equal(await store.consume(entry("nonce-a")), true)
  assert.equal(await store.consume(entry("nonce-a")), false)
  assert.equal(await store.consume(entry("nonce-a")), false)
})

test("S9: distinct nonces do not interfere with each other", async () => {
  const store = new InMemoryDecisionNonceStore()

  assert.equal(await store.consume(entry("nonce-a")), true)
  assert.equal(await store.consume(entry("nonce-b")), true)
  assert.equal(await store.consume(entry("nonce-a")), false)
  assert.equal(await store.consume(entry("nonce-b")), false)
})

test("S9: isConsumed is observational and does not consume", async () => {
  // If a read marked the nonce, a monitoring component would silently burn tokens. isConsumed
  // exists so evidence code can report without deciding.
  const store = new InMemoryDecisionNonceStore()

  assert.equal(await store.isConsumed(entry("nonce-a")), false)
  assert.equal(await store.isConsumed(entry("nonce-a")), false)
  assert.equal(await store.consume(entry("nonce-a")), true)
  assert.equal(await store.isConsumed(entry("nonce-a")), true)
})

test("S9: an empty nonce is still tracked, so it cannot be used as a free pass", async () => {
  // The token parser rejects an empty nonce before it reaches the store. This asserts the store
  // is not the only line of defence being relied on, and that if it is ever reached, "" is just
  // another value rather than a wildcard.
  const store = new InMemoryDecisionNonceStore()

  assert.equal(await store.consume(entry("")), true)
  assert.equal(await store.consume(entry("")), false)
})

test("S9: the in-memory store is per-process and does not survive a restart", async () => {
  // The documented limitation of *this* implementation, asserted so it cannot be quietly
  // forgotten. `ReplayStoreDecisionNonceStore` is the durable one; this is why it exists and why
  // a deployment that needs cross-restart replay resistance must wire that one instead.
  const first = new InMemoryDecisionNonceStore()
  await first.consume(entry("nonce-a"))

  const afterRestart = new InMemoryDecisionNonceStore()
  assert.equal(await afterRestart.isConsumed(entry("nonce-a")), false)
  assert.equal(await afterRestart.consume(entry("nonce-a")), true)
})

/**
 * A `ReplayStore` that records what it was asked and replays a scripted outcome.
 *
 * The point of these tests is the mapping in `ReplayStoreDecisionNonceStore`, not the database:
 * that mapping is what decides whether an outage becomes a permit.
 */
const scriptedReplayStore = (
  outcome: ReplayConsumeOutcome,
  consumed = new Set<string>(),
): ReplayStore & { readonly seen: DecisionNonceEntry[] } => {
  const seen: DecisionNonceEntry[] = []

  return {
    seen,
    async consume(candidate) {
      seen.push(candidate)

      if (candidate.nonce === "") {
        return outcome
      }

      if (consumed.has(candidate.nonce)) {
        return { outcome: "replayed", reason: "nonce_already_consumed" }
      }

      if (outcome.outcome === "consumed") {
        consumed.add(candidate.nonce)
      }

      return outcome
    },
    async isConsumed() {
      return false
    },
    async cleanupExpired() {
      return 0
    },
  }
}

test("S9: the durable store passes the decision identity through to the replay store", async () => {
  // The adapter must not drop the tenant or the permit id. A nonce claimed under one tenant is
  // not the same record as the same nonce claimed under another.
  const backing = scriptedReplayStore({ outcome: "consumed" })
  const store = new ReplayStoreDecisionNonceStore(backing)

  assert.equal(await store.consume(entry("nonce-a", { tenantId: "t_a", permitId: "dec_a" })), true)
  assert.deepEqual(backing.seen[0], {
    tenantId: "t_a",
    permitId: "dec_a",
    nonce: "nonce-a",
    expiresAt: new Date("2030-01-01T00:00:00.000Z"),
  })
})

test("S9: the durable store refuses a replay", async () => {
  const backing = scriptedReplayStore({ outcome: "consumed" })
  const store = new ReplayStoreDecisionNonceStore(backing)

  assert.equal(await store.consume(entry("nonce-a")), true)
  assert.equal(await store.consume(entry("nonce-a")), false)
})

test("S12: a store that cannot answer denies rather than permits", async () => {
  // The dangerous direction. `unavailable` is what a database outage looks like, and an outage
  // that reads as "first use" is a bypass: every captured token becomes replayable exactly when
  // the system is least able to notice.
  const store = new ReplayStoreDecisionNonceStore(
    scriptedReplayStore({ outcome: "unavailable", error: "connection refused" }),
  )

  assert.equal(await store.consume(entry("nonce-a")), false)
})

test("S12: a permit already consumed under a different nonce is refused", async () => {
  // Reusing a permit id is a replay even when the nonce looks fresh, and the durable store must
  // not let a caller launder a second execution through a new nonce.
  const store = new ReplayStoreDecisionNonceStore(
    scriptedReplayStore({ outcome: "replayed", reason: "permit_already_consumed" }),
  )

  assert.equal(await store.consume(entry("nonce-a")), false)
})
