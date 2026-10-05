import assert from "node:assert/strict"
import test from "node:test"

import { createDatabase, migrateDatabase } from "../database.ts"
import { EvidenceChain, type EvidenceBundle } from "./evidence.ts"
import { EffectGateway, type EffectGatewayOptions } from "./effect-gateway.ts"
import { issueEffectPermit, NonceStore } from "./effect-permit.ts"
import { InMemoryReplayStore, PostgreSQLReplayStore, type ReplayStore } from "./replay-store.ts"
import { ed25519 } from "./signature.ts"

/**
 * S9 at the gateway boundary.
 *
 * `replay-store.test.ts` proves the store's own behaviour. These tests prove the claim that
 * actually matters: a permit that the gateway has already spent cannot be spent again, even
 * though the process that spent it is gone, or a second process is running alongside it.
 *
 * A store in isolation cannot establish that. It is the gateway's ordering — verify, then claim
 * the durable nonce, then execute — that turns a durable record into a real-world guarantee. So
 * these drive the public `perform` path and count executor invocations.
 */

const DATABASE_URL = process.env["DATABASE_URL"]

// Opt-in and serialized, for the same reason as replay-store.test.ts: several files migrate one
// shared database, and Node runs files concurrently. `npm run test:substrate` sets this flag.
const SUBSTRATE_PASS = process.env["ACTANTOS_SUBSTRATE_TESTS"] === "1"

const skip = DATABASE_URL === undefined || !SUBSTRATE_PASS
const todo = skip
  ? "DATABASE_URL not set, or run `npm run test:substrate` — durability and replica claims need real PostgreSQL"
  : undefined

const NOW = new Date("2026-10-03T12:00:00.000Z")
const TENANT = "t_replay_gw"
const ISSUER = "issuer-replay"
const SPIFFE = `spiffe://actantos.local/tenant/${TENANT}/agent/merge-agent`
const EXECUTION = "exec-replay"
const TOOL = "github.pull-request.merge"
const ACTION = { tool: TOOL, resource: "org/repo#42", args: { number: 42, method: "squash" } }

const keyPair = ed25519.generateKeyPair()
const trustedIssuerKeys = new Map([[ISSUER, keyPair.publicKeyPem]])

/** Counts how many times the effect actually reached the outside world. */
const effectCounter = () => {
  let count = 0
  return {
    executors: {
      [TOOL]: async () => {
        count += 1
        return { ok: true as const, result: { merged: true, call: count } }
      },
    },
    get count() {
      return count
    },
  }
}

const buildGateway = (options: {
  readonly replayStore: ReplayStore | undefined
  readonly nonces?: NonceStore
  readonly executors: EffectGatewayOptions["executors"]
  readonly evidenceChain?: EvidenceChain
}) => new EffectGateway({
  tenantId: TENANT,
  trustedIssuerKeys,
  evidenceChain: options.evidenceChain ?? new EvidenceChain({
    tenantId: TENANT,
    issuerId: ISSUER,
    keyPair,
    sink: () => {},
  }),
  executors: options.executors,
  ...(options.replayStore === undefined ? {} : { replayStore: options.replayStore }),
  ...(options.nonces === undefined ? {} : { nonces: options.nonces }),
  now: () => NOW,
})

const spend = async (
  gateway: EffectGateway,
  permit: ReturnType<typeof issueEffectPermit>,
) => gateway.perform({
  permit,
  action: ACTION,
  executionId: EXECUTION,
  principalSpiffeId: SPIFFE,
  // "file_store" rather than "external_http": the default clearance of external_http is PUBLIC,
  // so a CONFIDENTIAL-labelled permit would be stopped by the IFC check before the replay store
  // was ever consulted. These tests are about first use, and must not pass or fail for an
  // unrelated reason.
  sinkType: "file_store",
})

/** One genuine permit, reused verbatim by every attempt below. */
const mintPermit = () => issueEffectPermit({
  principalSpiffeId: SPIFFE,
  tenantId: TENANT,
  executionId: EXECUTION,
  delegationDigest: "delegation-digest",
  action: ACTION,
  policyBundleDigest: "policy-digest",
  dataLabels: ["CONFIDENTIAL"],
  issuedAt: NOW,
  issuerId: ISSUER,
  keyPair,
})

const withDatabase = async <T>(body: (client: Awaited<ReturnType<typeof createDatabase>>) => Promise<T>) => {
  const database = createDatabase(DATABASE_URL!)
  try {
    await migrateDatabase(database)
    // Only this file's tenant. Node runs test files concurrently against one database, so a
    // blanket delete here would erase the rows `replay-store.test.ts` is relying on.
    await database.query("DELETE FROM v2_replay_guard WHERE tenant_id = $1", [TENANT])
    return await body(database)
  } finally {
    await database.close()
  }
}

// --- No database required ------------------------------------------------------------------

test("S9: a durable replay store makes the effect stop when the store is unreachable", async () => {
  const counter = effectCounter()
  const permit = mintPermit()

  // A store whose every query fails. The gateway cannot prove the permit is unused.
  const gateway = buildGateway({
    replayStore: new PostgreSQLReplayStore({
      client: {
        async query() {
          throw new Error("connection terminated unexpectedly")
        },
      },
    }),
    executors: counter.executors,
  })

  const outcome = await spend(gateway, permit)

  assert.equal(outcome.performed, false)
  assert.equal(outcome.performed === false && outcome.reason, "replay_store_unavailable")
  assert.equal(counter.count, 0, "an unreachable replay store must stop the effect, not warn about it")
})

test("S9: a durable replay store is the only first-use authority, not a second opinion", async () => {
  const counter = effectCounter()
  const permit = mintPermit()

  // The process-memory nonce set is pre-marked as if a previous use had happened, and a fresh
  // durable store has never seen the permit. If the gateway consulted the in-memory set, this
  // would be denied as a replay; it must succeed, because the durable store is authoritative.
  const nonces = new NonceStore()
  nonces.consume(permit.nonce)

  const gateway = buildGateway({
    replayStore: new InMemoryReplayStore(),
    nonces,
    executors: counter.executors,
  })

  const outcome = await spend(gateway, permit)

  assert.equal(outcome.performed, true)
  assert.equal(counter.count, 1)
})

test("S9: an unsigned permit is refused before it can burn a durable nonce", async () => {
  const counter = effectCounter()
  const store = new InMemoryReplayStore()

  const gateway = buildGateway({ replayStore: store, executors: counter.executors })
  const permit = { ...mintPermit(), signature: "not-a-signature" }

  const outcome = await spend(gateway, permit as never)

  assert.equal(outcome.performed, false)
  assert.equal(counter.count, 0)
  assert.equal(
    await store.isConsumed({ tenantId: TENANT, nonce: permit.nonce }),
    false,
    "a forged permit must not be able to deny the real permit its nonce",
  )
})

// --- Real PostgreSQL -----------------------------------------------------------------------

test("S9: a permit spent by one gateway is refused after that gateway is destroyed", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const permit = mintPermit()
    const first = effectCounter()

    const before = await spend(
      buildGateway({ replayStore: new PostgreSQLReplayStore({ client: database }), executors: first.executors }),
      permit,
    )
    assert.equal(before.performed, true)
    assert.equal(first.count, 1)

    // Everything in the first gateway is discarded. The permit is still in scope and unexpired,
    // so the only thing that can refuse it is the table.
    const after = effectCounter()
    const restarted = buildGateway({
      replayStore: new PostgreSQLReplayStore({ client: database }),
      executors: after.executors,
    })

    const outcome = await spend(restarted, permit)

    assert.equal(outcome.performed, false)
    assert.equal(outcome.performed === false && outcome.reason, "already_used")
    assert.equal(after.count, 0, "a restarted gateway must not repeat an effect that already happened")
  })
})

test("S9: two gateways sharing a database perform the effect exactly once", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const permit = mintPermit()
    const replicaOne = effectCounter()
    const replicaTwo = effectCounter()

    const gatewayOne = buildGateway({
      replayStore: new PostgreSQLReplayStore({ client: database }),
      executors: replicaOne.executors,
    })
    // A second process, with its own in-memory nonce set that has never seen the permit.
    const gatewayTwo = buildGateway({
      replayStore: new PostgreSQLReplayStore({ client: database }),
      nonces: new NonceStore(),
      executors: replicaTwo.executors,
    })

    const [a, b] = await Promise.all([spend(gatewayOne, permit), spend(gatewayTwo, permit)])

    assert.equal(replicaOne.count + replicaTwo.count, 1, "one permit, one real-world effect")
    assert.equal([a, b].filter((o) => o.performed).length, 1)
    assert.equal([a, b].filter((o) => !o.performed).length, 1)
  })
})

test("S9: 50 gateways racing one permit leave exactly one effect", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const permit = mintPermit()
    const counters = Array.from({ length: 50 }, () => effectCounter())
    const gateways = counters.map((counter) => buildGateway({
      replayStore: new PostgreSQLReplayStore({ client: database }),
      executors: counter.executors,
    }))

    const outcomes = await Promise.all(gateways.map((gateway) => spend(gateway, permit)))

    assert.equal(outcomes.filter((o) => o.performed).length, 1)
    assert.equal(
      counters.reduce((total, counter) => total + counter.count, 0),
      1,
      "the executor must be reached exactly once across every replica",
    )
  })
})

test("S9: a durable denial is recorded as a security violation in evidence", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const permit = mintPermit()

    const first = buildGateway({
      replayStore: new PostgreSQLReplayStore({ client: database }),
      executors: effectCounter().executors,
    })
    assert.equal((await spend(first, permit)).performed, true)

    // The second gateway collects its own evidence so the denial can be inspected. Evidence is
    // per-process here; a durable evidence store is a later phase, and this test does not
    // pretend otherwise.
    const bundles: EvidenceBundle[] = []
    const second = buildGateway({
      replayStore: new PostgreSQLReplayStore({ client: database }),
      executors: effectCounter().executors,
      evidenceChain: new EvidenceChain({
        tenantId: TENANT,
        issuerId: ISSUER,
        keyPair,
        sink: (bundle) => bundles.push(bundle),
      }),
    })

    const outcome = await spend(second, permit)

    assert.equal(outcome.performed, false)
    const violations = bundles
      .flatMap((bundle) => bundle.records)
      .filter((record) => record.evidence_type === "security_violation")
    assert.equal(violations.length, 1)
    assert.equal((violations[0]?.payload as Record<string, unknown>)["reason"], "already_used")
    assert.equal((violations[0]?.payload as Record<string, unknown>)["permit_id"], permit.permit_id)
  })
})
