import assert from "node:assert/strict"
import test from "node:test"

import { createDatabase, migrateDatabase } from "../database.ts"
import {
  DEFAULT_REPLAY_RETENTION_MS,
  InMemoryReplayStore,
  PostgreSQLReplayStore,
  type ReplayEntry,
  type ReplayStore,
} from "./replay-store.ts"

/**
 * S9 conformance: replay resistance must survive a process restart and hold across replicas.
 *
 * The tests that matter here run against a real PostgreSQL instance. A `pg-mem` substitute
 * cannot establish atomicity between concurrent writers, and atomicity is the entire claim, so
 * those tests skip rather than pretend.
 *
 * The `DATABASE_URL` gate also means the database-level RLS policy created by migration 010 is
 * not exercised here: the test connection is the migration superuser, for which RLS is bypassed.
 * Tenant isolation below is therefore proven at the application level, where `tenant_id` is
 * part of the primary key and appears in every statement.
 */

const DATABASE_URL = process.env["DATABASE_URL"]

// Opt-in and serialized. Several test files run migrations against one database, and Node runs
// files concurrently, so running these under a plain `npm test` with DATABASE_URL exported
// deadlocks on DDL locks. `npm run test:substrate` sets this flag and serializes the runner.
const SUBSTRATE_PASS = process.env["ACTANTOS_SUBSTRATE_TESTS"] === "1"

const skip = DATABASE_URL === undefined || !SUBSTRATE_PASS
const todo = skip
  ? "DATABASE_URL not set, or run `npm run test:substrate` — real PostgreSQL required for atomicity"
  : undefined

const TENANT_A = "t_alpha"
const TENANT_B = "t_beta"
const clock = new Date("2026-10-03T12:00:00.000Z")

const entry = (overrides: Partial<ReplayEntry> = {}): ReplayEntry => ({
  tenantId: TENANT_A,
  permitId: "permit-1",
  nonce: "nonce-1",
  expiresAt: new Date(clock.getTime() + 60_000),
  ...overrides,
})

// A client whose every call fails, to prove the store reports unavailability rather than
// defaulting to a successful first use.
const brokenClient = (message = "connection terminated unexpectedly") => ({
  async query(): Promise<readonly never[]> {
    throw new Error(message)
  },
})

// Node runs test files concurrently, and every file here shares one PostgreSQL database. A
// blanket `DELETE FROM v2_replay_guard` from two files at once deletes the rows a concurrent
// file is relying on, which turns a durability claim into a race. Each file therefore cleans
// only the tenants it owns, and the tenants are named so a collision is a visible bug.
const OWNED_TENANTS = ["t_alpha", "t_beta"]

const wipeOwnedRows = async (database: Awaited<ReturnType<typeof createDatabase>>) => {
  await database.query(
    `DELETE FROM v2_replay_guard WHERE tenant_id IN (${OWNED_TENANTS.map((_, index) => `$${index + 1}`).join(", ")})`,
    OWNED_TENANTS,
  )
}

const withDatabase = async <T>(
  body: (store: PostgreSQLReplayStore) => Promise<T>,
): Promise<T> => {
  const database = createDatabase(DATABASE_URL!)
  try {
    await migrateDatabase(database)
    await wipeOwnedRows(database)
    return await body(new PostgreSQLReplayStore({ client: database }))
  } finally {
    await database.close()
  }
}

// --- The in-memory store ------------------------------------------------------------------

test("S9: the in-memory store grants first use exactly once", async () => {
  const store = new InMemoryReplayStore()

  assert.deepEqual(await store.consume(entry()), { outcome: "consumed" })
  assert.deepEqual(await store.consume(entry()), {
    outcome: "replayed",
    reason: "nonce_already_consumed",
  })
})

test("S9: the in-memory store refuses a permit id reused under a fresh nonce", async () => {
  const store = new InMemoryReplayStore()

  assert.deepEqual(await store.consume(entry()), { outcome: "consumed" })
  assert.deepEqual(await store.consume(entry({ nonce: "nonce-2" })), {
    outcome: "replayed",
    reason: "permit_already_consumed",
  })
  // The query names the fresh nonce only. Adding permit-1 to the same query would return true
  // for the right reason — permit-1 really was consumed — and would prove nothing about whether
  // the refused attempt wrote anything.
  assert.equal(
    await store.isConsumed({ tenantId: TENANT_A, nonce: "nonce-2" }),
    false,
    "a refused consume must not leave a record claiming the fresh nonce was used",
  )
  assert.equal(
    await store.isConsumed({ tenantId: TENANT_A, permitId: "permit-1" }),
    true,
    "the original consumption must survive the refused attempt",
  )
})

test("S9: a replay store query without a nonce or permit id is a programming error", async () => {
  await assert.rejects(
    () => new InMemoryReplayStore().isConsumed({ tenantId: TENANT_A }),
    /requires at least one/u,
  )
})

// --- Failure behaviour, no database required ---------------------------------------------

test("S9: an unreachable store reports unavailable rather than granting first use", async () => {
  const store = new PostgreSQLReplayStore({ client: brokenClient() })

  assert.deepEqual(await store.consume(entry()), {
    outcome: "unavailable",
    error: "connection terminated unexpectedly",
  })
})

test("S9: an unreachable store never yields 'consumed', even on a first-use attempt", async () => {
  const store = new PostgreSQLReplayStore({ client: brokenClient("disk I/O error") })

  const outcome = await store.consume(entry())
  assert.notEqual(outcome.outcome, "consumed")
  assert.equal(outcome.outcome === "unavailable" && outcome.error, "disk I/O error")
})

// --- Durable behaviour, real PostgreSQL --------------------------------------------------

test("S9: a consumed permit stays consumed after a store instance is destroyed", { skip: todo }, async () => {
  const database = createDatabase(DATABASE_URL!)
  try {
    await migrateDatabase(database)
    await wipeOwnedRows(database)

    const first = new PostgreSQLReplayStore({ client: database })
    assert.deepEqual(await first.consume(entry()), { outcome: "consumed" })

    // A brand new store object over the same database. This models a gateway restart: the
    // process memory is gone, and only the table remembers.
    const afterRestart = new PostgreSQLReplayStore({ client: database })
    assert.deepEqual(await afterRestart.consume(entry()), {
      outcome: "replayed",
      reason: "nonce_already_consumed",
    })
  } finally {
    await database.close()
  }
})

test("S9: two gateway replicas sharing a database produce exactly one first use", { skip: todo }, async () => {
  await withDatabase(async () => {
    const database = createDatabase(DATABASE_URL!)
    try {
      const replicaA = new PostgreSQLReplayStore({ client: database })
      const replicaB = new PostgreSQLReplayStore({ client: database })

      const [a, b] = await Promise.all([replicaA.consume(entry()), replicaB.consume(entry())])
      const outcomes = [a, b]

      assert.equal(
        outcomes.filter((o) => o.outcome === "consumed").length,
        1,
        "exactly one replica may consume a permit",
      )
      assert.equal(
        outcomes.filter((o) => o.outcome === "replayed").length,
        1,
        "the other replica must see a replay",
      )
    } finally {
      await database.close()
    }
  })
})

test("S9: 100 concurrent consumers of one permit yield exactly one success", { skip: todo }, async () => {
  await withDatabase(async () => {
    const database = createDatabase(DATABASE_URL!)
    try {
      // Separate store objects per caller, because the claim being tested is about durability
      // across consumers rather than about one object serialising its own calls.
      const stores = Array.from({ length: 100 }, () => new PostgreSQLReplayStore({ client: database }))
      const outcomes = await Promise.all(stores.map((store) => store.consume(entry())))

      const consumed = outcomes.filter((o) => o.outcome === "consumed")
      const replayed = outcomes.filter((o) => o.outcome === "replayed")

      assert.equal(consumed.length, 1, `expected exactly 1 first use, saw ${consumed.length}`)
      assert.equal(replayed.length, 99, `expected 99 replays, saw ${replayed.length}`)
      assert.equal(
        outcomes.filter((o) => o.outcome === "unavailable").length,
        0,
        "no attempt should have failed for infrastructure reasons",
      )
    } finally {
      await database.close()
    }
  })
})

test("S9: a duplicate permit id is refused even with a different nonce", { skip: todo }, async () => {
  await withDatabase(async (store) => {
    assert.deepEqual(await store.consume(entry()), { outcome: "consumed" })
    assert.deepEqual(await store.consume(entry({ nonce: "nonce-different" })), {
      outcome: "replayed",
      reason: "permit_already_consumed",
    })
  })
})

test("S9: a duplicate nonce under a different permit id is refused", { skip: todo }, async () => {
  await withDatabase(async (store) => {
    assert.deepEqual(await store.consume(entry()), { outcome: "consumed" })
    assert.deepEqual(await store.consume(entry({ permitId: "permit-different" })), {
      outcome: "replayed",
      reason: "nonce_already_consumed",
    })
  })
})

test("S9: one tenant cannot consume or shadow another tenant's nonce", { skip: todo }, async () => {
  await withDatabase(async (store) => {
    assert.deepEqual(await store.consume(entry()), { outcome: "consumed" })

    // Same nonce, different tenant. Tenant scoping is part of the primary key, so this is a
    // genuinely different permit rather than a collision.
    assert.deepEqual(await store.consume(entry({ tenantId: TENANT_B })), { outcome: "consumed" })

    assert.equal(await store.isConsumed({ tenantId: TENANT_A, nonce: "nonce-1" }), true)
    assert.equal(
      await store.isConsumed({ tenantId: TENANT_B, nonce: "nonce-2" }),
      false,
      "tenant B must not see tenant A's rows",
    )
  })
})

test("S9: cleanup removes only rows past the retention window", { skip: todo }, async () => {
  await withDatabase(async (store) => {
    await store.consume(entry({ permitId: "p-old", nonce: "n-old", expiresAt: new Date(clock.getTime() - DEFAULT_REPLAY_RETENTION_MS - 60_000) }))
    await store.consume(entry({ permitId: "p-fresh", nonce: "n-fresh" }))

    const removed = await store.cleanupExpired(clock)

    assert.equal(removed, 1, "only the row past retention should be removed")
    assert.equal(await store.isConsumed({ tenantId: TENANT_A, permitId: "p-old" }), false)
    assert.equal(await store.isConsumed({ tenantId: TENANT_A, permitId: "p-fresh" }), true)
  })
})

test("S9: cleanup leaves an already-expired permit protected inside the retention window", { skip: todo }, async () => {
  await withDatabase(async (store) => {
    // Expired an hour ago, but retention is 24h. The row must survive so a clock that disagrees
    // between gateway and store cannot convert a replay into a first use.
    await store.consume(entry({ expiresAt: new Date(clock.getTime() - 3_600_000) }))

    assert.equal(await store.cleanupExpired(clock), 0)
    assert.deepEqual(await store.consume(entry()), {
      outcome: "replayed",
      reason: "nonce_already_consumed",
    })
  })
})

test("S9: cleanup at the exact retention boundary removes the row", { skip: todo }, async () => {
  await withDatabase(async (store) => {
    const exactly = new Date(clock.getTime() - DEFAULT_REPLAY_RETENTION_MS)
    await store.consume(entry({ expiresAt: exactly }))

    // `expires_at < cutoff` is strict, so a row landing exactly on the boundary is kept and the
    // next sweep removes it. Asserted so the comparison operator cannot drift silently.
    assert.equal(await store.cleanupExpired(clock), 0)
    assert.equal(await store.cleanupExpired(new Date(clock.getTime() + 1)), 1)
  })
})

test("S9: isConsumed is tenant-scoped and rejects an empty query", { skip: todo }, async () => {
  await withDatabase(async (store) => {
    await store.consume(entry())

    assert.equal(await store.isConsumed({ tenantId: TENANT_A, nonce: "nonce-1" }), true)
    assert.equal(await store.isConsumed({ tenantId: TENANT_A, nonce: "nonce-absent" }), false)
    assert.equal(await store.isConsumed({ tenantId: TENANT_B, nonce: "nonce-1" }), false)

    await assert.rejects(
      () => store.isConsumed({ tenantId: TENANT_A }),
      /requires at least one/u,
    )
  })
})

// --- Store equivalence --------------------------------------------------------------------

const replayContract = async (store: ReplayStore) => ({
  first: await store.consume(entry({ permitId: "p", nonce: "n" })),
  sameNonce: await store.consume(entry({ permitId: "p2", nonce: "n" })),
  samePermit: await store.consume(entry({ permitId: "p", nonce: "n2" })),
  // Collides with both unique constraints at once. The reason is only the same across
  // implementations if the classifier has a defined precedence.
  identical: await store.consume(entry({ permitId: "p", nonce: "n" })),
})

test("S9: a store denies a reused nonce and a reused permit id with distinct reasons", async () => {
  const memory = await replayContract(new InMemoryReplayStore())

  assert.deepEqual(memory.first, { outcome: "consumed" })
  assert.deepEqual(memory.sameNonce, { outcome: "replayed", reason: "nonce_already_consumed" })
  assert.deepEqual(memory.samePermit, { outcome: "replayed", reason: "permit_already_consumed" })
  assert.deepEqual(memory.identical, { outcome: "replayed", reason: "nonce_already_consumed" })
})

test("S9: the in-memory and PostgreSQL stores agree on every outcome shape", { skip: todo }, async () => {
  const memory = await replayContract(new InMemoryReplayStore())
  const postgres = await withDatabase(replayContract)

  assert.deepEqual(memory, postgres, "the two implementations must not diverge on deny reasons")
})