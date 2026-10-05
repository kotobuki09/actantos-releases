import assert from "node:assert/strict"
import test from "node:test"

import { createDatabase, migrateDatabase, type Database } from "../database.ts"
import { canonicalHash, canonicalStringify, toJsonValue } from "../hash.ts"
import { EvidenceChain, verifyEvidenceBundle } from "./evidence.ts"
import {
  auditEvidenceChain,
  genesisHash,
  PostgreSQLEvidenceStore,
  type EvidenceAppendOutcome,
  type EvidenceCheckpoint,
} from "./evidence-store.ts"
import { EffectGateway } from "./effect-gateway.ts"
import { issueEffectPermit } from "./effect-permit.ts"
import { InMemoryReplayStore } from "./replay-store.ts"
import { ed25519 } from "./signature.ts"

/**
 * S13 conformance, phase C: evidence that survives a restart and cannot be rewritten.
 *
 * The durability and append-only tests need real PostgreSQL. `pg-mem` has neither transactional
 * advisory locks nor triggers, and the properties under test *are* the database behaviour, so a
 * substitute would turn them into assertions about a mock.
 *
 * `auditEvidenceChain` is pure and is tested unconditionally. It is the part that has to work
 * offline, on an auditor's machine, with nothing running.
 *
 * Every database test runs under its own freshly named tenant rather than deleting rows first.
 * The evidence table is append-only, so a `DELETE` between tests is impossible by design, and a
 * fixture that quietly disables that trigger to clean up would defeat the point of the file.
 */

const DATABASE_URL = process.env["DATABASE_URL"]
const SUBSTRATE_PASS = process.env["ACTANTOS_SUBSTRATE_TESTS"] === "1"
const skip = DATABASE_URL === undefined || !SUBSTRATE_PASS
const todo = skip
  ? "DATABASE_URL not set, or run `npm run test:substrate` — durability needs real PostgreSQL"
  : undefined

const ISSUER = "issuer-evidence"
const AT = new Date("2026-10-03T12:00:00.000Z")
const ISOLATION_ROLE = "actantos_rls_test"

const keyPair = ed25519.generateKeyPair()
const trustedIssuerKeys = new Map([[ISSUER, keyPair.publicKeyPem]])

let tenantCounter = 0

/**
 * Identifies this process for tenant naming. The pid keeps concurrent runs apart; the clock
 * keeps repeated runs against one database apart. Neither needs to be unguessable.
 */
const RUN_ID = `${process.pid.toString(36)}${Date.now().toString(36)}`

/**
 * A tenant nobody has used. Chains are per tenant, so a new name is a clean chain with no
 * cleanup, and a stale row from an earlier run cannot make a test pass or fail by accident.
 *
 * The run id is part of the name because the substrate database is not thrown away between
 * runs. A counter alone restarts at 1 every process, so the second run against the same
 * database would meet the first run's chain and start at seq 2 instead of seq 0.
 */
const freshTenant = (label: string): string => {
  tenantCounter += 1
  return `t_ev_${RUN_ID}_${label}_${tenantCounter}`
}

const buildStore = (database: Database) =>
  new PostgreSQLEvidenceStore({ database, issuerId: ISSUER, keyPair })

const appendRecord = (
  store: PostgreSQLEvidenceStore,
  tenantId: string,
  payload: unknown = { ok: true },
  evidenceType: "effect_permit" | "effect_execution" | "data_access" = "effect_permit",
) => store.append({ tenantId, evidenceType, payload, occurredAt: AT })

const withDatabase = async <T>(body: (database: Database) => Promise<T>): Promise<T> => {
  const database = createDatabase(DATABASE_URL!)
  try {
    await migrateDatabase(database)
    return await body(database)
  } finally {
    await database.close()
  }
}

/**
 * Narrow an append outcome to the success case.
 *
 * `assert.ok` carries an assertion signature, so this both checks and narrows. A test that
 * asserted only on `seq` would compile against an outcome that never had one.
 */
const appended = (outcome: EvidenceAppendOutcome): { readonly seq: number; readonly hash: string } => {
  assert.ok(
    outcome.outcome === "appended",
    `expected the append to land, got ${outcome.outcome}`,
  )
  return outcome
}

/** Build a chain without a database, reusing `EvidenceChain` so the two cannot silently diverge. */
const chainOf = (count: number, tenantId: string) => {
  const chain = new EvidenceChain({ tenantId, issuerId: ISSUER, keyPair })

  for (let index = 0; index < count; index += 1) {
    chain.append("effect_permit", { step: index }, { occurredAt: AT })
  }

  return chain.export()
}

// --- Pure audit, no database --------------------------------------------------------------

test("S13: an untouched chain audits as intact", () => {
  const tenantId = "t_ev_pure_intact"
  const bundle = chainOf(5, tenantId)

  const audit = auditEvidenceChain({ tenantId, records: bundle.records, checkpoints: [] })

  assert.deepEqual(audit.issues, [])
  assert.equal(audit.intact, true)
  assert.equal(audit.recordCount, 5)
  assert.equal(audit.headHash, bundle.root_hash)
  assert.equal(audit.headSeq, 4)
})

test("S13: the store's genesis link is the in-process chain's genesis link", () => {
  // If these drifted, a chain resumed from the database could not be verified against a bundle
  // exported before the restart.
  assert.equal(genesisHash("t_ev_pure_genesis"), canonicalHash({ genesis: "t_ev_pure_genesis" }))
})

test("S13: a missing sequence number is reported as a gap", () => {
  const tenantId = "t_ev_pure_gap"
  const bundle = chainOf(4, tenantId)

  const audit = auditEvidenceChain({
    tenantId,
    records: [bundle.records[0]!, bundle.records[1]!, bundle.records[3]!],
    checkpoints: [],
  })

  assert.equal(audit.intact, false)
  const issue = audit.issues.find((entry) => entry.kind === "sequence_gap")
  assert.ok(issue, "a missing sequence number must be reported as a gap")
  assert.match(issue.detail, /expected seq 2, found 3/u)
})

test("S13: reordered records are reported as out of order", () => {
  const tenantId = "t_ev_pure_order"
  const bundle = chainOf(3, tenantId)

  const audit = auditEvidenceChain({
    tenantId,
    records: [bundle.records[0]!, bundle.records[2]!, bundle.records[1]!],
    checkpoints: [],
  })

  assert.equal(audit.intact, false)
  assert.ok(audit.issues.some((entry) => entry.kind === "sequence_out_of_order"))
})

test("S13: a record whose prev_hash does not match its predecessor is reported", () => {
  const tenantId = "t_ev_pure_link"
  const bundle = chainOf(3, tenantId)

  const audit = auditEvidenceChain({
    tenantId,
    records: [
      bundle.records[0]!,
      bundle.records[1]!,
      { ...bundle.records[2]!, prev_hash: canonicalHash({ forged: true }) },
    ],
    checkpoints: [],
  })

  assert.equal(audit.intact, false)
  assert.ok(audit.issues.some((entry) => entry.kind === "broken_linkage"))
})

test("S13: a record edited after signing is caught even when its linkage still fits", () => {
  const tenantId = "t_ev_pure_edit"
  const bundle = chainOf(3, tenantId)

  // Exactly what an attacker with table access produces: the payload is changed in place and the
  // linkage is left alone, so a linkage-only check would pass.
  const tampered = { ...bundle.records[2]!, payload: { permit_id: "someone-elses-permit" } }

  const audit = auditEvidenceChain({
    tenantId,
    records: [bundle.records[0]!, bundle.records[1]!, tampered],
    checkpoints: [],
  })

  assert.equal(audit.intact, false)
  assert.ok(audit.issues.some((entry) => entry.kind === "record_hash_mismatch"))
})

test("S13: two different records at one sequence number are reported as a duplicate", () => {
  const tenantId = "t_ev_pure_dup"
  const bundle = chainOf(2, tenantId)

  const audit = auditEvidenceChain({
    tenantId,
    records: [
      bundle.records[0]!,
      bundle.records[1]!,
      { ...bundle.records[1]!, hash: canonicalHash({ sibling: true }) },
    ],
    checkpoints: [],
  })

  assert.equal(audit.intact, false)
  assert.ok(audit.issues.some((entry) => entry.kind === "duplicate_sequence"))
})

test("S13: a chain shorter than its own checkpoint is reported as truncated", () => {
  const tenantId = "t_ev_pure_trunc"
  const bundle = chainOf(6, tenantId)
  const checkpoints: EvidenceCheckpoint[] = [
    { seq: 5, rootHash: bundle.records[5]!.hash, createdAt: AT.toISOString() },
  ]

  const audit = auditEvidenceChain({ tenantId, records: bundle.records.slice(0, 3), checkpoints })

  const issue = audit.issues.find((entry) => entry.kind === "truncated_after_checkpoint")
  assert.ok(issue, "a chain that stops before a checkpoint must be reported")
  assert.match(issue.detail, /stops at seq 2/u)
})

test("S13: a checkpoint that no longer matches its record reports a rewritten prefix", () => {
  const tenantId = "t_ev_pure_cp"
  const bundle = chainOf(3, tenantId)

  const audit = auditEvidenceChain({
    tenantId,
    records: bundle.records,
    checkpoints: [{ seq: 1, rootHash: canonicalHash({ what: "used to be here" }), createdAt: AT.toISOString() }],
  })

  assert.equal(audit.intact, false)
  assert.ok(audit.issues.some((entry) => entry.kind === "checkpoint_mismatch"))
})

test("S13: a consistent chain with matching checkpoints audits as intact", () => {
  const tenantId = "t_ev_pure_cp_ok"
  const bundle = chainOf(5, tenantId)
  const checkpoints: EvidenceCheckpoint[] = [1, 3].map((seq) => ({
    seq,
    rootHash: bundle.records[seq]!.hash,
    createdAt: AT.toISOString(),
  }))

  const audit = auditEvidenceChain({ tenantId, records: bundle.records, checkpoints })

  assert.deepEqual(audit.issues, [])
  assert.equal(audit.intact, true)
})

test("S13: an empty chain audits as intact, not as truncated", () => {
  const audit = auditEvidenceChain({ tenantId: "t_ev_pure_empty", records: [], checkpoints: [] })

  assert.equal(audit.intact, true)
  assert.equal(audit.headSeq, null)
  assert.equal(audit.headHash, null)
})

test("S13: a gateway with neither an evidence chain nor an evidence store refuses to exist", () => {
  assert.throws(
    () => new EffectGateway({ tenantId: "t_ev_none", trustedIssuerKeys, executors: {} }),
    /requires evidenceChain or evidenceStore/u,
  )
})

test("S13: an evidence store that cannot be reached fails the effect closed", async () => {
  const tenantId = "t_ev_unavailable"
  const principal = `spiffe://actantos.local/tenant/${tenantId}/agent/merge`
  const action = {
    tool: "github.pull-request.merge",
    resource: "org/repo#7",
    args: { number: 7 },
  }
  let effects = 0

  const gateway = new EffectGateway({
    tenantId,
    trustedIssuerKeys,
    evidenceStore: {
      append: async () => ({ outcome: "unavailable" as const, error: "no route to host" }),
      read: async () => [],
      head: async () => null,
      checkpoint: async () => null,
      readCheckpoints: async () => [],
      exportBundle: async () => {
        throw new Error("unreachable")
      },
    },
    replayStore: new InMemoryReplayStore(),
    executors: {
      "github.pull-request.merge": async () => {
        effects += 1
        return { ok: true as const, result: { merged: true } }
      },
    },
    now: () => AT,
  })

  const outcome = await gateway.perform({
    permit: issueEffectPermit({
      principalSpiffeId: principal,
      tenantId,
      executionId: "exec-ev",
      delegationDigest: "delegation-digest",
      action,
      policyBundleDigest: "policy-digest",
      dataLabels: ["CONFIDENTIAL"],
      issuedAt: AT,
      issuerId: ISSUER,
      keyPair,
    }),
    action,
    executionId: "exec-ev",
    principalSpiffeId: principal,
    sinkType: "file_store",
  })

  assert.equal(outcome.performed, false)
  assert.equal(outcome.performed === false && outcome.reason, "evidence_unavailable")
  assert.equal(effects, 0, "an effect whose authorization cannot be recorded must not happen")
})

// --- Durable behaviour, real PostgreSQL --------------------------------------------------

test("S13: appended records survive a new store object, continuing the same chain", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const tenantId = freshTenant("restart")

    const before = buildStore(database)
    const first = await appendRecord(before, tenantId, { step: 1 })
    assert.equal(first.outcome, "appended")
    assert.equal(appended(first).seq, 0)

    const beforeRestart = await before.exportBundle(tenantId)

    // A restart: a different object over the same database, with no memory of the first.
    const afterRestart = buildStore(database)
    const second = await appendRecord(afterRestart, tenantId, { step: 2 }, "effect_execution")

    assert.equal(appended(second).seq, 1, "the chain must not restart at 0")

    const bundle = await afterRestart.exportBundle(tenantId)
    assert.equal(bundle.records.length, 2)
    assert.equal(bundle.records[1]!.prev_hash, beforeRestart.records[0]!.hash)
    assert.equal(
      verifyEvidenceBundle(bundle, trustedIssuerKeys).valid,
      true,
      "a chain resumed from the database must verify like one never interrupted",
    )
  })
})

test("S13: a durable chain verifies offline with no running service", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const tenantId = freshTenant("offline")
    const store = buildStore(database)

    await appendRecord(store, tenantId, { step: 1 })
    await appendRecord(store, tenantId, { step: 2 }, "effect_execution")
    await appendRecord(store, tenantId, { step: 3 })

    const bundle = await store.exportBundle(tenantId)
    // Round-tripped through JSON so nothing can pass by virtue of holding live object references.
    const verification = verifyEvidenceBundle(
      JSON.parse(JSON.stringify(bundle)),
      trustedIssuerKeys,
    )

    assert.equal(verification.valid, true, JSON.stringify(verification))
    assert.equal(verification.valid === true ? verification.recordCount : -1, 3)
  })
})

test("S13: 100 concurrent appends produce one gapless chain", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const tenantId = freshTenant("concurrent")

    const stores = Array.from({ length: 100 }, () => buildStore(database))
    const outcomes = await Promise.all(
      stores.map((store, index) => appendRecord(store, tenantId, { index })),
    )

    assert.equal(
      outcomes.filter((outcome) => outcome.outcome === "appended").length,
      100,
      "every append must land; none may be lost to a lock timeout",
    )

    const seqs = outcomes
      .filter((outcome) => outcome.outcome === "appended")
      .map((outcome) => (appended(outcome).seq))
      .sort((left, right) => left - right)

    assert.deepEqual(
      seqs,
      Array.from({ length: 100 }, (_, index) => index),
      "sequence numbers must be 0..99 with no duplicates and no gaps",
    )

    const bundle = await buildStore(database).exportBundle(tenantId)
    const audit = auditEvidenceChain({ tenantId, records: bundle.records, checkpoints: [] })
    assert.deepEqual(audit.issues, [], "a concurrent chain must have no gaps and no forks")
  })
})

test("S13: two stores for one tenant interleave without forking", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const tenantId = freshTenant("interleave")
    const left = buildStore(database)
    const right = buildStore(database)

    await Promise.all(
      Array.from({ length: 20 }, (_, index) =>
        (index % 2 === 0 ? left : right).append({
          tenantId,
          evidenceType: "effect_permit",
          payload: { side: index % 2, index },
          occurredAt: AT,
        }),
      ),
    )

    const bundle = await left.exportBundle(tenantId)
    assert.equal(bundle.records.length, 20)

    const audit = auditEvidenceChain({ tenantId, records: bundle.records, checkpoints: [] })
    assert.deepEqual(audit.issues, [])
  })
})

test("S13: one tenant cannot see, extend, or shadow another tenant's chain", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const store = buildStore(database)
    const tenantA = freshTenant("iso_a")
    const tenantB = freshTenant("iso_b")

    await appendRecord(store, tenantB, { secret: "tenant b" })

    assert.deepEqual(await store.read(tenantA), [])
    assert.equal(await store.head(tenantA), null)
    assert.deepEqual(await store.readCheckpoints(tenantA), [])

    // Tenant A starts at seq 0 even though tenant B already has records, and its genesis link
    // is its own. That is what per-tenant primary keys buy.
    const started = await appendRecord(store, tenantA, { secret: "tenant a" })
    assert.equal(appended(started).seq, 0)
    // The record's own hash is not the genesis marker; the genesis marker is what it links back
    // to. Comparing `hash` against genesis here would pass or fail for the wrong reason.
    assert.notEqual(appended(started).hash, genesisHash(tenantA))

    const bundleA = await store.exportBundle(tenantA)
    assert.equal(bundleA.records.length, 1)
    assert.equal(bundleA.records[0]!.prev_hash, genesisHash(tenantA))
    assert.doesNotMatch(JSON.stringify(bundleA), /tenant b/u)
  })
})

test("S13: a record written outside the store is detected, not silently merged", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const tenantId = freshTenant("planted")
    const store = buildStore(database)

    await appendRecord(store, tenantId, { step: 1 })

    // A second writer that bypassed the store and wrote its own record at seq 1, using a hash
    // that does not match its own contents. This is the shape a fork takes in practice.
    await database.query(
      `INSERT INTO v2_evidence
         (tenant_id, seq, evidence_type, occurred_at, payload, prev_hash, hash, signature)
       VALUES ($1, 1, 'effect_permit', $2, $3::jsonb, $4, $5, $6::jsonb)`,
      [
        tenantId,
        AT.toISOString(),
        canonicalStringify(toJsonValue({ planted: true })),
        (await store.head(tenantId))!.hash,
        canonicalHash({ planted: true }),
        canonicalStringify(
          toJsonValue({ algorithm: "ed25519", issuer_id: ISSUER, value: "AA==" }),
        ),
      ],
    )

    // The honest store reads the real tail and appends after it, so the legitimate record is
    // not lost. Detection is the audit's job, and the audit does it.
    const outcome = await appendRecord(store, tenantId, { honest: true })
    assert.equal(appended(outcome).seq, 2)

    const bundle = await store.exportBundle(tenantId)
    const audit = auditEvidenceChain({ tenantId, records: bundle.records, checkpoints: [] })

    assert.equal(audit.intact, false, "a record written outside the chain must be detectable")
    const issue = audit.issues.find((entry) => entry.kind === "record_hash_mismatch")
    assert.ok(issue, "the planted record's hash does not cover its contents")
    assert.equal(issue.seq, 1)
  })
})

test("S13: evidence cannot be deleted or edited, even by the role that runs migrations", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const tenantId = freshTenant("appendonly")
    const store = buildStore(database)

    await appendRecord(store, tenantId, { permit_id: "p-1" })

    // This connection is the migration superuser. A privilege-based defence would not stop it;
    // the trigger is what stops it.
    await assert.rejects(
      () =>
        database.query(`UPDATE v2_evidence SET payload = '{}'::jsonb WHERE tenant_id = $1`, [tenantId]),
      /v2_evidence is append-only; UPDATE is not permitted/u,
    )

    await assert.rejects(
      () => database.query(`DELETE FROM v2_evidence WHERE tenant_id = $1`, [tenantId]),
      /v2_evidence is append-only; DELETE is not permitted/u,
    )

    const records = await store.read(tenantId)
    assert.equal(records.length, 1)
    assert.deepEqual(records[0]!.payload, { permit_id: "p-1" }, "the record must be untouched")
  })
})

test("S13: a checkpoint must name a record that exists and whose hash matches", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const tenantId = freshTenant("cp")
    const store = buildStore(database)
    await appendRecord(store, tenantId, { step: 1 })

    const head = (await store.head(tenantId))!

    await assert.rejects(
      () =>
        database.query(
          `INSERT INTO v2_evidence_checkpoint (tenant_id, seq, root_hash) VALUES ($1, 99, $2)`,
          [tenantId, "anything"],
        ),
      /no record at seq 99/u,
    )

    await assert.rejects(
      () =>
        database.query(
          `INSERT INTO v2_evidence_checkpoint (tenant_id, seq, root_hash) VALUES ($1, 0, $2)`,
          [tenantId, canonicalHash({ wrong: true })],
        ),
      /root_hash does not match the record at seq 0/u,
    )

    await database.query(
      `INSERT INTO v2_evidence_checkpoint (tenant_id, seq, root_hash) VALUES ($1, 0, $2)`,
      [tenantId, head.hash],
    )

    const checkpoint = await store.checkpoint(tenantId)
    assert.equal(checkpoint?.seq, 0)
    assert.equal(checkpoint?.rootHash, head.hash)
    assert.equal((await store.readCheckpoints(tenantId)).length, 1)

    // Checkpoints accumulate; the latest is the one an auditor compares against.
    await appendRecord(store, tenantId, { step: 2 })
    const newer = (await store.head(tenantId))!
    await database.query(
      `INSERT INTO v2_evidence_checkpoint (tenant_id, seq, root_hash) VALUES ($1, 1, $2)`,
      [tenantId, newer.hash],
    )
    assert.equal((await store.checkpoint(tenantId))?.seq, 1)
  })
})

test("S13: a checkpoint cannot be moved once written", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const tenantId = freshTenant("cp_frozen")
    const store = buildStore(database)
    await appendRecord(store, tenantId, { step: 1 })
    const head = (await store.head(tenantId))!

    await database.query(
      `INSERT INTO v2_evidence_checkpoint (tenant_id, seq, root_hash) VALUES ($1, 0, $2)`,
      [tenantId, head.hash],
    )

    await assert.rejects(
      () =>
        database.query(
          `UPDATE v2_evidence_checkpoint SET root_hash = $3 WHERE tenant_id = $1 AND seq = $2`,
          [tenantId, 0, canonicalHash({ rewritten: true })],
        ),
      /v2_evidence is append-only; UPDATE is not permitted/u,
    )

    await assert.rejects(
      () => database.query(`DELETE FROM v2_evidence_checkpoint WHERE tenant_id = $1`, [tenantId]),
      /v2_evidence is append-only; DELETE is not permitted/u,
    )

    assert.equal((await store.checkpoint(tenantId))?.rootHash, head.hash)
  })
})

test("S13: a stored chain audits as intact against the checkpoints taken during it", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const tenantId = freshTenant("cp_audit")
    const store = buildStore(database)

    for (let index = 0; index < 8; index += 1) {
      await appendRecord(store, tenantId, { step: index })
    }

    for (const seq of [2, 5, 7]) {
      const records = await store.read(tenantId)
      await database.query(
        `INSERT INTO v2_evidence_checkpoint (tenant_id, seq, root_hash) VALUES ($1, $2, $3)`,
        [tenantId, seq, records[seq]!.hash],
      )
    }

    const bundle = await store.exportBundle(tenantId)
    const audit = auditEvidenceChain({
      tenantId,
      records: bundle.records,
      checkpoints: await store.readCheckpoints(tenantId),
    })

    assert.deepEqual(audit.issues, [])
    assert.equal(audit.intact, true)
  })
})

test("S13: credentials are redacted before anything reaches the database", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const tenantId = freshTenant("redact")
    const store = buildStore(database)

    await store.append({
      tenantId,
      evidenceType: "data_access",
      payload: {
        tool: "aws.sts.assume-role",
        api_key: "AKIAIOSFODNN7EXAMPLE",
        authorization: "Bearer sk-live-do-not-store",
        nested: { secret: "hunter2", keep: "visible" },
      },
      occurredAt: AT,
    })

    const [record] = await store.read(tenantId)
    const payload = record!.payload as Record<string, unknown>

    assert.equal(payload["api_key"], "[redacted]")
    assert.equal(payload["authorization"], "[redacted]")
    assert.deepEqual(payload["nested"], { secret: "[redacted]", keep: "visible" })
    assert.equal(payload["tool"], "aws.sts.assume-role", "non-sensitive fields survive")

    // And nothing resembling a secret is anywhere in the stored row.
    const raw = await database.query(
      `SELECT payload::text AS text FROM v2_evidence WHERE tenant_id = $1`,
      [tenantId],
    )
    assert.doesNotMatch(String(raw[0]?.["text"]), /AKIAIOSFODNN7EXAMPLE|hunter2|sk-live/u)
  })
})

test("S13: row-level security hides one tenant's evidence from an ordinary role", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const store = buildStore(database)
    const tenantA = freshTenant("rls_a")
    const tenantB = freshTenant("rls_b")

    await appendRecord(store, tenantB, { permit_id: "b-secret" })

    await database.query(`
      DO $$
      BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${ISOLATION_ROLE}') THEN
          CREATE ROLE ${ISOLATION_ROLE} NOLOGIN;
        END IF;
      END
      $$;
    `)
    await database.query(`GRANT USAGE ON SCHEMA public TO ${ISOLATION_ROLE}`)
    await database.query(
      `GRANT SELECT, INSERT, UPDATE, DELETE ON v2_evidence, v2_evidence_checkpoint TO ${ISOLATION_ROLE}`,
    )

    const seen = await database.transaction(async (client) => {
      await client.query(`SET LOCAL ROLE ${ISOLATION_ROLE}`)
      await client.query(`SET LOCAL actantos.tenant_id = '${tenantA}'`)
      return client.query(`SELECT tenant_id, payload FROM v2_evidence`)
    })

    assert.deepEqual(seen, [], "an ordinary role must see no rows belonging to another tenant")

    const crossed = await database
      .transaction(async (client) => {
        await client.query(`SET LOCAL ROLE ${ISOLATION_ROLE}`)
        await client.query(`SET LOCAL actantos.tenant_id = '${tenantA}'`)
        await client.query(
          `INSERT INTO v2_evidence
             (tenant_id, seq, evidence_type, occurred_at, payload, prev_hash, hash, signature)
           VALUES ('${tenantB}', 0, 'effect_permit', $1, '{}'::jsonb, 'x', 'y', '{}'::jsonb)`,
          [AT.toISOString()],
        )
      })
      .then(() => "accepted", (error: Error) => error.message)

    assert.match(
      String(crossed),
      /row-level security policy/u,
      "writing into another tenant's evidence namespace must be refused",
    )
  })
})

test("S13: an effect performed through the gateway leaves its records in the database", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const tenantId = freshTenant("gateway")
    const store = buildStore(database)
    const principal = `spiffe://actantos.local/tenant/${tenantId}/agent/merge`
    const action = {
      tool: "github.pull-request.merge",
      resource: "org/repo#11",
      args: { number: 11, method: "squash" },
    }

    const gateway = new EffectGateway({
      tenantId,
      trustedIssuerKeys,
      evidenceStore: store,
      replayStore: new InMemoryReplayStore(),
      executors: {
        "github.pull-request.merge": async () => ({ ok: true as const, result: { merged: true } }),
      },
      now: () => AT,
    })

    const outcome = await gateway.perform({
      permit: issueEffectPermit({
        principalSpiffeId: principal,
        tenantId,
        executionId: "exec-durable",
        delegationDigest: "delegation-digest",
        action,
        policyBundleDigest: "policy-digest",
        dataLabels: ["CONFIDENTIAL"],
        issuedAt: AT,
        issuerId: ISSUER,
        keyPair,
      }),
      action,
      executionId: "exec-durable",
      principalSpiffeId: principal,
      sinkType: "file_store",
    })

    assert.equal(outcome.performed, true)

    const bundle = await store.exportBundle(tenantId)
    assert.deepEqual(
      bundle.records.map((record) => record.evidence_type),
      ["effect_permit", "effect_execution", "tool_result_commitment"],
    )

    const audit = auditEvidenceChain({ tenantId, records: bundle.records, checkpoints: [] })
    assert.deepEqual(audit.issues, [])
    assert.equal(
      verifyEvidenceBundle(JSON.parse(JSON.stringify(bundle)), trustedIssuerKeys).valid,
      true,
    )
  })
})

test("S13: a second effect through the same gateway continues the same durable chain", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const tenantId = freshTenant("gateway_twice")
    const store = buildStore(database)
    const principal = `spiffe://actantos.local/tenant/${tenantId}/agent/merge`

    const gateway = new EffectGateway({
      tenantId,
      trustedIssuerKeys,
      evidenceStore: store,
      replayStore: new InMemoryReplayStore(),
      executors: {
        "github.pull-request.merge": async () => ({ ok: true as const, result: { merged: true } }),
      },
      now: () => AT,
    })

    for (const number of [1, 2]) {
      const action = {
        tool: "github.pull-request.merge",
        resource: `org/repo#${number}`,
        args: { number },
      }

      const outcome = await gateway.perform({
        permit: issueEffectPermit({
          principalSpiffeId: principal,
          tenantId,
          executionId: `exec-${number}`,
          delegationDigest: "delegation-digest",
          action,
          policyBundleDigest: "policy-digest",
          dataLabels: ["CONFIDENTIAL"],
          issuedAt: AT,
          issuerId: ISSUER,
          keyPair,
        }),
        action,
        executionId: `exec-${number}`,
        principalSpiffeId: principal,
        sinkType: "file_store",
      })

      assert.equal(outcome.performed, true, `effect ${number} should have been performed`)
    }

    const bundle = await store.exportBundle(tenantId)
    assert.equal(bundle.records.length, 6, "two effects, three records each, in one chain")

    const audit = auditEvidenceChain({ tenantId, records: bundle.records, checkpoints: [] })
    assert.deepEqual(audit.issues, [])
  })
})
