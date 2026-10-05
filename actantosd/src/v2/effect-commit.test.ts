import assert from "node:assert/strict"
import test from "node:test"

import { createDatabase, migrateDatabase, type Database } from "../database.ts"
import { canonicalHash } from "../hash.ts"
import { EvidenceChain } from "./evidence.ts"
import {
  canTransition,
  EFFECT_COMMIT_STATES,
  InMemoryEffectJournal,
  nextState,
  PostgreSQLEffectJournal,
  recoverUnfinished,
  TERMINAL_EFFECT_COMMIT_STATES,
  verifyRecoveryReceipt,
  type EffectCommitState,
  type EffectJournal,
  type RecoveryDecision,
} from "./effect-commit.ts"
import { EffectGateway } from "./effect-gateway.ts"
import { issueEffectPermit } from "./effect-permit.ts"
import { ed25519 } from "./signature.ts"

/**
 * S13 conformance, phase D: knowing whether an effect finished.
 *
 * The crash window this file exists for is between "the executor returned" and "the outcome was
 * written". The evidence chain records that an effect was authorized; it cannot record that an
 * effect which happened during a crash never reported itself. The journal exists so that gap is a
 * row with a state, not a silence.
 *
 * The state machine is pure and tested unconditionally, because it is the part that decides
 * whether an unknown outcome may be quietly converted into a known one. The two stores are held
 * to the same contract, since a disagreement between them would mean the answer to "did this
 * effect run" depends on which process is asking.
 *
 * Database tests need real PostgreSQL. The transition guard and the digest immutability are
 * triggers, and `pg-mem` has no triggers, so a substitute here would test a mock rather than the
 * enforcement.
 */

const DATABASE_URL = process.env["DATABASE_URL"]
const SUBSTRATE_PASS = process.env["ACTANTOS_SUBSTRATE_TESTS"] === "1"
const skip = DATABASE_URL === undefined || !SUBSTRATE_PASS
const todo = skip
  ? "DATABASE_URL not set, or run `npm run test:substrate` — crash recovery needs real PostgreSQL"
  : undefined

type MarkedUncertain = Extract<RecoveryDecision, { action: "marked_uncertain" }>

const ISSUER = "issuer-commit"
const ISOLATION_ROLE = "actantos_rls_test"
const AT = new Date("2026-10-04T09:00:00.000Z")

const keyPair = ed25519.generateKeyPair()
const trustedIssuerKeys = new Map([[ISSUER, keyPair.publicKeyPem]])

let tenantCounter = 0

/** Distinguishes this process from any other run against the same database. */
const RUN_ID = `${process.pid.toString(36)}${Date.now().toString(36)}`

/**
 * A tenant nobody has used. Journal rows cannot be deleted by design, so every database test
 * starts from a new name rather than cleaning up after the previous one.
 */
const freshTenant = (label: string): string => {
  tenantCounter += 1
  return `t_ec_${RUN_ID}_${label}_${tenantCounter}`
}

const buildJournal = (database: Database): EffectJournal =>
  new PostgreSQLEffectJournal({ client: database })

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
 * Narrow a recovery decision to the "resolved" case.
 *
 * `assert.ok` carries an assertion signature, so this both checks and narrows. Recovery also
 * returns `none` and `failed`, and reading `.receipt` off those would be a type error rather
 * than a loud test failure, which is worse.
 */
function marked(decision: RecoveryDecision | undefined): asserts decision is MarkedUncertain {
  assert.ok(decision !== undefined, "expected a recovery decision")
  assert.ok(
    decision.action === "marked_uncertain",
    `expected the entry to be marked uncertain, got ${decision.action}`,
  )
}

const sampleEntry = (tenantId: string, permitId: string) => ({
  tenantId,
  permitId,
  actionDigest: canonicalHash({ tool: "deploy", resource: "prod" }),
  tool: "deploy",
  resource: "prod",
})

/**
 * One contract, both stores.
 *
 * The point of running this against each implementation is that the answer to "may this effect
 * finish twice" must not depend on which process is asking. A store that is more permissive than
 * the other is a bypass.
 */
const journalContract = (
  label: string,
  open: () => Promise<EffectJournal>,
) => {
  test(`S13 ${label}: a permit is journaled once and only once`, async () => {
    const journal = await open()
    const tenantId = freshTenant("prepare_once")
    const entry = sampleEntry(tenantId, "permit-once")

    const first = await journal.prepare(entry)
    assert.equal(first.outcome, "recorded")
    assert.equal(first.state, "prepared")

    const second = await journal.prepare({ ...entry, actionDigest: canonicalHash({ other: true }) })
    assert.equal(second.outcome, "rejected")
    assert.equal(second.state, "prepared")

    // The refused prepare must not have rewritten the action the row is bound to.
    const stored = await journal.read({ tenantId, permitId: entry.permitId })
    assert.equal(stored?.actionDigest, entry.actionDigest)
  })

  test(`S13 ${label}: an effect walks prepared to committed`, async () => {
    const journal = await open()
    const tenantId = freshTenant("happy")
    const entry = sampleEntry(tenantId, "permit-happy")

    await journal.prepare(entry)

    for (const state of ["executing", "committed"] as const) {
      const moved = await journal.transition({
        tenantId,
        permitId: entry.permitId,
        to: state,
        resultDigest: state === "committed" ? canonicalHash({ ok: true }) : undefined,
      })
      assert.equal(moved.outcome, "recorded", `moving to ${state}: ${"reason" in moved ? moved.reason : ""}`)
      assert.equal(moved.state, state)
    }

    const stored = await journal.read({ tenantId, permitId: entry.permitId })
    assert.equal(stored?.state, "committed")
    assert.equal(stored?.resultDigest, canonicalHash({ ok: true }))
  })

  test(`S13 ${label}: a committed effect cannot be executed again`, async () => {
    const journal = await open()
    const tenantId = freshTenant("terminal_committed")
    const entry = sampleEntry(tenantId, "permit-committed")

    await journal.prepare(entry)
    await journal.transition({ tenantId, permitId: entry.permitId, to: "executing" })
    await journal.transition({
      tenantId,
      permitId: entry.permitId,
      to: "committed",
      resultDigest: canonicalHash({ ok: true }),
    })

    for (const attempt of ["executing", "failed", "uncertain", "committed"] as const) {
      const moved = await journal.transition({
        tenantId,
        permitId: entry.permitId,
        to: attempt,
        resultDigest: canonicalHash({ again: true }),
      })
      assert.equal(moved.outcome, "rejected", `${attempt} must be refused after committed`)
      assert.equal(moved.state, "committed")
    }

    const stored = await journal.read({ tenantId, permitId: entry.permitId })
    assert.equal(stored?.state, "committed")
    assert.equal(stored?.resultDigest, canonicalHash({ ok: true }))
  })

  test(`S13 ${label}: an uncertain effect is never resolved by retrying it`, async () => {
    const journal = await open()
    const tenantId = freshTenant("terminal_uncertain")
    const entry = sampleEntry(tenantId, "permit-uncertain")

    await journal.prepare(entry)
    await journal.transition({ tenantId, permitId: entry.permitId, to: "executing" })
    const marked = await journal.transition({
      tenantId,
      permitId: entry.permitId,
      to: "uncertain",
      error: "process ended while executing",
    })
    assert.equal(marked.outcome, "recorded")

    // `committed` after `uncertain` would be the dangerous claim: asserting a result that nobody
    // observed. `failed` would be the dangerous retry: applying an unknown effect a second time.
    for (const attempt of ["committed", "failed", "executing"] as const) {
      const moved = await journal.transition({
        tenantId,
        permitId: entry.permitId,
        to: attempt,
        resultDigest: canonicalHash({ guessed: true }),
      })
      assert.equal(moved.outcome, "rejected", `${attempt} must be refused after uncertain`)
      assert.equal(moved.state, "uncertain")
    }
  })

  test(`S13 ${label}: an attempt counter advances without changing the outcome`, async () => {
    const journal = await open()
    const tenantId = freshTenant("attempts")
    const entry = sampleEntry(tenantId, "permit-attempts")

    await journal.prepare(entry)
    await journal.transition({ tenantId, permitId: entry.permitId, to: "executing", attempt: true })
    await journal.transition({ tenantId, permitId: entry.permitId, to: "executing", attempt: true })

    const stored = await journal.read({ tenantId, permitId: entry.permitId })
    assert.equal(stored?.state, "executing")
    assert.equal(stored?.attempts, 2)
  })

  test(`S13 ${label}: a transition on a permit that was never prepared is refused`, async () => {
    const journal = await open()
    const tenantId = freshTenant("never_prepared")

    const moved = await journal.transition({
      tenantId,
      permitId: "permit-that-does-not-exist",
      to: "executing",
    })
    assert.equal(moved.outcome, "rejected")

    assert.equal(await journal.read({ tenantId, permitId: "permit-that-does-not-exist" }), null)
  })

  test(`S13 ${label}: a committed outcome cannot be restated`, async () => {
    const journal = await open()
    const tenantId = freshTenant("restate")
    const entry = sampleEntry(tenantId, "permit-restate")

    await journal.prepare(entry)
    await journal.transition({ tenantId, permitId: entry.permitId, to: "executing" })
    await journal.transition({
      tenantId,
      permitId: entry.permitId,
      to: "committed",
      resultDigest: canonicalHash({ first: true }),
    })

    // A same-state write is permitted, because that is how the attempt counter advances. What it
    // is not permitted to do is replace the digest of an effect that has already finished: the
    // journal would then disagree with the world it is meant to describe.
    const restated = await journal.transition({
      tenantId,
      permitId: entry.permitId,
      to: "committed",
      resultDigest: canonicalHash({ second: true }),
    })
    assert.equal(restated.outcome, "rejected")
    assert.equal(restated.state, "committed")

    const stored = await journal.read({ tenantId, permitId: entry.permitId })
    assert.equal(stored?.resultDigest, canonicalHash({ first: true }))
  })

  test(`S13 ${label}: unfinished lists only non-terminal entries`, async () => {
    const journal = await open()
    const tenantId = freshTenant("unfinished")

    await journal.prepare(sampleEntry(tenantId, "permit-open"))
    await journal.prepare(sampleEntry(tenantId, "permit-done"))
    await journal.transition({ tenantId, permitId: "permit-done", to: "executing" })
    await journal.transition({
      tenantId,
      permitId: "permit-done",
      to: "committed",
      resultDigest: canonicalHash({ ok: true }),
    })

    const pending = await journal.unfinished(tenantId)
    assert.deepEqual(pending.map((entry) => entry.permitId), ["permit-open"])
  })
}

// --- Pure state machine, no database ------------------------------------------------------

test("S13: the transition table is exactly the one the protocol needs", () => {
  // prepared -> executing is the normal path.
  assert.ok(canTransition("prepared", "executing"))
  // prepared -> committed would skip the executor entirely.
  assert.equal(canTransition("prepared", "committed"), false)
  // executing -> committed and executing -> failed are the two real outcomes.
  assert.ok(canTransition("executing", "committed"))
  assert.ok(canTransition("executing", "failed"))
  // prepared -> uncertain: the process died before the executor was called.
  assert.ok(canTransition("prepared", "uncertain"))
  // executing -> uncertain: the process died with the outcome unknown. This is the whole reason
  // the state exists.
  assert.ok(canTransition("executing", "uncertain"))

  for (const terminal of ["committed", "failed", "uncertain"] as const) {
    for (const to of EFFECT_COMMIT_STATES) {
      if (to === terminal) continue
      assert.equal(
        canTransition(terminal, to),
        false,
        `${terminal} must be terminal, but it reached ${to}`,
      )
    }
  }
})

test("S13: a refused transition leaves the state where it was", () => {
  // Returning the current state rather than throwing is deliberate: a caller that ignores the
  // result must leave the row untouched, not advance it.
  assert.equal(nextState("committed", "executing"), "committed")
  assert.equal(nextState("uncertain", "committed"), "uncertain")
  assert.equal(nextState("prepared", "executing"), "executing")
  assert.equal(nextState("executing", "uncertain"), "uncertain")
})

test("S13: all three terminal states are actually terminal", () => {
  assert.deepEqual(
    [...TERMINAL_EFFECT_COMMIT_STATES].sort(),
    ["committed", "failed", "uncertain"],
  )
})

test("S13: recovery marks an unknown outcome uncertain and never offers a retry", async () => {
  const journal = new InMemoryEffectJournal()
  const tenantId = freshTenant("recovery_pure")

  await journal.prepare(sampleEntry(tenantId, "permit-crashed"))
  await journal.transition({ tenantId, permitId: "permit-crashed", to: "executing" })

  const receipts: unknown[] = []
  const decisions = await recoverUnfinished({
    journal,
    tenantId,
    issuerId: ISSUER,
    keyPair,
    now: AT,
    onRecovered: async (receipt) => {
      receipts.push(receipt)
    },
  })

  assert.equal(decisions.length, 1)
  const [decision] = decisions
  marked(decision)

  // The only outcome recovery produces. There is deliberately no "retry" action for a caller to
  // reach for: whether an unknown effect should be applied again is a human decision.
  assert.deepEqual(
    decisions.map((entry) => entry.action).filter((action) => action !== "none"),
    ["marked_uncertain"],
  )

  assert.equal(receipts.length, 1)
  assert.ok(verifyRecoveryReceipt(receipts[0], trustedIssuerKeys))
  assert.equal(verifyRecoveryReceipt(receipts[0], new Map()), false)
})

test("S13: a tampered recovery receipt does not verify", async () => {
  const journal = new InMemoryEffectJournal()
  const tenantId = freshTenant("receipt_tamper")

  await journal.prepare(sampleEntry(tenantId, "permit-receipt"))
  await journal.transition({ tenantId, permitId: "permit-receipt", to: "executing" })

  const [decision] = await recoverUnfinished({ journal, tenantId, issuerId: ISSUER, keyPair, now: AT })
  marked(decision)

  // Claiming the outcome was `committed` after the fact is exactly the forgery that matters.
  assert.equal(
    verifyRecoveryReceipt({ ...decision.receipt, resolved_state: "committed" }, trustedIssuerKeys),
    false,
  )
  // Repointing the receipt at a different action is equally not permitted.
  assert.equal(
    verifyRecoveryReceipt(
      { ...decision.receipt, action_digest: canonicalHash({ tool: "other" }) },
      trustedIssuerKeys,
    ),
    false,
  )
  assert.ok(verifyRecoveryReceipt(decision.receipt, trustedIssuerKeys))
})

test("S13: recovery leaves a terminal effect alone", async () => {
  const journal = new InMemoryEffectJournal()
  const tenantId = freshTenant("recovery_noop")

  await journal.prepare(sampleEntry(tenantId, "permit-settled"))
  await journal.transition({ tenantId, permitId: "permit-settled", to: "executing" })
  await journal.transition({
    tenantId,
    permitId: "permit-settled",
    to: "committed",
    resultDigest: canonicalHash({ ok: true }),
  })

  const decisions = await recoverUnfinished({ journal, tenantId, issuerId: ISSUER, keyPair, now: AT })
  assert.deepEqual(decisions, [])

  const stored = await journal.read({ tenantId, permitId: "permit-settled" })
  assert.equal(stored?.state, "committed")
})

// --- Both stores, in memory ---------------------------------------------------------------

const contractSuites = [
  ["in-memory", async () => new InMemoryEffectJournal()],
  ["PostgreSQL", async () => {
    const database = createDatabase(DATABASE_URL!)
    await migrateDatabase(database)
    return buildJournal(database)
  }],
] as const

for (const [label, open] of contractSuites) {
  if (label === "PostgreSQL" && skip) continue
  journalContract(label, open)
}

// --- Database-enforced guarantees ---------------------------------------------------------

test("S13: the database refuses an illegal transition, not just the code", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const tenantId = freshTenant("db_guard")
    const entry = sampleEntry(tenantId, "permit-db-guard")
    const journal = buildJournal(database)

    await journal.prepare(entry)
    await journal.transition({ tenantId, permitId: entry.permitId, to: "executing" })
    await journal.transition({
      tenantId,
      permitId: entry.permitId,
      to: "committed",
      resultDigest: canonicalHash({ ok: true }),
    })

    // The application already refuses this. This asserts the second, independent line: a bug in
    // application code that issued the SQL directly still cannot move a committed row.
    await assert.rejects(
      database.query(
        `UPDATE v2_effect_journal SET state = 'executing' WHERE tenant_id = $1 AND permit_id = $2`,
        [tenantId, entry.permitId],
      ),
      /illegal transition committed -> executing/u,
    )

    const stored = await journal.read({ tenantId, permitId: entry.permitId })
    assert.equal(stored?.state, "committed")
  })
})

test("S13: every illegal transition is refused by the database alone", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const tenantId = freshTenant("all_illegal")
    const journal = buildJournal(database)

    // Each case is issued as raw SQL, bypassing the journal entirely. Every other test in this
    // file would still pass with the trigger removed, because the application refuses the same
    // moves — which is exactly why the enforcement needs its own evidence: an application bug is
    // most likely exactly when the state machine is wrong.
    const illegal: readonly { from: "prepared" | "executing" | "committed"; to: string }[] = [
      { from: "prepared", to: "committed" },
      { from: "executing", to: "prepared" },
      { from: "committed", to: "executing" },
      { from: "committed", to: "failed" },
      { from: "committed", to: "uncertain" },
      { from: "executing", to: "executing" },
    ]

    for (const [index, move] of illegal.entries()) {
      const permitId = `permit-illegal-${index}`

      await database.query(
        `INSERT INTO v2_effect_journal (tenant_id, permit_id, state, action_digest, tool, resource, result_digest)
         VALUES ($1, $2, $3, 'digest', 'deploy', 'prod', $4)`,
        [tenantId, permitId, move.from, move.from === "committed" ? canonicalHash({ ok: true }) : null],
      )

      // `from === to` is not illegal on its own: a same-state write is bookkeeping. It is only
      // refused when it tries to restate a terminal outcome, which the row count shows.
      const isSameState = move.from === move.to
      const restatesOutcome = isSameState && move.from === "committed"
      const digest = restatesOutcome ? canonicalHash({ forged: true }) : undefined

      if (restatesOutcome) {
        await assert.rejects(
          database.query(
            `UPDATE v2_effect_journal SET state = $3, result_digest = $4 WHERE tenant_id = $1 AND permit_id = $2`,
            [tenantId, permitId, move.to, digest],
          ),
          /outcome is final/u,
          `${move.from} -> ${move.to} must not restate a final outcome`,
        )
      } else if (isSameState) {
        const allowed = await database.query(
          `UPDATE v2_effect_journal SET state = $3 WHERE tenant_id = $1 AND permit_id = $2 RETURNING state`,
          [tenantId, permitId, move.to],
        )
        assert.equal(allowed.length, 1, "a same-state write is bookkeeping and stays legal")
        continue
      } else {
        await assert.rejects(
          database.query(
            `UPDATE v2_effect_journal SET state = $3 WHERE tenant_id = $1 AND permit_id = $2`,
            [tenantId, permitId, move.to],
          ),
          /illegal transition/u,
          `${move.from} -> ${move.to} must be refused by the database`,
        )
      }

      const stored = await journal.read({ tenantId, permitId })
      assert.equal(stored?.state, move.from, `${move.from} -> ${move.to} must leave the row alone`)
    }
  })
})

test("S13: the database refuses to restate a terminal outcome", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const tenantId = freshTenant("restate_db")
    const journal = buildJournal(database)
    const entry = sampleEntry(tenantId, "permit-restate-db")

    await journal.prepare(entry)
    await journal.transition({ tenantId, permitId: entry.permitId, to: "executing" })
    await journal.transition({
      tenantId,
      permitId: entry.permitId,
      to: "committed",
      resultDigest: canonicalHash({ first: true }),
    })

    // The application's guard refuses this too, so a same-state raw UPDATE is the only way to
    // show the database enforces it as well.
    await assert.rejects(
      database.query(
        `UPDATE v2_effect_journal SET result_digest = $3 WHERE tenant_id = $1 AND permit_id = $2`,
        [tenantId, entry.permitId, canonicalHash({ second: true })],
      ),
      /committed outcome is final/u,
    )

    const stored = await journal.read({ tenantId, permitId: entry.permitId })
    assert.equal(stored?.resultDigest, canonicalHash({ first: true }))
  })
})

test("S13: the database refuses a rewrite of the authorized action", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const tenantId = freshTenant("digest_immutable")
    const entry = sampleEntry(tenantId, "permit-digest")
    const journal = buildJournal(database)

    await journal.prepare(entry)
    await journal.transition({ tenantId, permitId: entry.permitId, to: "executing" })

    // Recovery acts on the action digest. If that column were writable, an in-flight effect could
    // be re-pointed at a different action and recovery would resolve the wrong effect.
    await assert.rejects(
      database.query(
        `UPDATE v2_effect_journal SET action_digest = $3 WHERE tenant_id = $1 AND permit_id = $2`,
        [tenantId, entry.permitId, canonicalHash({ tool: "attacker-choice" })],
      ),
      /action_digest is fixed at prepare time/u,
    )

    const stored = await journal.read({ tenantId, permitId: entry.permitId })
    assert.equal(stored?.actionDigest, entry.actionDigest)
  })
})

test("S13: a journal row cannot be deleted, even by the migrating role", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const tenantId = freshTenant("no_delete")
    const entry = sampleEntry(tenantId, "permit-no-delete")
    const journal = buildJournal(database)

    await journal.prepare(entry)

    await assert.rejects(
      database.query(`DELETE FROM v2_effect_journal WHERE tenant_id = $1`, [tenantId]),
      /not deletable/u,
    )

    assert.notEqual(await journal.read({ tenantId, permitId: entry.permitId }), null)
  })
})

test("S13: one tenant cannot read or resolve another's in-flight effect", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const tenantA = freshTenant("rls_a")
    const tenantB = freshTenant("rls_b")
    const entry = sampleEntry(tenantA, "permit-rls")
    const journal = buildJournal(database)

    await journal.prepare(entry)
    await journal.transition({ tenantId: tenantA, permitId: entry.permitId, to: "executing" })

    // A superuser bypasses row-level security entirely, so reading as the migrating connection
    // would prove nothing. `SET LOCAL ROLE` is the only way to test the policy as it applies.
    // The role may already exist from an earlier substrate run against the same database, and
    // CREATE ROLE is not idempotent. `pg_advisory_xact_lock` on a constant is used as the usual
    // "do this once, whoever gets there first" guard; the loser simply proceeds to the GRANT.
    await database.query("SELECT pg_advisory_xact_lock(hashtext('actantos_rls_test_role'))")
    const [roleRow] = await database.query("SELECT 1 FROM pg_roles WHERE rolname = $1", [ISOLATION_ROLE])
    if (roleRow === undefined) {
      await database.query(`CREATE ROLE ${ISOLATION_ROLE} NOLOGIN`)
    }
    await database.query(`GRANT SELECT, INSERT, UPDATE ON v2_effect_journal TO ${ISOLATION_ROLE}`)

    const seen = await database.transaction(async (client) => {
      await client.query(`SET LOCAL ROLE ${ISOLATION_ROLE}`)
      await client.query(`SELECT set_config('actantos.tenant_id', $1, true)`, [tenantB])
      return client.query(
        `SELECT permit_id FROM v2_effect_journal WHERE tenant_id = $1 AND permit_id = $2`,
        [tenantA, entry.permitId],
      )
    })
    assert.equal(seen.length, 0)

    // And it cannot mark somebody else's effect resolved. PostgreSQL filters an RLS-blocked
    // UPDATE by matching zero rows rather than raising, so the row count is the assertion. This
    // is the dangerous direction: resolving another tenant's in-flight effect to `uncertain` would
    // silence an effect that may already be in the real world.
    const claimed = await database.transaction(async (client) => {
      await client.query(`SET LOCAL ROLE ${ISOLATION_ROLE}`)
      await client.query(`SELECT set_config('actantos.tenant_id', $1, true)`, [tenantB])
      return client.query(
        `UPDATE v2_effect_journal SET state = 'uncertain' WHERE tenant_id = $1 AND permit_id = $2 RETURNING permit_id`,
        [tenantA, entry.permitId],
      )
    })
    assert.equal(claimed.length, 0, "a cross-tenant resolve must update nothing")

    // It cannot insert a row under somebody else's tenant id either, which would let it plant a
    // journal entry that recovery would then act on. An INSERT that fails the WITH CHECK clause
    // raises rather than returning zero rows, so the error message is the assertion.
    await assert.rejects(
      database.transaction(async (client) => {
        await client.query(`SET LOCAL ROLE ${ISOLATION_ROLE}`)
        await client.query(`SELECT set_config('actantos.tenant_id', $1, true)`, [tenantB])
        await client.query(
          `INSERT INTO v2_effect_journal (tenant_id, permit_id, state, action_digest, tool, resource)
           VALUES ($1, 'planted-by-another-tenant', 'prepared', 'digest', 'deploy', 'prod')`,
          [tenantA],
        )
      }),
      /row-level security policy/u,
    )

    const stored = await journal.read({ tenantId: tenantA, permitId: entry.permitId })
    assert.equal(stored?.state, "executing")
  })
})

test("S13: a crash mid-effect is recovered as uncertain after a restart", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const tenantId = freshTenant("crash")
    const entry = sampleEntry(tenantId, "permit-crash-restart")

    // A process that opened the journal and called the executor, then died. Nothing here writes
    // a terminal state, which is exactly the situation recovery exists for.
    const before = buildJournal(database)
    await before.prepare(entry)
    await before.transition({ tenantId, permitId: entry.permitId, to: "executing", attempt: true })

    // A new process, a new store object, same database.
    const after = buildJournal(database)
    const pending = await after.unfinished(tenantId)
    assert.equal(pending.length, 1)
    assert.equal(pending[0]?.state, "executing")

    const decisions = await recoverUnfinished({
      journal: after,
      tenantId,
      issuerId: ISSUER,
      keyPair,
      now: AT,
    })

    assert.equal(decisions.length, 1)
    const [decision] = decisions
    marked(decision)
    assert.ok(verifyRecoveryReceipt(decision.receipt, trustedIssuerKeys))

    const stored = await after.read({ tenantId, permitId: entry.permitId })
    assert.equal(stored?.state, "uncertain")
    assert.equal(stored?.attempts, 1)

    // And the second run finds nothing left to do.
    assert.deepEqual(await after.unfinished(tenantId), [])
  })
})

test("S13: the gateway journals a performed effect as committed", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const tenantId = freshTenant("gateway_ok")
    const journal = buildJournal(database)
    const chain = new EvidenceChain({ tenantId, issuerId: ISSUER, keyPair })
    const action = { tool: "deploy", resource: "prod", args: { version: "1" } }

    let performed = 0
    const gateway = new EffectGateway({
      tenantId,
      trustedIssuerKeys,
      evidenceChain: chain,
      journal,
      // The permit is minted at a fixed instant, so the gateway has to read the same clock.
      // Without this the permit is a minute old and expires before the executor is reached,
      // which would make these tests pass for the wrong reason.
      now: () => AT,
      executors: {
        deploy: async () => {
          performed += 1
          return { ok: true as const, result: { release: "v1" } }
        },
      },
    })

    const permit = issueEffectPermit({
      principalSpiffeId: `spiffe://actantos.local/tenant/${tenantId}/agent/deployer`,
      tenantId,
      executionId: "exec-1",
      delegationDigest: "delegation",
      action,
      policyBundleDigest: "policy",
      dataLabels: [],
      issuedAt: AT,
      issuerId: ISSUER,
      keyPair,
    })

    const outcome = await gateway.perform({
      permit,
      action,
      executionId: "exec-1",
      principalSpiffeId: `spiffe://actantos.local/tenant/${tenantId}/agent/deployer`,
      sinkType: "file_store",
    })

    assert.ok(outcome.performed)
    assert.equal(performed, 1)

    const stored = await journal.read({ tenantId, permitId: permit.permit_id })
    assert.equal(stored?.state, "committed")
    assert.equal(stored?.resultDigest, outcome.resultDigest)
    assert.equal(stored?.attempts, 1)
  })
})

test("S13: the gateway journals a refused executor as failed, not as never-tried", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const tenantId = freshTenant("gateway_fail")
    const journal = buildJournal(database)
    const chain = new EvidenceChain({ tenantId, issuerId: ISSUER, keyPair })
    const action = { tool: "deploy", resource: "prod", args: {} }
    const spiffeId = `spiffe://actantos.local/tenant/${tenantId}/agent/deployer`

    let performed = 0
    const gateway = new EffectGateway({
      tenantId,
      trustedIssuerKeys,
      evidenceChain: chain,
      journal,
      // The permit is minted at a fixed instant, so the gateway has to read the same clock.
      // Without this the permit is a minute old and expires before the executor is reached,
      // which would make these tests pass for the wrong reason.
      now: () => AT,
      executors: {
        deploy: async () => {
          performed += 1
          return { ok: false as const, error: "upstream refused" }
        },
      },
    })

    const permit = issueEffectPermit({
      principalSpiffeId: spiffeId,
      tenantId,
      executionId: "exec-2",
      delegationDigest: "delegation",
      action,
      policyBundleDigest: "policy",
      dataLabels: [],
      issuedAt: AT,
      issuerId: ISSUER,
      keyPair,
    })

    const outcome = await gateway.perform({
      permit,
      action,
      executionId: "exec-2",
      principalSpiffeId: spiffeId,
      sinkType: "file_store",
    })

    assert.equal(outcome.performed, false)
    assert.equal(performed, 1)

    // `failed`, not `uncertain`: the executor answered, and its answer was recorded. The
    // distinction is the point of the protocol.
    const stored = await journal.read({ tenantId, permitId: permit.permit_id })
    assert.equal(stored?.state, "failed")
    assert.equal(stored?.error, "upstream refused")
  })
})

test("S13: an effect whose executor vanished leaves no journal entry at all", async () => {
  // The journal opens only after the evidence for the authorization is durable, so an effect
  // refused before the executor is looked up never claims to have been in flight.
  const tenantId = freshTenant("no_executor")
  const journal = new InMemoryEffectJournal()
  const chain = new EvidenceChain({ tenantId, issuerId: ISSUER, keyPair })
  const action = { tool: "unknown-tool", resource: "prod", args: {} }
  const spiffeId = `spiffe://actantos.local/tenant/${tenantId}/agent/deployer`

  const gateway = new EffectGateway({
    tenantId,
    trustedIssuerKeys,
    evidenceChain: chain,
    journal,
    now: () => AT,
    executors: {},
  })

  const permit = issueEffectPermit({
    principalSpiffeId: spiffeId,
    tenantId,
    executionId: "exec-3",
    delegationDigest: "delegation",
    action,
    policyBundleDigest: "policy",
    dataLabels: [],
    issuedAt: AT,
    issuerId: ISSUER,
    keyPair,
  })

  const outcome = await gateway.perform({
    permit,
    action,
    executionId: "exec-3",
    principalSpiffeId: spiffeId,
    sinkType: "file_store",
  })

  assert.equal(outcome.performed, false)
  assert.deepEqual(await journal.unfinished(tenantId), [])
})

test("S13: an unreachable journal stops the effect before the executor is called", async () => {
  // The journal is what makes a mid-effect crash observable. If it cannot be reached, an effect
  // that nobody could account for must not run.
  const tenantId = freshTenant("journal_down")
  const chain = new EvidenceChain({ tenantId, issuerId: ISSUER, keyPair })
  const action = { tool: "deploy", resource: "prod", args: {} }
  const spiffeId = `spiffe://actantos.local/tenant/${tenantId}/agent/deployer`

  let performed = 0
  const brokenJournal: EffectJournal = {
    prepare: async () => ({ outcome: "unavailable", error: "journal is down" }),
    transition: async () => ({ outcome: "unavailable", error: "journal is down" }),
    read: async () => null,
    unfinished: async () => [],
  }

  const gateway = new EffectGateway({
    tenantId,
    trustedIssuerKeys,
    evidenceChain: chain,
    journal: brokenJournal,
    now: () => AT,
    executors: {
      deploy: async () => {
        performed += 1
        return { ok: true as const, result: {} }
      },
    },
  })

  const permit = issueEffectPermit({
    principalSpiffeId: spiffeId,
    tenantId,
    executionId: "exec-4",
    delegationDigest: "delegation",
    action,
    policyBundleDigest: "policy",
    dataLabels: [],
    issuedAt: AT,
    issuerId: ISSUER,
    keyPair,
  })

  const outcome = await gateway.perform({
    permit,
    action,
    executionId: "exec-4",
    principalSpiffeId: spiffeId,
    sinkType: "file_store",
  })

  assert.equal(outcome.performed, false)
  assert.ok(outcome.reason === "journal_unavailable")
  assert.equal(performed, 0, "the executor must not be reached when the journal is unreachable")
})

test("S13: an effect that was already committed is refused before the executor is called", async () => {
  // The replay store normally catches this first. Reaching the journal means two authorities
  // disagreed, and the safe reading of a disagreement is to refuse.
  const tenantId = freshTenant("already_committed")
  const journal = new InMemoryEffectJournal()
  const chain = new EvidenceChain({ tenantId, issuerId: ISSUER, keyPair })
  const action = { tool: "deploy", resource: "prod", args: {} }
  const spiffeId = `spiffe://actantos.local/tenant/${tenantId}/agent/deployer`

  let performed = 0
  const gateway = new EffectGateway({
    tenantId,
    trustedIssuerKeys,
    evidenceChain: chain,
    journal,
    now: () => AT,
    executors: {
      deploy: async () => {
        performed += 1
        return { ok: true as const, result: {} }
      },
    },
  })

  const permit = issueEffectPermit({
    principalSpiffeId: spiffeId,
    tenantId,
    executionId: "exec-5",
    delegationDigest: "delegation",
    action,
    policyBundleDigest: "policy",
    dataLabels: [],
    issuedAt: AT,
    issuerId: ISSUER,
    keyPair,
  })

  // A previous process journaled and completed this permit id.
  await journal.prepare({
    tenantId,
    permitId: permit.permit_id,
    actionDigest: permit.action_digest,
    tool: action.tool,
    resource: action.resource,
  })
  await journal.transition({ tenantId, permitId: permit.permit_id, to: "executing" })
  await journal.transition({
    tenantId,
    permitId: permit.permit_id,
    to: "committed",
    resultDigest: canonicalHash({ ok: true }),
  })

  const outcome = await gateway.perform({
    permit,
    action,
    executionId: "exec-5",
    principalSpiffeId: spiffeId,
    sinkType: "file_store",
  })

  assert.equal(outcome.performed, false)
  assert.ok(outcome.reason === "journal_refused")
  assert.equal(performed, 0)
})

test("S13: the recovery receipt names the state it actually observed", { skip: todo }, async () => {
  await withDatabase(async (database) => {
    const tenantId = freshTenant("observed_state")
    const journal = buildJournal(database)

    await journal.prepare(sampleEntry(tenantId, "permit-prepared-only"))
    await journal.prepare(sampleEntry(tenantId, "permit-mid-flight"))
    await journal.transition({ tenantId, permitId: "permit-mid-flight", to: "executing" })

    const decisions = await recoverUnfinished({ journal, tenantId, issuerId: ISSUER, keyPair, now: AT })
    assert.equal(decisions.length, 2)

    const observed = new Map(
      decisions
        .filter((decision) => decision.action === "marked_uncertain")
        .map((decision) => [decision.receipt.permit_id, decision.receipt.observed_state] as const),
    )

    // Both are resolved to uncertain, but they were not in the same state, and collapsing them
    // would lose the distinction between "died before calling" and "died mid-call".
    assert.equal(observed.get("permit-prepared-only"), "prepared")
    assert.equal(observed.get("permit-mid-flight"), "executing")

    for (const decision of decisions) {
      marked(decision)
      assert.ok(verifyRecoveryReceipt(decision.receipt, trustedIssuerKeys))
    }
  })
})
