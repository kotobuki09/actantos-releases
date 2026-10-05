import type { DatabaseClient } from "../database.ts"
import { getSignatureAlgorithm } from "./signature.ts"

/**
 * Effect commit protocol (invariant S13, phase D).
 *
 * The gateway consumes a permit, records the authorization, calls the executor, then records the
 * outcome. A process that dies between the executor returning and the outcome being written leaves
 * nothing behind that says whether the external effect happened. The permit is spent either way,
 * so a retry is not automatic, but an operator looking at the evidence chain sees an authorization
 * with no execution and cannot tell a crash from a refusal.
 *
 * This journal closes that window by making the in-between states explicit and durable:
 *
 *   prepared    The permit was consumed and the intent is durable. The executor has not been called.
 *   executing   The executor has been called. Its outcome is not yet known.
 *   committed   The executor returned and the result is recorded.
 *   failed      The executor refused or threw, and the reason is recorded.
 *   uncertain   The process ended between executing and a terminal state. Nobody knows the outcome.
 *
 * `uncertain` is the reason this module exists. Collapsing it into `failed` invites a retry, and
 * retrying an effect that actually succeeded applies it twice. Collapsing it into `committed`
 * asserts a result nobody observed. Both errors are worse than recorded ignorance, so the state
 * exists, and the rule attached to it is: an uncertain effect is never retried automatically.
 *
 * The state machine itself is pure and lives in `nextState`. The database enforces the same
 * transitions with a trigger, because application code is the thing that crashed. The pure function
 * exists so the in-memory journal and the PostgreSQL journal cannot disagree about what is legal.
 */

export const EFFECT_COMMIT_STATES = [
  "prepared",
  "executing",
  "committed",
  "failed",
  "uncertain",
] as const

export type EffectCommitState = (typeof EFFECT_COMMIT_STATES)[number]

/** States from which no further transition is legal. */
export const TERMINAL_EFFECT_COMMIT_STATES: ReadonlySet<EffectCommitState> = new Set([
  "committed",
  "failed",
  "uncertain",
])

const LEGAL_TRANSITIONS: Readonly<Record<EffectCommitState, readonly EffectCommitState[]>> = {
  prepared: ["executing", "failed", "uncertain"],
  executing: ["committed", "failed", "uncertain"],
  // Terminal. An effect that already finished does not get to finish again, and an effect whose
  // outcome is unknown does not get to be resolved by a second attempt.
  committed: [],
  failed: [],
  uncertain: [],
}

/**
 * Whether `to` may follow `from`. Same state is always permitted: it carries updated detail such
 * as an attempt counter, not a new claim about the outcome.
 */
export const canTransition = (from: EffectCommitState, to: EffectCommitState): boolean =>
  from === to || LEGAL_TRANSITIONS[from].includes(to)

/**
 * Whether a write at the same state may carry these details.
 *
 * A same-state write is bookkeeping: it advances `attempts` and `updated_at`. It is not a licence
 * to restate the outcome. Once a row is `committed`, its result digest is a fact about the real
 * world; rewriting it would let a bug or an operator with write access make the evidence chain
 * disagree with what happened, which is the one thing the chain exists to prevent.
 *
 * Re-sending the identical digest is allowed, because that is a retry of the same claim and
 * changes nothing.
 */
export const canRestateOutcome = (
  state: EffectCommitState,
  current: { readonly resultDigest: string | null; readonly error: string | null },
  next: { readonly resultDigest?: string | undefined; readonly error?: string | undefined },
): boolean => {
  if (!TERMINAL_EFFECT_COMMIT_STATES.has(state)) return true

  if (next.resultDigest !== undefined && next.resultDigest !== current.resultDigest) return false
  if (next.error !== undefined && next.error !== current.error) return false

  return true
}

/**
 * The reason a write is refused, or null when it is allowed.
 *
 * Both stores call this so the in-memory journal and the PostgreSQL journal cannot disagree
 * about what is legal. The answer to "may this effect restate its outcome" must not depend on
 * which process is asking.
 */
export const describeRefusal = (
  current: EffectJournalEntry | null,
  request: { readonly to: EffectCommitState; readonly resultDigest?: string | undefined; readonly error?: string | undefined },
): string | null => {
  if (current === null) return "no journal entry for this permit"

  const resolved = nextState(current.state, request.to)

  if (resolved !== request.to) {
    return `illegal transition ${current.state} -> ${request.to}`
  }

  if (!canRestateOutcome(current.state, current, request)) {
    return `${current.state} outcome is final and may not be restated`
  }

  return null
}

/**
 * The next state, or the current one when the transition is illegal.
 *
 * Returns the *current* state rather than throwing, so a caller that ignores the result leaves the
 * journal where it was. A transition that is refused must not advance the row.
 */
export const nextState = (from: EffectCommitState, to: EffectCommitState): EffectCommitState =>
  canTransition(from, to) ? to : from

export type EffectJournalEntry = {
  readonly tenantId: string
  readonly permitId: string
  readonly state: EffectCommitState
  /** Digest of the authorized action. Fixed at prepare time; never changeable. */
  readonly actionDigest: string
  readonly tool: string
  readonly resource: string
  readonly startedAt: string
  readonly updatedAt: string
  readonly resultDigest: string | null
  readonly error: string | null
  readonly attempts: number
}

export type EffectJournalOutcome =
  /** The row now holds the requested state. */
  | { readonly outcome: "recorded"; readonly state: EffectCommitState }
  /**
   * The row is already in a state that does not permit this transition. `state` is what it
   * actually holds, so the caller can refuse without guessing.
   */
  | { readonly outcome: "rejected"; readonly state: EffectCommitState; readonly reason: string }
  /** The journal could not be reached. Callers must fail closed. */
  | { readonly outcome: "unavailable"; readonly error: string }

export interface EffectJournal {
  /**
   * Open a journal entry. A permit id may only be prepared once; a second prepare is a replay of
   * a decision, not a new one.
   */
  prepare(entry: {
    readonly tenantId: string
    readonly permitId: string
    readonly actionDigest: string
    readonly tool: string
    readonly resource: string
  }): Promise<EffectJournalOutcome>
  /** Move to a new state. Terminal states are refused rather than overwritten. */
  transition(entry: {
    readonly tenantId: string
    readonly permitId: string
    readonly to: EffectCommitState
    readonly resultDigest?: string | undefined
    readonly error?: string | undefined
    /** Counts an executor call attempt. */
    readonly attempt?: boolean | undefined
  }): Promise<EffectJournalOutcome>
  read(query: {
    readonly tenantId: string
    readonly permitId: string
  }): Promise<EffectJournalEntry | null>
  /**
   * Everything still in a non-terminal state for a tenant.
   *
   * This is the crash-recovery list. An entry in it means the process ended mid-effect and the
   * outcome is genuinely unknown.
   */
  unfinished(tenantId: string): Promise<readonly EffectJournalEntry[]>
}

/**
 * Process-memory journal. Tests and single-process development only.
 *
 * It cannot survive a restart, which is exactly the event it exists to describe, so it is not a
 * production control. `EffectGateway` accepts it so the in-process suites exercise the same state
 * machine; the PostgreSQL implementation is the one that belongs in a deployment.
 */
export class InMemoryEffectJournal implements EffectJournal {
  readonly #rows = new Map<string, Map<string, EffectJournalEntry>>()

  #tenant(tenantId: string): Map<string, EffectJournalEntry> {
    let entries = this.#rows.get(tenantId)

    if (entries === undefined) {
      entries = new Map()
      this.#rows.set(tenantId, entries)
    }

    return entries
  }

  async prepare(entry: {
    readonly tenantId: string
    readonly permitId: string
    readonly actionDigest: string
    readonly tool: string
    readonly resource: string
  }): Promise<EffectJournalOutcome> {
    const entries = this.#tenant(entry.tenantId)
    const existing = entries.get(entry.permitId)

    if (existing !== undefined) {
      return {
        outcome: "rejected",
        state: existing.state,
        reason: `permit already journaled as ${existing.state}`,
      }
    }

    const at = new Date().toISOString()
    entries.set(entry.permitId, {
      tenantId: entry.tenantId,
      permitId: entry.permitId,
      state: "prepared",
      actionDigest: entry.actionDigest,
      tool: entry.tool,
      resource: entry.resource,
      startedAt: at,
      updatedAt: at,
      resultDigest: null,
      error: null,
      attempts: 0,
    })

    return { outcome: "recorded", state: "prepared" }
  }

  async transition(entry: {
    readonly tenantId: string
    readonly permitId: string
    readonly to: EffectCommitState
    readonly resultDigest?: string | undefined
    readonly error?: string | undefined
    readonly attempt?: boolean | undefined
  }): Promise<EffectJournalOutcome> {
    const existing = this.#tenant(entry.tenantId).get(entry.permitId)

    // Checked before the refusal helper so the narrowing below is a real one rather than a cast.
    if (existing === undefined) {
      return {
        outcome: "rejected",
        state: "prepared",
        reason: "no journal entry for this permit",
      }
    }

    const refusal = describeRefusal(existing, entry)

    if (refusal !== null) {
      return { outcome: "rejected", state: existing.state, reason: refusal }
    }

    // A same-state write is how the attempt counter advances. It does not change the outcome.
    const attempts = existing.attempts + (entry.attempt === true ? 1 : 0)

    this.#tenant(entry.tenantId).set(entry.permitId, {
      ...existing,
      state: entry.to,
      attempts,
      resultDigest: entry.resultDigest ?? existing.resultDigest,
      error: entry.error ?? existing.error,
      updatedAt: new Date().toISOString(),
    })

    return { outcome: "recorded", state: entry.to }
  }

  async read(query: {
    readonly tenantId: string
    readonly permitId: string
  }): Promise<EffectJournalEntry | null> {
    return this.#tenant(query.tenantId).get(query.permitId) ?? null
  }

  async unfinished(tenantId: string): Promise<readonly EffectJournalEntry[]> {
    return [...this.#tenant(tenantId).values()].filter(
      (entry) => !TERMINAL_EFFECT_COMMIT_STATES.has(entry.state),
    )
  }
}

/**
 * Sign a recovery receipt.
 *
 * Recovery makes a decision about an effect that is already in the real world, and that decision
 * needs to be attributable afterwards. A journal row can be rewritten by anyone with write access
 * to the table; a receipt cannot be, because verifying it needs the issuer's public key.
 */
export type RecoveryReceipt = {
  readonly tenant_id: string
  readonly permit_id: string
  readonly action_digest: string
  readonly observed_state: EffectCommitState
  readonly resolved_state: EffectCommitState
  readonly recorded_at: string
  readonly signature: {
    readonly algorithm: string
    readonly issuer_id: string
    readonly value: string
  }
}

export const verifyRecoveryReceipt = (
  candidate: unknown,
  trustedIssuerKeys: ReadonlyMap<string, string>,
): boolean => {
  if (typeof candidate !== "object" || candidate === null) return false
  const receipt = candidate as Record<string, unknown>
  const signature = receipt["signature"]

  if (typeof signature !== "object" || signature === null) return false
  const { algorithm: algorithmName, issuer_id: issuerId, value } = signature as Record<string, unknown>

  if (typeof algorithmName !== "string" || typeof issuerId !== "string" || typeof value !== "string") {
    return false
  }

  if (typeof receipt["tenant_id"] !== "string" || typeof receipt["permit_id"] !== "string") {
    return false
  }

  if (typeof receipt["action_digest"] !== "string" || typeof receipt["observed_state"] !== "string") {
    return false
  }

  if (typeof receipt["resolved_state"] !== "string" || typeof receipt["recorded_at"] !== "string") {
    return false
  }

  const issuerKey = trustedIssuerKeys.get(issuerId)
  if (issuerKey === undefined) return false

  const algorithm = getSignatureAlgorithm(algorithmName as never)
  if (algorithm === undefined) return false

  const preimage = JSON.stringify({
    tenant_id: receipt["tenant_id"],
    permit_id: receipt["permit_id"],
    action_digest: receipt["action_digest"],
    observed_state: receipt["observed_state"],
    resolved_state: receipt["resolved_state"],
    recorded_at: receipt["recorded_at"],
  })

  try {
    return algorithm.verify(Buffer.from(preimage, "utf8"), Buffer.from(value, "base64"), issuerKey)
  } catch {
    return false
  }
}

const toEntry = (row: Record<string, unknown>): EffectJournalEntry => ({
  tenantId: String(row["tenant_id"]),
  permitId: String(row["permit_id"]),
  state: String(row["state"]) as EffectCommitState,
  actionDigest: String(row["action_digest"]),
  tool: String(row["tool"]),
  resource: String(row["resource"]),
  startedAt: new Date(String(row["started_at"])).toISOString(),
  updatedAt: new Date(String(row["updated_at"])).toISOString(),
  resultDigest: row["result_digest"] === null || row["result_digest"] === undefined
    ? null
    : String(row["result_digest"]),
  error: row["error"] === null || row["error"] === undefined ? null : String(row["error"]),
  attempts: Number(row["attempts"]),
})

/**
 * PostgreSQL journal. The production implementation.
 *
 * Two things are enforced here that no amount of application code can be trusted to enforce:
 * the transition table, and the immutability of `action_digest`. Both are `BEFORE UPDATE`
 * triggers in the migration, so a bug that tries to rewrite the authorized action of an
 * in-flight effect fails at the database instead of quietly changing what recovery will act on.
 */
export class PostgreSQLEffectJournal implements EffectJournal {
  readonly #client: DatabaseClient

  constructor(options: { readonly client: DatabaseClient }) {
    this.#client = options.client
  }

  async prepare(entry: {
    readonly tenantId: string
    readonly permitId: string
    readonly actionDigest: string
    readonly tool: string
    readonly resource: string
  }): Promise<EffectJournalOutcome> {
    try {
      const rows = await this.#client.query(
        `INSERT INTO v2_effect_journal (tenant_id, permit_id, state, action_digest, tool, resource)
         VALUES ($1, $2, 'prepared', $3, $4, $5)
         ON CONFLICT DO NOTHING
         RETURNING permit_id`,
        [entry.tenantId, entry.permitId, entry.actionDigest, entry.tool, entry.resource],
      )

      if (rows.length > 0) {
        return { outcome: "recorded", state: "prepared" }
      }

      const existing = await this.read({ tenantId: entry.tenantId, permitId: entry.permitId })

      return {
        outcome: "rejected",
        state: existing?.state ?? "prepared",
        reason: `permit already journaled as ${existing?.state ?? "unknown"}`,
      }
    } catch (error) {
      return {
        outcome: "unavailable",
        error: error instanceof Error ? error.message : String(error),
      }
    }
  }

  async transition(entry: {
    readonly tenantId: string
    readonly permitId: string
    readonly to: EffectCommitState
    readonly resultDigest?: string | undefined
    readonly error?: string | undefined
    readonly attempt?: boolean | undefined
  }): Promise<EffectJournalOutcome> {
    const existing = await this.read({ tenantId: entry.tenantId, permitId: entry.permitId })
    const refusal = describeRefusal(existing, entry)

    if (refusal !== null) {
      return {
        outcome: "rejected",
        state: existing?.state ?? "prepared",
        reason: refusal,
      }
    }

    try {
      // The `AND state = ANY($3)` guard is the whole point. It makes the update conditional on
      // the row still being in a state that permits the move, so two concurrent transitions
      // cannot both succeed and a late writer cannot resurrect a terminal state.
      //
      // The two outcome guards apply only once the row is terminal. A row that is merely in
      // flight must still be able to receive its result; a terminal one must not be able to have
      // its result replaced. The database enforces the same rule independently in the transition
      // trigger.
      const rows = await this.#client.query<{ "state": string }>(
        `UPDATE v2_effect_journal
            SET state = $4,
                result_digest = COALESCE($5, result_digest),
                error = COALESCE($6, error),
                attempts = attempts + CASE WHEN $7::boolean THEN 1 ELSE 0 END
          WHERE tenant_id = $1
            AND permit_id = $2
            AND state = ANY($3::text[])
            AND (state NOT IN ('committed', 'failed', 'uncertain')
                 OR $5::text IS NULL
                 OR result_digest = $5)
            AND (state NOT IN ('committed', 'failed', 'uncertain')
                 OR $6::text IS NULL
                 OR error = $6)
        RETURNING state`,
        [
          entry.tenantId,
          entry.permitId,
          [...LEGAL_TRANSITIONS_PREVIOUS(entry.to)],
          entry.to,
          entry.resultDigest ?? null,
          entry.error ?? null,
          entry.attempt === true,
        ],
      )

      if (rows.length > 0) {
        return { outcome: "recorded", state: String(rows[0]!["state"]) as EffectCommitState }
      }

      // The guard matched nothing. Either the state moved underneath us or a concurrent writer
      // claimed the same outcome first. Re-read rather than guess: a wrong answer here would be a
      // second, quieter authority about what happened to the effect.
      const settled = await this.read({ tenantId: entry.tenantId, permitId: entry.permitId })

      return {
        outcome: "rejected",
        state: settled?.state ?? "prepared",
        reason: `illegal transition ${settled?.state ?? "absent"} -> ${entry.to}`,
      }
    } catch (caught) {
      return {
        outcome: "unavailable",
        error: caught instanceof Error ? caught.message : String(caught),
      }
    }
  }

  async read(query: {
    readonly tenantId: string
    readonly permitId: string
  }): Promise<EffectJournalEntry | null> {
    try {
      const rows = await this.#client.query(
        `SELECT * FROM v2_effect_journal WHERE tenant_id = $1 AND permit_id = $2`,
        [query.tenantId, query.permitId],
      )

      const [row] = rows
      return row === undefined ? null : toEntry(row)
    } catch {
      return null
    }
  }

  async unfinished(tenantId: string): Promise<readonly EffectJournalEntry[]> {
    try {
      const rows = await this.#client.query(
        `SELECT * FROM v2_effect_journal
          WHERE tenant_id = $1 AND state IN ('prepared', 'executing')
          ORDER BY started_at`,
        [tenantId],
      )

      return rows.map(toEntry)
    } catch {
      return []
    }
  }
}

/**
 * The states a move to `to` may come from.
 *
 * Derived from the same table the pure `nextState` uses, so the SQL guard and the in-memory
 * journal cannot drift apart. `to` itself is always included, which is what lets a same-state
 * write advance the attempt counter.
 */
const LEGAL_TRANSITIONS_PREVIOUS = (to: EffectCommitState): ReadonlySet<EffectCommitState> => {
  const sources = EFFECT_COMMIT_STATES.filter((state) => canTransition(state, to))
  return new Set(sources)
}

export type RecoveryDecision =
  /** The entry was already terminal. Nothing to do. */
  | { readonly action: "none"; readonly state: EffectCommitState }
  /**
   * The entry is now `uncertain` and will not be retried automatically.
   *
   * This is the only outcome recovery produces. It deliberately offers no "retry" action: whether
   * an unknown-outcome effect should be attempted again is a decision for a human who can look at
   * the external system, not one a recovery routine should make on its own.
   */
  | {
      readonly action: "marked_uncertain"
      readonly entry: EffectJournalEntry
      readonly receipt: RecoveryReceipt
    }
  /** The journal could not be reached. Recovery did not complete. */
  | { readonly action: "failed"; readonly error: string }

/**
 * Resolve every unfinished entry for a tenant to `uncertain`, with a signed receipt each.
 *
 * Call this after a restart and before the gateway accepts work. Anything left non-terminal when
 * the process died is, by definition, an effect whose outcome nobody observed.
 */
export const recoverUnfinished = async (args: {
  readonly journal: EffectJournal
  readonly tenantId: string
  readonly issuerId: string
  readonly keyPair: { privateKeyPem: string }
  readonly now: Date
  /** Called for each resolution, so the caller can put it in the evidence chain. */
  readonly onRecovered?: (receipt: RecoveryReceipt) => Promise<void>
}): Promise<readonly RecoveryDecision[]> => {
  const { journal, tenantId, issuerId, keyPair, now } = args

  let pending: readonly EffectJournalEntry[]

  try {
    pending = await journal.unfinished(tenantId)
  } catch (error) {
    return [{ action: "failed", error: error instanceof Error ? error.message : String(error) }]
  }

  const decisions: RecoveryDecision[] = []

  for (const entry of pending) {
    const outcome = await journal.transition({
      tenantId,
      permitId: entry.permitId,
      to: "uncertain",
      error: `process ended while ${entry.state}`,
    })

    if (outcome.outcome === "unavailable") {
      return [...decisions, { action: "failed", error: outcome.error }]
    }

    if (outcome.outcome === "rejected") {
      // Another worker got there first, or the entry reached a terminal state meanwhile. Either
      // way there is nothing left to resolve, and guessing would be worse than reading the row.
      decisions.push({ action: "none", state: outcome.state })
      continue
    }

    const preimage = {
      tenant_id: tenantId,
      permit_id: entry.permitId,
      action_digest: entry.actionDigest,
      observed_state: entry.state,
      resolved_state: "uncertain" as const,
      recorded_at: now.toISOString(),
    }

    const algorithm = getSignatureAlgorithm("ed25519")

    if (algorithm === undefined) {
      return [...decisions, { action: "failed", error: "ed25519 unavailable" }]
    }

    const receipt: RecoveryReceipt = {
      ...preimage,
      signature: {
        algorithm: "ed25519",
        issuer_id: issuerId,
        value: Buffer.from(
          algorithm.sign(Buffer.from(JSON.stringify(preimage), "utf8"), keyPair.privateKeyPem),
        ).toString("base64"),
      },
    }

    await args.onRecovered?.(receipt)

    decisions.push({
      action: "marked_uncertain",
      entry,
      receipt,
    })
  }

  return decisions
}
