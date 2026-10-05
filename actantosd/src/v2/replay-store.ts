import type { DatabaseClient } from "../database.ts"

/**
 * Durable replay protection for effect permits (invariant S9).
 *
 * The previous implementation was a `Set<string>` inside the effect gateway process. That
 * prevents replay only while that process stays alive: restart it, and every consumed permit
 * becomes usable again. A gateway restart is an ordinary operational event, so this is a
 * security property stated too strongly, not an edge case.
 *
 * The contract is deliberately narrower than "remember which nonces I have seen". `consume`
 * must decide first-use atomically across processes and replicas, and when the store cannot
 * answer it must say so rather than default to allow. A replay store that fails open is worse
 * than no replay store, because it converts an outage into a bypass.
 */

export type ReplayEntry = {
  readonly tenantId: string
  readonly permitId: string
  readonly nonce: string
  /** When the permit itself expires. Used for retention, never for authorising anything. */
  readonly expiresAt: Date
}

export type ReplayDenialReason =
  /** This nonce was already consumed. The ordinary replay case. */
  | "nonce_already_consumed"
  /** A different nonce was already consumed under this permit id. */
  | "permit_already_consumed"

export type ReplayConsumeOutcome =
  /** First use. The caller may proceed. */
  | { readonly outcome: "consumed" }
  /**
   * Already used. Deny.
   *
   * `nonce` and `permit_id` are both constrained to be unique, so a collision on either is a
   * replay. Keeping them apart matters for evidence: a permit id reused under a fresh nonce is
   * a different failure from a nonce replayed under its original permit.
   */
  | { readonly outcome: "replayed"; readonly reason: ReplayDenialReason }
  /**
   * The store could not answer. The caller must fail closed.
   *
   * This is a distinct outcome rather than an exception so that "the database is down" cannot
   * be confused with "the permit was already used", and so no caller can accidentally treat an
   * infrastructure fault as a successful consume.
   */
  | { readonly outcome: "unavailable"; readonly error: string }

export type ReplayQuery = {
  readonly tenantId: string
  readonly nonce?: string | undefined
  readonly permitId?: string | undefined
}

export interface ReplayStore {
  /**
   * Atomically claim first use. Exactly one concurrent caller receives `"consumed"`.
   */
  consume(entry: ReplayEntry): Promise<ReplayConsumeOutcome>
  /** Read-only check. Never used to authorise; `consume` is the only authority. */
  isConsumed(query: ReplayQuery): Promise<boolean>
  /** Drop rows past retention. Returns the number removed. */
  cleanupExpired(now: Date): Promise<number>
}

/**
 * How long a consumed nonce is kept after its permit expires.
 *
 * Zero would be sufficient on paper, because `verifyEffectPermit` rejects an expired permit
 * before the replay store is ever consulted. The retention exists so that a clock that disagrees
 * between the gateway and the store cannot turn a replay into a first use, which is a cheap
 * insurance policy against a table of short rows.
 */
export const DEFAULT_REPLAY_RETENTION_MS = 24 * 60 * 60 * 1000

/**
 * Process-memory store. Tests and single-process development only.
 *
 * It is not a security control in production: it cannot survive a restart and cannot coordinate
 * two gateways. `EffectGateway` accepts it so the existing in-process suites keep exercising the
 * same code path, but the PostgreSQL implementation is the one that belongs in a deployment.
 */
export class InMemoryReplayStore implements ReplayStore {
  // Nested maps rather than one joined string key. A tenant id and a nonce are both
  // attacker-influenced text, so any printable separator between them is a collision waiting to
  // happen: a tenant literally named "a b" with nonce "c" would alias a tenant named "a" with
  // nonce "b c", and one tenant would silently consume the other's permit.
  readonly #byTenant = new Map<string, {
    nonces: Map<string, { permitId: string; expiresAt: Date }>
    permits: Map<string, string>
  }>()

  #tenant(tenantId: string) {
    let entry = this.#byTenant.get(tenantId)
    if (entry === undefined) {
      entry = { nonces: new Map(), permits: new Map() }
      this.#byTenant.set(tenantId, entry)
    }
    return entry
  }

  async consume(entry: ReplayEntry): Promise<ReplayConsumeOutcome> {
    const tenant = this.#tenant(entry.tenantId)

    if (tenant.nonces.has(entry.nonce)) {
      return { outcome: "replayed", reason: "nonce_already_consumed" }
    }

    if (tenant.permits.has(entry.permitId)) {
      return { outcome: "replayed", reason: "permit_already_consumed" }
    }

    // Both writes happen together with the check, so a rejected consume leaves no trace. A
    // half-applied replay record would let a later, differently-timed attempt succeed.
    tenant.nonces.set(entry.nonce, { permitId: entry.permitId, expiresAt: entry.expiresAt })
    tenant.permits.set(entry.permitId, entry.nonce)

    return { outcome: "consumed" }
  }

  async isConsumed(query: ReplayQuery): Promise<boolean> {
    if (query.nonce === undefined && query.permitId === undefined) {
      throw new Error("isConsumed requires at least one of nonce or permitId")
    }

    const tenant = this.#byTenant.get(query.tenantId)

    if (tenant === undefined) return false
    if (query.nonce !== undefined && tenant.nonces.has(query.nonce)) return true
    if (query.permitId !== undefined && tenant.permits.has(query.permitId)) return true

    return false
  }

  async cleanupExpired(now: Date): Promise<number> {
    const cutoff = now.getTime() - DEFAULT_REPLAY_RETENTION_MS
    let removed = 0

    for (const tenant of this.#byTenant.values()) {
      for (const [nonce, value] of [...tenant.nonces]) {
        if (value.expiresAt.getTime() < cutoff) {
          tenant.nonces.delete(nonce)
          tenant.permits.delete(value.permitId)
          removed += 1
        }
      }
    }

    return removed
  }

  /** Test affordance. A production store has no equivalent, which is the point. */
  get size(): number {
    let total = 0
    for (const tenant of this.#byTenant.values()) total += tenant.nonces.size
    return total
  }
}

const INSERT_SQL = `
INSERT INTO v2_replay_guard (tenant_id, nonce, permit_id, consumed_at, expires_at)
VALUES ($1, $2, $3, now(), $4)
ON CONFLICT DO NOTHING
RETURNING 1
`

/**
 * PostgreSQL store. The production implementation.
 *
 * Atomicity comes from the database, not from application logic: `INSERT ... ON CONFLICT DO
 * NOTHING` is a single statement that either inserts or does not, and the two unique constraints
 * are what make it exclusive. Two gateways racing on one permit produce one row and one empty
 * result set, whatever the order, and nothing in this process is involved in the decision.
 *
 * A read-then-write would not be safe here. Under `READ COMMITTED` two replicas can both observe
 * an absent row and both proceed to insert.
 */
export class PostgreSQLReplayStore implements ReplayStore {
  readonly #client: DatabaseClient
  readonly #retentionMs: number

  constructor(options: { readonly client: DatabaseClient; readonly retentionMs?: number }) {
    this.#client = options.client
    this.#retentionMs = options.retentionMs ?? DEFAULT_REPLAY_RETENTION_MS
  }

  async consume(entry: ReplayEntry): Promise<ReplayConsumeOutcome> {
    try {
      const rows = await this.#client.query(INSERT_SQL, [
        entry.tenantId,
        entry.nonce,
        entry.permitId,
        entry.expiresAt.toISOString(),
      ])

      if (rows.length > 0) {
        return { outcome: "consumed" }
      }

      // The insert lost. Work out which constraint rejected it, so evidence names the actual
      // cause rather than a generic "replayed".
      return { outcome: "replayed", reason: await this.#classifyCollision(entry) }
    } catch (error) {
      return {
        outcome: "unavailable",
        error: error instanceof Error ? error.message : String(error),
      }
    }
  }

  async #classifyCollision(entry: ReplayEntry): Promise<ReplayDenialReason> {
    const rows = await this.#client.query(
      `SELECT
         EXISTS (SELECT 1 FROM v2_replay_guard WHERE tenant_id = $1 AND nonce = $2) AS nonce_hit,
         EXISTS (SELECT 1 FROM v2_replay_guard WHERE tenant_id = $1 AND permit_id = $3) AS permit_hit`,
      [entry.tenantId, entry.nonce, entry.permitId],
    )

    // Nonce is checked first because an exact resend of a permit collides with both constraints
    // at once, and the nonce is the narrower statement about what the caller actually did. The
    // in-memory store checks in this order too, so the two implementations agree on the reason
    // rather than only on the denial.
    const [row] = rows
    return row?.["nonce_hit"] === true ? "nonce_already_consumed" : "permit_already_consumed"
  }

  async isConsumed(query: ReplayQuery): Promise<boolean> {
    if (query.nonce === undefined && query.permitId === undefined) {
      throw new Error("isConsumed requires at least one of nonce or permitId")
    }

    const rows = await this.#client.query(
      `SELECT 1 FROM v2_replay_guard
       WHERE tenant_id = $1
         AND (($2::text IS NOT NULL AND nonce = $2) OR ($3::text IS NOT NULL AND permit_id = $3))
       LIMIT 1`,
      [query.tenantId, query.nonce ?? null, query.permitId ?? null],
    )

    return rows.length > 0
  }

  async cleanupExpired(now: Date): Promise<number> {
    const cutoff = new Date(now.getTime() - this.#retentionMs).toISOString()
    const rows = await this.#client.query(
      `DELETE FROM v2_replay_guard WHERE expires_at < $1 RETURNING 1`,
      [cutoff],
    )
    return rows.length
  }
}