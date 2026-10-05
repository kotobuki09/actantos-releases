import { canonicalHash, canonicalStringify, toJsonValue } from "../hash.ts"
import type { Database, DatabaseClient } from "../database.ts"
import {
  computeRecordHash,
  redactSensitive,
  type EvidenceBundle,
  type EvidenceRecord,
  type EvidenceType,
} from "./evidence.ts"
import { getSignatureAlgorithm } from "./signature.ts"

/**
 * Durable evidence (invariant S13), phase C.
 *
 * `EvidenceChain` in `evidence.ts` is still the in-process chain and is unchanged. This module
 * is the version that outlives the process, and the two produce byte-identical records: the same
 * preimage, the same hash, the same signature. That is what lets a bundle exported from a
 * durable chain be verified by the existing offline verifier.
 *
 * Three properties the in-process chain cannot offer:
 *
 *   Durability    A restart resumes at the next sequence number with the last stored hash as its
 *                 link. Records written before the restart are still there and still signed.
 *   Append-only   `v2_evidence` refuses UPDATE and DELETE at the database, including for the
 *                 role that runs migrations. History cannot be rewritten in place.
 *   Detectability A checkpoint fixes a (seq, root_hash) pair. Comparing it against the chain
 *                 later proves the prefix has not been altered and that no suffix has vanished.
 *
 * Appends are serialized per tenant by a transaction-scoped advisory lock. This is not an
 * optimisation, it is a requirement: record N+1's `prev_hash` is record N's hash, so two writers
 * computing "the next record" at the same moment would each produce a valid-looking record and
 * one of them would be a fork.
 */

export type EvidenceAppendOutcome =
  | { readonly outcome: "appended"; readonly seq: number; readonly hash: string }
  /** A record already exists at that sequence number with a different hash. */
  | {
      readonly outcome: "fork_detected"
      readonly seq: number
      readonly existingHash: string
      readonly attemptedHash: string
    }
  /** The same record was already stored. An idempotent retry, not a failure. */
  | { readonly outcome: "already_present"; readonly seq: number; readonly hash: string }
  | { readonly outcome: "unavailable"; readonly error: string }

export type EvidenceCheckpoint = {
  readonly seq: number
  readonly rootHash: string
  readonly createdAt: string
}

export interface EvidenceStore {
  append(args: {
    readonly tenantId: string
    readonly evidenceType: EvidenceType
    readonly payload: unknown
    readonly occurredAt: Date
  }): Promise<EvidenceAppendOutcome>

  read(tenantId: string, options?: { readonly fromSeq?: number; readonly toSeq?: number }): Promise<
    readonly EvidenceRecord[]
  >

  head(tenantId: string): Promise<{ readonly seq: number; readonly hash: string } | null>

  checkpoint(tenantId: string): Promise<EvidenceCheckpoint | null>

  readCheckpoints(tenantId: string): Promise<readonly EvidenceCheckpoint[]>

  exportBundle(tenantId: string): Promise<EvidenceBundle>
}

export type EvidenceStoreOptions = {
  readonly database: Database
  readonly issuerId: string
  readonly keyPair: { privateKeyPem: string }
}

/** The genesis link for an empty chain. Matches `EvidenceChain`, so the two interoperate. */
export const genesisHash = (tenantId: string): string => canonicalHash({ genesis: tenantId })

export const APPEND_ONLY_MESSAGE = "v2_evidence is append-only"

export class PostgreSQLEvidenceStore implements EvidenceStore {
  readonly #database: Database
  readonly #issuerId: string
  readonly #keyPair: { privateKeyPem: string }

  constructor(options: EvidenceStoreOptions) {
    this.#database = options.database
    this.#issuerId = options.issuerId
    this.#keyPair = options.keyPair
  }

  async append(args: {
    readonly tenantId: string
    readonly evidenceType: EvidenceType
    readonly payload: unknown
    readonly occurredAt: Date
  }): Promise<EvidenceAppendOutcome> {
    // Redaction happens before anything is written, not on the way out. A durable store is a
    // place a credential survives a restart, which is exactly where a credential must not be.
    const payload = redactSensitive(args.payload)

    try {
      return await this.#database.transaction(async (client) => {
        await this.#lockTenant(client, args.tenantId)

        const tail = await this.#headWith(client, args.tenantId)
        const seq = tail === null ? 0 : tail.seq + 1
        const prevHash = tail === null ? genesisHash(args.tenantId) : tail.hash

        const record = this.#sealRecord({
          seq,
          evidenceType: args.evidenceType,
          occurredAt: args.occurredAt.toISOString(),
          payload,
          prevHash,
        })

        const inserted = await client.query<{ "v2_evidence_hash_uniq"?: string }>(
          `INSERT INTO v2_evidence
             (tenant_id, seq, evidence_type, occurred_at, payload, prev_hash, hash, signature)
           VALUES ($1, $2, $3, $4, $5::jsonb, $6, $7, $8::jsonb)
           ON CONFLICT DO NOTHING
           RETURNING seq`,
          [
            args.tenantId,
            record.seq,
            record.evidence_type,
            record.occurred_at,
            canonicalStringify(toJsonValue(record.payload)),
            record.prev_hash,
            record.hash,
            canonicalStringify(toJsonValue(record.signature)),
          ],
        )

        if (inserted.length > 0) {
          return { outcome: "appended", seq: record.seq, hash: record.hash }
        }

        // The insert lost. With the advisory lock held that should be unreachable, so treat it as
        // the alarming case it is rather than as an ordinary duplicate: something wrote to this
        // chain outside the store, which is precisely the fork this design is meant to catch.
        const existing = await client.query<{ hash: string }>(
          `SELECT hash FROM v2_evidence WHERE tenant_id = $1 AND seq = $2`,
          [args.tenantId, record.seq],
        )
        const existingHash = existing[0]?.["hash"]

        if (existingHash === undefined) {
          return {
            outcome: "fork_detected",
            seq: record.seq,
            existingHash: "<absent>",
            attemptedHash: record.hash,
          }
        }

        if (existingHash === record.hash) {
          return { outcome: "already_present", seq: record.seq, hash: record.hash }
        }

        return {
          outcome: "fork_detected",
          seq: record.seq,
          existingHash,
          attemptedHash: record.hash,
        }
      })
    } catch (error) {
      // Fail closed. An effect whose evidence cannot be recorded must not happen.
      return {
        outcome: "unavailable",
        error: error instanceof Error ? error.message : String(error),
      }
    }
  }

  async read(
    tenantId: string,
    options: { readonly fromSeq?: number; readonly toSeq?: number } = {},
  ): Promise<readonly EvidenceRecord[]> {
    const rows = await this.#database.query<Record<string, unknown>>(
      `SELECT seq, evidence_type, occurred_at, payload, prev_hash, hash, signature
         FROM v2_evidence
        WHERE tenant_id = $1
          AND ($2::int IS NULL OR seq >= $2)
          AND ($3::int IS NULL OR seq <= $3)
        ORDER BY seq`,
      [tenantId, options.fromSeq ?? null, options.toSeq ?? null],
    )

    return rows.map(toRecord)
  }

  async head(tenantId: string): Promise<{ readonly seq: number; readonly hash: string } | null> {
    return this.#headWith(this.#database, tenantId)
  }

  async checkpoint(tenantId: string): Promise<EvidenceCheckpoint | null> {
    const checkpoints = await this.readCheckpoints(tenantId)
    return checkpoints[checkpoints.length - 1] ?? null
  }

  async readCheckpoints(tenantId: string): Promise<readonly EvidenceCheckpoint[]> {
    const rows = await this.#database.query<Record<string, unknown>>(
      `SELECT seq, root_hash, created_at
         FROM v2_evidence_checkpoint
        WHERE tenant_id = $1
        ORDER BY seq`,
      [tenantId],
    )

    return rows.map((row) => ({
      seq: Number(row["seq"]),
      rootHash: String(row["root_hash"]),
      createdAt: new Date(String(row["created_at"])).toISOString(),
    }))
  }

  async exportBundle(tenantId: string): Promise<EvidenceBundle> {
    const records = await this.read(tenantId)

    return {
      tenant_id: tenantId,
      records: [...records],
      root_hash: records.length === 0 ? genesisHash(tenantId) : records[records.length - 1]!.hash,
    }
  }

  async #headWith(
    client: DatabaseClient,
    tenantId: string,
  ): Promise<{ seq: number; hash: string } | null> {
    const rows = await client.query<{ seq: number; hash: string }>(
      `SELECT seq, hash FROM v2_evidence WHERE tenant_id = $1 ORDER BY seq DESC LIMIT 1`,
      [tenantId],
    )

    const row = rows[0]
    return row === undefined ? null : { seq: Number(row.seq), hash: row.hash }
  }

  /**
   * Serialize appends for one tenant.
   *
   * Transaction-scoped, so the lock is released on commit or rollback and cannot be stranded by
   * a process that dies. The key is derived from the tenant id, which is also the isolation
   * boundary: two tenants never contend, and one tenant's writers always do.
   */
  async #lockTenant(client: DatabaseClient, tenantId: string): Promise<void> {
    await client.query(`SELECT pg_advisory_xact_lock(hashtext($1))`, [tenantId])
  }

  #sealRecord(args: {
    readonly seq: number
    readonly evidenceType: EvidenceType
    readonly occurredAt: string
    readonly payload: unknown
    readonly prevHash: string
  }): EvidenceRecord {
    const unsigned = {
      seq: args.seq,
      evidence_type: args.evidenceType,
      occurred_at: args.occurredAt,
      payload: toJsonValue(args.payload),
      prev_hash: args.prevHash,
    }

    const hash = computeRecordHash(unsigned)
    const algorithm = getSignatureAlgorithm("ed25519")

    if (algorithm === undefined) {
      throw new Error("Evidence store cannot sign: ed25519 unavailable")
    }

    return {
      ...unsigned,
      hash,
      signature: {
        algorithm: "ed25519",
        issuer_id: this.#issuerId,
        value: Buffer.from(
          algorithm.sign(
            Buffer.from(canonicalStringify(toJsonValue(unsigned)), "utf8"),
            this.#keyPair.privateKeyPem,
          ),
        ).toString("base64"),
      },
    }
  }
}

const toRecord = (row: Record<string, unknown>): EvidenceRecord => ({
  seq: Number(row["seq"]),
  evidence_type: row["evidence_type"] as EvidenceType,
  occurred_at: String(row["occurred_at"]),
  payload: row["payload"],
  prev_hash: String(row["prev_hash"]),
  hash: String(row["hash"]),
  signature: row["signature"] as EvidenceRecord["signature"],
})

// --- History auditing ----------------------------------------------------------------------

export type EvidenceAuditIssueKind =
  | "sequence_gap"
  | "sequence_out_of_order"
  | "broken_linkage"
  | "record_hash_mismatch"
  | "duplicate_sequence"
  | "truncated_after_checkpoint"
  | "checkpoint_mismatch"

export type EvidenceAuditIssue = {
  readonly kind: EvidenceAuditIssueKind
  readonly seq: number
  readonly detail: string
}

export type EvidenceAudit = {
  readonly recordCount: number
  readonly headSeq: number | null
  readonly headHash: string | null
  readonly issues: readonly EvidenceAuditIssue[]
  readonly intact: boolean
}

/**
 * Audit a chain against its checkpoints.
 *
 * `verifyEvidenceBundle` proves that a bundle is internally consistent: signatures, hashes and
 * linkage all agree. That is necessary but not sufficient, because an attacker who rewrote the
 * whole chain and re-signed it would produce a perfectly consistent bundle. What catches that
 * is a checkpoint the attacker did not have the signing key to move.
 *
 * This function is pure so it can be tested without a database, and so the same logic runs in the
 * offline verifier and in the audit command.
 */
export const auditEvidenceChain = (args: {
  readonly tenantId: string
  readonly records: readonly EvidenceRecord[]
  readonly checkpoints: readonly EvidenceCheckpoint[]
}): EvidenceAudit => {
  const issues: EvidenceAuditIssue[] = []
  const { records, checkpoints } = args

  let previousHash = genesisHash(args.tenantId)

  records.forEach((record, index) => {
    if (record.seq !== index) {
      issues.push({
        kind: record.seq < index ? "sequence_out_of_order" : "sequence_gap",
        seq: index,
        detail: `expected seq ${index}, found ${record.seq}`,
      })
    }

    if (record.prev_hash !== previousHash) {
      issues.push({
        kind: "broken_linkage",
        seq: index,
        detail: "prev_hash does not match the previous record's hash",
      })
    }

    const { hash, signature: _signature, ...unsigned } = record
    const expectedHash = computeRecordHash(unsigned)

    if (expectedHash !== hash) {
      issues.push({
        kind: "record_hash_mismatch",
        seq: index,
        detail: "record hash does not cover its own contents",
      })
    }

    previousHash = hash
  })

  // Two records claiming the same sequence number. The primary key prevents this in the
  // database; a bundle assembled elsewhere can still carry it, and it is the shape a splice
  // takes when an attacker has both branches.
  const bySeq = new Map<number, EvidenceRecord>()
  for (const record of records) {
    const existing = bySeq.get(record.seq)

    if (existing !== undefined && existing.hash !== record.hash) {
      issues.push({
        kind: "duplicate_sequence",
        seq: record.seq,
        detail: "two different records claim the same sequence number",
      })
    }

    bySeq.set(record.seq, record)
  }

  const headSeq = records.length === 0 ? null : records[records.length - 1]!.seq
  const headHash = records.length === 0 ? null : records[records.length - 1]!.hash

  for (const checkpoint of checkpoints) {
    const record = bySeq.get(checkpoint.seq)

    if (record === undefined) {
      // The checkpoint says history reached this point. A chain that stops before it has lost
      // records, and the only way that happens without a rejected write is a delete.
      issues.push({
        kind: "truncated_after_checkpoint",
        seq: checkpoint.seq,
        detail: `chain stops at seq ${headSeq ?? -1} but a checkpoint exists at ${checkpoint.seq}`,
      })
      continue
    }

    if (record.hash !== checkpoint.rootHash) {
      issues.push({
        kind: "checkpoint_mismatch",
        seq: checkpoint.seq,
        detail: "the record at this sequence number no longer matches its checkpoint",
      })
    }
  }

  return {
    recordCount: records.length,
    headSeq,
    headHash,
    issues,
    intact: issues.length === 0,
  }
}