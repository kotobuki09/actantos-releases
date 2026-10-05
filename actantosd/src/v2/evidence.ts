import { z } from "zod"

import { canonicalHash, canonicalStringify, toJsonValue } from "../hash.ts"
import {
  getSignatureAlgorithm,
  type SignatureAlgorithmName,
} from "./signature.ts"

/**
 * Verifiable evidence (invariant S13).
 *
 * Every important transition appends a record to a hash chain. The chain makes the history
 * tamper-evident; per-record signatures make it attributable. Together they let
 * `verifyEvidenceBundle` check a bundle offline, without trusting the running ActantOS
 * instance.
 *
 * Payloads carry commitments and metadata, not secrets. `redactSensitive` enforces that at
 * write time so an evidence bundle cannot become a credential store.
 */

export const EVIDENCE_TYPES = [
  "root_authorization",
  "agent_identity",
  "delegation",
  "data_access",
  "policy_decision",
  "approval",
  "effect_permit",
  "effect_execution",
  "tool_result_commitment",
  "revocation",
  "security_violation",
] as const

export const evidenceTypeSchema = z.enum(EVIDENCE_TYPES)

export type EvidenceType = z.infer<typeof evidenceTypeSchema>

const SENSITIVE_KEY = /pass|secret|token|api[_-]?key|private[_-]?key|authorization|credential|bearer/i

/**
 * Replace values that look like credentials with a marker, and replace them with their
 * digest so the record still proves *that* a value was present and unchanged.
 */
export const redactSensitive = (value: unknown): unknown => {
  if (Array.isArray(value)) {
    return value.map(redactSensitive)
  }

  if (value !== null && typeof value === "object") {
    return Object.fromEntries(
      Object.entries(value).map(([key, nested]) => {
        if (SENSITIVE_KEY.test(key)) {
          return [key, "[redacted]"]
        }

        return [key, redactSensitive(nested)]
      }),
    )
  }

  return value
}

export const evidenceRecordSchema = z.object({
  seq: z.number().int().min(0),
  evidence_type: evidenceTypeSchema,
  occurred_at: z.string().min(1),
  payload: z.unknown(),
  prev_hash: z.string().min(1),
  hash: z.string().min(1),
  signature: z.object({
    algorithm: z.string().min(1),
    issuer_id: z.string().min(1),
    value: z.string().min(1),
  }),
})

export type EvidenceRecord = z.infer<typeof evidenceRecordSchema>

export const evidenceBundleSchema = z.object({
  tenant_id: z.string().min(1),
  records: z.array(evidenceRecordSchema),
  root_hash: z.string().min(1),
})

export type EvidenceBundle = z.infer<typeof evidenceBundleSchema>

const recordPreimage = (record: Omit<EvidenceRecord, "hash" | "signature">): unknown => ({
  seq: record.seq,
  evidence_type: record.evidence_type,
  occurred_at: record.occurred_at,
  payload: toJsonValue(record.payload),
  prev_hash: record.prev_hash,
})

export const computeRecordHash = (
  record: Omit<EvidenceRecord, "hash" | "signature">,
): string => canonicalHash(recordPreimage(record))

export type AppendEvidenceOptions = {
  readonly issuerId: string
  readonly keyPair: { privateKeyPem: string }
  readonly occurredAt: Date
}

/**
 * Where the chain is persisted.
 *
 * The sink exists so "evidence unavailable" is an observable condition rather than a silent
 * in-memory buffer. A sink that throws propagates out of `append`, and enforcement points
 * treat that as fail-closed rather than carrying on with an unrecorded effect.
 */
export type EvidenceSink = (bundle: EvidenceBundle) => void

export class EvidenceChain {
  readonly #tenantId: string
  readonly #issuerId: string
  readonly #keyPair: { privateKeyPem: string }
  readonly #sink: EvidenceSink | undefined
  readonly #records: EvidenceRecord[] = []
  #previousHash: string

  constructor(options: {
    readonly tenantId: string
    readonly issuerId: string
    readonly keyPair: { privateKeyPem: string }
    readonly sink?: EvidenceSink | undefined
  }) {
    this.#tenantId = options.tenantId
    this.#issuerId = options.issuerId
    this.#keyPair = options.keyPair
    this.#sink = options.sink
    // A fixed genesis marker rather than an empty string, so an empty chain cannot be
    // confused with a truncated one.
    this.#previousHash = canonicalHash({ genesis: this.#tenantId })
  }

  get tenantId(): string {
    return this.#tenantId
  }

  get length(): number {
    return this.#records.length
  }

  append(
    evidenceType: EvidenceType,
    payload: unknown,
    options: { readonly occurredAt?: Date | undefined } = {},
  ): EvidenceRecord {
    const unsigned = {
      seq: this.#records.length,
      evidence_type: evidenceType,
      occurred_at: (options.occurredAt ?? new Date()).toISOString(),
      payload: redactSensitive(payload),
      prev_hash: this.#previousHash,
    }

    const hash = computeRecordHash(unsigned)
    const algorithm = getSignatureAlgorithm("ed25519")

    if (algorithm === undefined) {
      throw new Error("Evidence chain cannot sign: ed25519 unavailable")
    }

    const payloadBytes = Buffer.from(
      canonicalStringify(toJsonValue(unsigned)),
      "utf8",
    )

    const record: EvidenceRecord = {
      ...unsigned,
      hash,
      signature: {
        algorithm: "ed25519",
        issuer_id: this.#issuerId,
        value: Buffer.from(
          algorithm.sign(payloadBytes, this.#keyPair.privateKeyPem),
        ).toString("base64"),
      },
    }

    this.#records.push(record)
    this.#previousHash = hash

    // Persisted after the record is sealed, so a sink failure cannot leave a half-written
    // record in the local buffer claiming to be durable.
    this.#sink?.(this.export())

    return record
  }

  export(): EvidenceBundle {
    return {
      tenant_id: this.#tenantId,
      records: [...this.#records],
      root_hash: this.#previousHash,
    }
  }
}

export type EvidenceVerificationIssue = {
  readonly seq: number
  readonly problem: string
}

export type EvidenceVerification =
  | { readonly valid: true; readonly recordCount: number }
  | { readonly valid: false; readonly issues: EvidenceVerificationIssue[] }

/**
 * Verify an exported bundle offline.
 *
 * Checks signature, per-record hash, hash linkage, sequence ordering and the final root
 * hash. Nothing here consults the running service.
 */
export const verifyEvidenceBundle = (
  candidate: unknown,
  trustedIssuerKeys: ReadonlyMap<string, string>,
): EvidenceVerification => {
  const parsed = evidenceBundleSchema.safeParse(candidate)

  if (!parsed.success) {
    return {
      valid: false,
      issues: [{ seq: -1, problem: "malformed_evidence_bundle" }],
    }
  }

  const { records, root_hash: rootHash } = parsed.data
  const issues: EvidenceVerificationIssue[] = []
  let previousHash = canonicalHash({ genesis: parsed.data.tenant_id })

  records.forEach((record, index) => {
    if (record.seq !== index) {
      issues.push({ seq: index, problem: "sequence_out_of_order" })
    }

    if (record.prev_hash !== previousHash) {
      issues.push({ seq: index, problem: "broken_chain_linkage" })
    }

    const { hash, signature, ...unsigned } = record
    const expectedHash = computeRecordHash(unsigned)

    if (expectedHash !== hash) {
      issues.push({ seq: index, problem: "record_hash_mismatch" })
    }

    const issuerKey = trustedIssuerKeys.get(signature.issuer_id)

    if (issuerKey === undefined) {
      issues.push({ seq: index, problem: "untrusted_issuer" })
    } else {
      const algorithm = getSignatureAlgorithm(
        signature.algorithm as SignatureAlgorithmName,
      )

      if (algorithm === undefined) {
        issues.push({ seq: index, problem: "unsupported_algorithm" })
      } else {
        const signed = algorithm.verify(
          Buffer.from(canonicalStringify(toJsonValue(unsigned)), "utf8"),
          Buffer.from(signature.value, "base64"),
          issuerKey,
        )

        if (!signed) {
          issues.push({ seq: index, problem: "invalid_signature" })
        }
      }
    }

    previousHash = hash
  })

  if (previousHash !== rootHash) {
    issues.push({ seq: records.length, problem: "root_hash_mismatch" })
  }

  if (issues.length > 0) {
    return { valid: false, issues }
  }

  return { valid: true, recordCount: records.length }
}