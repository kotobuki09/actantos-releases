import { canonicalStringify, sha256, toJsonValue } from "./hash.ts"
import { parsePgBigInt, type Database } from "./database.ts"

type AuditEventRow = {
  readonly tenant_id: string
  readonly seq: string | number | bigint
  readonly payload_json: unknown
  readonly prev_hash: string
  readonly event_hash: string
  readonly created_at: string | Date
}

type AuditChainStateRow = {
  readonly last_hash: string
  readonly seq: string | number | bigint
}

export type AuditChainVerificationResult =
  | {
      readonly valid: true
      readonly tenantId: string
      readonly eventCount: number
    }
  | {
      readonly valid: false
      readonly tenantId: string
      readonly eventCount: number
      readonly error:
        | "prev_hash_mismatch"
        | "event_hash_mismatch"
        | "chain_state_mismatch"
    }

const computeEventHash = (event: AuditEventRow): string =>
  sha256(
    `${event.tenant_id}${parsePgBigInt(event.seq).toString()}${event.prev_hash}${canonicalStringify(toJsonValue(event.payload_json))}${new Date(event.created_at).toISOString()}`,
  )

export const verifyTenantAuditChain = async (
  database: Database,
  tenantId: string,
): Promise<AuditChainVerificationResult> => {
  const events = await database.query<AuditEventRow>(
    `
      SELECT tenant_id, seq, payload_json, prev_hash, event_hash, created_at
      FROM audit_events
      WHERE tenant_id = $1
      ORDER BY seq ASC
    `,
    [tenantId],
  )
  const chainStateRows = await database.query<AuditChainStateRow>(
    `
      SELECT last_hash, seq
      FROM audit_chain_state
      WHERE tenant_id = $1
    `,
    [tenantId],
  )

  let previousHash = "genesis"

  for (const event of events) {
    if (event.prev_hash !== previousHash) {
      return {
        valid: false,
        tenantId,
        eventCount: events.length,
        error: "prev_hash_mismatch",
      }
    }

    if (event.event_hash !== computeEventHash(event)) {
      return {
        valid: false,
        tenantId,
        eventCount: events.length,
        error: "event_hash_mismatch",
      }
    }

    previousHash = event.event_hash
  }

  const chainState = chainStateRows[0]
  const expectedSeq = BigInt(events.length)
  const actualSeq = parsePgBigInt(chainState?.seq)
  const actualLastHash = chainState?.last_hash ?? "genesis"

  if (actualSeq !== expectedSeq || actualLastHash !== previousHash) {
    return {
      valid: false,
      tenantId,
      eventCount: events.length,
      error: "chain_state_mismatch",
    }
  }

  return {
    valid: true,
    tenantId,
    eventCount: events.length,
  }
}
