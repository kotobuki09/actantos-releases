import { randomUUID } from "node:crypto"

import { canonicalHash } from "./hash.ts"

export type AuditEventInput = {
  readonly tenantId: string
  readonly eventType: string
  readonly actorType: string
  readonly actorId: string
  readonly payload: Readonly<Record<string, unknown>>
  readonly sessionId?: string
  readonly toolCallId?: string
  readonly decisionId?: string
}

export type AuditEventRecord = AuditEventInput & {
  readonly eventId: string
  readonly seq: number
  readonly prevHash: string
  readonly eventHash: string
  readonly createdAt: string
}

export type OutboxItem = {
  readonly id: string
  readonly tenantId: string
  readonly eventId: string
  readonly destination: string
  payload: Record<string, unknown>
  status: "pending" | "leased" | "delivered" | "dead_letter"
  attempts: number
  readonly idempotencyKey: string
  availableAt: string
  lastError?: string
}

export type TransactionalStore = {
  auditEvents: AuditEventRecord[]
  outbox: OutboxItem[]
  chainHeads: Map<string, { seq: number; lastHash: string }>
}

export const createTransactionalStore = (): TransactionalStore => ({
  auditEvents: [],
  outbox: [],
  chainHeads: new Map(),
})

/**
 * Canonical append: business mutation, audit event, and outbox item commit atomically
 * (in-memory unit model mirrors DB transaction boundaries).
 */
export const appendAuditAndOutbox = (
  store: TransactionalStore,
  input: AuditEventInput,
  destinations: readonly string[],
  options: { readonly failAfterAudit?: boolean } = {},
): { readonly event: AuditEventRecord; readonly outboxIds: readonly string[] } => {
  const head = store.chainHeads.get(input.tenantId) ?? { seq: 0, lastHash: "genesis" }
  const seq = head.seq + 1
  const createdAt = new Date().toISOString()
  const eventId = randomUUID()
  const eventHash = canonicalHash({
    eventId,
    seq,
    prevHash: head.lastHash,
    tenantId: input.tenantId,
    eventType: input.eventType,
    payload: input.payload,
  })
  const event: AuditEventRecord = {
    ...input,
    eventId,
    seq,
    prevHash: head.lastHash,
    eventHash,
    createdAt,
  }

  const outboxItems: OutboxItem[] = destinations.map((destination) => ({
    id: randomUUID(),
    tenantId: input.tenantId,
    eventId,
    destination,
    payload: { eventId, eventType: input.eventType, tenantId: input.tenantId },
    status: "pending",
    attempts: 0,
    idempotencyKey: `${eventId}:${destination}`,
    availableAt: createdAt,
  }))

  // Atomic commit boundary
  if (options.failAfterAudit === true) {
    throw new Error("injected crash after audit draft")
  }

  store.auditEvents.push(event)
  store.outbox.push(...outboxItems)
  store.chainHeads.set(input.tenantId, { seq, lastHash: eventHash })
  return { event, outboxIds: outboxItems.map((item) => item.id) }
}

export const leaseOutboxItem = (
  store: TransactionalStore,
  workerId: string,
  now: Date = new Date(),
): OutboxItem | undefined => {
  const item = store.outbox.find(
    (candidate) =>
      candidate.status === "pending" &&
      new Date(candidate.availableAt).getTime() <= now.getTime(),
  )
  if (item === undefined) {
    return undefined
  }
  item.status = "leased"
  item.attempts += 1
  item.payload = { ...item.payload, leasedBy: workerId }
  return item
}

export const completeOutboxDelivery = (
  store: TransactionalStore,
  id: string,
  result: "delivered" | "retry" | "dead_letter",
  error?: string,
): void => {
  const item = store.outbox.find((candidate) => candidate.id === id)
  if (item === undefined) {
    return
  }
  if (result === "delivered") {
    item.status = "delivered"
    return
  }
  if (result === "dead_letter" || item.attempts >= 5) {
    item.status = "dead_letter"
    if (error !== undefined) {
      item.lastError = error
    }
    return
  }
  item.status = "pending"
  if (error !== undefined) {
    item.lastError = error
  }
  item.availableAt = new Date(Date.now() + item.attempts * 1_000).toISOString()
}

export const verifyAuditChain = (
  store: TransactionalStore,
  tenantId: string,
): { readonly valid: boolean; readonly length: number } => {
  const events = store.auditEvents
    .filter((event) => event.tenantId === tenantId)
    .sort((left, right) => left.seq - right.seq)
  let prev = "genesis"
  for (const event of events) {
    if (event.prevHash !== prev) {
      return { valid: false, length: events.length }
    }
    const expected = canonicalHash({
      eventId: event.eventId,
      seq: event.seq,
      prevHash: event.prevHash,
      tenantId: event.tenantId,
      eventType: event.eventType,
      payload: event.payload,
    })
    if (expected !== event.eventHash) {
      return { valid: false, length: events.length }
    }
    prev = event.eventHash
  }
  return { valid: true, length: events.length }
}
