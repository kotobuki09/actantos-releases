import assert from "node:assert/strict"
import test from "node:test"

import {
  appendAuditAndOutbox,
  completeOutboxDelivery,
  createTransactionalStore,
  leaseOutboxItem,
  verifyAuditChain,
} from "./audit-outbox.ts"

test("append commits audit + outbox atomically and preserves hash chain", () => {
  const store = createTransactionalStore()
  appendAuditAndOutbox(
    store,
    {
      tenantId: "t_alpha",
      eventType: "decision.allow",
      actorType: "system",
      actorId: "daemon",
      payload: { decision: "allow" },
    },
    ["siem:webhook", "archive:s3"],
  )
  appendAuditAndOutbox(
    store,
    {
      tenantId: "t_alpha",
      eventType: "tool.result",
      actorType: "agent",
      actorId: "a1",
      payload: { status: "ok" },
    },
    ["siem:webhook"],
  )

  assert.equal(store.auditEvents.length, 2)
  assert.equal(store.outbox.length, 3)
  assert.deepEqual(verifyAuditChain(store, "t_alpha"), { valid: true, length: 2 })

  const before = store.auditEvents.length
  assert.throws(() =>
    appendAuditAndOutbox(
      store,
      {
        tenantId: "t_alpha",
        eventType: "admin.action",
        actorType: "user",
        actorId: "u1",
        payload: { action: "rotate" },
      },
      ["siem:webhook"],
      { failAfterAudit: true },
    ),
  )
  assert.equal(store.auditEvents.length, before)
  assert.equal(store.outbox.filter((item) => item.eventId === "missing").length, 0)
})

test("outbox workers lease, retry, and dead-letter with stable idempotency keys", () => {
  const store = createTransactionalStore()
  const { outboxIds } = appendAuditAndOutbox(
    store,
    {
      tenantId: "t_beta",
      eventType: "decision.deny",
      actorType: "system",
      actorId: "daemon",
      payload: { decision: "deny" },
    },
    ["siem:splunk"],
  )
  const first = leaseOutboxItem(store, "worker-1")
  assert.equal(first?.id, outboxIds[0])
  assert.equal(first?.status, "leased")
  completeOutboxDelivery(store, first!.id, "retry", "429")
  // Advance availability so the same idempotent item can be re-leased
  store.outbox[0]!.availableAt = new Date(0).toISOString()
  const second = leaseOutboxItem(store, "worker-2")
  assert.equal(second?.idempotencyKey, first?.idempotencyKey)
  completeOutboxDelivery(store, second!.id, "retry", "429")
  for (let attempt = 0; attempt < 10; attempt += 1) {
    store.outbox[0]!.availableAt = new Date(0).toISOString()
    const item = leaseOutboxItem(store, "worker-x")
    if (item === undefined) break
    completeOutboxDelivery(store, item.id, "retry", "5xx")
  }
  assert.equal(store.outbox[0]?.status, "dead_letter")
})
