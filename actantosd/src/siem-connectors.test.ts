import assert from "node:assert/strict"
import test from "node:test"

import { createSiemDispatcher, signSiemPayload, type SiemConnectorConfig } from "./siem-connectors.ts"

const connector = (overrides: Partial<SiemConnectorConfig> = {}): SiemConnectorConfig => ({
  id: "conn_1",
  tenantId: "t_alpha",
  kind: "webhook",
  endpoint: "https://siem.example.com/hooks/actantos",
  secretRef: "secret/siem",
  secretValue: "super-secret",
  enabled: true,
  paused: false,
  ...overrides,
})

test("siem dispatcher signs payloads and classifies auth/retry/reject outcomes", async () => {
  const statuses = [200, 401, 429, 400]
  let call = 0
  const dispatcher = createSiemDispatcher(async () => {
    const status = statuses[call] ?? 200
    call += 1
    return { status, body: "ok" }
  })

  const delivered = await dispatcher.deliver(connector(), {
    eventId: "evt_1",
    tenantId: "t_alpha",
    body: { decision: "allow" },
  })
  assert.equal(delivered.status, "delivered")
  assert.match(delivered.signature, /^[a-f0-9]{64}$/u)

  assert.equal(
    (await dispatcher.deliver(connector(), { eventId: "evt_2", tenantId: "t_alpha", body: {} })).status,
    "auth_failed",
  )
  assert.equal(
    (await dispatcher.deliver(connector(), { eventId: "evt_3", tenantId: "t_alpha", body: {} })).status,
    "retry",
  )
  assert.equal(
    (await dispatcher.deliver(connector(), { eventId: "evt_4", tenantId: "t_alpha", body: {} })).status,
    "rejected",
  )
})

test("siem dispatcher rejects private endpoints, cross-tenant, and oversize payloads", async () => {
  const dispatcher = createSiemDispatcher(async () => ({ status: 200, body: "ok" }))
  assert.equal(
    (
      await dispatcher.deliver(connector({ endpoint: "https://169.254.169.254/latest" }), {
        eventId: "e1",
        tenantId: "t_alpha",
        body: {},
      })
    ).status,
    "rejected",
  )
  assert.equal(
    (
      await dispatcher.deliver(connector(), {
        eventId: "e2",
        tenantId: "t_other",
        body: {},
      })
    ).status,
    "rejected",
  )
  assert.equal(
    (
      await dispatcher.deliver(connector(), {
        eventId: "e3",
        tenantId: "t_alpha",
        body: { blob: "x".repeat(300_000) },
      })
    ).status,
    "rejected",
  )

  const timestamp = "1710000000"
  const body = "{\"a\":1}"
  assert.equal(
    signSiemPayload("super-secret", timestamp, body).length,
    64,
  )
})
