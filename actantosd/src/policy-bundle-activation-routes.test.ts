import assert from "node:assert/strict"
import test from "node:test"

import { buildServer } from "./server.ts"
import { createTestDatabase } from "./test-database.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"

test("POST /v1/policy-bundles/:id/activate promotes a stored bundle version", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    policyValidator: async () => ({ ok: true }),
    database,
  })
  await server.ready()

  const createResponse = await server.inject({
    method: "POST",
    url: "/v1/policy-bundles",
    payload: {
      tenant_id: "t_demo",
      version: "0.2.0",
      engine: "cedar",
      source_text: "permit(principal, action, resource);",
      active: false,
    },
  })

  const activationResponse = await server.inject({
    method: "POST",
    url: `/v1/policy-bundles/${createResponse.json().policy_bundle.id}/activate`,
  })

  assert.equal(createResponse.statusCode, 201)
  assert.equal(activationResponse.statusCode, 200)
  assert.equal(activationResponse.json().policy_bundle.version, "0.2.0")
  assert.equal(activationResponse.json().policy_bundle.active, true)

  const rows = await database.query<{ version: string; active: boolean }>(
    `
      SELECT version, active
      FROM policy_bundles
      WHERE tenant_id = $1
      ORDER BY version ASC
    `,
    ["t_demo"],
  )
  assert.deepEqual(rows, [
    { version: "0.1.0", active: false },
    { version: "0.2.0", active: true },
  ])

  await server.close()
  await database.close()
})

test("POST /v1/policy-bundles/:id/activate rolls back to an older stored bundle", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    policyValidator: async () => ({ ok: true }),
    database,
  })
  await server.ready()

  const createResponse = await server.inject({
    method: "POST",
    url: "/v1/policy-bundles",
    payload: {
      tenant_id: "t_demo",
      version: "0.2.0",
      engine: "cedar",
      source_text: "forbid(principal, action, resource);",
      active: true,
    },
  })
  assert.equal(createResponse.statusCode, 201)

  const rollbackResponse = await server.inject({
    method: "POST",
    url: "/v1/policy-bundles/33333333-3333-3333-3333-333333333333/activate",
  })

  assert.equal(rollbackResponse.statusCode, 200)
  assert.equal(rollbackResponse.json().policy_bundle.version, "0.1.0")
  assert.equal(rollbackResponse.json().policy_bundle.active, true)

  const rows = await database.query<{ version: string; active: boolean }>(
    `
      SELECT version, active
      FROM policy_bundles
      WHERE tenant_id = $1
      ORDER BY version ASC
    `,
    ["t_demo"],
  )
  assert.deepEqual(rows, [
    { version: "0.1.0", active: true },
    { version: "0.2.0", active: false },
  ])

  await server.close()
  await database.close()
})
