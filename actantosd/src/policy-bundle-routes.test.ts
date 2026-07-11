import assert from "node:assert/strict"
import test from "node:test"

import { sha256 } from "./hash.ts"
import { buildServer } from "./server.ts"
import { createTestDatabase } from "./test-database.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"

test("GET /v1/policy-bundles returns tenant policy bundle summaries", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const response = await server.inject({
    method: "GET",
    url: "/v1/policy-bundles?tenant_id=t_demo",
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), {
    tenant_id: "t_demo",
    policy_bundles: [
      {
        id: "33333333-3333-3333-3333-333333333333",
        tenant_id: "t_demo",
        version: "0.1.0",
        engine: "cedar",
        source_hash: "5c8533bd835a317b9191d940ea78ef0c3a2f641a45add6affe6897d046989f1a",
        active: true,
        created_at: response.json().policy_bundles[0].created_at,
      },
    ],
  })
  assert.equal(typeof response.json().policy_bundles[0].created_at, "string")

  await server.close()
  await database.close()
})

test("POST /v1/policy-bundles creates an inactive policy bundle", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    policyValidator: async () => ({ ok: true }),
    database,
  })
  await server.ready()

  const response = await server.inject({
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

  assert.equal(response.statusCode, 201)
  assert.equal(response.json().policy_bundle.tenant_id, "t_demo")
  assert.equal(response.json().policy_bundle.version, "0.2.0")
  assert.equal(response.json().policy_bundle.engine, "cedar")
  assert.equal(response.json().policy_bundle.active, false)
  assert.equal(
    response.json().policy_bundle.source_hash,
    sha256("permit(principal, action, resource);"),
  )

  const rows = await database.query<{ active: boolean }>(
    "SELECT active FROM policy_bundles WHERE tenant_id = $1 AND version = $2",
    ["t_demo", "0.2.0"],
  )
  assert.deepEqual(rows, [{ active: false }])

  await server.close()
  await database.close()
})

test("POST /v1/policy-bundles with active=true promotes the new bundle", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    policyValidator: async () => ({ ok: true }),
    database,
  })
  await server.ready()

  const response = await server.inject({
    method: "POST",
    url: "/v1/policy-bundles",
    payload: {
      tenant_id: "t_demo",
      version: "0.3.0",
      engine: "cedar",
      source_text: "forbid(principal, action, resource);",
      active: true,
    },
  })

  const rows = await database.query<{ version: string; active: boolean }>(
    `
      SELECT version, active
      FROM policy_bundles
      WHERE tenant_id = $1
      ORDER BY version ASC
    `,
    ["t_demo"],
  )

  assert.equal(response.statusCode, 201)
  assert.equal(response.json().policy_bundle.active, true)
  assert.deepEqual(rows, [
    { version: "0.1.0", active: false },
    { version: "0.3.0", active: true },
  ])

  await server.close()
  await database.close()
})

test("POST /v1/policy-bundles rejects Cedar source that fails syntax validation", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    policyValidator: async () => ({
      ok: false,
      message: "parse error at line 1, column 8",
    }),
    database,
  })
  await server.ready()

  const response = await server.inject({
    method: "POST",
    url: "/v1/policy-bundles",
    payload: {
      tenant_id: "t_demo",
      version: "0.4.0",
      engine: "cedar",
      source_text: "permit(principal action, resource);",
      active: true,
    },
  })

  assert.equal(response.statusCode, 400)
  assert.deepEqual(response.json(), {
    error: "invalid_policy_bundle",
    message: "policy bundle source failed Cedar syntax validation",
    detail: "parse error at line 1, column 8",
  })

  const rows = await database.query<{ version: string }>(
    "SELECT version FROM policy_bundles WHERE tenant_id = $1 AND version = $2",
    ["t_demo", "0.4.0"],
  )
  assert.deepEqual(rows, [])

  await server.close()
  await database.close()
})

test("GET /v1/policy-bundles/:id returns the full policy bundle record", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const response = await server.inject({
    method: "GET",
    url: "/v1/policy-bundles/33333333-3333-3333-3333-333333333333",
  })

  assert.equal(response.statusCode, 200)
  const body = response.json()
  assert.equal(body.policy_bundle.id, "33333333-3333-3333-3333-333333333333")
  assert.equal(body.policy_bundle.tenant_id, "t_demo")
  assert.equal(body.policy_bundle.version, "0.1.0")
  assert.equal(body.policy_bundle.engine, "cedar")
  assert.equal(body.policy_bundle.active, true)
  assert.equal(
    body.policy_bundle.source_text.replaceAll("\r\n", "\n"),
    `permit (
  principal,
  action,
  resource
)
when {
  resource.credential_access == false
};`,
  )
  assert.equal(typeof body.policy_bundle.created_at, "string")

  await server.close()
  await database.close()
})
