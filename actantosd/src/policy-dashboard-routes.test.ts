import assert from "node:assert/strict"
import test from "node:test"

import { buildServer } from "./server.ts"
import { createTestDatabase } from "./test-database.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"

test("GET /dashboard/policy renders the active bundle, upload form, and activation controls", async () => {
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
      active: false,
    },
  })
  assert.equal(createResponse.statusCode, 201)

  const response = await server.inject({
    method: "GET",
    url: "/dashboard/policy?tenant_id=t_demo",
  })

  assert.equal(response.statusCode, 200)
  assert.match(String(response.headers["content-type"]), /^text\/html/u)
  assert.match(response.body, /Policy bundles/u)
  assert.match(response.body, /Currently enforcing bundle 0\.1\.0/u)
  assert.match(response.body, /data-active-policy-source="true"/u)
  assert.match(response.body, /data-policy-create-form="true"/u)
  assert.match(response.body, /Store bundle/u)
  assert.match(response.body, /data-policy-activate="/u)
  assert.match(response.body, /\/v1\/policy-bundles\/" \+ encodeURIComponent/u)
  assert.match(response.body, /0\.2\.0/u)

  await server.close()
  await database.close()
})
