import assert from "node:assert/strict"
import test from "node:test"

import { buildServer } from "./server.ts"
import { createTestDatabase } from "./test-database.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"

test("GET /dashboard/metrics renders pilot totals for operators", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const response = await server.inject({
    method: "GET",
    url: "/dashboard/metrics?tenant_id=t_demo",
  })

  assert.equal(response.statusCode, 200)
  assert.match(response.body, /ActantOS Metrics/u)
  assert.match(response.body, /Backed by <code>\/v1\/metrics\/usage<\/code>/u)
  assert.match(response.body, /Sessions/u)

  await server.close()
  await database.close()
})
