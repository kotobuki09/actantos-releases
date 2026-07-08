import assert from "node:assert/strict"
import test from "node:test"

import { buildServer } from "./server.ts"
import { createTestDatabase } from "./test-database.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"

test("GET /v1/agents returns seeded agents for the dashboard", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const response = await server.inject({
    method: "GET",
    url: "/v1/agents?tenant_id=t_demo",
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), {
    tenant_id: "t_demo",
    agents: [
      {
        id: "11111111-1111-1111-1111-111111111111",
        external_id: "pi_demo",
        tenant_id: "t_demo",
        name: "Pi Demo Agent",
        runtime_type: "pi",
        owner_user_id: "u_demo",
        environment: "dev",
        risk_tier: "low",
        status: "active",
        created_at: response.json().agents[0].created_at,
      },
    ],
  })
  assert.equal(typeof response.json().agents[0].created_at, "string")

  await server.close()
  await database.close()
})

test("GET /v1/agents returns an empty list for a tenant with no agents", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const response = await server.inject({
    method: "GET",
    url: "/v1/agents?tenant_id=t_empty",
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), {
    tenant_id: "t_empty",
    agents: [],
  })

  await server.close()
  await database.close()
})
