import assert from "node:assert/strict"
import test from "node:test"

import { buildServer } from "./server.ts"
import { createTestDatabase } from "./test-database.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"

test("GET /v1/sessions returns seeded sessions for the dashboard", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const response = await server.inject({
    method: "GET",
    url: "/v1/sessions?tenant_id=t_demo",
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), {
    tenant_id: "t_demo",
    filters: {
      status: null,
      agent_id: null,
    },
    sessions: [
      {
        id: "22222222-2222-2222-2222-222222222222",
        external_id: "s_demo",
        tenant_id: "t_demo",
        agent_id: "11111111-1111-1111-1111-111111111111",
        user_id: "u_demo",
        purpose: "Week 1 demo session",
        cwd: "/workspace",
        status: "active",
        started_at: response.json().sessions[0].started_at,
        ended_at: null,
        agent: {
          external_id: "pi_demo",
          name: "Pi Demo Agent",
        },
      },
    ],
  })
  assert.equal(typeof response.json().sessions[0].started_at, "string")

  await server.close()
  await database.close()
})

test("GET /v1/sessions returns an empty list for a tenant with no sessions", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const response = await server.inject({
    method: "GET",
    url: "/v1/sessions?tenant_id=t_empty",
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), {
    tenant_id: "t_empty",
    filters: {
      status: null,
      agent_id: null,
    },
    sessions: [],
  })

  await server.close()
  await database.close()
})

test("GET /v1/sessions filters by status and agent_id", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const active = await server.inject({
    method: "GET",
    url: "/v1/sessions?tenant_id=t_demo&status=active&agent_id=pi_demo",
  })
  assert.equal(active.statusCode, 200)
  assert.equal(active.json().sessions.length, 1)
  assert.equal(active.json().filters.status, "active")
  assert.equal(active.json().filters.agent_id, "pi_demo")

  const missing = await server.inject({
    method: "GET",
    url: "/v1/sessions?tenant_id=t_demo&status=ended",
  })
  assert.equal(missing.statusCode, 200)
  assert.deepEqual(missing.json().sessions, [])
  assert.equal(missing.json().filters.status, "ended")

  await server.close()
  await database.close()
})
