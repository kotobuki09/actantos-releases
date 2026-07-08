import assert from "node:assert/strict"
import test from "node:test"

import { safeReadRequest } from "./intercept-test-fixtures.ts"
import { buildServer } from "./server.ts"
import { createTestDatabase } from "./test-database.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"

test("GET /v1/budgets returns tenant budget usage", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })

  await database.query(
    `
      INSERT INTO budgets (
        id,
        tenant_id,
        scope_type,
        scope_id,
        metric,
        limit_value,
        window_seconds,
        current_value,
        window_start
      )
      VALUES (
        '00000000-0000-0000-0000-000000000101',
        't_demo',
        'tool',
        'guarded_read',
        'tool_calls',
        10,
        60,
        3,
        '2026-01-01T00:00:00.000Z'
      )
    `,
  )
  await server.ready()

  const response = await server.inject({
    method: "GET",
    url: "/v1/budgets?tenant_id=t_demo",
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), {
    tenant_id: "t_demo",
    budgets: [
      {
        id: "00000000-0000-0000-0000-000000000101",
        tenant_id: "t_demo",
        scope_type: "tool",
        scope_id: "guarded_read",
        metric: "tool_calls",
        limit_value: 10,
        window_seconds: 60,
        current_value: 3,
        window_start: "2026-01-01T00:00:00.000Z",
      },
    ],
  })

  await server.close()
  await database.close()
})

test("POST /v1/budgets creates a budget limit for a scope", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const response = await server.inject({
    method: "POST",
    url: "/v1/budgets",
    payload: {
      tenant_id: "t_demo",
      scope_type: "tenant",
      scope_id: "t_demo",
      metric: "tool_calls",
      limit_value: 5,
      window_seconds: 60,
    },
  })

  assert.equal(response.statusCode, 201)
  assert.equal(response.json().budget.tenant_id, "t_demo")
  assert.equal(response.json().budget.scope_type, "tenant")
  assert.equal(response.json().budget.limit_value, 5)
  assert.equal(response.json().budget.current_value, 0)

  await server.close()
  await database.close()
})

test("POST /v1/budgets replaces an existing scope metric budget", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  await server.inject({
    method: "POST",
    url: "/v1/budgets",
    payload: {
      tenant_id: "t_demo",
      scope_type: "tool",
      scope_id: "guarded_read",
      metric: "tool_calls",
      limit_value: 5,
      window_seconds: 60,
    },
  })
  const response = await server.inject({
    method: "POST",
    url: "/v1/budgets",
    payload: {
      tenant_id: "t_demo",
      scope_type: "tool",
      scope_id: "guarded_read",
      metric: "tool_calls",
      limit_value: 9,
      window_seconds: 120,
    },
  })
  const rows = await database.query<{ readonly count: string | number }>(
    `
      SELECT count(*) AS count
      FROM budgets
      WHERE tenant_id = $1 AND scope_type = $2 AND scope_id = $3 AND metric = $4
    `,
    ["t_demo", "tool", "guarded_read", "tool_calls"],
  )

  assert.equal(response.statusCode, 201)
  assert.equal(response.json().budget.limit_value, 9)
  assert.equal(response.json().budget.window_seconds, 120)
  assert.equal(Number(rows[0]?.count), 1)

  await server.close()
  await database.close()
})

test("POST /v1/budgets configures a limit enforced by intercept", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const budgetResponse = await server.inject({
    method: "POST",
    url: "/v1/budgets",
    payload: {
      tenant_id: "t_demo",
      scope_type: "tool",
      scope_id: "guarded_read",
      metric: "tool_calls",
      limit_value: 1,
      window_seconds: 60,
    },
  })
  const firstDecision = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: safeReadRequest("req_budget_route_enforce_0001"),
  })
  const secondDecision = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: safeReadRequest("req_budget_route_enforce_0002"),
  })

  assert.equal(budgetResponse.statusCode, 201)
  assert.equal(firstDecision.statusCode, 200)
  assert.equal(firstDecision.json().decision, "allow")
  assert.equal(secondDecision.statusCode, 200)
  assert.equal(secondDecision.json().decision, "deny")
  assert.equal(secondDecision.json().reason_code, "budget_exceeded")

  await server.close()
  await database.close()
})

test("configured expired budget window resets before intercept enforcement", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await database.query(
    `
      INSERT INTO budgets (
        id,
        tenant_id,
        scope_type,
        scope_id,
        metric,
        limit_value,
        window_seconds,
        current_value,
        window_start
      )
      VALUES (
        '00000000-0000-0000-0000-000000000102',
        't_demo',
        'tool',
        'guarded_read',
        'tool_calls',
        1,
        1,
        1,
        '2026-01-01T00:00:00.000Z'
      )
    `,
  )
  await server.ready()

  const decision = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: safeReadRequest("req_budget_window_reset_0001"),
  })
  const rows = await database.query<{ readonly current_value: string | number }>(
    `
      SELECT current_value
      FROM budgets
      WHERE id = '00000000-0000-0000-0000-000000000102'
    `,
  )

  assert.equal(decision.statusCode, 200)
  assert.equal(decision.json().decision, "allow")
  assert.equal(Number(rows[0]?.current_value), 1)

  await server.close()
  await database.close()
})
