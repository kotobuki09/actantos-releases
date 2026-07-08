import assert from "node:assert/strict"
import test from "node:test"

import { safeReadRequest } from "./intercept-test-fixtures.ts"
import { buildServer } from "./server.ts"
import { createTestDatabase } from "./test-database.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"

test("GET /v1/rate-limits returns tenant rate limits", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })

  await database.query(
    `
      INSERT INTO rate_limits (
        id,
        tenant_id,
        scope_type,
        scope_id,
        action_key,
        limit_value,
        window_seconds,
        current_value,
        window_start
      )
      VALUES (
        '00000000-0000-0000-0000-000000000201',
        't_demo',
        'tool',
        'guarded_read',
        'risk.file.readme.high',
        2,
        60,
        1,
        '2026-01-01T00:00:00.000Z'
      )
    `,
  )
  await server.ready()

  const response = await server.inject({
    method: "GET",
    url: "/v1/rate-limits?tenant_id=t_demo",
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), {
    tenant_id: "t_demo",
    rate_limits: [
      {
        id: "00000000-0000-0000-0000-000000000201",
        tenant_id: "t_demo",
        scope_type: "tool",
        scope_id: "guarded_read",
        action_key: "risk.file.readme.high",
        limit_value: 2,
        window_seconds: 60,
        current_value: 1,
        window_start: "2026-01-01T00:00:00.000Z",
      },
    ],
  })

  await server.close()
  await database.close()
})

test("PUT /v1/rate-limits stores a limit enforced on matching high-risk actions", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const riskRulesResponse = await server.inject({
    method: "PUT",
    url: "/v1/risk-rules",
    payload: {
      tenant_id: "t_demo",
      rules: [
        {
          rule_id: "risk.file.readme.high",
          description: "Mark README reads as high risk",
          when: {
            "tool.kind": "file",
            "resource.path": "/workspace/README.md",
          },
          approval_required: false,
          risk_class: "high",
        },
      ],
    },
  })
  const rateLimitResponse = await server.inject({
    method: "PUT",
    url: "/v1/rate-limits",
    payload: {
      tenant_id: "t_demo",
      scope_type: "tool",
      scope_id: "guarded_read",
      action_key: "risk.file.readme.high",
      limit_value: 1,
      window_seconds: 60,
    },
  })
  const firstDecision = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: safeReadRequest("req_rate_limit_enforce_0001"),
  })
  const secondDecision = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: safeReadRequest("req_rate_limit_enforce_0002"),
  })

  assert.equal(riskRulesResponse.statusCode, 200)
  assert.equal(rateLimitResponse.statusCode, 200)
  assert.equal(firstDecision.statusCode, 200)
  assert.equal(firstDecision.json().decision, "allow")
  assert.equal(secondDecision.statusCode, 200)
  assert.equal(secondDecision.json().decision, "deny")
  assert.equal(secondDecision.json().reason_code, "rate_limited")

  await server.close()
  await database.close()
})

test("expired rate-limit windows reset before enforcement", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })

  await server.inject({
    method: "PUT",
    url: "/v1/risk-rules",
    payload: {
      tenant_id: "t_demo",
      rules: [
        {
          rule_id: "risk.file.readme.high",
          description: "Mark README reads as high risk",
          when: {
            "tool.kind": "file",
            "resource.path": "/workspace/README.md",
          },
          approval_required: false,
          risk_class: "high",
        },
      ],
    },
  })
  await database.query(
    `
      INSERT INTO rate_limits (
        id,
        tenant_id,
        scope_type,
        scope_id,
        action_key,
        limit_value,
        window_seconds,
        current_value,
        window_start
      )
      VALUES (
        '00000000-0000-0000-0000-000000000202',
        't_demo',
        'tool',
        'guarded_read',
        'risk.file.readme.high',
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
    payload: safeReadRequest("req_rate_limit_reset_0001"),
  })
  const rows = await database.query<{ readonly current_value: string | number }>(
    `
      SELECT current_value
      FROM rate_limits
      WHERE id = '00000000-0000-0000-0000-000000000202'
    `,
  )

  assert.equal(decision.statusCode, 200)
  assert.equal(decision.json().decision, "allow")
  assert.equal(Number(rows[0]?.current_value), 1)

  await server.close()
  await database.close()
})
