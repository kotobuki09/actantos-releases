import assert from "node:assert/strict"
import test from "node:test"

import { safeReadRequest } from "./intercept-test-fixtures.ts"
import { buildServer } from "./server.ts"
import { createTestDatabase } from "./test-database.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"

test("GET /v1/risk-rules returns the file fallback when no tenant rules are stored", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const response = await server.inject({
    method: "GET",
    url: "/v1/risk-rules?tenant_id=t_demo",
  })

  assert.equal(response.statusCode, 200)
  assert.equal(response.json().risk_rule_set.tenant_id, "t_demo")
  assert.equal(response.json().risk_rule_set.source, "file_fallback")
  assert.equal(Array.isArray(response.json().risk_rule_set.rules), true)
  assert.equal(response.json().risk_rule_set.rules[0]?.rule_id, "risk.shell.ambiguous")

  await server.close()
  await database.close()
})

test("PUT /v1/risk-rules stores a tenant risk rule set", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const response = await server.inject({
    method: "PUT",
    url: "/v1/risk-rules",
    payload: {
      tenant_id: "t_demo",
      rules: [
        {
          rule_id: "risk.file.readme.approval",
          description: "Require approval for README reads",
          when: {
            "tool.kind": "file",
            "resource.path": "/workspace/README.md",
          },
          approval_required: true,
          risk_class: "medium",
        },
      ],
    },
  })

  assert.equal(response.statusCode, 200)
  assert.equal(response.json().risk_rule_set.source, "database")
  assert.equal(response.json().risk_rule_set.rules[0]?.rule_id, "risk.file.readme.approval")

  const rows = await database.query<{ rules_json: unknown }>(
    "SELECT rules_json FROM risk_rule_sets WHERE tenant_id = $1",
    ["t_demo"],
  )
  assert.equal(Array.isArray(rows[0]?.rules_json), true)

  await server.close()
  await database.close()
})

test("PUT /v1/risk-rules updates runtime enforcement for subsequent intercepts", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const updateResponse = await server.inject({
    method: "PUT",
    url: "/v1/risk-rules",
    payload: {
      tenant_id: "t_demo",
      rules: [
        {
          rule_id: "risk.file.readme.approval",
          description: "Require approval for README reads",
          when: {
            "tool.kind": "file",
            "resource.path": "/workspace/README.md",
          },
          approval_required: true,
          risk_class: "medium",
        },
      ],
    },
  })
  const interceptResponse = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: safeReadRequest("req_risk_rule_update_0001"),
  })

  assert.equal(updateResponse.statusCode, 200)
  assert.equal(interceptResponse.statusCode, 200)
  assert.equal(interceptResponse.json().decision, "approval_required")
  assert.equal(
    interceptResponse.json().reason,
    "risk.file.readme.approval — approval required",
  )

  await server.close()
  await database.close()
})
