import assert from "node:assert/strict"
import test from "node:test"

import { buildServer } from "./server.ts"
import { createTestDatabase } from "./test-database.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"

test("GET /v1/evidence/export returns a tenant evidence package with audit records", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const interceptResponse = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: {
      request_id: "req_export_allow_0001",
      tenant_id: "t_demo",
      agent: {
        id: "pi_demo",
        runtime_type: "pi",
        environment: "dev",
        risk_tier: "low",
      },
      subject: {
        user_id: "u_demo",
        role: "developer",
      },
      session: {
        id: "s_demo",
        cwd: "/workspace",
        budget_remaining_cents: 10_000,
      },
      tool: {
        kind: "file",
        name: "guarded_read",
        operation: "ReadFile",
        schema_hash: "",
      },
      resource: {
        id: "/workspace/README.md",
        kind: "file",
        path: "/workspace/README.md",
      },
      action: {
        operation: "ReadFile",
        args: { path: "/workspace/README.md" },
      },
      normalized: {
        verb: "read",
        mutation: false,
        destructive: false,
        network: false,
        credential_access: false,
        risk_class: "low",
      },
    },
  })

  assert.equal(interceptResponse.statusCode, 200)
  const decisionRows = await database.query<{ readonly id: string }>(
    `
      SELECT pd.id
      FROM policy_decisions pd
      INNER JOIN tool_calls tc ON tc.id = pd.tool_call_id
      WHERE tc.tenant_id = $1 AND tc.request_id = $2
    `,
    ["t_demo", "req_export_allow_0001"],
  )
  const decisionId = decisionRows[0]?.id
  if (decisionId === undefined) {
    throw new Error("missing decision row")
  }

  const toolResultResponse = await server.inject({
    method: "POST",
    url: "/v1/tool-result",
    payload: {
      request_id: "req_export_allow_0001",
      decision_id: decisionId,
      decision_token: interceptResponse.json().decision_token,
      tool_kind: "file",
      status: "executed",
      started_at: new Date().toISOString(),
      finished_at: new Date().toISOString(),
      result: {
        exit_code: 0,
        stdout_hash: "export-stdout",
        stderr_hash: null,
        redacted_preview: "README read",
      },
    },
  })

  assert.equal(toolResultResponse.statusCode, 200)

  const exportResponse = await server.inject({
    method: "GET",
    url: "/v1/evidence/export?tenant_id=t_demo&session_id=s_demo",
  })

  assert.equal(exportResponse.statusCode, 200)
  assert.match(String(exportResponse.headers["content-disposition"]), /actantos-evidence-t_demo-s_demo\.json/u)
  assert.deepEqual(exportResponse.json().tenant_id, "t_demo")
  assert.deepEqual(exportResponse.json().session_id, "s_demo")
  assert.equal(exportResponse.json().summary.session_count, 1)
  assert.ok(exportResponse.json().summary.decision_count >= 1)
  assert.ok(exportResponse.json().summary.audit_event_count >= 2)
  assert.match(JSON.stringify(exportResponse.json().decisions), /req_export_allow_0001/u)
  assert.match(JSON.stringify(exportResponse.json().audit_timelines), /tool_result\.recorded/u)

  await server.close()
  await database.close()
})
