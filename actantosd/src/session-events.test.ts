import assert from "node:assert/strict"
import test from "node:test"

import { newDb } from "pg-mem"

import type { Database } from "./database.ts"
import { migrateDatabase, seedDemoData } from "./database.ts"
import { buildServer } from "./server.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"

const baseRequest = {
  request_id: "req_events_0001",
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
} as const

const createTestDatabase = async (): Promise<Database> => {
  const memoryDb = newDb()
  const adapter = memoryDb.adapters.createPg()
  const { Pool } = adapter
  const pool = new Pool()

  const database: Database = {
    async query(sql, params = []) {
      const result = await pool.query(sql, [...params])
      return result.rows
    },
    async transaction(callback) {
      const client = await pool.connect()

      try {
        await client.query("BEGIN")
        const result = await callback({
          async query(sql, params = []) {
            const queryResult = await client.query(sql, [...params])
            return queryResult.rows
          },
        })
        await client.query("COMMIT")
        return result
      } catch (error) {
        await client.query("ROLLBACK")
        throw error
      } finally {
        client.release()
      }
    },
    async close() {
      await pool.end()
    },
  }

  await migrateDatabase(database)
  await seedDemoData(database)

  return database
}

test("GET /v1/sessions/:session_id/events returns ordered audit timeline fields", async () => {
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
    payload: baseRequest,
  })

  assert.equal(interceptResponse.statusCode, 200)
  assert.equal(interceptResponse.json().decision, "allow")

  const decisionRows = await database.query<{ readonly id: string }>(
    `
      SELECT pd.id
      FROM policy_decisions pd
      INNER JOIN tool_calls tc ON tc.id = pd.tool_call_id
      WHERE tc.tenant_id = $1 AND tc.request_id = $2
    `,
    [baseRequest.tenant_id, baseRequest.request_id],
  )
  const decisionId = decisionRows[0]?.id

  if (decisionId === undefined) {
    throw new Error("missing decision row")
  }

  const toolResultResponse = await server.inject({
    method: "POST",
    url: "/v1/tool-result",
    payload: {
      request_id: baseRequest.request_id,
      decision_id: decisionId,
      decision_token: interceptResponse.json().decision_token,
      tool_kind: "file",
      status: "executed",
      started_at: new Date().toISOString(),
      finished_at: new Date().toISOString(),
      result: {
        exit_code: 0,
        stdout_hash: "abc123",
        stderr_hash: null,
        redacted_preview: "hello",
      },
    },
  })

  assert.equal(toolResultResponse.statusCode, 200)

  const eventsResponse = await server.inject({
    method: "GET",
    url: "/v1/sessions/s_demo/events",
  })

  assert.equal(eventsResponse.statusCode, 200)
  assert.equal(eventsResponse.json().session_id, "s_demo")
  assert.deepEqual(
    eventsResponse.json().events.map((event: Record<string, unknown>) => event["event_type"]),
    ["policy_decision.created", "tool_result.recorded"],
  )
  assert.deepEqual(eventsResponse.json().events[0]?.actor, {
    type: "system",
    id: "actantosd",
  })
  assert.equal(eventsResponse.json().events[0]?.request_id, baseRequest.request_id)
  assert.deepEqual(eventsResponse.json().events[0]?.tool, {
    kind: "file",
    name: "guarded_read",
  })
  assert.equal(typeof eventsResponse.json().events[0]?.tool_call_id, "string")
  assert.equal(typeof eventsResponse.json().events[0]?.decision_id, "string")
  assert.equal(eventsResponse.json().events[0]?.final_decision, "allow")
  assert.equal(eventsResponse.json().events[0]?.risk_class, "low")
  assert.equal(eventsResponse.json().events[0]?.reason_code, "allowed")
  assert.equal(eventsResponse.json().events[0]?.approval_id, null)
  assert.equal(typeof eventsResponse.json().events[1]?.result_hash, "string")
  assert.equal(typeof eventsResponse.json().events[0]?.event_hash, "string")
  assert.equal(typeof eventsResponse.json().events[0]?.created_at, "string")

  await server.close()
  await database.close()
})

test("POST /v1/tool-result rejects a tampered decision_token on the Postgres-backed path", async () => {
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
      ...baseRequest,
      request_id: "req_events_token_0001",
    },
  })

  assert.equal(interceptResponse.statusCode, 200)
  assert.equal(interceptResponse.json().decision, "allow")

  const decisionRows = await database.query<{ readonly id: string }>(
    `
      SELECT pd.id
      FROM policy_decisions pd
      INNER JOIN tool_calls tc ON tc.id = pd.tool_call_id
      WHERE tc.tenant_id = $1 AND tc.request_id = $2
    `,
    [baseRequest.tenant_id, "req_events_token_0001"],
  )
  const decisionId = decisionRows[0]?.id

  if (decisionId === undefined) {
    throw new Error("missing decision row")
  }

  const response = await server.inject({
    method: "POST",
    url: "/v1/tool-result",
    payload: {
      request_id: "req_events_token_0001",
      decision_id: decisionId,
      decision_token: `${String(interceptResponse.json().decision_token)}tampered`,
      tool_kind: "file",
      status: "executed",
      started_at: new Date().toISOString(),
      finished_at: new Date().toISOString(),
      result: {
        exit_code: 0,
        stdout_hash: "abc123",
      },
    },
  })

  assert.equal(response.statusCode, 403)
  assert.equal(response.json().error, "invalid_decision_token")

  await server.close()
  await database.close()
})

test("POST /v1/tool-result allows blocked status without a decision_token on the Postgres-backed path", async () => {
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
      ...baseRequest,
      request_id: "req_events_blocked_0001",
      resource: {
        id: "/workspace/.env",
        kind: "file",
        path: "/workspace/.env",
      },
      action: {
        operation: "ReadFile",
        args: { path: "/workspace/.env" },
      },
      normalized: {
        ...baseRequest.normalized,
        credential_access: true,
      },
    },
  })

  assert.equal(interceptResponse.statusCode, 200)
  assert.equal(interceptResponse.json().decision, "deny")

  const decisionRows = await database.query<{ readonly id: string }>(
    `
      SELECT pd.id
      FROM policy_decisions pd
      INNER JOIN tool_calls tc ON tc.id = pd.tool_call_id
      WHERE tc.tenant_id = $1 AND tc.request_id = $2
    `,
    [baseRequest.tenant_id, "req_events_blocked_0001"],
  )
  const decisionId = decisionRows[0]?.id

  if (decisionId === undefined) {
    throw new Error("missing decision row")
  }

  const response = await server.inject({
    method: "POST",
    url: "/v1/tool-result",
    payload: {
      request_id: "req_events_blocked_0001",
      decision_id: decisionId,
      tool_kind: "file",
      status: "blocked",
      started_at: new Date().toISOString(),
      finished_at: new Date().toISOString(),
      result: {
        error_message: "blocked by policy",
      },
    },
  })

  assert.equal(response.statusCode, 200)

  const auditEvents = await database.query<{ readonly event_type: string }>(
    `
      SELECT event_type
      FROM audit_events
      WHERE tenant_id = $1
      ORDER BY seq ASC
    `,
    [baseRequest.tenant_id],
  )

  assert.deepEqual(
    auditEvents.map((row) => row.event_type),
    ["policy_decision.created", "tool_result.recorded"],
  )

  await server.close()
  await database.close()
})

test("GET /v1/sessions/:session_id/events includes approval context after an approval flow", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })

  await server.ready()

  const approvalRequired = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: {
      ...baseRequest,
      request_id: "req_events_approval_0001",
      tool: {
        kind: "shell",
        name: "guarded_bash",
        operation: "ExecuteShellCommand",
        schema_hash: "",
      },
      action: {
        operation: "ExecuteShellCommand",
        args: {
          command: "git push --dry-run origin main",
          argv: ["git", "push", "--dry-run", "origin", "main"],
        },
      },
      normalized: {
        verb: "execute",
        mutation: true,
        destructive: false,
        network: true,
        credential_access: false,
        risk_class: "high",
        command_family: "git",
        subcommand: "push",
      },
    },
  })

  assert.equal(approvalRequired.statusCode, 200)
  assert.equal(approvalRequired.json().decision, "approval_required")

  const approvalId = approvalRequired.json().approval?.approval_id
  if (typeof approvalId !== "string") {
    throw new Error("missing approval id")
  }

  const approveResponse = await server.inject({
    method: "POST",
    url: `/v1/approvals/${approvalId}/decide`,
    payload: {
      decision: "approved",
      approver_user_id: "u_admin",
    },
  })

  assert.equal(approveResponse.statusCode, 200)
  const approvalToken = approveResponse.json().approval_token
  if (typeof approvalToken !== "string") {
    throw new Error("missing approval token")
  }

  const allowedResponse = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: {
      ...baseRequest,
      request_id: "req_events_approval_0001_exec",
      tool: {
        kind: "shell",
        name: "guarded_bash",
        operation: "ExecuteShellCommand",
        schema_hash: "",
      },
      action: {
        operation: "ExecuteShellCommand",
        args: {
          command: "git push --dry-run origin main",
          argv: ["git", "push", "--dry-run", "origin", "main"],
        },
      },
      normalized: {
        verb: "execute",
        mutation: true,
        destructive: false,
        network: true,
        credential_access: false,
        risk_class: "high",
        command_family: "git",
        subcommand: "push",
      },
      authorization: {
        prior_decision_id: approvalRequired.json().decision_id,
        approval_id: approvalId,
        approval_token: approvalToken,
      },
    },
  })

  assert.equal(allowedResponse.statusCode, 200)
  assert.equal(allowedResponse.json().decision, "allow")

  const allowedDecisionId = allowedResponse.json().decision_id
  const allowedDecisionToken = allowedResponse.json().decision_token
  if (typeof allowedDecisionId !== "string" || typeof allowedDecisionToken !== "string") {
    throw new Error("missing allow decision context")
  }

  const toolResultResponse = await server.inject({
    method: "POST",
    url: "/v1/tool-result",
    payload: {
      request_id: "req_events_approval_0001_exec",
      decision_id: allowedDecisionId,
      decision_token: allowedDecisionToken,
      tool_kind: "shell",
      status: "executed",
      started_at: new Date().toISOString(),
      finished_at: new Date().toISOString(),
      result: {
        exit_code: 0,
        stdout_hash: "shell-stdout",
        stderr_hash: null,
        redacted_preview: "git push --dry-run completed",
      },
    },
  })

  assert.equal(toolResultResponse.statusCode, 200)

  const eventsResponse = await server.inject({
    method: "GET",
    url: "/v1/sessions/s_demo/events",
  })

  assert.equal(eventsResponse.statusCode, 200)
  const events = eventsResponse.json().events as Array<Record<string, unknown>>
  const approvalEvent = events.find((event) => event["decision_id"] === allowedDecisionId)

  assert.ok(approvalEvent)
  assert.equal(approvalEvent?.["final_decision"], "allow")
  assert.equal(approvalEvent?.["risk_class"], "high")
  assert.equal(approvalEvent?.["approval_id"], approvalId)
  assert.equal(approvalEvent?.["request_id"], "req_events_approval_0001_exec")
  assert.deepEqual(approvalEvent?.["tool"], {
    kind: "shell",
    name: "guarded_bash",
  })
  assert.equal(typeof approvalEvent?.["result_hash"], "string")

  await server.close()
  await database.close()
})
