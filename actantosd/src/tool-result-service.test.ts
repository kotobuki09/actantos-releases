import assert from "node:assert/strict"
import test from "node:test"

import { newDb } from "pg-mem"

import type { ToolCallInterceptionRequest } from "./contracts.ts"
import { migrateDatabase, seedDemoData, type Database } from "./database.ts"
import { signDecisionToken } from "./hash.ts"
import { createInterceptService } from "./intercept-service.ts"
import { recordToolResult } from "./tool-result-service.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"

const baseShellRequest = (): ToolCallInterceptionRequest => ({
  request_id: "req_60000001",
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
    kind: "shell",
    name: "guarded_bash",
    operation: "ExecuteShellCommand",
    schema_hash: "",
  },
  resource: {
    id: "/workspace",
    kind: "workspace",
    path: "/workspace",
  },
  action: {
    operation: "ExecuteShellCommand",
    args: {
      command: "printf hello",
      argv: ["printf", "hello"],
    },
  },
  normalized: {
    verb: "execute",
    mutation: false,
    destructive: false,
    network: false,
    credential_access: false,
    risk_class: "low",
    command_family: "printf",
    subcommand: "hello",
  },
})

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

test("recordToolResult appends an audit event and updates the tool call status", async () => {
  const database = await createTestDatabase()
  const repository = new PostgresToolCallRepository(database)
  const service = createInterceptService({ repository, hmacSecret: "test-secret" })
  const request = baseShellRequest()

  const decision = await service.intercept(request)

  assert.equal(decision.decision, "allow")
  if (decision.decision !== "allow") {
    throw new Error("expected an allow decision")
  }

  const decisionRows = await database.query<{ readonly id: string }>(
    "SELECT id FROM policy_decisions WHERE tenant_id = $1 AND request_id = $2",
    [request.tenant_id, request.request_id],
  )
  const decisionId = decisionRows[0]?.id

  if (decisionId === undefined) {
    throw new Error("missing decision row")
  }

  if (decision.decision_token === undefined) {
    throw new Error("missing decision token")
  }

  await recordToolResult(database, {
    request_id: request.request_id,
    decision_id: decisionId,
    decision_token: decision.decision_token,
    tool_kind: "shell",
    status: "executed",
    started_at: new Date().toISOString(),
    finished_at: new Date().toISOString(),
    result: {
      exit_code: 0,
      stdout_hash: "abc123",
      stderr_hash: null,
      redacted_preview: "hello",
    },
  }, "test-secret")

  const toolCalls = await database.query<{ readonly status: string }>(
    "SELECT status FROM tool_calls WHERE tenant_id = $1 AND request_id = $2",
    [request.tenant_id, request.request_id],
  )
  const auditEvents = await database.query<{
    readonly event_type: string
    readonly seq: number
  }>(
    "SELECT event_type, seq FROM audit_events WHERE tenant_id = $1 ORDER BY seq ASC",
    [request.tenant_id],
  )

  assert.equal(toolCalls[0]?.status, "executed")
  assert.deepEqual(
    auditEvents.map((row) => [row.seq, row.event_type]),
    [
      [1, "policy_decision.created"],
      [2, "tool_result.recorded"],
    ],
  )

  await database.close()
})

test("recordToolResult rejects an expired decision token", async () => {
  const database = await createTestDatabase()
  const repository = new PostgresToolCallRepository(database)
  const service = createInterceptService({ repository, hmacSecret: "test-secret" })
  const request = baseShellRequest()

  const decision = await service.intercept(request)

  assert.equal(decision.decision, "allow")
  if (decision.decision !== "allow" || decision.decision_token === undefined) {
    throw new Error("expected an allow decision with token")
  }

  const decisionRows = await database.query<{ readonly id: string }>(
    "SELECT id FROM policy_decisions WHERE tenant_id = $1 AND request_id = $2",
    [request.tenant_id, request.request_id],
  )
  const decisionId = decisionRows[0]?.id

  if (decisionId === undefined) {
    throw new Error("missing decision row")
  }

  const [encodedPayload] = decision.decision_token.split(".")
  if (encodedPayload === undefined) {
    throw new Error("invalid token format")
  }

  const payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8")) as Record<string, unknown>
  payload["exp"] = 1
  const expiredToken = signDecisionToken(JSON.stringify(payload), "test-secret")

  await assert.rejects(
    () => recordToolResult(database, {
      request_id: request.request_id,
      decision_id: decisionId,
      decision_token: expiredToken,
      tool_kind: "shell",
      status: "executed",
      started_at: new Date().toISOString(),
      finished_at: new Date().toISOString(),
      result: {
        exit_code: 0,
        stdout_hash: "abc123",
      },
    }, "test-secret"),
    /invalid_decision_token/u,
  )

  await database.close()
})

test("recordToolResult rejects a signed decision token with an invalid JSON payload", async () => {
  const database = await createTestDatabase()
  const repository = new PostgresToolCallRepository(database)
  const service = createInterceptService({ repository, hmacSecret: "test-secret" })
  const request = baseShellRequest()

  const decision = await service.intercept(request)

  assert.equal(decision.decision, "allow")
  if (decision.decision !== "allow") {
    throw new Error("expected an allow decision")
  }

  const decisionRows = await database.query<{ readonly id: string }>(
    "SELECT id FROM policy_decisions WHERE tenant_id = $1 AND request_id = $2",
    [request.tenant_id, request.request_id],
  )
  const decisionId = decisionRows[0]?.id

  if (decisionId === undefined) {
    throw new Error("missing decision row")
  }

  const invalidJsonToken = signDecisionToken("{", "test-secret")

  await assert.rejects(
    () => recordToolResult(database, {
      request_id: request.request_id,
      decision_id: decisionId,
      decision_token: invalidJsonToken,
      tool_kind: "shell",
      status: "executed",
      started_at: new Date().toISOString(),
      finished_at: new Date().toISOString(),
      result: {
        exit_code: 0,
        stdout_hash: "abc123",
      },
    }, "test-secret"),
    /invalid_decision_token/u,
  )

  await database.close()
})
