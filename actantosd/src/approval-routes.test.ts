import assert from "node:assert/strict"
import test from "node:test"

import { newDb } from "pg-mem"

import type { Database } from "./database.ts"
import { migrateDatabase, seedDemoData } from "./database.ts"
import { buildServer } from "./server.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"

const approvalRequest = {
  request_id: "req_pending_approval_0001",
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
    id: "git push --dry-run origin main",
    kind: "shell_command",
    path: "git push --dry-run origin main",
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

test("GET /v1/approvals/pending returns pending approvals for the dashboard", async () => {
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
    payload: approvalRequest,
  })

  assert.equal(interceptResponse.statusCode, 200)
  assert.equal(interceptResponse.json().decision, "approval_required")

  const response = await server.inject({
    method: "GET",
    url: "/v1/approvals/pending?tenant_id=t_demo",
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), {
    tenant_id: "t_demo",
    approvals: [
      {
        approval_id: interceptResponse.json().approval.approval_id,
        status: "pending",
        expires_at: interceptResponse.json().approval.expires_at,
        created_at: response.json().approvals[0].created_at,
        decision_id: response.json().approvals[0].decision_id,
        request_id: "req_pending_approval_0001",
        reason: "risk.shell.git_push — approval required",
        reason_code: "approval_required",
        tool: {
          kind: "shell",
          name: "guarded_bash",
        },
        session_id: "s_demo",
        agent_id: "pi_demo",
      },
    ],
  })
  assert.equal(typeof response.json().approvals[0].created_at, "string")
  assert.equal(typeof response.json().approvals[0].decision_id, "string")

  await server.close()
  await database.close()
})

test("POST /v1/approvals/:approval_id/decide rejects an unknown approver user for the tenant", async () => {
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
    payload: approvalRequest,
  })

  assert.equal(interceptResponse.statusCode, 200)
  assert.equal(interceptResponse.json().decision, "approval_required")

  const approvalId = interceptResponse.json().approval?.approval_id
  assert.equal(typeof approvalId, "string")

  const response = await server.inject({
    method: "POST",
    url: `/v1/approvals/${approvalId}/decide`,
    payload: {
      decision: "approved",
      approver_user_id: "u_missing",
    },
  })

  assert.equal(response.statusCode, 400)
  assert.deepEqual(response.json(), {
    error: "invalid_request",
    message: "approver_user_id must reference an existing tenant user",
  })

  await server.close()
  await database.close()
})

test("POST /v1/approvals/:approval_id/decide rejects replay after the approval is already decided", async () => {
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
      ...approvalRequest,
      request_id: "req_pending_approval_replay_0001",
    },
  })

  assert.equal(interceptResponse.statusCode, 200)
  assert.equal(interceptResponse.json().decision, "approval_required")

  const approvalId = interceptResponse.json().approval?.approval_id
  assert.equal(typeof approvalId, "string")

  const firstDecision = await server.inject({
    method: "POST",
    url: `/v1/approvals/${approvalId}/decide`,
    payload: {
      decision: "approved",
      approver_user_id: "u_admin",
    },
  })

  assert.equal(firstDecision.statusCode, 200)
  assert.equal(firstDecision.json().decision, "approved")

  const replayDecision = await server.inject({
    method: "POST",
    url: `/v1/approvals/${approvalId}/decide`,
    payload: {
      decision: "denied",
      approver_user_id: "u_admin",
    },
  })

  assert.equal(replayDecision.statusCode, 409)
  assert.deepEqual(replayDecision.json(), {
    error: "approval_not_pending",
    message: "approval has already been decided",
  })

  await server.close()
  await database.close()
})
