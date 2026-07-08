import assert from "node:assert/strict"
import test from "node:test"

import { newDb } from "pg-mem"

import { verifyTenantAuditChain } from "./audit-chain-verifier.ts"
import type { ToolCallInterceptionRequest } from "./contracts.ts"
import { migrateDatabase, seedDemoData, type Database } from "./database.ts"
import { createInterceptService } from "./intercept-service.ts"
import { recordToolResult } from "./tool-result-service.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"

const baseShellRequest = (): ToolCallInterceptionRequest => ({
  request_id: "req_audit_verifier_0001",
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

const createRecordedAuditChain = async (database: Database): Promise<void> => {
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
      stdout_hash: "stdout-hash",
      stderr_hash: null,
      redacted_preview: "hello",
    },
  }, "test-secret")
}

test("verifyTenantAuditChain accepts an untampered tenant chain", async () => {
  const database = await createTestDatabase()
  await createRecordedAuditChain(database)

  const result = await verifyTenantAuditChain(database, "t_demo")

  assert.deepEqual(result, {
    valid: true,
    tenantId: "t_demo",
    eventCount: 2,
  })

  await database.close()
})

test("verifyTenantAuditChain detects tampered audit payloads", async () => {
  const database = await createTestDatabase()
  await createRecordedAuditChain(database)

  await database.query(
    `
      UPDATE audit_events
      SET payload_json = '{"request_id":"tampered","status":"executed"}'::jsonb
      WHERE tenant_id = $1
        AND event_type = 'tool_result.recorded'
    `,
    ["t_demo"],
  )

  const result = await verifyTenantAuditChain(database, "t_demo")

  assert.deepEqual(result, {
    valid: false,
    tenantId: "t_demo",
    eventCount: 2,
    error: "event_hash_mismatch",
  })

  await database.close()
})
