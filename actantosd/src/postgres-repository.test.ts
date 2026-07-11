import assert from "node:assert/strict"
import test from "node:test"

import { newDb } from "pg-mem"

import type { ToolCallInterceptionRequest } from "./contracts.ts"
import { migrateDatabaseForUnitTests, seedDemoData, type Database } from "./database.ts"
import { createInterceptService } from "./intercept-service.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"

const baseRequest = (): ToolCallInterceptionRequest => ({
  request_id: "req_20000001",
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

  await migrateDatabaseForUnitTests(database)
  await seedDemoData(database)

  return database
}

test("Given a Postgres-backed repository when intercepting twice Then no duplicate decision rows are created", async () => {
  const database = await createTestDatabase()
  const repository = new PostgresToolCallRepository(database)
  const service = createInterceptService({ repository, hmacSecret: "test-secret" })
  const request = baseRequest()

  const first = await service.intercept(request)
  const second = await service.intercept(request)

  const toolCalls = await database.query<{ readonly count: string }>(
    "SELECT COUNT(*)::text AS count FROM tool_calls WHERE tenant_id = $1 AND request_id = $2",
    [request.tenant_id, request.request_id],
  )
  const decisions = await database.query<{ readonly count: string }>(
    "SELECT COUNT(*)::text AS count FROM policy_decisions WHERE tenant_id = $1 AND request_id = $2",
    [request.tenant_id, request.request_id],
  )
  const auditEvents = await database.query<{ readonly seq: number }>(
    "SELECT seq FROM audit_events WHERE tenant_id = $1 ORDER BY seq ASC",
    [request.tenant_id],
  )

  assert.deepEqual(second, first)
  assert.equal(toolCalls[0]?.count, "1")
  assert.equal(decisions[0]?.count, "1")
  assert.deepEqual(auditEvents.map((row) => row.seq), [1])

  await database.close()
})
