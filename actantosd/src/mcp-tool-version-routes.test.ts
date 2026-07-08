import assert from "node:assert/strict"
import test from "node:test"

import { newDb } from "pg-mem"

import type { Database } from "./database.ts"
import { migrateDatabase, seedDemoData } from "./database.ts"
import { buildServer } from "./server.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"

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

const createMcpRequest = (requestId: string, schemaHash: string) => ({
  request_id: requestId,
  tenant_id: "t_demo",
  agent: {
    id: "pi_demo",
    runtime_type: "pi",
    environment: "dev",
    risk_tier: "low",
  },
  subject: {
    user_id: "u_demo",
  },
  session: {
    id: "s_demo",
    cwd: "/workspace",
  },
  tool: {
    kind: "mcp",
    name: "read_repo_file",
    operation: "tools/call",
    schema_hash: schemaHash,
  },
  action: {
    operation: "tools/call",
    args: {
      path: "README.md",
    },
  },
  resource: {
    id: "mcp://github/tools/read_repo_file",
    kind: "mcp_tool",
    path: "/mcp/github/tools/read_repo_file",
  },
  normalized: {
    verb: "read",
    mutation: false,
    destructive: false,
    network: false,
    credential_access: false,
    risk_class: "low",
  },
  mcp: {
    server_id: "github",
    server_identity_hash: "server-hash-v1",
    tool_name: "read_repo_file",
    tool_schema_hash: schemaHash,
    tool_description_hash: "description-v1",
    transport: "sse",
  },
})

test("Given a drifted MCP tool version when listing pending versions Then the route returns it for approval", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    database,
    repository: new PostgresToolCallRepository(database),
  })
  await server.ready()

  await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: createMcpRequest("req_pending_0001", "schema-v1"),
  })
  await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: createMcpRequest("req_pending_0002", "schema-v2"),
  })

  const response = await server.inject({
    method: "GET",
    url: "/v1/mcp/tool-versions/pending?tenant_id=t_demo",
  })

  assert.equal(response.statusCode, 200)
  assert.equal(response.json().tool_versions.length, 1)
  assert.equal(response.json().tool_versions[0].tool_name, "read_repo_file")
  assert.equal(response.json().tool_versions[0].schema_hash, "schema-v2")

  await server.close()
  await database.close()
})

test("Given a pending MCP tool version when it is approved Then the new manifest becomes the active baseline", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    database,
    repository: new PostgresToolCallRepository(database),
  })
  await server.ready()

  const baseline = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: createMcpRequest("req_approve_manifest_0001", "schema-v1"),
  })
  const drift = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: createMcpRequest("req_approve_manifest_0002", "schema-v2"),
  })

  assert.equal(baseline.json().decision, "allow")
  assert.equal(drift.json().reason_code, "schema_hash_mismatch")

  const pending = await server.inject({
    method: "GET",
    url: "/v1/mcp/tool-versions/pending?tenant_id=t_demo",
  })
  const pendingId = pending.json().tool_versions[0].id

  const approve = await server.inject({
    method: "POST",
    url: `/v1/mcp/tool-versions/${pendingId}/approve`,
  })
  const replay = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: createMcpRequest("req_approve_manifest_0003", "schema-v2"),
  })
  const approvedRows = await database.query<{
    readonly schema_hash: string
    readonly approved: boolean
  }>(
    `
      SELECT schema_hash, approved
      FROM mcp_tool_versions
      WHERE tool_name = 'read_repo_file'
      ORDER BY created_at ASC
    `,
  )

  assert.equal(approve.statusCode, 200)
  assert.equal(approve.json().approved, true)
  assert.equal(replay.json().decision, "allow")
  assert.deepEqual(
    approvedRows.map((row) => ({ schema_hash: row.schema_hash, approved: row.approved })),
    [
      { schema_hash: "schema-v1", approved: false },
      { schema_hash: "schema-v2", approved: true },
    ],
  )

  await server.close()
  await database.close()
})
