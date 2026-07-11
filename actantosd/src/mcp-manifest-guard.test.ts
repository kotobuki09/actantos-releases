import assert from "node:assert/strict"
import test from "node:test"

import { newDb } from "pg-mem"

import type { ToolCallInterceptionRequest } from "./contracts.ts"
import { migrateDatabaseForUnitTests, seedDemoData, type Database } from "./database.ts"
import { PostgresMcpManifestGuard } from "./mcp-manifest-guard.ts"

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

const createMcpRequest = (
  overrides: Partial<ToolCallInterceptionRequest["mcp"]> = {},
): ToolCallInterceptionRequest => ({
  request_id: "req_mcp_0001",
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
    schema_hash: "schema-v1",
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
    tool_schema_hash: "schema-v1",
    tool_description_hash: "description-v1",
    transport: "sse",
    ...overrides,
  },
})

test("Given a first-seen MCP manifest when evaluated Then it establishes an approved baseline", async () => {
  const database = await createTestDatabase()
  const guard = new PostgresMcpManifestGuard(database)

  const result = await guard.evaluate(createMcpRequest())
  const versions = await database.query<{
    readonly approved: boolean
    readonly schema_hash: string
    readonly description_hash: string
  }>(
    `
      SELECT approved, schema_hash, description_hash
      FROM mcp_tool_versions
      ORDER BY created_at ASC
    `,
  )

  assert.deepEqual(result, { allowed: true })
  assert.equal(versions.length, 1)
  assert.equal(versions[0]?.approved, true)
  assert.equal(versions[0]?.schema_hash, "schema-v1")
  assert.equal(versions[0]?.description_hash, "description-v1")

  await database.close()
})

test("Given a changed MCP tool schema when evaluated Then it is denied as schema_hash_mismatch", async () => {
  const database = await createTestDatabase()
  const guard = new PostgresMcpManifestGuard(database)

  await guard.evaluate(createMcpRequest())

  const result = await guard.evaluate(
    createMcpRequest({
      tool_schema_hash: "schema-v2",
    }),
  )
  const versions = await database.query<{
    readonly approved: boolean
    readonly schema_hash: string
  }>(
    `
      SELECT approved, schema_hash
      FROM mcp_tool_versions
      ORDER BY created_at ASC
    `,
  )

  assert.deepEqual(result, {
    allowed: false,
    reason: "MCP tool schema changed since approval",
    reasonCode: "schema_hash_mismatch",
  })
  assert.deepEqual(
    versions.map((row) => ({ approved: row.approved, schema_hash: row.schema_hash })),
    [
      { approved: true, schema_hash: "schema-v1" },
      { approved: false, schema_hash: "schema-v2" },
    ],
  )

  await database.close()
})

test("Given a changed MCP tool description when evaluated Then it is denied as manifest_drift", async () => {
  const database = await createTestDatabase()
  const guard = new PostgresMcpManifestGuard(database)

  await guard.evaluate(createMcpRequest())

  const result = await guard.evaluate(
    createMcpRequest({
      tool_description_hash: "description-v2",
    }),
  )
  const versions = await database.query<{
    readonly approved: boolean
    readonly description_hash: string
  }>(
    `
      SELECT approved, description_hash
      FROM mcp_tool_versions
      ORDER BY created_at ASC
    `,
  )

  assert.deepEqual(result, {
    allowed: false,
    reason: "MCP tool manifest drift detected",
    reasonCode: "manifest_drift",
  })
  assert.deepEqual(
    versions.map((row) => ({
      approved: row.approved,
      description_hash: row.description_hash,
    })),
    [
      { approved: true, description_hash: "description-v1" },
      { approved: false, description_hash: "description-v2" },
    ],
  )

  await database.close()
})
