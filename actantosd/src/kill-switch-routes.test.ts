import assert from "node:assert/strict"
import test from "node:test"

import { newDb } from "pg-mem"

import type { Database } from "./database.ts"
import { migrateDatabaseForUnitTests, seedDemoData } from "./database.ts"
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

  await migrateDatabaseForUnitTests(database)
  await seedDemoData(database)

  return database
}

test("GET /v1/kill-switches returns active kill switches for ops visibility", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })

  await server.ready()

  const createResponse = await server.inject({
    method: "POST",
    url: "/v1/kill-switches",
    payload: {
      tenant_id: "t_demo",
      scope_type: "agent",
      scope_id: "pi_demo",
      reason: "maintenance window",
    },
  })

  assert.equal(createResponse.statusCode, 201)

  const listResponse = await server.inject({
    method: "GET",
    url: "/v1/kill-switches?tenant_id=t_demo",
  })

  assert.equal(listResponse.statusCode, 200)
  assert.deepEqual(listResponse.json(), {
    tenant_id: "t_demo",
    kill_switches: [
      {
        id: createResponse.json().id,
        tenant_id: "t_demo",
        scope_type: "agent",
        scope_id: "pi_demo",
        reason: "maintenance window",
        enabled: true,
        created_at: listResponse.json().kill_switches[0].created_at,
      },
    ],
  })
  assert.equal(typeof listResponse.json().kill_switches[0].created_at, "string")

  await server.close()
  await database.close()
})
