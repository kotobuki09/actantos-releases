import assert from "node:assert/strict"
import test from "node:test"

import { newDb } from "pg-mem"

import { PostgresBudgetProvider } from "./budget-provider.ts"
import { migrateDatabaseForUnitTests, seedDemoData, type Database } from "./database.ts"

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

test("PostgresBudgetProvider denies when the matching budget is exhausted", async () => {
  const database = await createTestDatabase()
  const provider = new PostgresBudgetProvider(database)

  await database.query(
    `
      INSERT INTO budgets (
        id, tenant_id, scope_type, scope_id, metric, limit_value,
        window_seconds, current_value
      ) VALUES (
        '44444444-4444-4444-4444-444444444444',
        't_demo', 'agent', 'pi_demo', 'tool_calls', 1, 60, 1
      )
    `,
  )

  const result = await provider.checkAndConsume({
    tenantId: "t_demo",
    agentId: "pi_demo",
    sessionId: "s_demo",
    toolName: "guarded_read",
  })

  assert.equal(result.allowed, false)

  await database.close()
})

test("PostgresBudgetProvider consumes one unit when budget is available", async () => {
  const database = await createTestDatabase()
  const provider = new PostgresBudgetProvider(database)

  await database.query(
    `
      INSERT INTO budgets (
        id, tenant_id, scope_type, scope_id, metric, limit_value,
        window_seconds, current_value
      ) VALUES (
        '55555555-5555-5555-5555-555555555555',
        't_demo', 'session', 's_demo', 'tool_calls', 2, 60, 0
      )
    `,
  )

  const result = await provider.checkAndConsume({
    tenantId: "t_demo",
    agentId: "pi_demo",
    sessionId: "s_demo",
    toolName: "guarded_read",
  })
  const rows = await database.query<{ readonly current_value: number }>(
    "SELECT current_value FROM budgets WHERE id = $1",
    ["55555555-5555-5555-5555-555555555555"],
  )

  assert.equal(result.allowed, true)
  assert.equal(rows[0]?.current_value, 1)

  await database.close()
})

test("PostgresBudgetProvider denies when any matching budget scope is exhausted", async () => {
  const database = await createTestDatabase()
  const provider = new PostgresBudgetProvider(database)

  await database.query(
    `
      INSERT INTO budgets (
        id, tenant_id, scope_type, scope_id, metric, limit_value,
        window_seconds, current_value
      ) VALUES
        (
          '88888888-8888-8888-8888-888888888888',
          't_demo', 'tenant', 't_demo', 'tool_calls', 1, 60, 1
        ),
        (
          '99999999-9999-9999-9999-999999999999',
          't_demo', 'tool', 'guarded_read', 'tool_calls', 10, 60, 0
        )
    `,
  )

  const result = await provider.checkAndConsume({
    tenantId: "t_demo",
    agentId: "pi_demo",
    sessionId: "s_demo",
    toolName: "guarded_read",
  })
  const rows = await database.query<{ readonly id: string; readonly current_value: number }>(
    "SELECT id, current_value FROM budgets ORDER BY id",
  )

  assert.equal(result.allowed, false)
  assert.deepEqual(rows, [
    { id: "88888888-8888-8888-8888-888888888888", current_value: 1 },
    { id: "99999999-9999-9999-9999-999999999999", current_value: 0 },
  ])

  await database.close()
})

test("PostgresBudgetProvider consumes each matching budget scope when allowed", async () => {
  const database = await createTestDatabase()
  const provider = new PostgresBudgetProvider(database)

  await database.query(
    `
      INSERT INTO budgets (
        id, tenant_id, scope_type, scope_id, metric, limit_value,
        window_seconds, current_value
      ) VALUES
        (
          'aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa',
          't_demo', 'tenant', 't_demo', 'tool_calls', 10, 60, 0
        ),
        (
          'bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb',
          't_demo', 'tool', 'guarded_read', 'tool_calls', 10, 60, 3
        )
    `,
  )

  const result = await provider.checkAndConsume({
    tenantId: "t_demo",
    agentId: "pi_demo",
    sessionId: "s_demo",
    toolName: "guarded_read",
  })
  const rows = await database.query<{ readonly id: string; readonly current_value: number }>(
    "SELECT id, current_value FROM budgets ORDER BY id",
  )

  assert.equal(result.allowed, true)
  assert.deepEqual(rows, [
    { id: "aaaaaaaa-aaaa-4aaa-aaaa-aaaaaaaaaaaa", current_value: 1 },
    { id: "bbbbbbbb-bbbb-4bbb-bbbb-bbbbbbbbbbbb", current_value: 4 },
  ])

  await database.close()
})

test("PostgresBudgetProvider checks matching scopes without consuming when requested", async () => {
  const database = await createTestDatabase()
  const provider = new PostgresBudgetProvider(database)

  await database.query(
    `
      INSERT INTO budgets (
        id, tenant_id, scope_type, scope_id, metric, limit_value,
        window_seconds, current_value
      ) VALUES
        (
          'cccccccc-cccc-4ccc-cccc-cccccccccccc',
          't_demo', 'tenant', 't_demo', 'tool_calls', 10, 60, 0
        ),
        (
          'dddddddd-dddd-4ddd-dddd-dddddddddddd',
          't_demo', 'tool', 'guarded_read', 'tool_calls', 10, 60, 3
        )
    `,
  )

  const result = await provider.checkAndConsume({
    tenantId: "t_demo",
    agentId: "pi_demo",
    sessionId: "s_demo",
    toolName: "guarded_read",
    consume: false,
  })
  const rows = await database.query<{ readonly id: string; readonly current_value: number }>(
    "SELECT id, current_value FROM budgets ORDER BY id",
  )

  assert.equal(result.allowed, true)
  assert.deepEqual(rows, [
    { id: "cccccccc-cccc-4ccc-cccc-cccccccccccc", current_value: 0 },
    { id: "dddddddd-dddd-4ddd-dddd-dddddddddddd", current_value: 3 },
  ])

  await database.close()
})

test("PostgresBudgetProvider resets an expired budget window before consuming", async () => {
  const database = await createTestDatabase()
  const provider = new PostgresBudgetProvider(database)

  await database.query(
    `
      INSERT INTO budgets (
        id, tenant_id, scope_type, scope_id, metric, limit_value,
        window_seconds, current_value, window_start
      ) VALUES (
        '77777777-7777-7777-7777-777777777777',
        't_demo', 'tool', 'guarded_read', 'tool_calls', 1, 60, 1,
        now() - interval '120 seconds'
      )
    `,
  )

  const result = await provider.checkAndConsume({
    tenantId: "t_demo",
    agentId: "pi_demo",
    sessionId: "s_demo",
    toolName: "guarded_read",
  })
  const rows = await database.query<{ readonly current_value: number }>(
    "SELECT current_value FROM budgets WHERE id = $1",
    ["77777777-7777-7777-7777-777777777777"],
  )

  assert.equal(result.allowed, true)
  assert.equal(rows[0]?.current_value, 1)

  await database.close()
})
