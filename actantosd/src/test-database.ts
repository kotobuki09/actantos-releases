import { newDb } from "pg-mem"

import type { Database } from "./database.ts"
import { migrateDatabase, seedDemoData } from "./database.ts"

/**
 * Returns true if the SQL block should be silently skipped in the pg-mem test
 * environment. Postgres-only DDL (triggers, RLS, roles) is marked with the
 * sentinel comment `-- actantos-pg-only` at the top of the migration file, or
 * the trigger-function snippet that pg-mem cannot parse.
 */
const isPgMemUnsupported = (sql: string): boolean =>
  sql.includes("-- actantos-pg-only") ||
  sql.includes("CREATE OR REPLACE FUNCTION enforce_tool_call_state_transitions") ||
  sql.includes("CREATE TRIGGER trg_enforce_tool_call_transitions")

export const createTestDatabase = async (): Promise<Database> => {
  const memoryDb = newDb()
  const adapter = memoryDb.adapters.createPg()
  const { Pool } = adapter
  const pool = new Pool()

  const database: Database = {
    async query(sql, params = []) {
      if (isPgMemUnsupported(sql)) {
        return []
      }
      const result = await pool.query(sql, [...params])
      return result.rows
    },
    async transaction(callback) {
      const client = await pool.connect()

      try {
        await client.query("BEGIN")
        const result = await callback({
          async query(sql, params = []) {
            if (isPgMemUnsupported(sql)) {
              return []
            }
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
