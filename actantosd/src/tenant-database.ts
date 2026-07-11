import type { Database, DatabaseClient } from "./database.ts"

export const tenantContextSql = "SELECT set_config('actantos.tenant_id', $1, true)"

export const withTenantTransaction = async <T>(
  database: Database,
  tenantId: string,
  callback: (client: DatabaseClient) => Promise<T>,
): Promise<T> => database.transaction(async (client) => {
  await client.query(tenantContextSql, [tenantId])
  return callback(client)
})
