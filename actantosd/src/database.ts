import { readdir, readFile } from "node:fs/promises"
import path from "node:path"
import { fileURLToPath } from "node:url"
import { AsyncLocalStorage } from "node:async_hooks"

import { CompiledQuery, Kysely, PostgresDialect } from "kysely"
import { Pool } from "pg"

import type { ActantDatabaseSchema } from "./database-schema.ts"

export const tenantLocalStorage = new AsyncLocalStorage<string>()

/**
 * Validates a tenant ID to prevent SQL injection via SET LOCAL interpolation.
 * Only alphanumeric, dash, and underscore characters are allowed.
 */
const TENANT_ID_SAFE = /^[a-zA-Z0-9_-]+$/

const sanitizeTenantId = (value: string): string => {
  if (!TENANT_ID_SAFE.test(value)) {
    throw new Error(`invalid_tenant_id: tenant_id contains illegal characters`)
  }
  return value
}

type QueryRow = Record<string, unknown>

export interface DatabaseClient {
  readonly db?: Kysely<ActantDatabaseSchema>
  query<TRow extends QueryRow = QueryRow>(
    sql: string,
    params?: readonly unknown[],
  ): Promise<readonly TRow[]>
}

export interface Database extends DatabaseClient {
  close(): Promise<void>
  transaction<T>(
    callback: (client: DatabaseClient) => Promise<T>,
  ): Promise<T>
}

export const parsePgBigInt = (
  value: string | number | bigint | undefined,
): bigint => {
  if (typeof value === "bigint") {
    return value
  }
  if (typeof value === "number") {
    return BigInt(value)
  }
  if (typeof value === "string") {
    return BigInt(value)
  }
  return 0n
}

export class PostgresDatabase implements Database {
  readonly db: Kysely<ActantDatabaseSchema>

  constructor(pool: Pool) {
    this.db = new Kysely<ActantDatabaseSchema>({
      dialect: new PostgresDialect({ pool }),
    })
  }

  async query<TRow extends QueryRow = QueryRow>(
    sql: string,
    params: readonly unknown[] = [],
  ): Promise<readonly TRow[]> {
    const tenantId = tenantLocalStorage.getStore()
    if (tenantId) {
      const safeTenantId = sanitizeTenantId(tenantId)
      return this.db.transaction().execute(async (trx) => {
        try {
          await trx.executeQuery(
            CompiledQuery.raw(`SET LOCAL actantos.tenant_id = '${safeTenantId}'`),
          )
        } catch (error: any) {
          if (
            error &&
            typeof error.message === "string" &&
            (error.message.includes("unrecognized configuration parameter") ||
              error.message.includes("pg-mem"))
          ) {
            console.warn("Unrecognized configuration parameter actantos.tenant_id in transaction query")
          } else {
            throw error
          }
        }
        const result = await trx.executeQuery<TRow>(
          CompiledQuery.raw(sql, [...params]),
        )
        return result.rows
      })
    }

    const result = await this.db.executeQuery<TRow>(
      CompiledQuery.raw(sql, [...params]),
    )
    return result.rows
  }

  async transaction<T>(
    callback: (client: DatabaseClient) => Promise<T>,
  ): Promise<T> {
    return this.db.transaction().execute(async (transaction) => {
      const tenantId = tenantLocalStorage.getStore()
      if (tenantId) {
        const safeTenantId = sanitizeTenantId(tenantId)
        try {
          await transaction.executeQuery(
            CompiledQuery.raw(`SET LOCAL actantos.tenant_id = '${safeTenantId}'`),
          )
        } catch (error: any) {
          if (
            error &&
            typeof error.message === "string" &&
            (error.message.includes("unrecognized configuration parameter") ||
              error.message.includes("pg-mem"))
          ) {
            console.warn("Unrecognized configuration parameter actantos.tenant_id in transaction block")
          } else {
            throw error
          }
        }
      }
      return callback(createQueryClient(transaction))
    })
  }

  async close(): Promise<void> {
    await this.db.destroy()
  }
}

const createQueryClient = (
  queryable: Kysely<ActantDatabaseSchema>,
): DatabaseClient => ({
  db: queryable,
  async query<TRow extends QueryRow = QueryRow>(
    sql: string,
    params: readonly unknown[] = [],
  ): Promise<readonly TRow[]> {
    const result = await queryable.executeQuery<TRow>(
      CompiledQuery.raw(sql, [...params]),
    )
    return result.rows
  },
})

const currentDirectory = path.dirname(fileURLToPath(import.meta.url))
const projectRoot = path.resolve(currentDirectory, "..")

export const runSqlDirectory = async (
  database: DatabaseClient,
  relativeDirectoryPath: string,
  rootDirectory: string = projectRoot,
): Promise<void> => {
  const directoryPath = path.join(rootDirectory, relativeDirectoryPath)
  const directoryEntries = await readdir(directoryPath, { withFileTypes: true })
  const sqlFileNames = directoryEntries
    .filter((entry) => entry.isFile() && entry.name.endsWith(".sql"))
    .map((entry) => entry.name)
    .sort((left, right) => left.localeCompare(right))

  for (const sqlFileName of sqlFileNames) {
    const sql = await readFile(path.join(directoryPath, sqlFileName), "utf8")
    await database.query(sql)
  }
}

export const createDatabase = (connectionString: string): Database =>
  new PostgresDatabase(
    new Pool({
      connectionString,
    }),
  )

export const migrateDatabase = async (database: Database): Promise<void> => {
  await runSqlDirectory(database, "sql/migrations")
}

export const seedDemoData = async (database: Database): Promise<void> => {
  await runSqlDirectory(database, "sql/seeds")
}
