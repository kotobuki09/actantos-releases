import { readdir, readFile } from "node:fs/promises"
import path from "node:path"
import { fileURLToPath } from "node:url"

import { CompiledQuery, Kysely, PostgresDialect } from "kysely"
import { Pool } from "pg"

import type { ActantDatabaseSchema } from "./database-schema.ts"

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

class PostgresDatabase implements Database {
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
    const result = await this.db.executeQuery<TRow>(
      CompiledQuery.raw(sql, [...params]),
    )
    return result.rows
  }

  async transaction<T>(
    callback: (client: DatabaseClient) => Promise<T>,
  ): Promise<T> {
    return this.db.transaction().execute(async (transaction) =>
      callback(createQueryClient(transaction)),
    )
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
