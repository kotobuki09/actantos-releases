import { pathToFileURL } from "node:url"

import { createDatabase, migrateDatabase, seedDemoData } from "./database.ts"

const COMMANDS = {
  migrate: "migrate",
  "seed-demo": "seed-demo",
} as const

type DatabaseAdminCommand = (typeof COMMANDS)[keyof typeof COMMANDS]

export const parseDatabaseAdminCommand = (
  value: string | undefined,
): DatabaseAdminCommand => {
  if (value === COMMANDS.migrate || value === COMMANDS["seed-demo"]) {
    return value
  }

  throw new Error("Expected a database command: migrate | seed-demo")
}

const requireDatabaseUrl = (value: string | undefined): string => {
  if (value !== undefined && value.length > 0) {
    return value
  }

  throw new Error("DATABASE_URL is required for database admin commands")
}

export const runDatabaseAdminCommand = async (
  command: DatabaseAdminCommand,
  databaseUrl: string,
): Promise<void> => {
  const database = createDatabase(databaseUrl)

  try {
    await migrateDatabase(database)

    if (command === COMMANDS["seed-demo"]) {
      await seedDemoData(database)
    }
  } finally {
    await database.close()
  }
}

const main = async (): Promise<void> => {
  const command = parseDatabaseAdminCommand(process.argv[2])
  const databaseUrl = requireDatabaseUrl(process.env["DATABASE_URL"])
  await runDatabaseAdminCommand(command, databaseUrl)
}

const entrypointPath = process.argv[1]

if (entrypointPath !== undefined && import.meta.url === pathToFileURL(entrypointPath).href) {
  main().catch((error: unknown) => {
    console.error(error)
    process.exitCode = 1
  })
}
