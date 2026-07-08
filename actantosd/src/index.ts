import { createDatabase } from "./database.ts"
import { buildServer } from "./server.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"

const port = Number.parseInt(process.env["PORT"] ?? "3100", 10)
const host = process.env["HOST"] ?? "0.0.0.0"
const databaseUrl = process.env["DATABASE_URL"]
const rawApiKey = process.env["ACTANTOS_API_KEY"]?.trim()
const apiKey = rawApiKey !== undefined && rawApiKey.length > 0 ? rawApiKey : undefined
const hmacSecret = process.env["HMAC_SECRET"]

const bootstrap = async (): Promise<void> => {
  if (databaseUrl !== undefined) {
    const database = createDatabase(databaseUrl)

    const server = buildServer({
      ...(apiKey === undefined ? {} : { apiKey }),
      ...(hmacSecret === undefined ? {} : { hmacSecret }),
      repository: new PostgresToolCallRepository(database),
      database,
    })

    await server.listen({ port, host })
    server.log.info({ host, port }, "actantosd listening")
    return
  }

  const server = buildServer({
    ...(apiKey === undefined ? {} : { apiKey }),
    ...(hmacSecret === undefined ? {} : { hmacSecret }),
  })
  await server.listen({ port, host })
  server.log.info({ host, port }, "actantosd listening")
}

bootstrap()
  .catch((error: unknown) => {
    console.error(error)
    process.exitCode = 1
  })
