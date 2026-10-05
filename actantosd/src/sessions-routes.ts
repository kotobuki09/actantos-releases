import type { FastifyInstance } from "fastify"
import { z, ZodError } from "zod"

import type { Database } from "./database.ts"

const sessionsQuerySchema = z.object({
  tenant_id: z.string().min(1).optional().default("t_demo"),
})

type SessionRow = {
  readonly id: string
  readonly external_id: string
  readonly tenant_id: string
  readonly agent_id: string
  readonly user_id: string
  readonly purpose: string | null
  readonly cwd: string | null
  readonly status: string
  readonly started_at: string | Date
  readonly ended_at: string | Date | null
  readonly agent_external_id: string
  readonly agent_name: string
}

type RegisterSessionsRoutesOptions = {
  readonly database?: Database
}

const serializeSession = (row: SessionRow) => ({
  id: row.id,
  external_id: row.external_id,
  tenant_id: row.tenant_id,
  agent_id: row.agent_id,
  user_id: row.user_id,
  purpose: row.purpose,
  cwd: row.cwd,
  status: row.status,
  started_at: new Date(row.started_at).toISOString(),
  ended_at: row.ended_at === null ? null : new Date(row.ended_at).toISOString(),
  agent: {
    external_id: row.agent_external_id,
    name: row.agent_name,
  },
})

export const listSessions = async (
  database: Database | undefined,
  tenantId: string,
): Promise<readonly ReturnType<typeof serializeSession>[]> => {
  if (database === undefined) {
    return []
  }

  const rows = await database.query<SessionRow>(
    `
      SELECT sessions.id,
             sessions.external_id,
             sessions.tenant_id,
             sessions.agent_id,
             sessions.user_id,
             sessions.purpose,
             sessions.cwd,
             sessions.status,
             sessions.started_at,
             sessions.ended_at,
             agents.external_id AS agent_external_id,
             agents.name AS agent_name
      FROM sessions
      INNER JOIN agents
        ON agents.id = sessions.agent_id
      WHERE sessions.tenant_id = $1
      ORDER BY sessions.started_at DESC, sessions.external_id ASC
    `,
    [tenantId],
  )

  return rows.map(serializeSession)
}

export const registerSessionsRoutes = (
  server: FastifyInstance,
  options: RegisterSessionsRoutesOptions,
): void => {
  server.get("/v1/sessions", async (request, reply) => {
    try {
      const query = sessionsQuerySchema.parse(request.query)
      const sessions = await listSessions(options.database, query.tenant_id)

      return reply.code(200).send({
        tenant_id: query.tenant_id,
        sessions,
      })
    } catch (error) {
      if (error instanceof ZodError) {
        return reply.code(400).send({ error: "invalid_request", issues: error.issues })
      }
      throw error
    }
  })
}
