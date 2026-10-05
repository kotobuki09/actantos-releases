import type { FastifyInstance } from "fastify"
import { z, ZodError } from "zod"

import type { Database } from "./database.ts"

const agentsQuerySchema = z.object({
  tenant_id: z.string().min(1).optional().default("t_demo"),
})

type AgentRow = {
  readonly id: string
  readonly external_id: string
  readonly tenant_id: string
  readonly name: string
  readonly runtime_type: string
  readonly owner_user_id: string
  readonly environment: string
  readonly risk_tier: string
  readonly status: string
  readonly created_at: string | Date
}

type RegisterAgentsRoutesOptions = {
  readonly database?: Database
}

const serializeAgent = (row: AgentRow) => ({
  id: row.id,
  external_id: row.external_id,
  tenant_id: row.tenant_id,
  name: row.name,
  runtime_type: row.runtime_type,
  owner_user_id: row.owner_user_id,
  environment: row.environment,
  risk_tier: row.risk_tier,
  status: row.status,
  created_at: new Date(row.created_at).toISOString(),
})

export const listAgents = async (
  database: Database | undefined,
  tenantId: string,
): Promise<readonly ReturnType<typeof serializeAgent>[]> => {
  if (database === undefined) {
    return []
  }

  const rows = await database.query<AgentRow>(
    `
      SELECT id,
             external_id,
             tenant_id,
             name,
             runtime_type,
             owner_user_id,
             environment,
             risk_tier,
             status,
             created_at
      FROM agents
      WHERE tenant_id = $1
      ORDER BY created_at ASC, external_id ASC
    `,
    [tenantId],
  )

  return rows.map(serializeAgent)
}

export const registerAgentsRoutes = (
  server: FastifyInstance,
  options: RegisterAgentsRoutesOptions,
): void => {
  server.get("/v1/agents", async (request, reply) => {
    try {
      const query = agentsQuerySchema.parse(request.query)
      const agents = await listAgents(options.database, query.tenant_id)

      return reply.code(200).send({
        tenant_id: query.tenant_id,
        agents,
      })
    } catch (error) {
      if (error instanceof ZodError) {
        return reply.code(400).send({ error: "invalid_request", issues: error.issues })
      }
      throw error
    }
  })
}
