import type { FastifyInstance } from "fastify"
import { z, ZodError } from "zod"

import { InMemoryToolCallRepository } from "./tool-call-repository.ts"
import type { Database } from "./database.ts"
import type { ToolCallRepository } from "./tool-call-repository.ts"

const killSwitchBodySchema = z.object({
  scope_type: z.enum(["tenant", "agent", "session", "tool"]),
  scope_id: z.string().min(1),
  reason: z.string().min(1),
  tenant_id: z.string().min(1),
})

const killSwitchQuerySchema = z.object({
  tenant_id: z.string().min(1),
})

type KillSwitchRow = {
  readonly id: string
  readonly tenant_id: string
  readonly scope_type: "tenant" | "agent" | "session" | "tool"
  readonly scope_id: string
  readonly reason: string
  readonly enabled: boolean
  readonly created_at: string | Date
}

type RegisterKillSwitchRoutesOptions = {
  readonly database?: Database
  readonly repository: ToolCallRepository
}

export const listActiveKillSwitches = async (
  database: Database | undefined,
  tenantId: string,
): Promise<readonly {
  readonly id: string
  readonly tenant_id: string
  readonly scope_type: "tenant" | "agent" | "session" | "tool"
  readonly scope_id: string
  readonly reason: string
  readonly enabled: boolean
  readonly created_at: string
}[]> => {
  if (database === undefined) {
    return []
  }

  const rows = await database.query<KillSwitchRow>(
    `
      SELECT id, tenant_id, scope_type, scope_id, reason, enabled, created_at
      FROM kill_switches
      WHERE tenant_id = $1
        AND enabled = true
      ORDER BY created_at ASC
    `,
    [tenantId],
  )

  return rows.map((row) => ({
    id: row.id,
    tenant_id: row.tenant_id,
    scope_type: row.scope_type,
    scope_id: row.scope_id,
    reason: row.reason,
    enabled: row.enabled,
    created_at: new Date(row.created_at).toISOString(),
  }))
}

export const registerKillSwitchRoutes = (
  server: FastifyInstance,
  options: RegisterKillSwitchRoutesOptions,
): void => {
  server.get("/v1/kill-switches", async (request, reply) => {
    try {
      const query = killSwitchQuerySchema.parse(request.query)

      if (options.database === undefined) {
        return reply.code(200).send({ tenant_id: query.tenant_id, kill_switches: [] })
      }

      return reply.code(200).send({
        tenant_id: query.tenant_id,
        kill_switches: await listActiveKillSwitches(options.database, query.tenant_id),
      })
    } catch (error) {
      if (error instanceof ZodError) {
        return reply.code(400).send({ error: "invalid_request", issues: error.issues })
      }
      throw error
    }
  })

  server.post("/v1/kill-switches", async (request, reply) => {
    try {
      const body = killSwitchBodySchema.parse(request.body)

      if (options.database !== undefined) {
        const id = crypto.randomUUID()
        await options.database.query(
          `
            INSERT INTO kill_switches (id, tenant_id, scope_type, scope_id, reason, enabled)
            VALUES ($1, $2, $3, $4, $5, true)
          `,
          [id, body.tenant_id, body.scope_type, body.scope_id, body.reason],
        )
        return reply.code(201).send({ id, scope_type: body.scope_type, scope_id: body.scope_id, enabled: true })
      }

      if (options.repository instanceof InMemoryToolCallRepository) {
        options.repository.enableKillSwitch()
      }

      return reply.code(201).send({
        id: crypto.randomUUID(),
        scope_type: body.scope_type,
        scope_id: body.scope_id,
        enabled: true,
      })
    } catch (error) {
      if (error instanceof ZodError) {
        return reply.code(400).send({ error: "invalid_request", issues: error.issues })
      }
      throw error
    }
  })

  server.delete<{ Params: { id: string } }>(
    "/v1/kill-switches/:id",
    async (request, reply) => {
      const { id } = request.params

      if (options.database !== undefined) {
        await options.database.query(
          `UPDATE kill_switches SET enabled = false WHERE id = $1`,
          [id],
        )
      }

      return reply.code(200).send({ id, enabled: false })
    },
  )
}
