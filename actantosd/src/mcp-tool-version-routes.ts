import type { FastifyInstance } from "fastify"
import { z, ZodError } from "zod"

import type { Database } from "./database.ts"

const pendingToolVersionsQuerySchema = z.object({
  tenant_id: z.string().min(1),
})

type PendingToolVersionRow = {
  readonly id: string
  readonly server_name: string
  readonly tool_name: string
  readonly schema_hash: string
  readonly description_hash: string
  readonly created_at: string | Date
}

type ApprovalTargetRow = {
  readonly id: string
  readonly server_id: string
  readonly tool_name: string
}

export const registerMcpToolVersionRoutes = (
  server: FastifyInstance,
  options: {
    readonly database: Database
  },
): void => {
  server.get("/v1/mcp/tool-versions/pending", async (request, reply) => {
    try {
      const query = pendingToolVersionsQuerySchema.parse(request.query)
      const rows = await options.database.query<PendingToolVersionRow>(
        `
          SELECT
            mtv.id,
            ms.name AS server_name,
            mtv.tool_name,
            mtv.schema_hash,
            mtv.description_hash,
            mtv.created_at
          FROM mcp_tool_versions mtv
          INNER JOIN mcp_servers ms
            ON ms.id = mtv.server_id
          WHERE ms.tenant_id = $1
            AND mtv.approved = false
          ORDER BY mtv.created_at ASC
        `,
        [query.tenant_id],
      )

      return reply.code(200).send({
        tenant_id: query.tenant_id,
        tool_versions: rows.map((row) => ({
          id: row.id,
          server_id: row.server_name,
          tool_name: row.tool_name,
          schema_hash: row.schema_hash,
          description_hash: row.description_hash,
          created_at: new Date(row.created_at).toISOString(),
        })),
      })
    } catch (error) {
      if (error instanceof ZodError) {
        return reply.code(400).send({ error: "invalid_request", issues: error.issues })
      }
      throw error
    }
  })

  server.post<{ Params: { id: string } }>(
    "/v1/mcp/tool-versions/:id/approve",
    async (request, reply) => {
      const target = await options.database.transaction(async (client) => {
        const rows = await client.query<ApprovalTargetRow>(
          `
            SELECT id, server_id, tool_name
            FROM mcp_tool_versions
            WHERE id = $1
            FOR UPDATE
          `,
          [request.params.id],
        )

        const toolVersion = rows[0]
        if (toolVersion === undefined) {
          return null
        }

        await client.query(
          `
            UPDATE mcp_tool_versions
            SET approved = false
            WHERE server_id = $1
              AND tool_name = $2
              AND approved = true
          `,
          [toolVersion.server_id, toolVersion.tool_name],
        )

        await client.query(
          `
            UPDATE mcp_tool_versions
            SET approved = true
            WHERE id = $1
          `,
          [toolVersion.id],
        )

        return toolVersion
      })

      if (target === null) {
        return reply.code(404).send({ error: "not_found", message: "MCP tool version not found" })
      }

      return reply.code(200).send({
        id: target.id,
        tool_name: target.tool_name,
        approved: true,
      })
    },
  )
}
