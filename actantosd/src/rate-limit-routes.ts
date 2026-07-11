import { randomUUID } from "node:crypto"

import type { FastifyInstance } from "fastify"
import { z, ZodError } from "zod"

import type { Database } from "./database.ts"

const rateLimitsQuerySchema = z.object({
  tenant_id: z.string().min(1),
})

const rateLimitBodySchema = z.object({
  tenant_id: z.string().min(1),
  scope_type: z.enum(["tenant", "agent", "session", "tool"]),
  scope_id: z.string().min(1),
  action_key: z.string().min(1),
  limit_value: z.number().int().positive(),
  window_seconds: z.number().int().positive(),
})

type RateLimitRow = {
  readonly id: string
  readonly tenant_id: string
  readonly scope_type: "tenant" | "agent" | "session" | "tool"
  readonly scope_id: string
  readonly action_key: string
  readonly limit_value: string | number
  readonly window_seconds: number
  readonly current_value: string | number
  readonly window_start: Date | string
}

type RegisterRateLimitRoutesOptions = {
  readonly database: Database
}

const toInteger = (value: string | number): number =>
  typeof value === "number" ? value : Number.parseInt(value, 10)

const serializeRateLimit = (row: RateLimitRow) => ({
  id: row.id,
  tenant_id: row.tenant_id,
  scope_type: row.scope_type,
  scope_id: row.scope_id,
  action_key: row.action_key,
  limit_value: toInteger(row.limit_value),
  window_seconds: row.window_seconds,
  current_value: toInteger(row.current_value),
  window_start: new Date(row.window_start).toISOString(),
})

export const registerRateLimitRoutes = (
  server: FastifyInstance,
  options: RegisterRateLimitRoutesOptions,
): void => {
  server.get("/v1/rate-limits", async (request, reply) => {
    try {
      const query = rateLimitsQuerySchema.parse(request.query)
      const rows = await options.database.query<RateLimitRow>(
        `
          SELECT id,
                 tenant_id,
                 scope_type,
                 scope_id,
                 action_key,
                 limit_value,
                 window_seconds,
                 current_value,
                 window_start
          FROM rate_limits
          WHERE tenant_id = $1
          ORDER BY scope_type, scope_id, action_key
        `,
        [query.tenant_id],
      )

      return reply.code(200).send({
        tenant_id: query.tenant_id,
        rate_limits: rows.map(serializeRateLimit),
      })
    } catch (error) {
      if (error instanceof ZodError) {
        return reply.code(400).send({ error: "invalid_request", issues: error.issues })
      }
      throw error
    }
  })

  server.put("/v1/rate-limits", async (request, reply) => {
    try {
      const body = rateLimitBodySchema.parse(request.body)
      const rateLimitId = randomUUID()
      const rows = await options.database.transaction(async (client) => {
        await client.query(
          `
            DELETE FROM rate_limits
            WHERE tenant_id = $1
              AND scope_type = $2
              AND scope_id = $3
              AND action_key = $4
          `,
          [body.tenant_id, body.scope_type, body.scope_id, body.action_key],
        )

        return client.query<RateLimitRow>(
          `
            INSERT INTO rate_limits (
              id,
              tenant_id,
              scope_type,
              scope_id,
              action_key,
              limit_value,
              window_seconds,
              current_value,
              window_start
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, 0, now())
            RETURNING id,
                      tenant_id,
                      scope_type,
                      scope_id,
                      action_key,
                      limit_value,
                      window_seconds,
                      current_value,
                      window_start
          `,
          [
            rateLimitId,
            body.tenant_id,
            body.scope_type,
            body.scope_id,
            body.action_key,
            body.limit_value,
            body.window_seconds,
          ],
        )
      })

      const rateLimit = rows[0]

      if (rateLimit === undefined) {
        throw new Error("rate limit insert returned no row")
      }

      return reply.code(200).send({ rate_limit: serializeRateLimit(rateLimit) })
    } catch (error) {
      if (error instanceof ZodError) {
        return reply.code(400).send({ error: "invalid_request", issues: error.issues })
      }
      throw error
    }
  })
}
