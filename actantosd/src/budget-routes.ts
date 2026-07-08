import { randomUUID } from "node:crypto"

import type { FastifyInstance } from "fastify"
import { z, ZodError } from "zod"

import type { Database } from "./database.ts"

const budgetsQuerySchema = z.object({
  tenant_id: z.string().min(1).optional().default("t_demo"),
})

const budgetBodySchema = z.object({
  tenant_id: z.string().min(1).optional().default("t_demo"),
  scope_type: z.enum(["tenant", "agent", "session", "tool"]),
  scope_id: z.string().min(1),
  metric: z.literal("tool_calls").optional().default("tool_calls"),
  limit_value: z.number().int().positive(),
  window_seconds: z.number().int().positive(),
})

type BudgetRow = {
  readonly id: string
  readonly tenant_id: string
  readonly scope_type: "tenant" | "agent" | "session" | "tool"
  readonly scope_id: string
  readonly metric: string
  readonly limit_value: string | number
  readonly window_seconds: number
  readonly current_value: string | number
  readonly window_start: Date | string
}

type RegisterBudgetRoutesOptions = {
  readonly database: Database
}

const toInteger = (value: string | number): number =>
  typeof value === "number" ? value : Number.parseInt(value, 10)

const serializeBudget = (row: BudgetRow) => ({
  id: row.id,
  tenant_id: row.tenant_id,
  scope_type: row.scope_type,
  scope_id: row.scope_id,
  metric: row.metric,
  limit_value: toInteger(row.limit_value),
  window_seconds: row.window_seconds,
  current_value: toInteger(row.current_value),
  window_start: new Date(row.window_start).toISOString(),
})

export const registerBudgetRoutes = (
  server: FastifyInstance,
  options: RegisterBudgetRoutesOptions,
): void => {
  server.get("/v1/budgets", async (request, reply) => {
    try {
      const query = budgetsQuerySchema.parse(request.query)
      const rows = await options.database.query<BudgetRow>(
        `
          SELECT id,
                 tenant_id,
                 scope_type,
                 scope_id,
                 metric,
                 limit_value,
                 window_seconds,
                 current_value,
                 window_start
          FROM budgets
          WHERE tenant_id = $1
          ORDER BY scope_type, scope_id, metric
        `,
        [query.tenant_id],
      )

      return reply.code(200).send({
        tenant_id: query.tenant_id,
        budgets: rows.map(serializeBudget),
      })
    } catch (error) {
      if (error instanceof ZodError) {
        return reply.code(400).send({ error: "invalid_request", issues: error.issues })
      }
      throw error
    }
  })

  server.post("/v1/budgets", async (request, reply) => {
    try {
      const body = budgetBodySchema.parse(request.body)
      const budgetId = randomUUID()
      const rows = await options.database.transaction(async (client) => {
        await client.query(
          `
            DELETE FROM budgets
            WHERE tenant_id = $1
              AND scope_type = $2
              AND scope_id = $3
              AND metric = $4
          `,
          [body.tenant_id, body.scope_type, body.scope_id, body.metric],
        )

        return client.query<BudgetRow>(
          `
            INSERT INTO budgets (
              id,
              tenant_id,
              scope_type,
              scope_id,
              metric,
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
                      metric,
                      limit_value,
                      window_seconds,
                      current_value,
                      window_start
          `,
          [
            budgetId,
            body.tenant_id,
            body.scope_type,
            body.scope_id,
            body.metric,
            body.limit_value,
            body.window_seconds,
          ],
        )
      })

      const budget = rows[0]

      if (budget === undefined) {
        throw new Error("budget insert returned no row")
      }

      return reply.code(201).send({ budget: serializeBudget(budget) })
    } catch (error) {
      if (error instanceof ZodError) {
        return reply.code(400).send({ error: "invalid_request", issues: error.issues })
      }
      throw error
    }
  })
}
