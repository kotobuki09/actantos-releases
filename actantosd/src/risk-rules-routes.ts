import type { FastifyInstance } from "fastify"
import { z, ZodError } from "zod"

import { riskRulesSchema } from "./contracts.ts"
import type { Database } from "./database.ts"
import { loadDefaultRiskRules } from "./risk-engine.ts"

const riskRulesQuerySchema = z.object({
  tenant_id: z.string().min(1).optional().default("t_demo"),
})

const putRiskRulesBodySchema = z.object({
  tenant_id: z.string().min(1).optional().default("t_demo"),
  rules: riskRulesSchema,
})

type RiskRuleSetRow = {
  readonly tenant_id: string
  readonly rules_json: unknown
  readonly updated_at: string | Date
}

type RegisterRiskRulesRoutesOptions = {
  readonly database: Database
}

const serializeRiskRuleSet = (
  row: RiskRuleSetRow,
  source: "database" | "file_fallback",
) => ({
  tenant_id: row.tenant_id,
  source,
  updated_at: new Date(row.updated_at).toISOString(),
  rules: riskRulesSchema.parse(row.rules_json),
})

export const registerRiskRulesRoutes = (
  server: FastifyInstance,
  options: RegisterRiskRulesRoutesOptions,
): void => {
  server.get("/v1/risk-rules", async (request, reply) => {
    try {
      const query = riskRulesQuerySchema.parse(request.query)
      const rows = await options.database.query<RiskRuleSetRow>(
        `
          SELECT tenant_id, rules_json, updated_at
          FROM risk_rule_sets
          WHERE tenant_id = $1
        `,
        [query.tenant_id],
      )

      const riskRuleSet = rows[0]
      if (riskRuleSet !== undefined) {
        return reply.code(200).send({ risk_rule_set: serializeRiskRuleSet(riskRuleSet, "database") })
      }

      const rules = await loadDefaultRiskRules()
      return reply.code(200).send({
        risk_rule_set: {
          tenant_id: query.tenant_id,
          source: "file_fallback",
          updated_at: new Date(0).toISOString(),
          rules,
        },
      })
    } catch (error) {
      if (error instanceof ZodError) {
        return reply.code(400).send({ error: "invalid_request", issues: error.issues })
      }
      throw error
    }
  })

  server.put("/v1/risk-rules", async (request, reply) => {
    try {
      const body = putRiskRulesBodySchema.parse(request.body)
      const rows = await options.database.transaction(async (client) =>
        client.query<RiskRuleSetRow>(
          `
            INSERT INTO risk_rule_sets (tenant_id, rules_json, updated_at)
            VALUES ($1, $2::jsonb, now())
            ON CONFLICT (tenant_id)
            DO UPDATE SET
              rules_json = EXCLUDED.rules_json,
              updated_at = now()
            RETURNING tenant_id, rules_json, updated_at
          `,
          [body.tenant_id, JSON.stringify(body.rules)],
        ))

      const riskRuleSet = rows[0]
      if (riskRuleSet === undefined) {
        throw new Error("risk rule set upsert returned no row")
      }

      return reply.code(200).send({ risk_rule_set: serializeRiskRuleSet(riskRuleSet, "database") })
    } catch (error) {
      if (error instanceof ZodError) {
        return reply.code(400).send({ error: "invalid_request", issues: error.issues })
      }
      throw error
    }
  })
}
