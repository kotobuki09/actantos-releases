import type { FastifyInstance } from "fastify"
import { z, ZodError } from "zod"

import type { Database } from "./database.ts"
import { buildOpsHomeSummary } from "./ops-metrics.ts"

const usageMetricsQuerySchema = z.object({
  tenant_id: z.string().min(1),
})

type RegisterUsageMetricsRoutesOptions = {
  readonly database: Database
}

type CountRow = {
  readonly count: string | number
}

type ToolKindRow = {
  readonly tool_kind: string
  readonly count: string | number
}

const readCount = async (
  database: Database,
  sql: string,
  params: readonly unknown[],
): Promise<number> => {
  const rows = await database.query<CountRow>(sql, [...params])
  const value = rows[0]?.count
  return Number(value ?? 0)
}

export const listUsageMetrics = async (
  database: Database,
  tenantId: string,
): Promise<{
  readonly tenant_id: string
  readonly summary: {
    readonly session_count: number
    readonly decision_count: number
    readonly allow_count: number
    readonly deny_count: number
    readonly approval_required_count: number
    readonly approval_count: number
    readonly executed_tool_result_count: number
    readonly failed_tool_result_count: number
    readonly timeout_tool_result_count: number
    readonly blocked_tool_result_count: number
    readonly active_kill_switch_count: number
  }
  readonly ops_home: {
    readonly allow_rate: number
    readonly deny_rate: number
    readonly approval_required_rate: number
    readonly decision_count: number
    readonly allow_count: number
    readonly deny_count: number
    readonly approval_required_count: number
    readonly active_kill_switch_count: number
    readonly kill_switch_armed: boolean
    readonly budget_remaining: number
    readonly budget_limit: number
  }
  readonly tool_kinds: readonly {
    readonly tool_kind: string
    readonly count: number
  }[]
}> => {
  const [
    sessionCount,
    decisionCount,
    allowCount,
    denyCount,
    approvalRequiredCount,
    approvalCount,
    executedToolResultCount,
    failedToolResultCount,
    timeoutToolResultCount,
    blockedToolResultCount,
    activeKillSwitchCount,
    toolKinds,
  ] = await Promise.all([
    readCount(database, "SELECT COUNT(*) AS count FROM sessions WHERE tenant_id = $1", [tenantId]),
    readCount(database, "SELECT COUNT(*) AS count FROM policy_decisions WHERE tenant_id = $1", [tenantId]),
    readCount(
      database,
      "SELECT COUNT(*) AS count FROM policy_decisions WHERE tenant_id = $1 AND final_decision = 'allow'",
      [tenantId],
    ),
    readCount(
      database,
      "SELECT COUNT(*) AS count FROM policy_decisions WHERE tenant_id = $1 AND final_decision = 'deny'",
      [tenantId],
    ),
    readCount(
      database,
      "SELECT COUNT(*) AS count FROM policy_decisions WHERE tenant_id = $1 AND final_decision = 'approval_required'",
      [tenantId],
    ),
    readCount(database, "SELECT COUNT(*) AS count FROM approvals WHERE tenant_id = $1", [tenantId]),
    readCount(
      database,
      "SELECT COUNT(*) AS count FROM tool_calls WHERE tenant_id = $1 AND status = 'executed'",
      [tenantId],
    ),
    readCount(
      database,
      "SELECT COUNT(*) AS count FROM tool_calls WHERE tenant_id = $1 AND status = 'failed'",
      [tenantId],
    ),
    readCount(
      database,
      "SELECT COUNT(*) AS count FROM tool_calls WHERE tenant_id = $1 AND status = 'timeout'",
      [tenantId],
    ),
    readCount(
      database,
      "SELECT COUNT(*) AS count FROM tool_calls WHERE tenant_id = $1 AND status = 'blocked'",
      [tenantId],
    ),
    readCount(
      database,
      "SELECT COUNT(*) AS count FROM kill_switches WHERE tenant_id = $1 AND enabled = true",
      [tenantId],
    ),
    database.query<ToolKindRow>(
      `
        SELECT tool_kind, COUNT(*) AS count
        FROM tool_calls
        WHERE tenant_id = $1
        GROUP BY tool_kind
        ORDER BY tool_kind ASC
      `,
      [tenantId],
    ),
  ])

  const summary = {
    session_count: sessionCount,
    decision_count: decisionCount,
    allow_count: allowCount,
    deny_count: denyCount,
    approval_required_count: approvalRequiredCount,
    approval_count: approvalCount,
    executed_tool_result_count: executedToolResultCount,
    failed_tool_result_count: failedToolResultCount,
    timeout_tool_result_count: timeoutToolResultCount,
    blocked_tool_result_count: blockedToolResultCount,
    active_kill_switch_count: activeKillSwitchCount,
  }

  const budgetRows = await database.query<{ remaining: string | number; limit_value: string | number }>(
    `
      SELECT
        COALESCE(SUM(GREATEST(limit_value - current_value, 0)), 0) AS remaining,
        COALESCE(SUM(limit_value), 0) AS limit_value
      FROM budgets
      WHERE tenant_id = $1
    `,
    [tenantId],
  )

  const budgetRemaining = Number(budgetRows[0]?.remaining ?? 0)
  const budgetLimit = Number(budgetRows[0]?.limit_value ?? 0)

  return {
    tenant_id: tenantId,
    summary,
    ops_home: {
      ...buildOpsHomeSummary({
        decision_count: decisionCount,
        allow_count: allowCount,
        deny_count: denyCount,
        approval_required_count: approvalRequiredCount,
        active_kill_switch_count: activeKillSwitchCount,
      }),
      budget_remaining: budgetRemaining,
      budget_limit: budgetLimit,
    },
    tool_kinds: toolKinds.map((row) => ({
      tool_kind: row.tool_kind,
      count: Number(row.count),
    })),
  }
}

export const registerUsageMetricsRoutes = (
  server: FastifyInstance,
  options: RegisterUsageMetricsRoutesOptions,
): void => {
  server.get("/v1/metrics/usage", async (request, reply) => {
    try {
      const query = usageMetricsQuerySchema.parse(request.query)
      return reply.code(200).send(await listUsageMetrics(options.database, query.tenant_id))
    } catch (error) {
      if (error instanceof ZodError) {
        return reply.code(400).send({ error: "invalid_request", issues: error.issues })
      }
      throw error
    }
  })
}
