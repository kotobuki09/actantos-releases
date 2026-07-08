import type { FastifyInstance } from "fastify"
import { z, ZodError } from "zod"

import type { Database } from "./database.ts"

const decisionsQuerySchema = z.object({
  tenant_id: z.string().min(1).optional().default("t_demo"),
})

type DecisionRow = {
  readonly decision_id: string
  readonly request_id: string
  readonly final_decision: "allow" | "deny" | "approval_required"
  readonly decision_mode: "enforce" | "dry_run"
  readonly reason: string
  readonly reason_code: string
  readonly risk_class: string
  readonly approval_req: boolean
  readonly tool_kind: "file" | "shell" | "http" | "github" | "mcp" | "db" | "custom"
  readonly tool_name: string
  readonly operation: string
  readonly session_external_id: string
  readonly agent_external_id: string
  readonly approval_id: string | null
  readonly approval_status: "pending" | "approved" | "denied" | "expired" | null
  readonly created_at: string | Date
}

type RegisterDecisionsRoutesOptions = {
  readonly database?: Database
}

const serializeDecision = (row: DecisionRow) => ({
  decision_id: row.decision_id,
  request_id: row.request_id,
  final_decision: row.final_decision,
  decision_mode: row.decision_mode,
  reason: row.reason,
  reason_code: row.reason_code,
  risk_class: row.risk_class,
  approval_required: row.approval_req,
  tool: {
    kind: row.tool_kind,
    name: row.tool_name,
    operation: row.operation,
  },
  session_id: row.session_external_id,
  agent_id: row.agent_external_id,
  approval:
    row.approval_id === null
      ? null
      : {
          approval_id: row.approval_id,
          status: row.approval_status,
        },
  created_at: new Date(row.created_at).toISOString(),
})

export const listDecisions = async (
  database: Database | undefined,
  tenantId: string,
): Promise<readonly ReturnType<typeof serializeDecision>[]> => {
  if (database === undefined) {
    return []
  }

  const rows = await database.query<DecisionRow>(
    `
      SELECT
        pd.id AS decision_id,
        pd.request_id,
        pd.final_decision,
        pd.decision_mode,
        pd.reason,
        pd.reason_code,
        pd.risk_class,
        pd.approval_req,
        tc.tool_kind,
        tc.tool_name,
        tc.operation,
        s.external_id AS session_external_id,
        ag.external_id AS agent_external_id,
        a.id AS approval_id,
        a.status AS approval_status,
        pd.created_at
      FROM policy_decisions pd
      INNER JOIN tool_calls tc
        ON tc.id = pd.tool_call_id
      INNER JOIN sessions s
        ON s.id = tc.session_id
      INNER JOIN agents ag
        ON ag.id = tc.agent_id
      LEFT JOIN approvals a
        ON a.decision_id = pd.id
      WHERE pd.tenant_id = $1
      ORDER BY pd.created_at DESC, pd.request_id DESC
    `,
    [tenantId],
  )

  return rows.map(serializeDecision)
}

export const registerDecisionsRoutes = (
  server: FastifyInstance,
  options: RegisterDecisionsRoutesOptions,
): void => {
  server.get("/v1/decisions", async (request, reply) => {
    try {
      const query = decisionsQuerySchema.parse(request.query)
      const decisions = await listDecisions(options.database, query.tenant_id)

      return reply.code(200).send({
        tenant_id: query.tenant_id,
        decisions,
      })
    } catch (error) {
      if (error instanceof ZodError) {
        return reply.code(400).send({ error: "invalid_request", issues: error.issues })
      }
      throw error
    }
  })
}
