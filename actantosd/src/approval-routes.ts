import { randomBytes } from "node:crypto"

import type { FastifyInstance } from "fastify"
import { z, ZodError } from "zod"

import { sha256 } from "./hash.ts"
import { InMemoryToolCallRepository } from "./tool-call-repository.ts"
import type { Database } from "./database.ts"
import type { ToolCallRepository } from "./tool-call-repository.ts"

const approveDecideBodySchema = z.object({
  decision: z.enum(["approved", "denied"]),
  approver_user_id: z.string().min(1),
})

const pendingApprovalsQuerySchema = z.object({
  tenant_id: z.string().min(1).optional().default("t_demo"),
})

type PendingApprovalRow = {
  readonly approval_id: string
  readonly status: "pending" | "approved" | "denied" | "expired"
  readonly expires_at: string | Date
  readonly created_at: string | Date
  readonly decision_id: string
  readonly request_id: string
  readonly reason: string
  readonly reason_code: string
  readonly tool_name: string
  readonly tool_kind: "file" | "shell" | "http" | "github" | "mcp" | "db" | "custom"
  readonly session_external_id: string
  readonly agent_external_id: string
}

type ApprovalTenantRow = {
  readonly tenant_id: string
  readonly status: "pending" | "approved" | "denied" | "expired"
}

type TenantUserRow = {
  readonly id: string
}

type RegisterApprovalRoutesOptions = {
  readonly database?: Database
  readonly repository: ToolCallRepository
}

const serializePendingApproval = (row: PendingApprovalRow) => ({
  approval_id: row.approval_id,
  status: row.status,
  expires_at: new Date(row.expires_at).toISOString(),
  created_at: new Date(row.created_at).toISOString(),
  decision_id: row.decision_id,
  request_id: row.request_id,
  reason: row.reason,
  reason_code: row.reason_code,
  tool: {
    kind: row.tool_kind,
    name: row.tool_name,
  },
  session_id: row.session_external_id,
  agent_id: row.agent_external_id,
})

export const listPendingApprovals = async (
  database: Database | undefined,
  tenantId: string,
): Promise<readonly ReturnType<typeof serializePendingApproval>[]> => {
  if (database === undefined) {
    return []
  }

  const rows = await database.query<PendingApprovalRow>(
    `
      SELECT
        a.id AS approval_id,
        a.status,
        a.expires_at,
        a.created_at,
        pd.id AS decision_id,
        pd.request_id,
        pd.reason,
        pd.reason_code,
        tc.tool_name,
        tc.tool_kind,
        s.external_id AS session_external_id,
        ag.external_id AS agent_external_id
      FROM approvals a
      INNER JOIN policy_decisions pd
        ON pd.id = a.decision_id
      INNER JOIN tool_calls tc
        ON tc.id = a.tool_call_id
      INNER JOIN sessions s
        ON s.id = tc.session_id
      INNER JOIN agents ag
        ON ag.id = tc.agent_id
      WHERE a.tenant_id = $1
        AND a.status = 'pending'
      ORDER BY a.created_at ASC
    `,
    [tenantId],
  )

  return rows.map(serializePendingApproval)
}

const findApprovalTenantId = async (
  database: Database,
  approvalId: string,
): Promise<ApprovalTenantRow | undefined> => {
  const rows = await database.query<ApprovalTenantRow>(
    "SELECT tenant_id, status FROM approvals WHERE id = $1",
    [approvalId],
  )

  return rows[0]
}

const tenantUserExists = async (
  database: Database,
  tenantId: string,
  userId: string,
): Promise<boolean> => {
  const rows = await database.query<TenantUserRow>(
    "SELECT id FROM users WHERE tenant_id = $1 AND id = $2",
    [tenantId, userId],
  )

  return rows.length > 0
}

export const registerApprovalRoutes = (
  server: FastifyInstance,
  options: RegisterApprovalRoutesOptions,
): void => {
  server.get("/v1/approvals/pending", async (request, reply) => {
    try {
      const query = pendingApprovalsQuerySchema.parse(request.query)
      const approvals = await listPendingApprovals(options.database, query.tenant_id)

      return reply.code(200).send({
        tenant_id: query.tenant_id,
        approvals,
      })
    } catch (error) {
      if (error instanceof ZodError) {
        return reply.code(400).send({ error: "invalid_request", issues: error.issues })
      }
      throw error
    }
  })

  server.post<{ Params: { approval_id: string } }>(
    "/v1/approvals/:approval_id/decide",
    async (request, reply) => {
      try {
        const { approval_id } = request.params
        const body = approveDecideBodySchema.parse(request.body)
        const decidedAt = new Date().toISOString()
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString()
        const rawToken =
          body.decision === "approved"
            ? randomBytes(32).toString("base64url")
            : undefined
        const tokenHash = rawToken === undefined ? null : sha256(rawToken)

        if (options.database !== undefined) {
          const approval = await findApprovalTenantId(options.database, approval_id)
          if (approval === undefined) {
            return reply.code(404).send({ error: "not_found", message: "approval not found" })
          }

          if (approval.status !== "pending") {
            return reply.code(409).send({
              error: "approval_not_pending",
              message: "approval has already been decided",
            })
          }

          if (!(await tenantUserExists(options.database, approval.tenant_id, body.approver_user_id))) {
            return reply.code(400).send({
              error: "invalid_request",
              message: "approver_user_id must reference an existing tenant user",
            })
          }

          await options.database.query(
            `
              UPDATE approvals
              SET status = $1,
                  approver_user_id = $2,
                  decided_by = $2,
                  one_use_token_hash = $3,
                  decided_at = $4,
                  expires_at = $5
              WHERE id = $6
            `,
            [body.decision, body.approver_user_id, tokenHash, decidedAt, expiresAt, approval_id],
          )
        } else if (options.repository instanceof InMemoryToolCallRepository) {
          if (body.decision === "approved" && rawToken !== undefined) {
            options.repository.approveRequest(approval_id, rawToken)
          }
        }

        return reply.code(200).send({
          approval_id,
          decision: body.decision,
          approval_token: rawToken,
          decided_at: decidedAt,
          expires_at: expiresAt,
        })
      } catch (error) {
        if (error instanceof ZodError) {
          return reply.code(400).send({ error: "invalid_request", issues: error.issues })
        }
        throw error
      }
    },
  )
}
