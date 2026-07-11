import type { FastifyInstance } from "fastify"
import { z, ZodError } from "zod"

import { listDecisions } from "./decisions-routes.ts"
import type { Database } from "./database.ts"
import { listActiveKillSwitches } from "./kill-switch-routes.ts"
import { listSessionEvents } from "./session-events.ts"
import { listSessions } from "./sessions-routes.ts"

const evidenceExportQuerySchema = z.object({
  tenant_id: z.string().min(1),
  session_id: z.string().min(1).optional(),
})

type RegisterEvidenceExportRoutesOptions = {
  readonly database?: Database
}

type ApprovalExportRow = {
  readonly approval_id: string
  readonly status: "pending" | "approved" | "denied" | "expired"
  readonly approver_user_id: string | null
  readonly decided_by: string | null
  readonly expires_at: string | Date
  readonly decided_at: string | Date | null
  readonly used_at: string | Date | null
  readonly used_by_request_id: string | null
  readonly created_at: string | Date
  readonly decision_id: string
  readonly request_id: string
  readonly session_external_id: string
  readonly tool_name: string
  readonly tool_kind: "file" | "shell" | "http" | "github" | "mcp" | "db" | "custom"
}

const listApprovalsForExport = async (
  database: Database | undefined,
  tenantId: string,
  sessionId: string | undefined,
): Promise<readonly {
  readonly approval_id: string
  readonly status: "pending" | "approved" | "denied" | "expired"
  readonly approver_user_id: string | null
  readonly decided_by: string | null
  readonly expires_at: string
  readonly decided_at: string | null
  readonly used_at: string | null
  readonly used_by_request_id: string | null
  readonly created_at: string
  readonly decision_id: string
  readonly request_id: string
  readonly session_id: string
  readonly tool: {
    readonly name: string
    readonly kind: "file" | "shell" | "http" | "github" | "mcp" | "db" | "custom"
  }
}[]> => {
  if (database === undefined) {
    return []
  }

  const rows = await database.query<ApprovalExportRow>(
    `
      SELECT
        a.id AS approval_id,
        a.status,
        a.approver_user_id,
        a.decided_by,
        a.expires_at,
        a.decided_at,
        a.used_at,
        a.used_by_request_id,
        a.created_at,
        pd.id AS decision_id,
        pd.request_id,
        s.external_id AS session_external_id,
        tc.tool_name,
        tc.tool_kind
      FROM approvals a
      INNER JOIN policy_decisions pd
        ON pd.id = a.decision_id
      INNER JOIN tool_calls tc
        ON tc.id = a.tool_call_id
      INNER JOIN sessions s
        ON s.id = tc.session_id
      WHERE a.tenant_id = $1
        AND ($2::text IS NULL OR s.external_id = $2)
      ORDER BY a.created_at ASC, a.id ASC
    `,
    [tenantId, sessionId ?? null],
  )

  return rows.map((row) => ({
    approval_id: row.approval_id,
    status: row.status,
    approver_user_id: row.approver_user_id,
    decided_by: row.decided_by,
    expires_at: new Date(row.expires_at).toISOString(),
    decided_at: row.decided_at === null ? null : new Date(row.decided_at).toISOString(),
    used_at: row.used_at === null ? null : new Date(row.used_at).toISOString(),
    used_by_request_id: row.used_by_request_id,
    created_at: new Date(row.created_at).toISOString(),
    decision_id: row.decision_id,
    request_id: row.request_id,
    session_id: row.session_external_id,
    tool: {
      name: row.tool_name,
      kind: row.tool_kind,
    },
  }))
}

export const exportEvidencePackage = async (
  database: Database | undefined,
  tenantId: string,
  sessionId: string | undefined,
): Promise<{
  readonly tenant_id: string
  readonly session_id: string | null
  readonly exported_at: string
  readonly summary: {
    readonly session_count: number
    readonly decision_count: number
    readonly approval_count: number
    readonly active_kill_switch_count: number
    readonly audit_event_count: number
  }
  readonly sessions: readonly Awaited<ReturnType<typeof listSessions>>[number][]
  readonly decisions: readonly Awaited<ReturnType<typeof listDecisions>>[number][]
  readonly approvals: readonly Awaited<ReturnType<typeof listApprovalsForExport>>[number][]
  readonly kill_switches: readonly Awaited<ReturnType<typeof listActiveKillSwitches>>[number][]
  readonly audit_timelines: readonly {
    readonly session_id: string
    readonly events: Awaited<ReturnType<typeof listSessionEvents>>
  }[]
}> => {
  const allSessions = await listSessions(database, tenantId)
  const sessions = sessionId === undefined
    ? allSessions
    : allSessions.filter((session) => session.external_id === sessionId)
  const allDecisions = await listDecisions(database, tenantId)
  const decisions = sessionId === undefined
    ? allDecisions
    : allDecisions.filter((decision) => decision.session_id === sessionId)
  const approvals = await listApprovalsForExport(database, tenantId, sessionId)
  const killSwitches = await listActiveKillSwitches(database, tenantId)
  const auditTimelines = database === undefined
    ? []
    : await Promise.all(
        sessions.map(async (session) => ({
          session_id: session.external_id,
          events: await listSessionEvents(database, tenantId, session.external_id),
        })),
      )

  return {
    tenant_id: tenantId,
    session_id: sessionId ?? null,
    exported_at: new Date().toISOString(),
    summary: {
      session_count: sessions.length,
      decision_count: decisions.length,
      approval_count: approvals.length,
      active_kill_switch_count: killSwitches.length,
      audit_event_count: auditTimelines.reduce((count, timeline) => count + timeline.events.length, 0),
    },
    sessions,
    decisions,
    approvals,
    kill_switches: killSwitches,
    audit_timelines: auditTimelines,
  }
}

export const registerEvidenceExportRoutes = (
  server: FastifyInstance,
  options: RegisterEvidenceExportRoutesOptions,
): void => {
  server.get("/v1/evidence/export", async (request, reply) => {
    try {
      const query = evidenceExportQuerySchema.parse(request.query)
      const evidencePackage = await exportEvidencePackage(
        options.database,
        query.tenant_id,
        query.session_id,
      )
      const filename = query.session_id === undefined
        ? `actantos-evidence-${query.tenant_id}.json`
        : `actantos-evidence-${query.tenant_id}-${query.session_id}.json`

      return reply
        .header("content-disposition", `attachment; filename="${filename}"`)
        .code(200)
        .send(evidencePackage)
    } catch (error) {
      if (error instanceof ZodError) {
        return reply.code(400).send({ error: "invalid_request", issues: error.issues })
      }
      throw error
    }
  })
}
