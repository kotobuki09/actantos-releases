import type { Database } from "./database.ts"

export type SessionEvent = {
  readonly event_type: string
  readonly actor: {
    readonly type: string
    readonly id: string
  }
  readonly request_id: string | null
  readonly tool: {
    readonly kind: string
    readonly name: string
  } | null
  readonly tool_call_id: string | null
  readonly decision_id: string | null
  readonly final_decision: string | null
  readonly risk_class: string | null
  readonly reason_code: string | null
  readonly approval_id: string | null
  readonly result_hash: string | null
  readonly event_hash: string
  readonly created_at: string
}

type SessionEventRow = {
  readonly event_type: string
  readonly actor_type: string
  readonly actor_id: string
  readonly request_id: string | null
  readonly tool_kind: string | null
  readonly tool_name: string | null
  readonly tool_call_id: string | null
  readonly decision_id: string | null
  readonly final_decision: string | null
  readonly risk_class: string | null
  readonly reason_code: string | null
  readonly approval_id: string | null
  readonly result_hash: string | null
  readonly event_hash: string
  readonly created_at: string
}

export const listSessionEvents = async (
  database: Database,
  tenantId: string,
  sessionExternalId: string,
): Promise<readonly SessionEvent[]> => {
  const rows = await database.query<SessionEventRow>(
    `
      SELECT
        ae.event_type,
        ae.actor_type,
        ae.actor_id,
        tc.request_id,
        tc.tool_kind,
        tc.tool_name,
        ae.tool_call_id,
        ae.decision_id,
        pd.final_decision,
        pd.risk_class,
        pd.reason_code,
        a.id AS approval_id,
        tc.result_hash,
        ae.event_hash,
        ae.created_at
      FROM audit_events ae
      LEFT JOIN tool_calls tc ON tc.id = ae.tool_call_id
      LEFT JOIN policy_decisions pd ON pd.id = ae.decision_id
      LEFT JOIN approvals a
        ON a.decision_id = ae.decision_id
        OR a.used_by_request_id = tc.request_id
      INNER JOIN sessions s ON s.id = ae.session_id
      WHERE ae.tenant_id = $1
        AND s.external_id = $2
      ORDER BY ae.created_at ASC, ae.seq ASC
    `,
    [tenantId, sessionExternalId],
  )

  return rows.map((row) => ({
    event_type: row.event_type,
    actor: {
      type: row.actor_type,
      id: row.actor_id,
    },
    request_id: row.request_id,
    tool:
      row.tool_kind === null || row.tool_name === null
        ? null
        : {
            kind: row.tool_kind,
            name: row.tool_name,
          },
    tool_call_id: row.tool_call_id,
    decision_id: row.decision_id,
    final_decision: row.final_decision,
    risk_class: row.risk_class,
    reason_code: row.reason_code,
    approval_id: row.approval_id,
    result_hash: row.result_hash,
    event_hash: row.event_hash,
    created_at: row.created_at,
  }))
}
