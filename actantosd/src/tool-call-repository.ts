import { createHash } from "node:crypto"

import type {
  ToolCallContext,
  ToolCallInterceptionRequest,
  ToolCallInterceptionResponse,
} from "./contracts.ts"
import type { CedarDecision } from "./fake-cedar-provider.ts"
import { parsePgBigInt, type Database } from "./database.ts"
import { canonicalStringify, sha256 } from "./hash.ts"

export type StoredDecision = {
  readonly request: ToolCallInterceptionRequest
  readonly response: ToolCallInterceptionResponse
}

export type NewStoredDecision = StoredDecision & {
  readonly toolCallId?: string
  readonly context: ToolCallContext
  readonly cedarResult: CedarDecision
  readonly riskClass: string
  readonly approvalId?: string
  readonly approvalExpiresAt?: string
  readonly priorDecisionId?: string
  readonly approvalConsumed?: boolean
}

export type ApprovalVerificationResult =
  | { readonly valid: true }
  | { readonly valid: false; readonly reason: string }

export interface ToolCallRepository {
  findByRequestId(
    tenantId: string,
    requestId: string,
  ): Promise<StoredDecision | null>

  saveDecision(record: NewStoredDecision): Promise<void>

  isKillSwitchActive(
    tenantId: string,
    agentExternalId: string,
    sessionExternalId: string,
    toolName: string,
  ): Promise<boolean>

  verifyAndConsumeApproval(params: {
    tenantId: string
    approvalId: string
    approvalToken: string
    scopeHash: string
    requestId: string
    consume?: boolean
  }): Promise<ApprovalVerificationResult>
}

// ---------------------------------------------------------------------------
// In-memory implementation (for tests and development without Postgres)
// ---------------------------------------------------------------------------

type InMemoryApproval = {
  readonly approvalId: string
  readonly tenantId: string
  readonly scopeHash: string
  readonly expiresAt: string
  status: "pending" | "approved" | "denied" | "expired"
  tokenHash?: string
  usedAt?: string
}

export class InMemoryToolCallRepository implements ToolCallRepository {
  readonly #decisions = new Map<string, StoredDecision>()
  readonly #approvals = new Map<string, InMemoryApproval>()
  #killSwitchActive = false

  async findByRequestId(
    tenantId: string,
    requestId: string,
  ): Promise<StoredDecision | null> {
    return this.#decisions.get(this.#key(tenantId, requestId)) ?? null
  }

  async saveDecision(record: NewStoredDecision): Promise<void> {
    this.#decisions.set(
      this.#key(record.request.tenant_id, record.request.request_id),
      record,
    )

    // Store approval record if this is an approval_required decision
    if (record.approvalId !== undefined && record.approvalExpiresAt !== undefined) {
      this.#approvals.set(record.approvalId, {
        approvalId: record.approvalId,
        tenantId: record.request.tenant_id,
        scopeHash: record.context.scope_hash,
        expiresAt: record.approvalExpiresAt,
        status: "pending",
      })
    }
  }

  async isKillSwitchActive(
    _tenantId: string,
    _agentExternalId: string,
    _sessionExternalId: string,
    _toolName: string,
  ): Promise<boolean> {
    return this.#killSwitchActive
  }

  async verifyAndConsumeApproval(params: {
    tenantId: string
    approvalId: string
    approvalToken: string
    scopeHash: string
    requestId: string
    consume?: boolean
  }): Promise<ApprovalVerificationResult> {
    const approval = this.#approvals.get(params.approvalId)

    if (approval === undefined || approval.tenantId !== params.tenantId) {
      return { valid: false, reason: "approval not found" }
    }
    if (approval.status !== "approved") {
      return { valid: false, reason: "approval not in approved state" }
    }
    if (new Date(approval.expiresAt) <= new Date()) {
      return { valid: false, reason: "approval expired" }
    }
    if (approval.usedAt !== undefined) {
      return { valid: false, reason: "approval already used" }
    }
    if (approval.scopeHash !== params.scopeHash) {
      return { valid: false, reason: "scope hash mismatch" }
    }
    if (approval.tokenHash === undefined) {
      return { valid: false, reason: "no token set" }
    }
    const submittedHash = sha256(params.approvalToken)
    if (submittedHash !== approval.tokenHash) {
      return { valid: false, reason: "invalid token" }
    }

    // Atomically mark as used
    if (params.consume !== false) {
      approval.usedAt = new Date().toISOString()
    }
    return { valid: true }
  }

  /** Test helpers */
  count(): number {
    return this.#decisions.size
  }

  enableKillSwitch(): void {
    this.#killSwitchActive = true
  }

  approveRequest(approvalId: string, rawToken: string): void {
    const approval = this.#approvals.get(approvalId)
    if (approval === undefined) {
      throw new Error(`no approval with id=${approvalId}`)
    }
    approval.status = "approved"
    approval.tokenHash = sha256(rawToken)
  }

  getApproval(approvalId: string): InMemoryApproval | undefined {
    return this.#approvals.get(approvalId)
  }

  #key(tenantId: string, requestId: string): string {
    return `${tenantId}:${requestId}`
  }
}

// ---------------------------------------------------------------------------
// Postgres implementation
// ---------------------------------------------------------------------------

type AgentRow = {
  readonly id: string
}

type SessionRow = {
  readonly id: string
}

type PolicyBundleRow = {
  readonly id: string
}

type DecisionLookupRow = {
  readonly decision_id: string
  readonly decision: string
  readonly decision_mode: string
  readonly reason: string
  readonly reason_code: string
  readonly audit_event_id: string
  readonly decision_token: string | null
  readonly constraints_json: unknown
  readonly approval_id: string | null
  readonly approval_expires_at: string | null
}

type AuditChainStateRow = {
  readonly last_hash: string
  readonly seq: string | number | bigint
}

type ApprovalRow = {
  readonly id: string
  readonly status: string
  readonly scope_hash: string
  readonly expires_at: string
  readonly used_at: string | null
  readonly one_use_token_hash: string | null
}

type KillSwitchRow = {
  readonly id: string
}

type AllowResponseConstraints = Extract<
  ToolCallInterceptionResponse,
  { readonly decision: "allow" }
>["constraints"]

export class PostgresToolCallRepository implements ToolCallRepository {
  readonly #database: Database

  constructor(database: Database) {
    this.#database = database
  }

  async isKillSwitchActive(
    tenantId: string,
    agentExternalId: string,
    sessionExternalId: string,
    toolName: string,
  ): Promise<boolean> {
    // Check tenant-level, agent-level, session-level, and tool-level kill switches
    const rows = await this.#database.query<KillSwitchRow>(
      `
        SELECT ks.id
        FROM kill_switches ks
        WHERE ks.tenant_id = $1
          AND ks.enabled = true
          AND (
            (ks.scope_type = 'tenant' AND ks.scope_id = $1) OR
            (ks.scope_type = 'agent'   AND ks.scope_id = $2) OR
            (ks.scope_type = 'session' AND ks.scope_id = $3) OR
            (ks.scope_type = 'tool'    AND ks.scope_id = $4)
          )
        LIMIT 1
      `,
      [tenantId, agentExternalId, sessionExternalId, toolName],
    )
    return rows.length > 0
  }

  async verifyAndConsumeApproval(params: {
    tenantId: string
    approvalId: string
    approvalToken: string
    scopeHash: string
    requestId: string
    consume?: boolean
  }): Promise<ApprovalVerificationResult> {
    return this.#database.transaction(async (client) => {
      const rows = await client.query<ApprovalRow>(
        `
          SELECT id, status, scope_hash, expires_at, used_at, one_use_token_hash
          FROM approvals
          WHERE id = $1 AND tenant_id = $2
          FOR UPDATE
        `,
        [params.approvalId, params.tenantId],
      )

      const approval = rows[0]

      if (approval === undefined) {
        return { valid: false, reason: "approval not found" }
      }
      if (approval.status !== "approved") {
        return { valid: false, reason: "approval not in approved state" }
      }
      if (new Date(approval.expires_at) <= new Date()) {
        return { valid: false, reason: "approval expired" }
      }
      if (approval.used_at !== null) {
        return { valid: false, reason: "approval already used" }
      }
      if (approval.scope_hash !== params.scopeHash) {
        return { valid: false, reason: "scope hash mismatch" }
      }
      if (approval.one_use_token_hash === null) {
        return { valid: false, reason: "no token set on approval" }
      }

      const submittedHash = sha256(params.approvalToken)
      if (submittedHash !== approval.one_use_token_hash) {
        return { valid: false, reason: "invalid token" }
      }

      // Atomically consume the token
      if (params.consume !== false) {
        await client.query(
          `UPDATE approvals SET used_at = now(), used_by_request_id = $1 WHERE id = $2 AND used_at IS NULL`,
          [params.requestId, params.approvalId],
        )
      }

      return { valid: true }
    })
  }

  async findByRequestId(
    tenantId: string,
    requestId: string,
  ): Promise<StoredDecision | null> {
    const rows = await this.#database.query<DecisionLookupRow>(
      `
        SELECT
          pd.id AS decision_id,
          pd.final_decision AS decision,
          pd.decision_mode,
          pd.reason,
          pd.reason_code,
          ae.id AS audit_event_id,
          tc.mcp_json->>'decision_token' AS decision_token,
          pd.constraints_json,
          a.id AS approval_id,
          a.expires_at AS approval_expires_at
        FROM policy_decisions pd
        INNER JOIN tool_calls tc
          ON tc.id = pd.tool_call_id
        INNER JOIN audit_events ae
          ON ae.decision_id = pd.id
        LEFT JOIN approvals a
          ON a.decision_id = pd.id
        WHERE pd.tenant_id = $1
          AND pd.request_id = $2
        ORDER BY ae.created_at ASC
        LIMIT 1
      `,
      [tenantId, requestId],
    )

    const row = rows[0]

    if (row === undefined) {
      return null
    }

    const baseResponse = {
      decision: row.decision as ToolCallInterceptionResponse["decision"],
      decision_mode: row.decision_mode as ToolCallInterceptionResponse["decision_mode"],
      decision_id: row.decision_id,
      reason: row.reason,
      reason_code: row.reason_code,
      audit_event_id: row.audit_event_id,
    }

    let response: ToolCallInterceptionResponse

    if (row.decision === "allow") {
      response = {
        ...baseResponse,
        decision: "allow" as const,
        decision_token: row.decision_token ?? undefined,
        ...(typeof row.constraints_json === "object" && row.constraints_json !== null
          ? { constraints: row.constraints_json as AllowResponseConstraints }
          : {}),
      }
    } else if (row.decision === "approval_required" && row.approval_id !== null) {
      response = {
        ...baseResponse,
        decision: "approval_required" as const,
        approval: {
          approval_id: row.approval_id,
          status: "pending" as const,
          expires_at: row.approval_expires_at ?? "",
        },
      }
    } else {
      response = {
        ...baseResponse,
        decision: "deny" as const,
      }
    }

    return {
      request: {
        request_id: requestId,
        tenant_id: tenantId,
        agent: { id: "", runtime_type: "pi", environment: "dev", risk_tier: "low" },
        subject: { user_id: "" },
        session: { id: "" },
        tool: { kind: "file" as const, name: "", operation: "" },
        resource: {},
        action: {},
        normalized: { credential_access: row.reason_code === "policy_forbid.credential_path" },
      },
      response,
    }
  }

  async saveDecision(record: NewStoredDecision): Promise<void> {
    await this.#database.transaction(async (client) => {
      const agent = await client.query<AgentRow>(
        "SELECT id FROM agents WHERE tenant_id = $1 AND external_id = $2",
        [record.request.tenant_id, record.request.agent.id],
      )
      const session = await client.query<SessionRow>(
        "SELECT id FROM sessions WHERE tenant_id = $1 AND external_id = $2",
        [record.request.tenant_id, record.request.session.id],
      )
      const policyBundle = await client.query<PolicyBundleRow>(
        "SELECT id FROM policy_bundles WHERE tenant_id = $1 AND active = true LIMIT 1",
        [record.request.tenant_id],
      )

      const agentId = agent[0]?.id
      const sessionId = session[0]?.id
      const policyBundleId = policyBundle[0]?.id

      if (agentId === undefined || sessionId === undefined || policyBundleId === undefined) {
        throw new Error("seed bootstrap is incomplete")
      }

      const toolCallId = record.toolCallId ?? crypto.randomUUID()
      const decisionId = record.response.decision_id
      const auditEventId = record.response.audit_event_id
      const now = new Date().toISOString()

      // Derive decision_token from response (only present on allow)
      const decisionToken =
        record.response.decision === "allow" ? (record.response.decision_token ?? null) : null

      // Determine tool call status
      const toolCallStatus =
        record.response.decision === "deny" ? "denied" :
        record.response.decision === "approval_required" ? "approval_pending" :
        "decision_created"

      await client.query(
        `
          INSERT INTO tool_calls (
            id, request_id, tenant_id, session_id, agent_id, tool_kind, tool_name,
            operation, resource_json, action_json, normalized_json, scope_hash,
            status, result_hash, mcp_json, started_at, finished_at, error_code, created_at
          ) VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            $8, $9::jsonb, $10::jsonb, $11::jsonb, $12,
            $13, NULL, $14::jsonb, NULL, NULL, NULL, $15
          )
        `,
        [
          toolCallId,
          record.request.request_id,
          record.request.tenant_id,
          sessionId,
          agentId,
          record.request.tool.kind,
          record.request.tool.name,
          record.request.tool.operation,
          JSON.stringify(record.request.resource),
          JSON.stringify(record.request.action),
          JSON.stringify(record.request.normalized),
          record.context.scope_hash,
          toolCallStatus,
          JSON.stringify({ decision_token: decisionToken }),
          now,
        ],
      )

      const approvalReq =
        record.response.decision === "approval_required" ||
        (record.approvalId !== undefined)
      const constraintsJson =
        record.response.decision === "allow" ? JSON.stringify(record.response.constraints ?? null) : null

      await client.query(
        `
          INSERT INTO policy_decisions (
            id, request_id, tenant_id, tool_call_id, policy_bundle_id, cedar_result,
            risk_class, approval_req, final_decision, decision_mode, reason, reason_code,
            constraints_json, created_at
          ) VALUES (
            $1, $2, $3, $4, $5, $6,
            $7, $8, $9, $10, $11, $12,
            $13::jsonb, $14
          )
        `,
        [
          decisionId,
          record.request.request_id,
          record.request.tenant_id,
          toolCallId,
          policyBundleId,
          record.cedarResult,
          record.riskClass,
          approvalReq,
          record.response.decision,
          record.response.decision_mode,
          record.response.reason,
          record.response.reason_code,
          constraintsJson,
          now,
        ],
      )

      // Insert approval record if needed
      if (
        record.approvalId !== undefined &&
        record.approvalExpiresAt !== undefined &&
        record.response.decision === "approval_required"
      ) {
        await client.query(
          `
            INSERT INTO approvals (
              id, tenant_id, decision_id, tool_call_id, status, scope_hash,
              expires_at, created_at
            ) VALUES ($1, $2, $3, $4, 'pending', $5, $6, $7)
          `,
          [
            record.approvalId,
            record.request.tenant_id,
            decisionId,
            toolCallId,
            record.context.scope_hash,
            record.approvalExpiresAt,
            now,
          ],
        )
      }

      // Hash-chain audit event
      const chainState = await client.query<AuditChainStateRow>(
        `
          SELECT last_hash, seq
          FROM audit_chain_state
          WHERE tenant_id = $1
          FOR UPDATE
        `,
        [record.request.tenant_id],
      )

      const previousHash = chainState[0]?.last_hash ?? "genesis"
      const nextSequence = parsePgBigInt(chainState[0]?.seq) + 1n
      const payload = {
        request_id: record.request.request_id,
        final_decision: record.response.decision,
        reason_code: record.response.reason_code,
        decision_mode: record.response.decision_mode,
      }
      const eventHash = sha256(
        `${record.request.tenant_id}${nextSequence.toString()}${previousHash}${canonicalStringify(payload)}${now}`,
      )

      await client.query(
        `
          INSERT INTO audit_events (
            id, tenant_id, event_type, actor_type, actor_id, session_id, tool_call_id,
            decision_id, seq, payload_json, prev_hash, event_hash, created_at
          ) VALUES (
            $1, $2, $3, $4, $5, $6, $7,
            $8, $9, $10::jsonb, $11, $12, $13
          )
        `,
        [
          auditEventId,
          record.request.tenant_id,
          "policy_decision.created",
          "system",
          "actantosd",
          sessionId,
          toolCallId,
          decisionId,
          nextSequence.toString(),
          JSON.stringify(payload),
          previousHash,
          eventHash,
          now,
        ],
      )

      await client.query(
        `
          UPDATE audit_chain_state
          SET last_hash = $1, seq = $2, updated_at = $3
          WHERE tenant_id = $4
        `,
        [eventHash, nextSequence.toString(), now, record.request.tenant_id],
      )
    })
  }
}
