import { createHash, randomUUID } from "node:crypto"

import { parsePgBigInt, type Database } from "./database.ts"
import { canonicalHash, canonicalStringify, verifyDecisionToken } from "./hash.ts"

type ToolResultStatus = "executed" | "failed" | "timeout" | "blocked"

type ToolResultPayload = {
  readonly request_id: string
  readonly decision_id: string
  readonly decision_token?: string
  readonly tool_kind: "file" | "shell" | "http" | "github" | "mcp" | "db" | "custom"
  readonly status: ToolResultStatus
  readonly started_at: string
  readonly finished_at: string
  readonly result: {
    readonly exit_code?: number
    readonly stdout_hash?: string | null
    readonly stderr_hash?: string | null
    readonly redacted_preview?: string
    readonly error_message?: string
  }
}

type ToolCallLookupRow = {
  readonly id: string
  readonly tenant_id: string
  readonly agent_external_id: string
  readonly session_external_id: string
  readonly tool_name: string
  readonly scope_hash: string
  readonly session_id: string
  readonly constraints_json: unknown
}

type AuditChainStateRow = {
  readonly last_hash: string
  readonly seq: string | number | bigint
}

type DecisionTokenClaims = {
  readonly decision_id: string
  readonly tool_call_id: string
  readonly request_id: string
  readonly tenant_id: string
  readonly agent_id: string
  readonly session_id: string
  readonly tool_name: string
  readonly scope_hash: string
  readonly constraints_hash: string
  readonly decision: "allow"
  readonly exp: number
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null

const sha256Text = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex")

const parseDecisionTokenClaims = (
  token: string,
  secret: string,
): DecisionTokenClaims => {
  const verification = verifyDecisionToken(token, secret)

  if (!verification.valid) {
    throw new Error("invalid_decision_token")
  }

  let payload: unknown

  try {
    payload = JSON.parse(verification.payload) as unknown
  } catch {
    throw new Error("invalid_decision_token")
  }

  if (!isRecord(payload)) {
    throw new Error("invalid_decision_token")
  }

  const requestId = payload["request_id"]
  const decisionId = payload["decision_id"]
  const toolCallId = payload["tool_call_id"]
  const tenantId = payload["tenant_id"]
  const agentId = payload["agent_id"]
  const sessionId = payload["session_id"]
  const toolName = payload["tool_name"]
  const scopeHash = payload["scope_hash"]
  const constraintsHash = payload["constraints_hash"]
  const decision = payload["decision"]
  const exp = payload["exp"]

  if (
    typeof decisionId !== "string" ||
    typeof toolCallId !== "string" ||
    typeof requestId !== "string" ||
    typeof tenantId !== "string" ||
    typeof agentId !== "string" ||
    typeof sessionId !== "string" ||
    typeof toolName !== "string" ||
    typeof scopeHash !== "string" ||
    typeof constraintsHash !== "string" ||
    decision !== "allow" ||
    typeof exp !== "number"
  ) {
    throw new Error("invalid_decision_token")
  }

  return {
    decision_id: decisionId,
    tool_call_id: toolCallId,
    request_id: requestId,
    tenant_id: tenantId,
    agent_id: agentId,
    session_id: sessionId,
    tool_name: toolName,
    scope_hash: scopeHash,
    constraints_hash: constraintsHash,
    decision,
    exp,
  }
}

const requiresDecisionToken = (status: ToolResultStatus): boolean =>
  status === "executed" || status === "failed" || status === "timeout"

export const recordToolResult = async (
  database: Database,
  payload: ToolResultPayload,
  hmacSecret: string,
): Promise<void> => {
  await database.transaction(async (client) => {
    const toolCalls = await client.query<ToolCallLookupRow>(
      `
        SELECT tc.id, tc.tenant_id, tc.session_id, tc.tool_name, tc.scope_hash
             , pd.constraints_json
             , a.external_id AS agent_external_id
             , s.external_id AS session_external_id
        FROM tool_calls tc
        INNER JOIN policy_decisions pd
          ON pd.tool_call_id = tc.id
        INNER JOIN agents a
          ON a.id = tc.agent_id
        INNER JOIN sessions s
          ON s.id = tc.session_id
        WHERE tc.request_id = $1
          AND pd.id = $2
        FOR UPDATE
      `,
      [payload.request_id, payload.decision_id],
    )

    const toolCall = toolCalls[0]

    if (toolCall === undefined) {
      throw new Error("tool call result target not found")
    }

    if (requiresDecisionToken(payload.status)) {
      if (payload.decision_token === undefined) {
        throw new Error("decision_token_required")
      }

      const claims = parseDecisionTokenClaims(payload.decision_token, hmacSecret)

      if (
        claims.decision_id !== payload.decision_id ||
        claims.tool_call_id !== toolCall.id ||
        claims.request_id !== payload.request_id ||
        claims.tenant_id !== toolCall.tenant_id ||
        claims.agent_id !== toolCall.agent_external_id ||
        claims.session_id !== toolCall.session_external_id ||
        claims.tool_name !== toolCall.tool_name ||
        claims.scope_hash !== toolCall.scope_hash
      ) {
        throw new Error("invalid_decision_token")
      }

      if (claims.exp <= Math.floor(Date.now() / 1_000)) {
        throw new Error("invalid_decision_token")
      }

      if (
        toolCall.constraints_json === null ||
        typeof toolCall.constraints_json !== "object" ||
        claims.constraints_hash !== canonicalHash(toolCall.constraints_json)
      ) {
        throw new Error("invalid_decision_token")
      }
    }

    const resultHash = sha256Text(JSON.stringify(payload.result))

    await client.query(
      `
        UPDATE tool_calls
        SET status = $1,
            result_hash = $2,
            started_at = $3,
            finished_at = $4,
            error_code = $5
        WHERE id = $6
      `,
      [
        payload.status,
        resultHash,
        payload.started_at,
        payload.finished_at,
        payload.result.error_message ?? null,
        toolCall.id,
      ],
    )

    const chainState = await client.query<AuditChainStateRow>(
      `
        SELECT last_hash, seq
        FROM audit_chain_state
        WHERE tenant_id = $1
        FOR UPDATE
      `,
      [toolCall.tenant_id],
    )

    const previousHash = chainState[0]?.last_hash ?? "genesis"
    const nextSequence = parsePgBigInt(chainState[0]?.seq) + 1n
    const createdAt = new Date().toISOString()
    const payloadJson = {
      request_id: payload.request_id,
      status: payload.status,
      stdout_hash: payload.result.stdout_hash ?? null,
      stderr_hash: payload.result.stderr_hash ?? null,
      redacted_preview: payload.result.redacted_preview ?? "",
      error_message: payload.result.error_message ?? null,
    }
    const eventHash = sha256Text(
      `${toolCall.tenant_id}${nextSequence.toString()}${previousHash}${canonicalStringify(payloadJson)}${createdAt}`,
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
        randomUUID(),
        toolCall.tenant_id,
        "tool_result.recorded",
        "system",
        "actantosd",
        toolCall.session_id,
        toolCall.id,
        payload.decision_id,
        nextSequence.toString(),
        JSON.stringify(payloadJson),
        previousHash,
        eventHash,
        createdAt,
      ],
    )

    await client.query(
      `
        UPDATE audit_chain_state
        SET last_hash = $1, seq = $2, updated_at = $3
        WHERE tenant_id = $4
      `,
      [eventHash, nextSequence.toString(), createdAt, toolCall.tenant_id],
    )
  })
}
