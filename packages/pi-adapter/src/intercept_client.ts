import { randomUUID } from "node:crypto"

type AgentIdentity = {
  readonly id: string
  readonly runtime_type: "pi" | "mcp" | "langgraph" | "custom"
  readonly environment: "dev" | "staging" | "prod"
  readonly risk_tier: "low" | "medium" | "high"
}

type SubjectIdentity = {
  readonly user_id: string
  readonly role?: string
}

type SessionIdentity = {
  readonly id: string
  readonly cwd: string
  readonly purpose?: string
  readonly budget_remaining_cents?: number
}

type InterceptConstraints = {
  readonly timeout_ms?: number
  readonly max_output_bytes?: number
  readonly network_mode?: "none" | "egress_proxy"
  readonly network_allowlist?: readonly string[]
}

export type InterceptDecision =
  | {
      readonly decision: "allow"
      readonly decision_id: string
      readonly reason: string
      readonly reason_code: string
      readonly decision_token?: string
      readonly constraints?: InterceptConstraints
    }
  | {
      readonly decision: "deny"
      readonly decision_id: string
      readonly reason: string
      readonly reason_code: string
    }
  | {
      readonly decision: "approval_required"
      readonly decision_id: string
      readonly reason: string
      readonly reason_code: string
      readonly approval: {
        readonly approval_id: string
      }
    }

type FetchLike = (input: string, init?: RequestInit) => Promise<Response>

export type ApprovalDecisionResponse = {
  readonly approval_id: string
  readonly decision: "approved" | "denied"
  readonly approval_token?: string
  readonly decided_at: string
  readonly expires_at?: string
}

export type ToolResultRequest = {
  readonly request_id: string
  readonly decision_id: string
  readonly decision_token?: string
  readonly tool_kind: "file" | "shell" | "http" | "github" | "mcp" | "db" | "custom"
  readonly status: "executed" | "failed" | "timeout" | "blocked"
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

export type InterceptDependencies = {
  readonly workspaceRoot: string
  readonly interceptUrl: string
  readonly tenantId: string
  readonly agent: AgentIdentity
  readonly subject: SubjectIdentity
  readonly session: SessionIdentity
  readonly fetchImpl?: FetchLike
  readonly requestIdFactory?: () => string
  readonly timeoutMs?: number
}

type InterceptRequest = {
  readonly requestId: string
  readonly tool: {
    readonly kind: "file" | "shell"
    readonly name: "guarded_read" | "guarded_write" | "guarded_edit" | "guarded_ls" | "guarded_grep" | "guarded_find" | "guarded_bash"
    readonly operation: "ReadFile" | "WriteFile" | "EditFile" | "ListFiles" | "SearchFiles" | "ExecuteShellCommand"
  }
  readonly resource: Record<string, string>
  readonly action: {
    readonly operation: "ReadFile" | "WriteFile" | "EditFile" | "ListFiles" | "SearchFiles" | "ExecuteShellCommand"
    readonly args: Record<string, unknown>
  }
  readonly normalized: Record<string, unknown>
  readonly authorization?: {
    readonly prior_decision_id: string
    readonly approval_id: string
    readonly approval_token: string
  }
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null

const parseConstraints = (value: unknown): InterceptConstraints | undefined => {
  if (!isRecord(value)) {
    return undefined
  }

  const timeoutMs = value["timeout_ms"]
  const maxOutputBytes = value["max_output_bytes"]
  const networkMode = value["network_mode"]
  const networkAllowlist = value["network_allowlist"]

  const constraints: {
    timeout_ms?: number
    max_output_bytes?: number
    network_mode?: "none" | "egress_proxy"
    network_allowlist?: readonly string[]
  } = {}

  if (typeof timeoutMs === "number") {
    constraints.timeout_ms = timeoutMs
  }
  if (typeof maxOutputBytes === "number") {
    constraints.max_output_bytes = maxOutputBytes
  }
  if (networkMode === "none" || networkMode === "egress_proxy") {
    constraints.network_mode = networkMode
  }
  if (
    Array.isArray(networkAllowlist) &&
    networkAllowlist.every((entry) => typeof entry === "string")
  ) {
    constraints.network_allowlist = networkAllowlist
  }

  return constraints
}

const parseInterceptDecision = (value: unknown): InterceptDecision => {
  if (!isRecord(value)) {
    throw new Error("invalid intercept response payload")
  }

  const decision = value["decision"]
  const decisionId = value["decision_id"]
  const reason = value["reason"]
  const reasonCode = value["reason_code"]

  if (
    typeof decision !== "string" ||
    typeof decisionId !== "string" ||
    typeof reason !== "string" ||
    typeof reasonCode !== "string"
  ) {
    throw new Error("invalid intercept response fields")
  }

  switch (decision) {
    case "allow": {
      const decisionToken = value["decision_token"]
      const allowDecision: {
        decision: "allow"
        decision_id: string
        reason: string
        reason_code: string
        decision_token?: string
        constraints?: InterceptConstraints
      } = {
        decision,
        decision_id: decisionId,
        reason,
        reason_code: reasonCode,
      }

      if (typeof decisionToken === "string") {
        allowDecision.decision_token = decisionToken
      }

      const constraints = parseConstraints(value["constraints"])
      if (constraints !== undefined) {
        allowDecision.constraints = constraints
      }

      return allowDecision
    }
    case "deny":
      return { decision, decision_id: decisionId, reason, reason_code: reasonCode }
    case "approval_required": {
      const approval = value["approval"]
      if (!isRecord(approval)) {
        throw new Error("invalid approval response")
      }
      const approvalId = approval["approval_id"]
      if (typeof approvalId !== "string") {
        throw new Error("invalid approval id")
      }
      return {
        decision,
        decision_id: decisionId,
        reason,
        reason_code: reasonCode,
        approval: { approval_id: approvalId },
      }
    }
    default:
      throw new Error(`unsupported decision: ${String(decision)}`)
  }
}

export const createRequestId = (dependencies: InterceptDependencies): string =>
  dependencies.requestIdFactory?.() ?? `req_${randomUUID()}`

export const postInterceptDecision = async (
  dependencies: InterceptDependencies,
  request: InterceptRequest,
): Promise<InterceptDecision> => {
  const fetchImpl = dependencies.fetchImpl ?? fetch
  const timeoutMs = dependencies.timeoutMs ?? 5_000
  const response = await fetchImpl(dependencies.interceptUrl, {
    method: "POST",
    headers: {
      "content-type": "application/json",
    },
    body: JSON.stringify({
      request_id: request.requestId,
      tenant_id: dependencies.tenantId,
      agent: dependencies.agent,
      subject: dependencies.subject,
      session: dependencies.session,
      tool: request.tool,
      resource: request.resource,
      action: request.action,
      normalized: request.normalized,
      authorization: request.authorization,
    }),
    signal: AbortSignal.timeout(timeoutMs),
  })

  if (!response.ok) {
    throw new Error(`intercept request failed with status ${response.status}`)
  }

  return parseInterceptDecision(await response.json())
}

export const postApprovalDecision = async (
  dependencies: InterceptDependencies,
  approvalId: string,
  approverUserId: string,
  decision: "approved" | "denied" = "approved",
): Promise<ApprovalDecisionResponse> => {
  const fetchImpl = dependencies.fetchImpl ?? fetch
  const timeoutMs = dependencies.timeoutMs ?? 5_000
  const response = await fetchImpl(
    `${dependencies.interceptUrl.replace(/\/v1\/intercept\/tool-call$/, "")}/v1/approvals/${approvalId}/decide`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify({
        decision,
        approver_user_id: approverUserId,
      }),
      signal: AbortSignal.timeout(timeoutMs),
    },
  )

  if (!response.ok) {
    throw new Error(`approval decision request failed with status ${response.status}`)
  }

  const payload = await response.json()
  if (!isRecord(payload)) {
    throw new Error("invalid approval decision response payload")
  }

  const returnedApprovalId = payload["approval_id"]
  const returnedDecision = payload["decision"]
  const approvalToken = payload["approval_token"]
  const decidedAt = payload["decided_at"]
  const expiresAt = payload["expires_at"]

  if (
    typeof returnedApprovalId !== "string" ||
    (returnedDecision !== "approved" && returnedDecision !== "denied") ||
    typeof decidedAt !== "string"
  ) {
    throw new Error("invalid approval decision response fields")
  }

  const parsed: {
    approval_id: string
    decision: "approved" | "denied"
    approval_token?: string
    decided_at: string
    expires_at?: string
  } = {
    approval_id: returnedApprovalId,
    decision: returnedDecision,
    decided_at: decidedAt,
  }

  if (typeof approvalToken === "string") {
    parsed.approval_token = approvalToken
  }
  if (typeof expiresAt === "string") {
    parsed.expires_at = expiresAt
  }

  return parsed
}

export const postToolResult = async (
  dependencies: InterceptDependencies,
  payload: ToolResultRequest,
): Promise<Record<string, unknown>> => {
  const fetchImpl = dependencies.fetchImpl ?? fetch
  const timeoutMs = dependencies.timeoutMs ?? 5_000
  const response = await fetchImpl(
    `${dependencies.interceptUrl.replace(/\/v1\/intercept\/tool-call$/, "")}/v1/tool-result`,
    {
      method: "POST",
      headers: {
        "content-type": "application/json",
      },
      body: JSON.stringify(payload),
      signal: AbortSignal.timeout(timeoutMs),
    },
  )

  if (!response.ok) {
    throw new Error(`tool result request failed with status ${response.status}`)
  }

  const result = await response.json()
  if (!isRecord(result)) {
    throw new Error("invalid tool result response payload")
  }

  return result
}
