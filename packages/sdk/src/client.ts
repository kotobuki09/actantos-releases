import { randomUUID } from "node:crypto"

export type InterceptDecision = 
  | { decision: "allow"; decision_id: string; reason: string; reason_code: string; decision_token?: string; constraints?: any }
  | { decision: "deny"; decision_id: string; reason: string; reason_code: string }
  | { decision: "approval_required"; decision_id: string; reason: string; reason_code: string; approval: { approval_id: string } }

export type ToolCallRequest = {
  request_id?: string
  tool: {
    kind: "file" | "shell" | "http" | "github" | "mcp" | "db" | "custom"
    name: string
    operation?: string
  }
  resource?: Record<string, string>
  action: {
    operation?: string
    args: Record<string, unknown>
  }
  normalized?: Record<string, unknown>
  authorization?: {
    prior_decision_id: string
    approval_id: string
    approval_token: string
  }
}

export type ClientOptions = {
  baseUrl: string
  tenantId: string
  agentId: string
  sessionId: string
  fetchImpl?: typeof fetch
  pollIntervalMs?: number
}

export class ActantClient {
  private baseUrl: string
  private tenantId: string
  private agentId: string
  private sessionId: string
  private fetchImpl: typeof fetch
  private pollIntervalMs: number

  constructor(options: ClientOptions) {
    this.baseUrl = options.baseUrl.replace(/\/$/, "")
    this.tenantId = options.tenantId
    this.agentId = options.agentId
    this.sessionId = options.sessionId
    this.fetchImpl = options.fetchImpl ?? globalThis.fetch.bind(globalThis)
    this.pollIntervalMs = options.pollIntervalMs ?? 2000
  }

  async interceptToolCall(request: ToolCallRequest): Promise<InterceptDecision> {
    const requestId = request.request_id ?? `req_${randomUUID()}`
    
    const response = await this.fetchImpl(`${this.baseUrl}/v1/intercept/tool-call`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        request_id: requestId,
        tenant_id: this.tenantId,
        agent: { id: this.agentId },
        session: { id: this.sessionId },
        tool: request.tool,
        resource: request.resource ?? {},
        action: request.action,
        normalized: request.normalized ?? {},
        authorization: request.authorization,
      }),
    })

    if (!response.ok) {
      throw new Error(`intercept request failed with status ${response.status}`)
    }

    return (await response.json()) as InterceptDecision
  }

  async reportToolResult(payload: any): Promise<void> {
    const response = await this.fetchImpl(`${this.baseUrl}/v1/tool-result`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(payload),
    })

    if (!response.ok) {
      throw new Error(`tool result request failed with status ${response.status}`)
    }
  }

  async listPendingApprovals(): Promise<any[]> {
    const url = new URL(`${this.baseUrl}/v1/approvals/pending`)
    url.searchParams.set("tenant_id", this.tenantId)
    
    const response = await this.fetchImpl(url.toString(), { method: "GET" })
    if (!response.ok) {
      throw new Error(`list approvals request failed with status ${response.status}`)
    }

    const data = await response.json() as any
    return data.approvals ?? []
  }

  async decideApproval(approvalId: string, approverUserId: string, decision: "approved" | "denied" = "approved"): Promise<{ approval_token?: string }> {
    const response = await this.fetchImpl(`${this.baseUrl}/v1/approvals/${approvalId}/decide`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        decision,
        approver_user_id: approverUserId,
      }),
    })

    if (!response.ok) {
      throw new Error(`approval decision request failed with status ${response.status}`)
    }

    return (await response.json()) as { approval_token?: string }
  }

  /**
   * Polls for the approval decision to be resolved.
   * Note: This method only checks if the approval has been resolved (i.e. is no longer pending).
   * It does NOT retrieve the approval_token because the ActantOS API does not provide a way to
   * fetch an approval_token for an already-decided approval via polling.
   */
  async waitForApproval(approvalId: string): Promise<void> {
    while (true) {
      const pending = await this.listPendingApprovals()
      const isPending = pending.some((a: any) => a.approval_id === approvalId)
      if (!isPending) {
        return
      }
      await new Promise((resolve) => setTimeout(resolve, this.pollIntervalMs))
    }
  }
}
