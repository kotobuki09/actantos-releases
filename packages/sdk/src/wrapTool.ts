import type { ActantClient, ToolCallRequest } from "./client.ts"

export type ToolDefinition = {
  name: string
  description?: string
  schema?: any
  execute: (args: any) => Promise<any>
}

export type WrappedToolOptions = {
  kind?: ToolCallRequest["tool"]["kind"]
  operation?: string
  resourceFactory?: (args: any) => Record<string, string>
  normalizedFactory?: (args: any) => Record<string, unknown>
}

export class GuardedAccessDenied extends Error {
  public readonly reasonCode: string;
  public readonly reason: string;
  public readonly decisionId: string;

  constructor(reasonCode: string, reason: string, decisionId: string) {
    super(`Access denied (${reasonCode}): ${reason}`)
    this.name = "GuardedAccessDenied"
    this.reasonCode = reasonCode
    this.reason = reason
    this.decisionId = decisionId
  }
}

export class ApprovalRequired extends Error {
  public readonly approvalId: string;
  public readonly reasonCode: string;
  public readonly reason: string;
  public readonly decisionId: string;

  constructor(approvalId: string, reasonCode: string, reason: string, decisionId: string) {
    super(`Approval required (${reasonCode}): ${reason}`)
    this.name = "ApprovalRequired"
    this.approvalId = approvalId
    this.reasonCode = reasonCode
    this.reason = reason
    this.decisionId = decisionId
  }
}

export const wrapTool = (
  client: ActantClient,
  tool: ToolDefinition,
  options: WrappedToolOptions = {}
) => {
  return async (args: any, authorization?: ToolCallRequest["authorization"]): Promise<any> => {
    const requestId = `req_${crypto.randomUUID()}`
    const request: ToolCallRequest = {
      request_id: requestId,
      tool: {
        kind: options.kind ?? "custom",
        name: tool.name,
        operation: options.operation,
      },
      action: {
        operation: options.operation,
        args,
      },
      resource: options.resourceFactory?.(args),
      normalized: options.normalizedFactory?.(args),
      authorization,
    }

    const decision = await client.interceptToolCall(request)

    if (decision.decision === "deny") {
      await client.reportToolResult({
        request_id: requestId,
        decision_id: decision.decision_id,
        tool_kind: request.tool.kind,
        status: "blocked",
        started_at: new Date().toISOString(),
        finished_at: new Date().toISOString(),
        result: {
          error_message: `Access denied: ${decision.reason}`,
        },
      })
      throw new GuardedAccessDenied(decision.reason_code, decision.reason, decision.decision_id)
    }

    if (decision.decision === "approval_required") {
      await client.reportToolResult({
        request_id: requestId,
        decision_id: decision.decision_id,
        tool_kind: request.tool.kind,
        status: "blocked",
        started_at: new Date().toISOString(),
        finished_at: new Date().toISOString(),
        result: {
          error_message: `Approval required: ${decision.reason}`,
        },
      })
      throw new ApprovalRequired(
        decision.approval.approval_id,
        decision.reason_code,
        decision.reason,
        decision.decision_id,
      )
    }

    // decision === "allow"
    const startedAt = new Date().toISOString()
    try {
      const result = await tool.execute(args)
      const finishedAt = new Date().toISOString()
      
      await client.reportToolResult({
        request_id: requestId,
        decision_id: decision.decision_id,
        decision_token: decision.decision_token,
        tool_kind: request.tool.kind,
        status: "executed",
        started_at: startedAt,
        finished_at: finishedAt,
        result: {
          exit_code: 0,
          redacted_preview: String(result).slice(0, 200),
        },
      })
      
      return result
    } catch (error: any) {
      const finishedAt = new Date().toISOString()
      
      await client.reportToolResult({
        request_id: requestId,
        decision_id: decision.decision_id,
        decision_token: decision.decision_token,
        tool_kind: request.tool.kind,
        status: "failed",
        started_at: startedAt,
        finished_at: finishedAt,
        result: {
          exit_code: 1,
          error_message: error.message ?? String(error),
          redacted_preview: "",
        },
      })
      
      throw error
    }
  }
}
