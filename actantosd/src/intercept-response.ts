import {
  type ToolCallContext,
  type ToolCallInterceptionRequest,
  type ToolCallInterceptionResponse,
  toolCallInterceptionResponseSchema,
} from "./contracts.ts"
import { canonicalHash, canonicalStringify, signDecisionToken } from "./hash.ts"
import type { DecisionConstraints } from "./decision-constraints.ts"

type CreateDecisionTokenOptions = {
  readonly decisionId: string
  readonly toolCallId: string
  readonly request: ToolCallInterceptionRequest
  readonly scopeHash: string
  readonly constraints: DecisionConstraints
  readonly expiresAtEpochSeconds: number
  readonly hmacSecret: string
  readonly approved?: boolean
}

type CreateResponseBaseOptions = {
  readonly decisionId: string
  readonly auditEventId: string
  readonly decisionMode: "enforce" | "dry_run"
}

type CreateDenyResponseOptions = CreateResponseBaseOptions & {
  readonly reason: string
  readonly reasonCode: string
}

type CreateAllowResponseOptions = CreateResponseBaseOptions & {
  readonly reason: string
  readonly reasonCode: string
  readonly decisionToken?: string
  readonly constraints?: DecisionConstraints
}

type CreateApprovalRequiredResponseOptions = CreateResponseBaseOptions & {
  readonly reason: string
  readonly approvalId: string
  readonly expiresAt: string
}

export const mapForbidReason = (context: ToolCallContext): string => {
  if (context.normalized.credential_access) {
    return "policy_forbid.credential_path"
  }
  if (context.normalized.destructive && context.normalized.recursive_delete) {
    return "policy_forbid.destructive_delete"
  }
  if (context.agent.environment === "prod" && context.normalized.mutation) {
    return "policy_forbid.prod_mutation"
  }
  return "policy_forbid"
}

export const createToolCallContext = (
  request: ToolCallInterceptionRequest,
): ToolCallContext => ({
  ...request,
  scope_hash: canonicalHash({
    tenant_id: request.tenant_id,
    agent_id: request.agent.id,
    user_id: request.subject.user_id,
    session_id: request.session.id,
    tool_name: request.tool.name,
    resource: request.resource,
    normalized: request.normalized,
  }),
})

export const createDecisionToken = (
  options: CreateDecisionTokenOptions,
): string =>
  signDecisionToken(
    canonicalStringify({
      decision_id: options.decisionId,
      tool_call_id: options.toolCallId,
      request_id: options.request.request_id,
      tenant_id: options.request.tenant_id,
      agent_id: options.request.agent.id,
      session_id: options.request.session.id,
      tool_name: options.request.tool.name,
      scope_hash: options.scopeHash,
      constraints_hash: canonicalHash(options.constraints),
      decision: "allow",
      exp: options.expiresAtEpochSeconds,
      ...(options.approved === true ? { approved: true } : {}),
    }),
    options.hmacSecret,
  )

export const createDenyResponse = (
  options: CreateDenyResponseOptions,
): ToolCallInterceptionResponse =>
  toolCallInterceptionResponseSchema.parse({
    decision: "deny",
    decision_mode: options.decisionMode,
    decision_id: options.decisionId,
    reason: options.reason,
    reason_code: options.reasonCode,
    audit_event_id: options.auditEventId,
  })

export const createAllowResponse = (
  options: CreateAllowResponseOptions,
): ToolCallInterceptionResponse =>
  toolCallInterceptionResponseSchema.parse({
    decision: "allow",
    decision_mode: options.decisionMode,
    decision_id: options.decisionId,
    reason: options.reason,
    reason_code: options.reasonCode,
    audit_event_id: options.auditEventId,
    ...(options.decisionToken === undefined
      ? {}
      : { decision_token: options.decisionToken }),
    ...(options.constraints === undefined ? {} : { constraints: options.constraints }),
  })

export const createApprovalRequiredResponse = (
  options: CreateApprovalRequiredResponseOptions,
): ToolCallInterceptionResponse =>
  toolCallInterceptionResponseSchema.parse({
    decision: "approval_required",
    decision_mode: options.decisionMode,
    decision_id: options.decisionId,
    reason: options.reason,
    reason_code: "approval_required",
    audit_event_id: options.auditEventId,
    approval: {
      approval_id: options.approvalId,
      status: "pending",
      expires_at: options.expiresAt,
    },
  })
