import { randomUUID } from "node:crypto"

import type {
  ToolCallContext,
  ToolCallInterceptionRequest,
  ToolCallInterceptionResponse,
} from "./contracts.ts"
import { createDenyResponse } from "./intercept-response.ts"
import type { CedarDecision } from "./fake-cedar-provider.ts"
import type { ToolCallRepository } from "./tool-call-repository.ts"

type PersistFailClosedDecisionOptions = {
  readonly repository: ToolCallRepository
  readonly request: ToolCallInterceptionRequest
  readonly context: ToolCallContext
  readonly decisionMode: "enforce" | "dry_run"
  readonly reason: string
  readonly reasonCode: string
  readonly riskClass: string
  readonly cedarResult?: CedarDecision
  readonly priorDecisionId?: string
}

export const persistFailClosedDecision = async (
  options: PersistFailClosedDecisionOptions,
): Promise<ToolCallInterceptionResponse> => {
  const response = createDenyResponse({
    decisionId: randomUUID(),
    decisionMode: options.decisionMode,
    reason: options.reason,
    reasonCode: options.reasonCode,
    auditEventId: randomUUID(),
  })

  try {
    await options.repository.saveDecision({
      request: options.request,
      response,
      context: options.context,
      cedarResult: options.cedarResult ?? "forbid",
      riskClass: options.riskClass,
      ...(options.priorDecisionId === undefined
        ? {}
        : { priorDecisionId: options.priorDecisionId }),
    })
  } catch {
    return response
  }

  return response
}
