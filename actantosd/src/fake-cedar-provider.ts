import type { ToolCallContext } from "./contracts.ts"

export type CedarDecision = "permit" | "forbid"

export interface CedarProvider {
  evaluate(context: ToolCallContext): Promise<CedarDecision> | CedarDecision
}

export class FakeCedarProvider implements CedarProvider {
  evaluate(context: ToolCallContext): CedarDecision {
    return context.normalized.credential_access ? "forbid" : "permit"
  }
}
