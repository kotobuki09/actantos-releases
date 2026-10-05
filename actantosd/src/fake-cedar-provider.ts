import type { ToolCallContext } from "./contracts.ts"

export type CedarDecision = { decision: "permit" | "forbid", reasonCode?: string }

export interface CedarProvider {
  evaluate(context: ToolCallContext): Promise<CedarDecision> | CedarDecision
  reloadPolicy?(newPolicyContent: string): void
}

export class FakeCedarProvider implements CedarProvider {
  #policyContent?: string

  evaluate(context: ToolCallContext): CedarDecision {
    if (this.#policyContent === "permit(principal, action, resource);") {
      return { decision: "permit" }
    }
    if (this.#policyContent === "forbid(principal, action, resource);") {
      return { decision: "forbid" }
    }
    return { decision: context.normalized.credential_access ? "forbid" : "permit" }
  }

  reloadPolicy(newPolicyContent: string): void {
    this.#policyContent = newPolicyContent
  }
}
