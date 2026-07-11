import { mkdtemp, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"

import { CedarCliProvider } from "./cedar-cli-provider.ts"
import type { ToolCallInterceptionRequest } from "./contracts.ts"
import type { CedarProvider } from "./fake-cedar-provider.ts"
import { createInterceptService } from "./intercept-service.ts"
import { RiskEngine } from "./risk-engine.ts"
import { InMemoryToolCallRepository } from "./tool-call-repository.ts"

export type PolicyBundleDryRunResult = {
  readonly policy_bundle: {
    readonly id: string
    readonly version: string
    readonly tenant_id: string
  }
  readonly decision: string
  readonly decision_mode: "dry_run"
  readonly decision_id: string
  readonly reason: string
  readonly reason_code: string
  readonly approval_id?: string
}

export const runPolicyBundleDryRun = async (options: {
  readonly bundle: {
    readonly id: string
    readonly version: string
    readonly tenant_id: string
    readonly source_text: string
  }
  readonly request: ToolCallInterceptionRequest
  readonly cedarProvider?: CedarProvider
}): Promise<PolicyBundleDryRunResult> => {
  let temporaryPolicyDirectory: string | undefined

  try {
    let cedarProvider = options.cedarProvider
    if (cedarProvider === undefined) {
      temporaryPolicyDirectory = await mkdtemp(path.join(tmpdir(), "actantos-bundle-test-"))
      const policyPath = path.join(temporaryPolicyDirectory, "candidate.cedar")
      await writeFile(policyPath, options.bundle.source_text, "utf8")
      cedarProvider = new CedarCliProvider({ policyPath })
    }

    const service = createInterceptService({
      repository: new InMemoryToolCallRepository(),
      hmacSecret: "actantos-policy-bundle-test",
      cedarProvider,
      riskEngine: new RiskEngine({ database: undefined, rulesPath: undefined }),
    })

    const response = await service.intercept({
      ...options.request,
      tenant_id: options.bundle.tenant_id,
      dry_run: true,
    })

    return {
      policy_bundle: {
        id: options.bundle.id,
        version: options.bundle.version,
        tenant_id: options.bundle.tenant_id,
      },
      decision: response.decision,
      decision_mode: "dry_run",
      decision_id: response.decision_id,
      reason: response.reason,
      reason_code: response.reason_code,
      ...(response.decision === "approval_required"
        ? { approval_id: response.approval.approval_id }
        : {}),
    }
  } finally {
    if (temporaryPolicyDirectory !== undefined) {
      await rm(temporaryPolicyDirectory, { recursive: true, force: true })
    }
  }
}
