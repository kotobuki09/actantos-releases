import assert from "node:assert/strict"
import test from "node:test"

import type { BudgetProvider } from "./budget-provider.ts"
import type { ToolCallInterceptionRequest } from "./contracts.ts"
import { createInterceptService } from "./intercept-service.ts"
import { InMemoryToolCallRepository } from "./tool-call-repository.ts"

const baseRequest = (): ToolCallInterceptionRequest => ({
  request_id: "req_budget_0001",
  tenant_id: "t_demo",
  agent: {
    id: "pi_demo",
    runtime_type: "pi",
    environment: "dev",
    risk_tier: "low",
  },
  subject: {
    user_id: "u_demo",
    role: "developer",
  },
  session: {
    id: "s_demo",
    cwd: "/workspace",
    budget_remaining_cents: 10_000,
  },
  tool: {
    kind: "file",
    name: "guarded_read",
    operation: "ReadFile",
    schema_hash: "",
  },
  resource: {
    id: "/workspace/README.md",
    kind: "file",
    path: "/workspace/README.md",
  },
  action: {
    operation: "ReadFile",
    args: { path: "/workspace/README.md" },
  },
  normalized: {
    verb: "read",
    mutation: false,
    destructive: false,
    network: false,
    credential_access: false,
    risk_class: "low",
  },
})

class ExhaustedBudgetProvider implements BudgetProvider {
  calls = 0

  async checkAndConsume(): Promise<{ readonly allowed: boolean }> {
    this.calls += 1
    return { allowed: false }
  }
}

test("intercept denies budget_exceeded before policy evaluation and replays idempotently", async () => {
  const repository = new InMemoryToolCallRepository()
  const budgetProvider = new ExhaustedBudgetProvider()
  const service = createInterceptService({
    repository,
    hmacSecret: "test-secret",
    budgetProvider,
  })
  const request = baseRequest()

  const first = await service.intercept(request)
  const second = await service.intercept(request)

  assert.equal(first.decision, "deny")
  assert.equal(first.reason_code, "budget_exceeded")
  assert.deepEqual(second, first)
  assert.equal(budgetProvider.calls, 1)
  assert.equal(repository.count(), 1)
})
