import assert from "node:assert/strict"
import test from "node:test"

import { toolCallInterceptionRequestSchema, type ToolCallInterceptionRequest } from "./contracts.ts"
import { safeReadRequest } from "./intercept-test-fixtures.ts"
import { buildServer } from "./server.ts"
import { createTestDatabase } from "./test-database.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"

const createRegressionHarness = async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()
  return { database, server }
}

const credentialReadRequest = (requestId: string): ToolCallInterceptionRequest =>
  toolCallInterceptionRequestSchema.parse({
    ...safeReadRequest(requestId),
    normalized: {
      ...safeReadRequest(requestId).normalized,
      credential_access: true,
      risk_class: "critical",
    },
    resource: {
      id: "/workspace/.env",
      kind: "file",
      path: "/workspace/.env",
    },
    action: {
      operation: "ReadFile",
      args: { path: "/workspace/.env" },
    },
  })

const gitPushRequest = (requestId: string): ToolCallInterceptionRequest =>
  toolCallInterceptionRequestSchema.parse({
    ...safeReadRequest(requestId),
    tool: {
      kind: "shell",
      name: "guarded_bash",
      operation: "ExecuteShellCommand",
      schema_hash: "",
    },
    resource: {
      id: "git push --dry-run origin main",
      kind: "shell_command",
      path: "git push --dry-run origin main",
    },
    action: {
      operation: "ExecuteShellCommand",
      args: {
        command: "git push --dry-run origin main",
        argv: ["git", "push", "--dry-run", "origin", "main"],
      },
    },
    normalized: {
      verb: "execute",
      mutation: true,
      destructive: false,
      network: true,
      credential_access: false,
      risk_class: "high",
      command_family: "git",
      subcommand: "push",
    },
  })

test("policy regression: safe read remains allow", async () => {
  const { database, server } = await createRegressionHarness()

  try {
    const response = await server.inject({
      method: "POST",
      url: "/v1/intercept/tool-call",
      payload: safeReadRequest("req_policy_regression_allow_0001"),
    })

    assert.equal(response.statusCode, 200)
    assert.equal(response.json().decision, "allow")
    assert.equal(response.json().reason_code, "allowed")
    assert.equal(response.json().decision_mode, "enforce")
  } finally {
    await server.close()
    await database.close()
  }
})

test("policy regression: credential read remains deny", async () => {
  const { database, server } = await createRegressionHarness()

  try {
    const response = await server.inject({
      method: "POST",
      url: "/v1/intercept/tool-call",
      payload: credentialReadRequest("req_policy_regression_deny_0001"),
    })

    assert.equal(response.statusCode, 200)
    assert.equal(response.json().decision, "deny")
    assert.equal(response.json().reason_code, "policy_forbid.credential_path")
    assert.equal(response.json().decision_mode, "enforce")
  } finally {
    await server.close()
    await database.close()
  }
})

test("policy regression: git push remains approval_required", async () => {
  const { database, server } = await createRegressionHarness()

  try {
    const response = await server.inject({
      method: "POST",
      url: "/v1/intercept/tool-call",
      payload: gitPushRequest("req_policy_regression_approval_0001"),
    })

    assert.equal(response.statusCode, 200)
    assert.equal(response.json().decision, "approval_required")
    assert.equal(response.json().reason_code, "approval_required")
    assert.equal(response.json().decision_mode, "enforce")
  } finally {
    await server.close()
    await database.close()
  }
})

test("policy regression: configured tool budget remains enforced", async () => {
  const { database, server } = await createRegressionHarness()

  try {
    const budgetResponse = await server.inject({
      method: "POST",
      url: "/v1/budgets",
      payload: {
        tenant_id: "t_demo",
        scope_type: "tool",
        scope_id: "guarded_read",
        metric: "tool_calls",
        limit_value: 1,
        window_seconds: 60,
      },
    })
    const firstDecision = await server.inject({
      method: "POST",
      url: "/v1/intercept/tool-call",
      payload: safeReadRequest("req_policy_regression_budget_0001"),
    })
    const secondDecision = await server.inject({
      method: "POST",
      url: "/v1/intercept/tool-call",
      payload: safeReadRequest("req_policy_regression_budget_0002"),
    })

    assert.equal(budgetResponse.statusCode, 201)
    assert.equal(firstDecision.json().decision, "allow")
    assert.equal(secondDecision.json().decision, "deny")
    assert.equal(secondDecision.json().reason_code, "budget_exceeded")
  } finally {
    await server.close()
    await database.close()
  }
})

test("policy regression: dry run preserves non-executing deny behavior", async () => {
  const { database, server } = await createRegressionHarness()

  try {
    const response = await server.inject({
      method: "POST",
      url: "/v1/intercept/tool-call",
      payload: {
        ...credentialReadRequest("req_policy_regression_dry_run_0001"),
        dry_run: true,
      },
    })

    assert.equal(response.statusCode, 200)
    assert.equal(response.json().decision, "deny")
    assert.equal(response.json().decision_mode, "dry_run")
    assert.equal("decision_token" in response.json(), false)
  } finally {
    await server.close()
    await database.close()
  }
})
