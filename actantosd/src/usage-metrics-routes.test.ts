import assert from "node:assert/strict"
import test from "node:test"

import { buildServer } from "./server.ts"
import { createTestDatabase } from "./test-database.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"

const recordExecutedRead = async (
  server: ReturnType<typeof buildServer>,
  requestId: string,
): Promise<void> => {
  const interceptResponse = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: {
      request_id: requestId,
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
    },
  })

  assert.equal(interceptResponse.statusCode, 200)
  const { decision_id, decision_token } = interceptResponse.json()
  assert.equal(typeof decision_id, "string")
  assert.equal(typeof decision_token, "string")

  const resultResponse = await server.inject({
    method: "POST",
    url: "/v1/tool-result",
    payload: {
      request_id: requestId,
      decision_id,
      decision_token,
      tool_kind: "file",
      status: "executed",
      started_at: new Date().toISOString(),
      finished_at: new Date().toISOString(),
      result: {
        exit_code: 0,
        stdout_hash: "stdout-hash",
        stderr_hash: null,
        redacted_preview: "README read",
      },
    },
  })

  assert.equal(resultResponse.statusCode, 200)
}

const createApprovalRequiredDecision = async (
  server: ReturnType<typeof buildServer>,
  requestId: string,
): Promise<void> => {
  const approvalResponse = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: {
      request_id: requestId,
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
        kind: "shell",
        name: "guarded_bash",
        operation: "ExecuteShellCommand",
        schema_hash: "",
      },
      resource: {
        id: "/workspace",
        kind: "workspace",
        path: "/workspace",
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
        risk_class: "low",
        command_family: "git",
        subcommand: "push",
        target_type: "argv_command",
        recursive_delete: false,
        force: false,
      },
    },
  })

  assert.equal(approvalResponse.statusCode, 200)
  assert.equal(approvalResponse.json().decision, "approval_required")
}

test("GET /v1/metrics/usage returns pilot usage totals for a tenant", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  await recordExecutedRead(server, "req_usage_allow_0001")
  await createApprovalRequiredDecision(server, "req_usage_approval_0001")

  const response = await server.inject({
    method: "GET",
    url: "/v1/metrics/usage?tenant_id=t_demo",
  })

  assert.equal(response.statusCode, 200)
  const body = response.json()
  assert.equal(body.tenant_id, "t_demo")
  assert.deepEqual(body.summary, {
    session_count: 1,
    decision_count: 2,
    allow_count: 1,
    deny_count: 0,
    approval_required_count: 1,
    approval_count: 1,
    executed_tool_result_count: 1,
    failed_tool_result_count: 0,
    timeout_tool_result_count: 0,
    blocked_tool_result_count: 0,
    active_kill_switch_count: 0,
  })
  assert.equal(body.ops_home.allow_rate, 0.5)
  assert.equal(body.ops_home.deny_rate, 0)
  assert.equal(body.ops_home.approval_required_rate, 0.5)
  assert.equal(body.ops_home.kill_switch_armed, false)
  assert.equal(typeof body.ops_home.budget_remaining, "number")
  assert.equal(typeof body.ops_home.budget_limit, "number")
  assert.deepEqual(body.tool_kinds, [
    { tool_kind: "file", count: 1 },
    { tool_kind: "shell", count: 1 },
  ])

  await server.close()
  await database.close()
})
