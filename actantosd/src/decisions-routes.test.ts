import assert from "node:assert/strict"
import test from "node:test"

import { buildServer } from "./server.ts"
import { createTestDatabase } from "./test-database.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"

const allowDecisionRequest = {
  request_id: "req_decisions_allow_0001",
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
    purpose: "Dashboard decision coverage",
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
} as const

const denyDecisionRequest = {
  ...allowDecisionRequest,
  request_id: "req_decisions_deny_0001",
  resource: {
    id: "/workspace/.env",
    kind: "file",
    path: "/workspace/.env",
  },
  action: {
    operation: "ReadFile",
    args: { path: "/workspace/.env" },
  },
  normalized: {
    ...allowDecisionRequest.normalized,
    credential_access: true,
  },
} as const

const approvalDecisionRequest = {
  ...allowDecisionRequest,
  request_id: "req_decisions_approval_0001",
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
} as const

test("GET /v1/decisions returns recent allow, deny, and approval_required decisions", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const allowResponse = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: allowDecisionRequest,
  })
  const denyResponse = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: denyDecisionRequest,
  })
  const approvalResponse = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: approvalDecisionRequest,
  })

  assert.equal(allowResponse.json().decision, "allow")
  assert.equal(denyResponse.json().decision, "deny")
  assert.equal(approvalResponse.json().decision, "approval_required")

  const response = await server.inject({
    method: "GET",
    url: "/v1/decisions?tenant_id=t_demo",
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), {
    tenant_id: "t_demo",
    filters: {
      final_decision: null,
      risk_class: null,
      session_id: null,
      agent_id: null,
    },
    decisions: [
      {
        decision_id: response.json().decisions[0].decision_id,
        request_id: "req_decisions_approval_0001",
        final_decision: "approval_required",
        decision_mode: "enforce",
        reason: "risk.shell.git_push — approval required",
        reason_code: "approval_required",
        risk_class: "high",
        approval_required: true,
        tool: {
          kind: "shell",
          name: "guarded_bash",
          operation: "ExecuteShellCommand",
        },
        session_id: "s_demo",
        agent_id: "pi_demo",
        approval: {
          approval_id: approvalResponse.json().approval.approval_id,
          status: "pending",
        },
        created_at: response.json().decisions[0].created_at,
      },
      {
        decision_id: response.json().decisions[1].decision_id,
        request_id: "req_decisions_deny_0001",
        final_decision: "deny",
        decision_mode: "enforce",
        reason: "blocked by policy",
        reason_code: "policy_forbid.credential_path",
        risk_class: "critical",
        approval_required: false,
        tool: {
          kind: "file",
          name: "guarded_read",
          operation: "ReadFile",
        },
        session_id: "s_demo",
        agent_id: "pi_demo",
        approval: null,
        created_at: response.json().decisions[1].created_at,
      },
      {
        decision_id: response.json().decisions[2].decision_id,
        request_id: "req_decisions_allow_0001",
        final_decision: "allow",
        decision_mode: "enforce",
        reason: "permitted by policy",
        reason_code: "allowed",
        risk_class: "low",
        approval_required: false,
        tool: {
          kind: "file",
          name: "guarded_read",
          operation: "ReadFile",
        },
        session_id: "s_demo",
        agent_id: "pi_demo",
        approval: null,
        created_at: response.json().decisions[2].created_at,
      },
    ],
  })
  assert.equal(typeof response.json().decisions[0].decision_id, "string")
  assert.equal(typeof response.json().decisions[0].created_at, "string")

  await server.close()
  await database.close()
})

test("GET /v1/decisions returns an empty list for a tenant with no decisions", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const response = await server.inject({
    method: "GET",
    url: "/v1/decisions?tenant_id=t_empty",
  })

  assert.equal(response.statusCode, 200)
  assert.deepEqual(response.json(), {
    tenant_id: "t_empty",
    filters: {
      final_decision: null,
      risk_class: null,
      session_id: null,
      agent_id: null,
    },
    decisions: [],
  })

  await server.close()
  await database.close()
})

test("GET /v1/decisions filters by final_decision, risk_class, session_id, and agent_id", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  for (const payload of [allowDecisionRequest, denyDecisionRequest, approvalDecisionRequest]) {
    const intercept = await server.inject({
      method: "POST",
      url: "/v1/intercept/tool-call",
      payload,
    })
    assert.ok(intercept.statusCode === 200 || intercept.statusCode === 201 || intercept.json().decision !== undefined)
  }

  const denyOnly = await server.inject({
    method: "GET",
    url: "/v1/decisions?tenant_id=t_demo&final_decision=deny",
  })
  assert.equal(denyOnly.statusCode, 200)
  assert.equal(denyOnly.json().filters.final_decision, "deny")
  assert.ok(denyOnly.json().decisions.length >= 1)
  assert.ok(denyOnly.json().decisions.every((row: { final_decision: string }) => row.final_decision === "deny"))

  const highRisk = await server.inject({
    method: "GET",
    url: "/v1/decisions?tenant_id=t_demo&risk_class=high",
  })
  assert.equal(highRisk.statusCode, 200)
  assert.ok(highRisk.json().decisions.length >= 1)
  assert.ok(highRisk.json().decisions.every((row: { risk_class: string }) => row.risk_class === "high"))

  const bySession = await server.inject({
    method: "GET",
    url: "/v1/decisions?tenant_id=t_demo&session_id=s_demo&agent_id=pi_demo",
  })
  assert.equal(bySession.statusCode, 200)
  assert.equal(bySession.json().filters.session_id, "s_demo")
  assert.equal(bySession.json().filters.agent_id, "pi_demo")
  assert.ok(bySession.json().decisions.length >= 1)

  await server.close()
  await database.close()
})
