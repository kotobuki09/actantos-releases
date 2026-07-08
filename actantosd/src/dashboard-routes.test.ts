import assert from "node:assert/strict"
import test from "node:test"

import { buildServer } from "./server.ts"
import { createTestDatabase } from "./test-database.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"

test("GET /dashboard renders the Agents screen with seeded agent data", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const response = await server.inject({
    method: "GET",
    url: "/dashboard?tenant_id=t_demo",
  })

  assert.equal(response.statusCode, 200)
  assert.match(String(response.headers["content-type"]), /^text\/html/u)
  assert.match(response.body, /ActantOS Dashboard/u)
  assert.match(response.body, /Agent inventory/u)
  assert.match(response.body, /Pi Demo Agent/u)
  assert.match(response.body, /pi_demo/u)
  assert.match(response.body, /data-loading-state="ready"/u)

  await server.close()
  await database.close()
})

test("GET /dashboard renders an empty Agents state when a tenant has no agents", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const response = await server.inject({
    method: "GET",
    url: "/dashboard?tenant_id=t_empty",
  })

  assert.equal(response.statusCode, 200)
  assert.match(response.body, /No agents registered/u)
  assert.match(response.body, /data-empty-state="true"/u)

  await server.close()
  await database.close()
})

test("GET /dashboard renders the Sessions screen with seeded session data", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const response = await server.inject({
    method: "GET",
    url: "/dashboard?tenant_id=t_demo&section=sessions",
  })

  assert.equal(response.statusCode, 200)
  assert.match(String(response.headers["content-type"]), /^text\/html/u)
  assert.match(response.body, /Session inventory/u)
  assert.match(response.body, /Week 1 demo session/u)
  assert.match(response.body, /Pi Demo Agent/u)
  assert.match(response.body, /data-session-id="s_demo"/u)
  assert.match(response.body, /class="tab active" href="\/dashboard\?tenant_id=t_demo&amp;section=sessions"/u)

  await server.close()
  await database.close()
})

test("GET /dashboard renders an empty Sessions state when a tenant has no sessions", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const response = await server.inject({
    method: "GET",
    url: "/dashboard?tenant_id=t_empty&section=sessions",
  })

  assert.equal(response.statusCode, 200)
  assert.match(response.body, /No sessions recorded/u)
  assert.match(response.body, /data-empty-state="true"/u)

  await server.close()
  await database.close()
})

test("GET /dashboard renders the Decisions screen with allow, deny, and approval_required states", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: {
      request_id: "req_dashboard_allow_0001",
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

  await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: {
      request_id: "req_dashboard_deny_0001",
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
        id: "/workspace/.env",
        kind: "file",
        path: "/workspace/.env",
      },
      action: {
        operation: "ReadFile",
        args: { path: "/workspace/.env" },
      },
      normalized: {
        verb: "read",
        mutation: false,
        destructive: false,
        network: false,
        credential_access: true,
        risk_class: "low",
      },
    },
  })

  await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: {
      request_id: "req_dashboard_approval_0001",
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
    },
  })

  const response = await server.inject({
    method: "GET",
    url: "/dashboard?tenant_id=t_demo&section=decisions",
  })

  assert.equal(response.statusCode, 200)
  assert.match(String(response.headers["content-type"]), /^text\/html/u)
  assert.match(response.body, /Decision inventory/u)
  assert.match(response.body, /req_dashboard_allow_0001/u)
  assert.match(response.body, /req_dashboard_deny_0001/u)
  assert.match(response.body, /req_dashboard_approval_0001/u)
  assert.match(response.body, /decision-allow/u)
  assert.match(response.body, /decision-deny/u)
  assert.match(response.body, /decision-approval_required/u)
  assert.match(response.body, /policy_forbid\.credential_path/u)
  assert.match(response.body, /class="tab active" href="\/dashboard\?tenant_id=t_demo&amp;section=decisions"/u)

  await server.close()
  await database.close()
})

test("GET /dashboard renders an empty Decisions state when a tenant has no decisions", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const response = await server.inject({
    method: "GET",
    url: "/dashboard?tenant_id=t_empty&section=decisions",
  })

  assert.equal(response.statusCode, 200)
  assert.match(response.body, /No decisions recorded/u)
  assert.match(response.body, /data-empty-state="true"/u)

  await server.close()
  await database.close()
})

test("GET /dashboard renders the Pending Approvals screen with visible approve and deny actions", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const approvalRequired = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: {
      request_id: "req_dashboard_pending_approval_0001",
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
    },
  })

  assert.equal(approvalRequired.statusCode, 200)
  assert.equal(approvalRequired.json().decision, "approval_required")

  const response = await server.inject({
    method: "GET",
    url: "/dashboard?tenant_id=t_demo&section=approvals",
  })

  assert.equal(response.statusCode, 200)
  assert.match(String(response.headers["content-type"]), /^text\/html/u)
  assert.match(response.body, /Pending approvals/u)
  assert.match(response.body, /req_dashboard_pending_approval_0001/u)
  assert.match(response.body, /approval_required/u)
  assert.match(response.body, /data-approval-id="/u)
  assert.match(response.body, /data-approval-actions="true"/u)
  assert.match(response.body, /data-approval-action="approved"/u)
  assert.match(response.body, /data-approval-action="denied"/u)
  assert.match(response.body, /\/v1\/approvals\/"\s*\+\s*encodeURIComponent/u)
  assert.match(response.body, /class="tab active" href="\/dashboard\?tenant_id=t_demo&amp;section=approvals"/u)

  await server.close()
  await database.close()
})

test("GET /dashboard renders an empty Pending Approvals state when a tenant has no approvals", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const response = await server.inject({
    method: "GET",
    url: "/dashboard?tenant_id=t_empty&section=approvals",
  })

  assert.equal(response.statusCode, 200)
  assert.match(response.body, /No approvals pending/u)
  assert.match(response.body, /data-empty-state="true"/u)

  await server.close()
  await database.close()
})

test("GET /dashboard renders the Audit Timeline screen and drills into a session", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const interceptResponse = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: {
      request_id: "req_dashboard_audit_0001",
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
  assert.equal(interceptResponse.json().decision, "allow")

  const decisionRows = await database.query<{ readonly id: string }>(
    `
      SELECT pd.id
      FROM policy_decisions pd
      INNER JOIN tool_calls tc ON tc.id = pd.tool_call_id
      WHERE tc.tenant_id = $1 AND tc.request_id = $2
    `,
    ["t_demo", "req_dashboard_audit_0001"],
  )
  const decisionId = decisionRows[0]?.id
  if (decisionId === undefined) {
    throw new Error("missing decision row")
  }

  const toolResultResponse = await server.inject({
    method: "POST",
    url: "/v1/tool-result",
    payload: {
      request_id: "req_dashboard_audit_0001",
      decision_id: decisionId,
      decision_token: interceptResponse.json().decision_token,
      tool_kind: "file",
      status: "executed",
      started_at: new Date().toISOString(),
      finished_at: new Date().toISOString(),
      result: {
        exit_code: 0,
        stdout_hash: "audit-stdout",
        stderr_hash: null,
        redacted_preview: "README read",
      },
    },
  })

  assert.equal(toolResultResponse.statusCode, 200)

  const response = await server.inject({
    method: "GET",
    url: "/dashboard?tenant_id=t_demo&section=audit&session_id=s_demo",
  })

  assert.equal(response.statusCode, 200)
  assert.match(String(response.headers["content-type"]), /^text\/html/u)
  assert.match(response.body, /Audit timeline/u)
  assert.match(response.body, /data-audit-session-links="true"/u)
  assert.match(response.body, /data-audit-session="s_demo"/u)
  assert.match(response.body, /policy_decision\.created/u)
  assert.match(response.body, /tool_result\.recorded/u)
  assert.match(response.body, /req_dashboard_audit_0001/u)
  assert.match(response.body, /guarded_read/u)
  assert.match(response.body, /class="tab active" href="\/dashboard\?tenant_id=t_demo&amp;section=audit&amp;session_id=s_demo"/u)

  await server.close()
  await database.close()
})

test("GET /dashboard renders an empty Audit Timeline state when a tenant has no sessions", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const response = await server.inject({
    method: "GET",
    url: "/dashboard?tenant_id=t_empty&section=audit",
  })

  assert.equal(response.statusCode, 200)
  assert.match(response.body, /No sessions available/u)
  assert.match(response.body, /data-empty-state="true"/u)

  await server.close()
  await database.close()
})

test("GET /dashboard renders a visible tenant kill-switch control with an empty state", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const response = await server.inject({
    method: "GET",
    url: "/dashboard?tenant_id=t_empty",
  })

  assert.equal(response.statusCode, 200)
  assert.match(response.body, /Operator shell/u)
  assert.match(response.body, /Tenant kill switch/u)
  assert.match(response.body, /No active kill switches/u)
  assert.match(response.body, /data-kill-switch-button="tenant"/u)
  assert.match(response.body, /data-kill-switch-state="empty"/u)
  assert.match(response.body, /\/v1\/kill-switches/u)

  await server.close()
  await database.close()
})

test("GET /dashboard shows an active tenant kill switch after successful activation", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const createResponse = await server.inject({
    method: "POST",
    url: "/v1/kill-switches",
    payload: {
      tenant_id: "t_demo",
      scope_type: "tenant",
      scope_id: "t_demo",
      reason: "dashboard emergency stop",
    },
  })

  assert.equal(createResponse.statusCode, 201)

  const response = await server.inject({
    method: "GET",
    url: "/dashboard?tenant_id=t_demo",
  })

  assert.equal(response.statusCode, 200)
  assert.match(response.body, /Operator shell/u)
  assert.match(response.body, /Tenant kill switch/u)
  assert.match(response.body, /dashboard emergency stop/u)
  assert.match(response.body, /data-kill-switch-id="/u)
  assert.match(response.body, /data-kill-switch-state="active"/u)
  assert.match(response.body, /data-kill-switch-button="tenant"/u)

  await server.close()
  await database.close()
})

test("GET /dashboard renders a visible evidence export control from the operator shell", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const response = await server.inject({
    method: "GET",
    url: "/dashboard?tenant_id=t_demo&section=audit&session_id=s_demo",
  })

  assert.equal(response.statusCode, 200)
  assert.match(response.body, /Evidence export/u)
  assert.match(response.body, /Download JSON/u)
  assert.match(response.body, /data-evidence-export-button="session"/u)
  assert.match(response.body, /data-evidence-export-tenant="t_demo"/u)
  assert.match(response.body, /data-evidence-export-session="s_demo"/u)
  assert.match(response.body, /\/v1\/evidence\/export/u)

  await server.close()
  await database.close()
})
