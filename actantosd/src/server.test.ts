import assert from "node:assert/strict"
import test from "node:test"

import { buildServer } from "./server.ts"

const baseRequest = {
  request_id: "req_00000001",
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
}

test("Given a safe route request when posting to intercept Then the server returns allow", async () => {
  const server = buildServer({ hmacSecret: "test-secret" })

  await server.ready()

  const response = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: baseRequest,
  })

  assert.equal(response.statusCode, 200)
  assert.equal(response.json().decision, "allow")
  assert.equal(response.json().reason_code, "allowed")
  assert.equal(typeof response.json().decision_id, "string")

  await server.close()
})

test("Given an invalid route request when posting to intercept Then the server returns 400", async () => {
  const server = buildServer()

  await server.ready()

  const response = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: {
      tenant_id: "t_demo",
    },
  })

  assert.equal(response.statusCode, 400)
  assert.equal(response.json().error, "invalid_request")

  await server.close()
})

// T11: tool-result without decision_token → rejected
test("T11: tool-result with executed status but no decision_token → 400", async () => {
  const server = buildServer()
  await server.ready()

  const response = await server.inject({
    method: "POST",
    url: "/v1/tool-result",
    payload: {
      request_id: "req_11000001",
      decision_id: "a1b2c3d4-e5f6-7890-abcd-ef1234567891",
      tool_kind: "shell",
      status: "executed",
      started_at: new Date().toISOString(),
      finished_at: new Date().toISOString(),
      result: {
        exit_code: 0,
        stdout_hash: "sha256:abc",
      },
      // decision_token intentionally omitted
    },
  })

  assert.equal(response.statusCode, 400)
  assert.equal(response.json().error, "decision_token_required")

  await server.close()
})

test("tool-result with blocked status needs no decision_token → 200", async () => {
  const server = buildServer()
  await server.ready()

  const response = await server.inject({
    method: "POST",
    url: "/v1/tool-result",
    payload: {
      request_id: "req_11000002",
      decision_id: "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
      tool_kind: "file",
      status: "blocked",
      started_at: new Date().toISOString(),
      finished_at: new Date().toISOString(),
      result: {},
    },
  })

  assert.equal(response.statusCode, 200)

  await server.close()
})

test("approval decide returns a one-use token and expires_at when approved", async () => {
  const server = buildServer()
  await server.ready()

  const approvalRequired = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: {
      ...baseRequest,
      request_id: "req_approve_0001",
      tool: {
        kind: "shell",
        name: "guarded_bash",
        operation: "ExecuteShellCommand",
        schema_hash: "",
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
  const approvalId = approvalRequired.json().approval.approval_id

  const response = await server.inject({
    method: "POST",
    url: `/v1/approvals/${approvalId}/decide`,
    payload: {
      decision: "approved",
      approver_user_id: "u_admin",
    },
  })

  assert.equal(response.statusCode, 200)
  assert.equal(response.json().approval_id, approvalId)
  assert.equal(response.json().decision, "approved")
  assert.equal(typeof response.json().approval_token, "string")
  assert.equal(typeof response.json().decided_at, "string")
  assert.equal(typeof response.json().expires_at, "string")

  await server.close()
})

test("GET /health/live returns process liveness", async () => {
  const server = buildServer()
  await server.ready()

  const response = await server.inject({
    method: "GET",
    url: "/health/live",
  })

  assert.equal(response.statusCode, 200)
  assert.equal(response.json().status, "ok")

  await server.close()
})

test("GET /health/ready returns ready without Postgres when running in-memory", async () => {
  const server = buildServer()
  await server.ready()

  const response = await server.inject({
    method: "GET",
    url: "/health/ready",
  })

  assert.equal(response.statusCode, 200)
  assert.equal(response.json().status, "ready")
  assert.equal(response.json().database, "not_configured")

  await server.close()
})

test("GET /health/ready returns 503 when the Postgres dependency probe fails", async () => {
  const server = buildServer({
    database: {
      async query() {
        throw new Error("connection refused")
      },
      async close() {
        return undefined
      },
      async transaction(callback) {
        return callback(this)
      },
    },
  })
  await server.ready()

  const response = await server.inject({
    method: "GET",
    url: "/health/ready",
  })

  assert.equal(response.statusCode, 503)
  assert.equal(response.json().status, "not_ready")
  assert.equal(response.json().database, "unreachable")

  await server.close()
})

test("GET /dashboard returns 401 when operator auth is configured and no API key is provided", async () => {
  const server = buildServer({ apiKey: "test-api-key" })
  await server.ready()

  const response = await server.inject({
    method: "GET",
    url: "/dashboard?tenant_id=t_demo",
  })

  assert.equal(response.statusCode, 401)
  assert.equal(response.json().error, "unauthorized")

  await server.close()
})

test("GET /dashboard accepts the configured API key via query string", async () => {
  const server = buildServer({ apiKey: "test-api-key" })
  await server.ready()

  const response = await server.inject({
    method: "GET",
    url: "/dashboard?tenant_id=t_demo&api_key=test-api-key",
  })

  assert.equal(response.statusCode, 200)
  assert.match(response.body, /ActantOS Dashboard/)

  await server.close()
})

test("POST /v1/kill-switches returns 401 when operator auth is configured and no API key is provided", async () => {
  const server = buildServer({ apiKey: "test-api-key" })
  await server.ready()

  const response = await server.inject({
    method: "POST",
    url: "/v1/kill-switches",
    payload: {
      tenant_id: "t_demo",
      scope_type: "tenant",
      scope_id: "t_demo",
      reason: "test",
    },
  })

  assert.equal(response.statusCode, 401)
  assert.equal(response.json().error, "unauthorized")

  await server.close()
})

test("POST /v1/intercept/tool-call remains available without API key auth for runtime enforcement", async () => {
  const server = buildServer({ apiKey: "test-api-key", hmacSecret: "test-secret" })
  await server.ready()

  const response = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: baseRequest,
  })

  assert.equal(response.statusCode, 200)
  assert.equal(response.json().decision, "allow")

  await server.close()
})
