import assert from "node:assert/strict"
import test from "node:test"

import type { ToolCallInterceptionRequest } from "./contracts.ts"
import { canonicalHash } from "./hash.ts"
import { createInterceptService } from "./intercept-service.ts"
import type { McpManifestGuard } from "./mcp-manifest-guard.ts"
import { InMemoryToolCallRepository } from "./tool-call-repository.ts"

const baseRequest = (): ToolCallInterceptionRequest => ({
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
})

// T2: Credential path → deny
test("T2: .env read → deny, policy_forbid.credential_path", async () => {
  const repository = new InMemoryToolCallRepository()
  const service = createInterceptService({ repository, hmacSecret: "test-secret" })

  const response = await service.intercept({
    ...baseRequest(),
    request_id: "req_T2000001",
    normalized: {
      verb: "read",
      mutation: false,
      destructive: false,
      network: false,
      credential_access: true,
      risk_class: "critical",
    },
  })

  assert.equal(response.decision, "deny")
  assert.equal(response.reason_code, "policy_forbid.credential_path")
  assert.equal(response.decision_mode, "enforce")
  assert.equal(
    "decision_token" in response ? response.decision_token : undefined,
    undefined,
  )
})

// T6: Idempotency
test("T6: same request_id retry → same decision, no new DB row", async () => {
  const repository = new InMemoryToolCallRepository()
  const service = createInterceptService({ repository, hmacSecret: "test-secret" })
  const request = baseRequest()

  const first = await service.intercept(request)
  const second = await service.intercept(request)

  assert.deepEqual(second, first)
  assert.equal(repository.count(), 1)
})

// T1: Safe read → allow with decision_token
test("T1: README.md read → allow, reason_code=allowed, decision_token issued", async () => {
  const repository = new InMemoryToolCallRepository()
  const service = createInterceptService({ repository, hmacSecret: "test-secret" })

  const response = await service.intercept(baseRequest())

  assert.equal(response.decision, "allow")
  assert.equal(response.decision_mode, "enforce")
  if (response.decision === "allow") {
    assert.ok(response.decision_token)
    assert.equal(typeof response.decision_token, "string")
    assert.deepEqual(response.constraints, {
      timeout_ms: 30_000,
      max_output_bytes: 200_000,
      network_mode: "none",
      network_allowlist: [],
    })

    const [encodedPayload] = response.decision_token.split(".")
    if (encodedPayload === undefined) {
      throw new Error("missing token payload")
    }

    const payload = JSON.parse(Buffer.from(encodedPayload, "base64url").toString("utf8")) as Record<string, unknown>

    assert.equal(payload["decision_id"], response.decision_id)
    assert.equal(payload["tenant_id"], "t_demo")
    assert.equal(payload["agent_id"], "pi_demo")
    assert.equal(payload["session_id"], "s_demo")
    assert.equal(payload["decision"], "allow")
    assert.equal(typeof payload["tool_call_id"], "string")
    assert.equal(
      payload["constraints_hash"],
      canonicalHash(response.constraints),
    )
    assert.equal(typeof payload["exp"], "number")
  }
})

// T12: dry_run on policy_forbid → deny, decision_mode=dry_run, no token
test("T12: dry_run=true on credential path → deny, decision_mode=dry_run, no decision_token", async () => {
  const repository = new InMemoryToolCallRepository()
  const service = createInterceptService({ repository, hmacSecret: "test-secret" })

  const response = await service.intercept({
    ...baseRequest(),
    request_id: "req_T12000001",
    normalized: {
      verb: "read",
      mutation: false,
      destructive: false,
      network: false,
      credential_access: true,
      risk_class: "critical",
    },
    dry_run: true,
  })

  assert.equal(response.decision, "deny")
  assert.equal(response.decision_mode, "dry_run")
  assert.equal(
    "decision_token" in response ? response.decision_token : undefined,
    undefined,
  )
})

test("dry_run preserves approval_required decisions without issuing execution authorization", async () => {
  const repository = new InMemoryToolCallRepository()
  const service = createInterceptService({ repository, hmacSecret: "test-secret" })

  const response = await service.intercept({
    ...baseRequest(),
    request_id: "req_dry_run_approval_0001",
    tool: {
      kind: "shell",
      name: "guarded_bash",
      operation: "ExecuteShellCommand",
      schema_hash: "",
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
    dry_run: true,
  })

  assert.equal(response.decision, "approval_required")
  assert.equal(response.decision_mode, "dry_run")
  assert.equal("decision_token" in response, false)
  if (response.decision === "approval_required") {
    assert.ok(response.approval.approval_id)
    assert.equal(response.approval.status, "pending")
  }
})

// T7: git push → approval_required
test("T7: git push --dry-run → approval_required", async () => {
  const repository = new InMemoryToolCallRepository()
  const service = createInterceptService({ repository, hmacSecret: "test-secret" })

  const response = await service.intercept({
    ...baseRequest(),
    request_id: "req_T7000001",
    tool: {
      kind: "shell",
      name: "guarded_bash",
      operation: "ExecuteShellCommand",
      schema_hash: "",
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

  assert.equal(response.decision, "approval_required")
  assert.equal(response.reason_code, "approval_required")
  if (response.decision === "approval_required") {
    assert.ok(response.approval.approval_id)
    assert.equal(response.approval.status, "pending")
  }
})

// T8: approve + new request_id → allow, used_at set
test("T8: approve + NEW request_id → allow, used_at set", async () => {
  const repository = new InMemoryToolCallRepository()
  const service = createInterceptService({ repository, hmacSecret: "test-secret" })

  // First: get approval_required
  const firstReq: ToolCallInterceptionRequest = {
    ...baseRequest(),
    request_id: "req_T8000001",
    tool: {
      kind: "shell",
      name: "guarded_bash",
      operation: "ExecuteShellCommand",
      schema_hash: "",
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
  }

  const approval = await service.intercept(firstReq)
  assert.equal(approval.decision, "approval_required")

  if (approval.decision !== "approval_required") return

  const approvalId = approval.approval.approval_id
  const rawToken = "test-raw-token-12345"

  // Admin approves
  repository.approveRequest(approvalId, rawToken)

  // Re-submit with NEW request_id and authorization
  const secondReq: ToolCallInterceptionRequest = {
    ...firstReq,
    request_id: "req_T8000001_exec",
    authorization: {
      prior_decision_id: "some-prior-id",
      approval_id: approvalId,
      approval_token: rawToken,
    },
  }

  const result = await service.intercept(secondReq)
  assert.equal(result.decision, "allow")
  assert.equal(result.reason_code, "allowed")
  if (result.decision === "allow") {
    assert.ok(result.decision_token)
  }

  // Confirm used_at set
  const storedApproval = repository.getApproval(approvalId)
  assert.ok(storedApproval?.usedAt)
})

test("dry_run approval resubmission verifies without consuming the approval token", async () => {
  const repository = new InMemoryToolCallRepository()
  const service = createInterceptService({ repository, hmacSecret: "test-secret" })

  const firstRequest: ToolCallInterceptionRequest = {
    ...baseRequest(),
    request_id: "req_dry_run_exec_approval_0001",
    tool: {
      kind: "shell",
      name: "guarded_bash",
      operation: "ExecuteShellCommand",
      schema_hash: "",
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
  }

  const approval = await service.intercept(firstRequest)
  assert.equal(approval.decision, "approval_required")

  if (approval.decision !== "approval_required") return

  repository.approveRequest(approval.approval.approval_id, "dry-run-token")

  const response = await service.intercept({
    ...firstRequest,
    request_id: "req_dry_run_exec_approval_0002",
    authorization: {
      prior_decision_id: approval.decision_id,
      approval_id: approval.approval.approval_id,
      approval_token: "dry-run-token",
    },
    dry_run: true,
  })

  assert.equal(response.decision, "allow")
  assert.equal(response.decision_mode, "dry_run")
  assert.equal("decision_token" in response, false)
  assert.equal(repository.getApproval(approval.approval.approval_id)?.usedAt, undefined)
})

// T9: same approval_token reused → deny, invalid_approval
test("T9: same approval_token reused → deny, reason_code=invalid_approval", async () => {
  const repository = new InMemoryToolCallRepository()
  const service = createInterceptService({ repository, hmacSecret: "test-secret" })

  const firstReq: ToolCallInterceptionRequest = {
    ...baseRequest(),
    request_id: "req_T9000001",
    tool: {
      kind: "shell",
      name: "guarded_bash",
      operation: "ExecuteShellCommand",
      schema_hash: "",
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
  }

  const approval = await service.intercept(firstReq)
  assert.equal(approval.decision, "approval_required")

  if (approval.decision !== "approval_required") return

  const approvalId = approval.approval.approval_id
  const rawToken = "reuse-test-token-99999"

  repository.approveRequest(approvalId, rawToken)

  const makeResubmit = (reqId: string): ToolCallInterceptionRequest => ({
    ...firstReq,
    request_id: reqId,
    authorization: {
      prior_decision_id: "some-prior-id",
      approval_id: approvalId,
      approval_token: rawToken,
    },
  })

  // First use: valid
  const first = await service.intercept(makeResubmit("req_T9000001_exec1"))
  assert.equal(first.decision, "allow")

  // Second use: invalid (token already consumed)
  const second = await service.intercept(makeResubmit("req_T9000001_exec2"))
  assert.equal(second.decision, "deny")
  assert.equal(second.reason_code, "invalid_approval")
})

// T10: kill switch → deny, kill_switch_active
test("T10: kill switch active → deny, reason_code=kill_switch_active", async () => {
  const repository = new InMemoryToolCallRepository()
  repository.enableKillSwitch()
  const service = createInterceptService({ repository, hmacSecret: "test-secret" })

  const response = await service.intercept({
    ...baseRequest(),
    request_id: "req_T10000001",
  })

  assert.equal(response.decision, "deny")
  assert.equal(response.reason_code, "kill_switch_active")
})

test("Given an MCP manifest drift check failure when intercepting Then it denies before policy evaluation", async () => {
  const repository = new InMemoryToolCallRepository()
  let evaluationCount = 0
  const mcpManifestGuard: McpManifestGuard = {
    async evaluate() {
      evaluationCount += 1
      return {
        allowed: false,
        reason: "MCP tool schema changed since approval",
        reasonCode: "schema_hash_mismatch",
      }
    },
  }
  const service = createInterceptService({
    repository,
    hmacSecret: "test-secret",
    mcpManifestGuard,
  })

  const response = await service.intercept({
    ...baseRequest(),
    request_id: "req_manifest_0001",
    tool: {
      kind: "mcp",
      name: "read_repo_file",
      operation: "tools/call",
      schema_hash: "schema-v2",
    },
    resource: {
      id: "mcp://github/tools/read_repo_file",
      kind: "mcp_tool",
      path: "/mcp/github/tools/read_repo_file",
    },
    mcp: {
      server_id: "github",
      server_identity_hash: "server-hash-v1",
      tool_name: "read_repo_file",
      tool_schema_hash: "schema-v2",
      tool_description_hash: "description-v1",
      transport: "sse",
    },
  })

  assert.equal(evaluationCount, 1)
  assert.equal(response.decision, "deny")
  assert.equal(response.reason_code, "schema_hash_mismatch")
})

test("Given a localhost URL target when intercepting Then it denies before policy evaluation", async () => {
  const repository = new InMemoryToolCallRepository()
  const service = createInterceptService({ repository, hmacSecret: "test-secret" })

  const response = await service.intercept({
    ...baseRequest(),
    request_id: "req_ssrf_0001",
    tool: {
      kind: "http",
      name: "guarded_fetch",
      operation: "GET",
      schema_hash: "",
    },
    resource: {
      id: "http://127.0.0.1:8080/secret",
      kind: "url",
      url: "http://127.0.0.1:8080/secret",
    },
    action: {
      operation: "GET",
      args: {
        url: "http://127.0.0.1:8080/secret",
      },
    },
    normalized: {
      verb: "network",
      mutation: false,
      destructive: false,
      network: true,
      credential_access: false,
      risk_class: "high",
    },
  })

  assert.equal(response.decision, "deny")
  assert.equal(response.reason_code, "policy_forbid")
  assert.equal(response.reason, "URL target is blocked by the SSRF policy")
})
