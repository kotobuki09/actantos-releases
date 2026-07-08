import assert from "node:assert/strict"
import test from "node:test"

import type { RiskEvaluation, ToolCallContext, ToolCallInterceptionRequest } from "./contracts.ts"
import { executeGatewayToolCall } from "./mcp-gateway.ts"
import type { CedarProvider } from "./fake-cedar-provider.ts"
import { createInterceptService } from "./intercept-service.ts"
import { RiskEngine } from "./risk-engine.ts"
import {
  InMemoryToolCallRepository,
  type ApprovalVerificationResult,
  type StoredDecision,
  type ToolCallRepository,
  type NewStoredDecision,
} from "./tool-call-repository.ts"

const baseRequest = (): ToolCallInterceptionRequest => ({
  request_id: "req_fail_closed_0001",
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

const approvalRequest = (): ToolCallInterceptionRequest => ({
  ...baseRequest(),
  request_id: "req_fail_closed_approval_0001",
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
})

class ThrowingRiskEngine extends RiskEngine {
  override async evaluate(_context: ToolCallContext): Promise<RiskEvaluation> {
    throw new Error("risk engine unavailable")
  }
}

class ApprovalVerificationFailureRepository implements ToolCallRepository {
  readonly #delegate: InMemoryToolCallRepository

  constructor(delegate: InMemoryToolCallRepository) {
    this.#delegate = delegate
  }

  async findByRequestId(tenantId: string, requestId: string): Promise<StoredDecision | null> {
    return this.#delegate.findByRequestId(tenantId, requestId)
  }

  async saveDecision(record: NewStoredDecision): Promise<void> {
    return this.#delegate.saveDecision(record)
  }

  async isKillSwitchActive(
    tenantId: string,
    agentExternalId: string,
    sessionExternalId: string,
    toolName: string,
  ): Promise<boolean> {
    return this.#delegate.isKillSwitchActive(
      tenantId,
      agentExternalId,
      sessionExternalId,
      toolName,
    )
  }

  async verifyAndConsumeApproval(): Promise<ApprovalVerificationResult> {
    throw new Error("approval storage unavailable")
  }
}

test("fail-closed: policy evaluation dependency failure denies instead of throwing", async () => {
  const repository = new InMemoryToolCallRepository()
  const cedarProvider: CedarProvider = {
    async evaluate() {
      throw new Error("cedar unavailable")
    },
  }
  const service = createInterceptService({
    repository,
    hmacSecret: "test-secret",
    cedarProvider,
  })

  const response = await service.intercept(baseRequest())

  assert.equal(response.decision, "deny")
  assert.equal(response.reason_code, "dependency_failure.policy_evaluation")
  assert.match(response.reason, /policy evaluation/i)
  assert.equal(repository.count(), 1)
})

test("fail-closed: risk evaluation failure denies instead of allowing after permit", async () => {
  const repository = new InMemoryToolCallRepository()
  const service = createInterceptService({
    repository,
    hmacSecret: "test-secret",
    riskEngine: new ThrowingRiskEngine(),
  })

  const response = await service.intercept(baseRequest())

  assert.equal(response.decision, "deny")
  assert.equal(response.reason_code, "dependency_failure.risk_evaluation")
  assert.match(response.reason, /risk evaluation/i)
  assert.equal(repository.count(), 1)
})

test("fail-closed: approval verification storage failure denies the resubmission", async () => {
  const repository = new InMemoryToolCallRepository()
  const service = createInterceptService({ repository, hmacSecret: "test-secret" })

  const firstDecision = await service.intercept(approvalRequest())
  assert.equal(firstDecision.decision, "approval_required")
  if (firstDecision.decision !== "approval_required") {
    throw new Error("expected approval_required decision")
  }

  repository.approveRequest(firstDecision.approval.approval_id, "approved-token")

  const failClosedService = createInterceptService({
    repository: new ApprovalVerificationFailureRepository(repository),
    hmacSecret: "test-secret",
  })

  const response = await failClosedService.intercept({
    ...approvalRequest(),
    request_id: "req_fail_closed_approval_0002",
    authorization: {
      prior_decision_id: firstDecision.decision_id,
      approval_id: firstDecision.approval.approval_id,
      approval_token: "approved-token",
    },
  })

  assert.equal(response.decision, "deny")
  assert.equal(response.reason_code, "dependency_failure.approval_verification")
  assert.match(response.reason, /approval verification/i)
})

test("fail-closed: MCP execution returns an error when result recording fails", async () => {
  const result = await executeGatewayToolCall({
    params: {
      name: "read_repo_file",
      arguments: { path: "README.md" },
    },
    upstreamClient: {
      listTools: async () => ({
        tools: [{
          name: "read_repo_file",
          description: "Read a repository file",
          inputSchema: {
            type: "object",
            properties: {
              path: { type: "string" },
            },
          },
          annotations: {
            readOnlyHint: true,
          },
        }],
      }),
      callTool: async () => ({
        content: [{ type: "text", text: "tool executed" }],
      }),
    },
    interceptService: {
      intercept: async () => ({
        decision: "allow",
        decision_mode: "enforce",
        decision_id: "44444444-4444-4444-8444-444444444444",
        reason: "permitted by policy",
        reason_code: "allowed",
        audit_event_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        decision_token: "decision-token",
      }),
    },
    context: {
      tenantId: "t_demo",
      agentId: "pi_demo",
      runtimeType: "pi",
      environment: "dev",
      riskTier: "low",
      userId: "u_demo",
      sessionId: "s_demo",
      cwd: "/workspace",
    },
    config: {
      upstreamUrl: "http://localhost:8080/sse",
      serverId: "github",
      transport: "sse",
    },
    toolCache: new Map(),
    recordToolResult: async () => {
      throw new Error("result recorder unavailable")
    },
  })

  assert.equal(result.isError, true)
  assert.match(
    (result.content[0] as { readonly text: string }).text,
    /failed closed/i,
  )
})
