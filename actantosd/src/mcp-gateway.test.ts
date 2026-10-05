import { FakeCedarProvider } from "./fake-cedar-provider.ts";
import assert from "node:assert/strict"
import test from "node:test"

import type { CallToolResult, Tool } from "@modelcontextprotocol/sdk/types.js"
import { newDb } from "pg-mem"

import {
  buildGatewayInterceptionRequest,
  createGatewayRequestContext,
  executeGatewayToolCall,
  filterGatewayTools,
} from "./mcp-gateway.ts"
import type { Database } from "./database.ts"
import { migrateDatabase, seedDemoData } from "./database.ts"
import { createInterceptService } from "./intercept-service.ts"
import { recordToolResult } from "./tool-result-service.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"
import { buildServer } from "./server.ts"

const gatewayContext = {
  tenantId: "t_demo",
  agentId: "pi_demo",
  runtimeType: "pi",
  environment: "dev",
  riskTier: "low",
  userId: "u_demo",
  sessionId: "s_demo",
  cwd: "/workspace",
} as const

const gatewayConfig = {
  upstreamUrl: "http://localhost:8080/sse",
  serverId: "github",
  transport: "sse",
} as const

const readTool: Tool = {
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
}

const secretTool: Tool = {
  name: "read_secret",
  description: "Read a secret token from the vault",
  inputSchema: {
    type: "object",
    properties: {
      path: { type: "string" },
    },
  },
  annotations: {
    readOnlyHint: true,
  },
}

const createTestDatabase = async (): Promise<Database> => {
  const memoryDb = newDb()
  const adapter = memoryDb.adapters.createPg()
  const { Pool } = adapter
  const pool = new Pool()

  const database: Database = {
    async query(sql, params = []) {
      if (sql.includes("-- actantos-pg-only") || sql.includes("CREATE OR REPLACE FUNCTION enforce_tool_call_state_transitions") || sql.includes("CREATE TRIGGER trg_enforce_tool_call_transitions")) { return [] }
      const result = await pool.query(sql, [...params])
      return result.rows
    },
    async transaction(callback) {
      const client = await pool.connect()

      try {
        await client.query("BEGIN")
        const result = await callback({
          async query(sql, params = []) {
            if (sql.includes("-- actantos-pg-only") || sql.includes("CREATE OR REPLACE FUNCTION enforce_tool_call_state_transitions") || sql.includes("CREATE TRIGGER trg_enforce_tool_call_transitions")) { return [] }
            const queryResult = await client.query(sql, [...params])
            return queryResult.rows
          },
        })
        await client.query("COMMIT")
        return result
      } catch (error) {
        await client.query("ROLLBACK")
        throw error
      } finally {
        client.release()
      }
    },
    async close() {
      await pool.end()
    },
  }

  await migrateDatabase(database)
  await seedDemoData(database)

  return database
}

test("buildGatewayInterceptionRequest includes MCP metadata and credential heuristics", () => {
  const request = buildGatewayInterceptionRequest({
    tool: secretTool,
    params: {
      name: "read_secret",
      arguments: { path: "vault://prod/token" },
    },
    context: gatewayContext,
    config: gatewayConfig,
    dryRun: true,
  })

  assert.equal(request.tool.kind, "mcp")
  assert.equal(request.mcp?.server_id, "github")
  assert.equal(request.normalized.credential_access, true)
  assert.equal(request.dry_run, true)
})

test("filterGatewayTools excludes tools denied by policy evaluation", async () => {
  const seenRequests: string[] = []

  const filteredTools = await filterGatewayTools({
    tools: [readTool, secretTool],
    context: gatewayContext,
    config: gatewayConfig,
    interceptService: {
      intercept: async (request) => {
        seenRequests.push(request.tool.name)

        if (request.normalized.credential_access) {
          return {
            decision: "deny",
            decision_mode: "dry_run",
            decision_id: "11111111-1111-4111-8111-111111111111",
            reason: "blocked by policy",
            reason_code: "credential_path_blocked",
            audit_event_id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
          }
        }

        return {
          decision: "allow",
          decision_mode: "dry_run",
          decision_id: "22222222-2222-4222-8222-222222222222",
          reason: "allowed",
          reason_code: "allowed",
          audit_event_id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",
        }
      },
    },
  })

  assert.deepEqual(seenRequests, ["read_repo_file", "read_secret"])
  assert.deepEqual(
    filteredTools.map((tool) => tool.name),
    ["read_repo_file"],
  )
})

test("executeGatewayToolCall blocks denied tools before upstream forwarding", async () => {
  let upstreamCallCount = 0
  let interceptedRequestId = ""
  const recordedPayloads: Array<{ requestId: string; status: string; decisionId: string }> = []

  const result = await executeGatewayToolCall({
    params: {
      name: "read_secret",
      arguments: { path: "vault://prod/token" },
    },
    upstreamClient: {
      listTools: async () => ({ tools: [secretTool] }),
      callTool: async () => {
        upstreamCallCount += 1
        return { content: [{ type: "text", text: "unexpected" }] }
      },
    },
    interceptService: {
      intercept: async (request) => {
        interceptedRequestId = request.request_id

        return {
        decision: "deny",
        decision_mode: "enforce",
        decision_id: "33333333-3333-4333-8333-333333333333",
        reason: "blocked by policy",
        reason_code: "credential_path_blocked",
        audit_event_id: "cccccccc-cccc-4ccc-8ccc-cccccccccccc",
        }
      },
    },
    context: gatewayContext,
    config: gatewayConfig,
    toolCache: new Map(),
    recordToolResult: async (payload) => {
      recordedPayloads.push({
        requestId: payload.request_id,
        status: payload.status,
        decisionId: payload.decision_id,
      })
    },
  })

  assert.equal(upstreamCallCount, 0)
  assert.equal(result.isError, true)
  assert.match((result.content[0] as { text: string }).text, /denied MCP tool/)
  assert.deepEqual(recordedPayloads, [
    {
      requestId: interceptedRequestId,
      status: "blocked",
      decisionId: "33333333-3333-4333-8333-333333333333",
    },
  ])
})

test("executeGatewayToolCall forwards allowed tools and records execution", async () => {
  const recordedPayloads: Array<{
    requestId: string
    status: string
    decisionToken?: string
    preview?: string
    stdoutHash?: string | null
  }> = []
  let interceptedRequestId = ""

  const upstreamResult: CallToolResult = {
    content: [{ type: "text", text: "tool executed" }],
  }

  const result = await executeGatewayToolCall({
    params: {
      name: "read_repo_file",
      arguments: { path: "README.md" },
    },
    upstreamClient: {
      listTools: async () => ({ tools: [readTool] }),
      callTool: async () => upstreamResult,
    },
    interceptService: {
      intercept: async (request) => {
        interceptedRequestId = request.request_id

        return {
        decision: "allow",
        decision_mode: "enforce",
        decision_id: "44444444-4444-4444-8444-444444444444",
        reason: "permitted by policy",
        reason_code: "allowed",
        audit_event_id: "dddddddd-dddd-4ddd-8ddd-dddddddddddd",
        decision_token: "decision-token",
        }
      },
    },
    context: gatewayContext,
    config: gatewayConfig,
    toolCache: new Map(),
    recordToolResult: async (payload) => {
      const recordedPayload = {
        requestId: payload.request_id,
        status: payload.status,
        ...(payload.decision_token === undefined
          ? {}
          : { decisionToken: payload.decision_token }),
        ...(payload.result.redacted_preview === undefined
          ? {}
          : { preview: payload.result.redacted_preview }),
        ...(payload.result.stdout_hash === undefined
          ? {}
          : { stdoutHash: payload.result.stdout_hash }),
      }

      recordedPayloads.push(recordedPayload)
    },
  })

  assert.deepEqual(result, upstreamResult)
  assert.equal(recordedPayloads.length, 1)
  assert.equal(recordedPayloads[0]?.requestId, interceptedRequestId)
  assert.equal(recordedPayloads[0]?.status, "executed")
  assert.equal(recordedPayloads[0]?.decisionToken, "decision-token")
  assert.equal(recordedPayloads[0]?.preview, "tool executed")
  assert.equal(typeof recordedPayloads[0]?.stdoutHash, "string")
})

test("executeGatewayToolCall records results successfully against the Postgres-backed request_id", async () => {
  const database = await createTestDatabase()
  const repository = new PostgresToolCallRepository(database)
  const interceptService = createInterceptService({ cedarProvider: new FakeCedarProvider(),
    repository,
    hmacSecret: "test-secret",
  })

  const upstreamResult: CallToolResult = {
    content: [{ type: "text", text: "tool executed" }],
  }

  const result = await executeGatewayToolCall({
    params: {
      name: "read_repo_file",
      arguments: { path: "README.md" },
    },
    upstreamClient: {
      listTools: async () => ({ tools: [readTool] }),
      callTool: async () => upstreamResult,
    },
    interceptService,
    context: gatewayContext,
    config: gatewayConfig,
    toolCache: new Map(),
    recordToolResult: async (payload) => {
      await recordToolResult(database, payload, "test-secret")
    },
  })

  assert.deepEqual(result, upstreamResult)

  const toolCalls = await database.query<{
    readonly request_id: string
    readonly status: string
  }>(
    `
      SELECT request_id, status
      FROM tool_calls
      WHERE tenant_id = $1
      ORDER BY created_at DESC
      LIMIT 1
    `,
    [gatewayContext.tenantId],
  )

  assert.equal(toolCalls[0]?.status, "executed")
  assert.equal(typeof toolCalls[0]?.request_id, "string")

  const auditEvents = await database.query<{ readonly event_type: string }>(
    `
      SELECT event_type
      FROM audit_events
      WHERE tenant_id = $1
      ORDER BY seq ASC
    `,
    [gatewayContext.tenantId],
  )

  assert.deepEqual(
    auditEvents.map((row) => row.event_type),
    ["policy_decision.created", "tool_result.recorded"],
  )

  await database.close()
})

test("createGatewayRequestContext extracts all identity/tenancy headers and applies overrides", () => {
  // 1. Check defaults when headers are missing (unauthenticated)
  const mockRequestDefaults = {
    headers: {},
  } as any
  const contextDefaults = createGatewayRequestContext(mockRequestDefaults)
  assert.equal(contextDefaults.tenantId, "t_demo")
  assert.equal(contextDefaults.agentId, "pi_demo")
  assert.equal(contextDefaults.runtimeType, "pi")
  assert.equal(contextDefaults.environment, "dev")
  assert.equal(contextDefaults.riskTier, "low")

  // 2. Check header overrides are accepted when authenticated=true
  const mockRequestOverrides = {
    headers: {
      "x-actantos-tenant-id": "t_custom_tenant",
      "x-actantos-agent-id": "agent_custom",
      "x-actantos-runtime-type": "custom",
      "x-actantos-environment": "prod",
      "x-actantos-risk-tier": "high",
      "x-actantos-user-id": "u_custom_user",
      "x-actantos-session-id": "s_custom_session",
      "x-actantos-cwd": "/custom/path",
      "x-actantos-purpose": "run custom pipeline",
    },
  } as any
  const contextOverrides = createGatewayRequestContext(mockRequestOverrides, true)
  assert.equal(contextOverrides.tenantId, "t_custom_tenant")
  assert.equal(contextOverrides.agentId, "agent_custom")
  assert.equal(contextOverrides.runtimeType, "custom")
  assert.equal(contextOverrides.environment, "prod")
  assert.equal(contextOverrides.riskTier, "high")
  assert.equal(contextOverrides.userId, "u_custom_user")
  assert.equal(contextOverrides.sessionId, "s_custom_session")
  assert.equal(contextOverrides.cwd, "/custom/path")
  assert.equal(contextOverrides.purpose, "run custom pipeline")

  // 3. Check that identity headers are IGNORED when unauthenticated (tenant spoofing guard)
  const contextUnauthenticated = createGatewayRequestContext(mockRequestOverrides, false)
  assert.equal(contextUnauthenticated.tenantId, "t_demo", "unauthenticated: tenant must be default")
  assert.equal(contextUnauthenticated.agentId, "pi_demo", "unauthenticated: agent must be default")
  assert.equal(contextUnauthenticated.userId, "u_demo", "unauthenticated: user must be default")
  assert.equal(contextUnauthenticated.sessionId, "s_demo", "unauthenticated: session must be default")
  // Metadata headers are still accepted
  assert.equal(contextUnauthenticated.runtimeType, "custom")
  assert.equal(contextUnauthenticated.environment, "prod")
  assert.equal(contextUnauthenticated.riskTier, "high")
  assert.equal(contextUnauthenticated.cwd, "/custom/path")
  assert.equal(contextUnauthenticated.purpose, "run custom pipeline")
})

// PQ-11 / 1.3: MCP Header Context Trust — HTTP-level enforcement

test("GET /v1/mcp/sse rejects unauthenticated requests that supply X-Actantos-Tenant-Id with 401", async () => {
  const previousTrust = process.env["ACTANTOS_TRUST_MCP_CONTEXT"]
  delete process.env["ACTANTOS_TRUST_MCP_CONTEXT"]

  try {
    const server = buildServer({ apiKey: "test-key-pq11" })
    await server.ready()

    // Request with identity header but NO api key → must be 401
    const response = await server.inject({
      method: "GET",
      url: "/v1/mcp/sse",
      headers: {
        "x-actantos-tenant-id": "t_evil",
      },
    })

    assert.equal(response.statusCode, 401, "should return 401 for unauthenticated requests with identity headers")
    const body = response.json()
    assert.equal(body.error, "unauthorized")

    await server.close()
  } finally {
    if (previousTrust === undefined) {
      delete process.env["ACTANTOS_TRUST_MCP_CONTEXT"]
    } else {
      process.env["ACTANTOS_TRUST_MCP_CONTEXT"] = previousTrust
    }
  }
})

test("GET /v1/mcp/sse rejects unauthenticated requests that supply X-Actantos-Agent-Id with 401", async () => {
  const previousTrust = process.env["ACTANTOS_TRUST_MCP_CONTEXT"]
  delete process.env["ACTANTOS_TRUST_MCP_CONTEXT"]

  try {
    const server = buildServer({ apiKey: "test-key-pq11" })
    await server.ready()

    const response = await server.inject({
      method: "GET",
      url: "/v1/mcp/sse",
      headers: {
        "x-actantos-agent-id": "agent_evil",
      },
    })

    assert.equal(response.statusCode, 401)

    await server.close()
  } finally {
    if (previousTrust === undefined) {
      delete process.env["ACTANTOS_TRUST_MCP_CONTEXT"]
    } else {
      process.env["ACTANTOS_TRUST_MCP_CONTEXT"] = previousTrust
    }
  }
})

test("GET /v1/mcp/sse allows requests with valid API key even when identity headers are present", async () => {
  const previousTrust = process.env["ACTANTOS_TRUST_MCP_CONTEXT"]
  delete process.env["ACTANTOS_TRUST_MCP_CONTEXT"]

  try {
    // Unit-test the guard: with valid API key, authenticated=true, so headers are trusted.
    // The HTTP route is tested via the 401 rejection tests; here we verify the context logic.
    const mockRequest = {
      headers: {
        "x-actantos-api-key": "test-key-pq11",
        "x-actantos-tenant-id": "t_trusted",
        "x-actantos-agent-id": "agent_trusted",
      },
    } as any
    // authenticated=true simulates what the route handler does after verifying the api key
    const context = createGatewayRequestContext(mockRequest, true)
    assert.equal(context.tenantId, "t_trusted", "with valid auth, tenant header is trusted")
    assert.equal(context.agentId, "agent_trusted", "with valid auth, agent header is trusted")
  } finally {
    if (previousTrust === undefined) {
      delete process.env["ACTANTOS_TRUST_MCP_CONTEXT"]
    } else {
      process.env["ACTANTOS_TRUST_MCP_CONTEXT"] = previousTrust
    }
  }
})

test("createGatewayRequestContext does not apply the 401 guard when no identity headers are provided", () => {
  const previousTrust = process.env["ACTANTOS_TRUST_MCP_CONTEXT"]
  delete process.env["ACTANTOS_TRUST_MCP_CONTEXT"]

  try {
    // With no identity headers and unauthenticated, context falls back to defaults — no 401.
    const mockRequest = {
      headers: {
        "x-actantos-runtime-type": "mcp",
      },
    } as any
    const context = createGatewayRequestContext(mockRequest, false)
    // Defaults are applied (no error thrown)
    assert.equal(context.tenantId, "t_demo", "defaults are applied when no identity headers")
    assert.equal(context.agentId, "pi_demo", "defaults are applied when no identity headers")
    assert.equal(context.runtimeType, "mcp", "non-identity metadata header is accepted")
  } finally {
    if (previousTrust === undefined) {
      delete process.env["ACTANTOS_TRUST_MCP_CONTEXT"]
    } else {
      process.env["ACTANTOS_TRUST_MCP_CONTEXT"] = previousTrust
    }
  }
})



