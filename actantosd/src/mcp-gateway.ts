import { randomUUID } from "node:crypto"

import { Client } from "@modelcontextprotocol/sdk/client/index.js"
import { SSEClientTransport } from "@modelcontextprotocol/sdk/client/sse.js"
import { Server } from "@modelcontextprotocol/sdk/server/index.js"
import { SSEServerTransport } from "@modelcontextprotocol/sdk/server/sse.js"
import {
  CallToolRequestSchema,
  CallToolResultSchema,
  ListToolsRequestSchema,
  type CallToolRequest,
  type CallToolResult,
  type ListToolsRequest,
  type ListToolsResult,
  type Tool,
} from "@modelcontextprotocol/sdk/types.js"
import type { FastifyInstance, FastifyRequest } from "fastify"

import type { ToolCallInterceptionRequest, ToolCallInterceptionResponse } from "./contracts.ts"
import { canonicalHash, sha256 } from "./hash.ts"

const DEFAULT_UPSTREAM_URL = "http://localhost:8080/sse"
const DEFAULT_SERVER_ID = "upstream-mcp"
const DEFAULT_GATEWAY_CONTEXT = {
  tenantId: "t_demo",
  agentId: "pi_demo",
  runtimeType: "pi",
  environment: "dev",
  riskTier: "low",
  userId: "u_demo",
  sessionId: "s_demo",
  cwd: "/workspace",
} as const

type GatewayRequestContext = {
  readonly tenantId: string
  readonly agentId: string
  readonly runtimeType: "pi" | "mcp" | "langgraph" | "custom"
  readonly environment: "dev" | "staging" | "prod"
  readonly riskTier: "low" | "medium" | "high"
  readonly userId: string
  readonly sessionId: string
  readonly cwd?: string
  readonly purpose?: string
}

type GatewayConfig = {
  readonly upstreamUrl: string
  readonly serverId: string
  readonly transport: "sse"
}

type InterceptService = {
  readonly intercept: (
    request: ToolCallInterceptionRequest,
  ) => Promise<ToolCallInterceptionResponse>
}

type UpstreamClient = {
  readonly listTools: (params?: ListToolsRequest["params"]) => Promise<ListToolsResult>
  readonly callTool: (params: CallToolRequest["params"]) => Promise<unknown>
}

type ToolResultPayload = {
  readonly request_id: string
  readonly decision_id: string
  readonly decision_token?: string
  readonly tool_kind: "mcp"
  readonly status: "executed" | "failed" | "timeout" | "blocked"
  readonly started_at: string
  readonly finished_at: string
  readonly result: {
    readonly stdout_hash?: string | null
    readonly redacted_preview?: string
    readonly error_message?: string
  }
}

type ToolResultRecorder = (payload: ToolResultPayload) => Promise<void>

type GatewaySession = {
  readonly transport: SSEServerTransport
  readonly mcpServer: Server
  readonly upstreamClient: UpstreamClient
  readonly context: GatewayRequestContext
  readonly config: GatewayConfig
  readonly toolCache: Map<string, Tool>
}

const toGatewayRuntimeType = (value: string | undefined): GatewayRequestContext["runtimeType"] => {
  if (value === "mcp" || value === "langgraph" || value === "custom") {
    return value
  }
  return "pi"
}

const toGatewayEnvironment = (value: string | undefined): GatewayRequestContext["environment"] => {
  if (value === "staging" || value === "prod") {
    return value
  }
  return "dev"
}

const toGatewayRiskTier = (value: string | undefined): GatewayRequestContext["riskTier"] => {
  if (value === "medium" || value === "high") {
    return value
  }
  return "low"
}

export const createGatewayRequestContext = (request: FastifyRequest): GatewayRequestContext => {
  const purposeHeader = request.headers["x-actantos-purpose"]

  return {
    tenantId: String(request.headers["x-actantos-tenant-id"] ?? DEFAULT_GATEWAY_CONTEXT.tenantId),
    agentId: String(request.headers["x-actantos-agent-id"] ?? DEFAULT_GATEWAY_CONTEXT.agentId),
    runtimeType: toGatewayRuntimeType(
      request.headers["x-actantos-runtime-type"] as string | undefined,
    ),
    environment: toGatewayEnvironment(
      request.headers["x-actantos-environment"] as string | undefined,
    ),
    riskTier: toGatewayRiskTier(request.headers["x-actantos-risk-tier"] as string | undefined),
    userId: String(request.headers["x-actantos-user-id"] ?? DEFAULT_GATEWAY_CONTEXT.userId),
    sessionId: String(
      request.headers["x-actantos-session-id"] ?? DEFAULT_GATEWAY_CONTEXT.sessionId,
    ),
    cwd: String(request.headers["x-actantos-cwd"] ?? DEFAULT_GATEWAY_CONTEXT.cwd),
    ...(purposeHeader === undefined ? {} : { purpose: String(purposeHeader) }),
  }
}

const getGatewayConfig = (): GatewayConfig => ({
  upstreamUrl: process.env["ACTANTOS_MCP_UPSTREAM_URL"] ?? DEFAULT_UPSTREAM_URL,
  serverId: process.env["ACTANTOS_MCP_SERVER_ID"] ?? DEFAULT_SERVER_ID,
  transport: "sse",
})

const getToolMetadata = (tool: Tool, config: GatewayConfig) => ({
  schemaHash: canonicalHash({
    inputSchema: tool.inputSchema,
    outputSchema: tool.outputSchema ?? null,
  }),
  descriptionHash: canonicalHash({
    name: tool.name,
    title: tool.title ?? "",
    description: tool.description ?? "",
    annotations: tool.annotations ?? null,
  }),
  serverIdentityHash: sha256(`${config.serverId}:${config.upstreamUrl}`),
})

const credentialPattern =
  /\b(secret|token|credential|password|passwd|api[_-]?key|private[_-]?key|auth)\b/i

const isCredentialSensitive = (tool: Tool, argumentsValue?: Record<string, unknown>): boolean => {
  const toolText = `${tool.name} ${tool.title ?? ""} ${tool.description ?? ""}`
  if (credentialPattern.test(toolText)) {
    return true
  }

  if (argumentsValue === undefined) {
    return false
  }

  return credentialPattern.test(JSON.stringify(argumentsValue))
}

const normalizeMcpTool = (tool: Tool, argumentsValue?: Record<string, unknown>) => {
  const mutation = tool.annotations?.readOnlyHint !== true
  const destructive = tool.annotations?.destructiveHint === true
  const credentialAccess = isCredentialSensitive(tool, argumentsValue)

  return {
    verb: destructive ? "delete" : mutation ? "execute" : "read",
    mutation,
    destructive,
    network: tool.annotations?.openWorldHint === true,
    credential_access: credentialAccess,
    risk_class: credentialAccess || destructive || mutation ? "high" : "low",
    target_type: "mcp_tool",
  } as const
}

export const buildGatewayInterceptionRequest = ({
  tool,
  params,
  context,
  config,
  dryRun = false,
}: {
  readonly tool: Tool
  readonly params: CallToolRequest["params"]
  readonly context: GatewayRequestContext
  readonly config: GatewayConfig
  readonly dryRun?: boolean
}): ToolCallInterceptionRequest => {
  const metadata = getToolMetadata(tool, config)
  const argumentsValue = params.arguments ?? {}

  return {
    request_id: randomUUID(),
    tenant_id: context.tenantId,
    agent: {
      id: context.agentId,
      runtime_type: context.runtimeType,
      environment: context.environment,
      risk_tier: context.riskTier,
    },
    subject: {
      user_id: context.userId,
    },
    session: {
      id: context.sessionId,
      cwd: context.cwd,
      purpose: context.purpose,
    },
    tool: {
      kind: "mcp",
      name: tool.name,
      operation: "tools/call",
      schema_hash: metadata.schemaHash,
    },
    action: {
      operation: "tools/call",
      name: params.name,
      args: argumentsValue,
    },
    resource: {
      id: `mcp://${config.serverId}/tools/${tool.name}`,
      kind: "mcp_tool",
      path: `/mcp/${config.serverId}/tools/${tool.name}`,
    },
    normalized: normalizeMcpTool(tool, argumentsValue),
    mcp: {
      server_id: config.serverId,
      server_identity_hash: metadata.serverIdentityHash,
      tool_name: tool.name,
      tool_schema_hash: metadata.schemaHash,
      tool_description_hash: metadata.descriptionHash,
      transport: config.transport,
    },
    dry_run: dryRun,
  }
}

const formatDecisionMessage = (decision: ToolCallInterceptionResponse, toolName: string): string => {
  if (decision.decision === "approval_required") {
    return `ActantOS blocked MCP tool '${toolName}' pending approval: ${decision.reason}`
  }

  return `ActantOS denied MCP tool '${toolName}': ${decision.reason}`
}

const toBlockedCallToolResult = (
  decision: ToolCallInterceptionResponse,
  toolName: string,
): CallToolResult => ({
  content: [{ type: "text", text: formatDecisionMessage(decision, toolName) }],
  isError: true,
})

const toFailClosedCallToolResult = (toolName: string, message: string): CallToolResult => ({
  content: [{
    type: "text",
    text: `ActantOS failed closed for MCP tool '${toolName}': ${message}`,
  }],
  isError: true,
})

const resultPreview = (result: CallToolResult): string => {
  const textParts = result.content
    .filter(
      (
        item,
      ): item is Extract<CallToolResult["content"][number], { readonly type: "text" }> =>
        item.type === "text",
    )
    .map((item) => item.text)

  return textParts.join("\n").slice(0, 512)
}

const resultHash = (result: CallToolResult): string => canonicalHash(result)

const isCallToolResult = (value: unknown): value is CallToolResult =>
  typeof value === "object" && value !== null && "content" in value

const hasToolResult = (value: unknown): value is { readonly toolResult: unknown } =>
  typeof value === "object" && value !== null && "toolResult" in value

const normalizeCallToolResult = (value: unknown): CallToolResult => {
  if (isCallToolResult(value)) {
    return value
  }

  if (hasToolResult(value)) {
    return {
      content: [{ type: "text", text: JSON.stringify(value.toolResult) }],
    }
  }

  return {
    content: [{ type: "text", text: JSON.stringify(value) }],
    isError: true,
  }
}

const tryRecordGatewayToolResult = async ({
  recordToolResult,
  payload,
  toolName,
  fallbackMessage,
}: {
  readonly recordToolResult: ToolResultRecorder
  readonly payload: ToolResultPayload
  readonly toolName: string
  readonly fallbackMessage: string
}): Promise<CallToolResult | null> => {
  try {
    await recordToolResult(payload)
    return null
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    return toFailClosedCallToolResult(
      toolName,
      `${fallbackMessage}: ${message}`,
    )
  }
}

const refreshToolCache = async (
  upstreamClient: UpstreamClient,
  toolCache: Map<string, Tool>,
): Promise<void> => {
  const response = await upstreamClient.listTools()
  toolCache.clear()

  for (const tool of response.tools) {
    toolCache.set(tool.name, tool)
  }
}

const lookupTool = async (
  upstreamClient: UpstreamClient,
  toolCache: Map<string, Tool>,
  toolName: string,
): Promise<Tool | null> => {
  const existingTool = toolCache.get(toolName)
  if (existingTool !== undefined) {
    return existingTool
  }

  await refreshToolCache(upstreamClient, toolCache)
  return toolCache.get(toolName) ?? null
}

export const filterGatewayTools = async ({
  tools,
  interceptService,
  context,
  config,
}: {
  readonly tools: readonly Tool[]
  readonly interceptService: InterceptService | undefined
  readonly context: GatewayRequestContext
  readonly config: GatewayConfig
}): Promise<Tool[]> => {
  if (interceptService === undefined) {
    return [...tools]
  }

  const filteredTools: Tool[] = []

  for (const tool of tools) {
    const decision = await interceptService.intercept(
      buildGatewayInterceptionRequest({
        tool,
        params: { name: tool.name, arguments: {} },
        context,
        config,
        dryRun: true,
      }),
    )

    if (decision.decision === "deny") {
      continue
    }

    filteredTools.push(tool)
  }

  return filteredTools
}

export const executeGatewayToolCall = async ({
  params,
  upstreamClient,
  interceptService,
  context,
  config,
  toolCache,
  recordToolResult,
}: {
  readonly params: CallToolRequest["params"]
  readonly upstreamClient: UpstreamClient
  readonly interceptService: InterceptService | undefined
  readonly context: GatewayRequestContext
  readonly config: GatewayConfig
  readonly toolCache: Map<string, Tool>
  readonly recordToolResult: ToolResultRecorder
}): Promise<CallToolResult> => {
  const startedAt = new Date().toISOString()
  const tool = await lookupTool(upstreamClient, toolCache, params.name)

  if (tool === null) {
    return {
      content: [{ type: "text", text: `Unknown MCP tool '${params.name}'` }],
      isError: true,
    }
  }

  if (interceptService === undefined) {
    return normalizeCallToolResult(await upstreamClient.callTool(params))
  }

  const interceptRequest = buildGatewayInterceptionRequest({
    tool,
    params,
    context,
    config,
  })
  const decision = await interceptService.intercept(interceptRequest)

  if (decision.decision !== "allow") {
    const blockedPayload: ToolResultPayload = {
      request_id: interceptRequest.request_id,
      decision_id: decision.decision_id,
      tool_kind: "mcp",
      status: "blocked",
      started_at: startedAt,
      finished_at: new Date().toISOString(),
      result: {
        redacted_preview: formatDecisionMessage(decision, tool.name),
      },
    }
    const blockedRecordingFailure = await tryRecordGatewayToolResult({
      recordToolResult,
      payload: blockedPayload,
      toolName: tool.name,
      fallbackMessage: "blocked decision could not be recorded",
    })
    if (blockedRecordingFailure !== null) {
      return blockedRecordingFailure
    }

    return toBlockedCallToolResult(decision, tool.name)
  }

  try {
    const result = normalizeCallToolResult(await upstreamClient.callTool(params))
    const status = result.isError === true ? "failed" : "executed"
    const executedPayload: ToolResultPayload = {
      request_id: interceptRequest.request_id,
      decision_id: decision.decision_id,
      tool_kind: "mcp",
      status,
      started_at: startedAt,
      finished_at: new Date().toISOString(),
      result: {
        stdout_hash: resultHash(result),
        redacted_preview: resultPreview(result),
      },
      ...(decision.decision_token === undefined
        ? {}
        : { decision_token: decision.decision_token }),
    }

    const executionRecordingFailure = await tryRecordGatewayToolResult({
      recordToolResult,
      payload: executedPayload,
      toolName: tool.name,
      fallbackMessage: "execution result could not be recorded",
    })
    if (executionRecordingFailure !== null) {
      return executionRecordingFailure
    }

    return result
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    const failedPayload: ToolResultPayload = {
      request_id: interceptRequest.request_id,
      decision_id: decision.decision_id,
      tool_kind: "mcp",
      status: "failed",
      started_at: startedAt,
      finished_at: new Date().toISOString(),
      result: {
        error_message: message,
      },
      ...(decision.decision_token === undefined
        ? {}
        : { decision_token: decision.decision_token }),
    }

    const failureRecordingFailure = await tryRecordGatewayToolResult({
      recordToolResult,
      payload: failedPayload,
      toolName: tool.name,
      fallbackMessage: "failure result could not be recorded",
    })
    if (failureRecordingFailure !== null) {
      return failureRecordingFailure
    }

    return {
      content: [{ type: "text", text: `Upstream MCP tool '${tool.name}' failed: ${message}` }],
      isError: true,
    }
  }
}

const createToolResultRecorder = (server: FastifyInstance): ToolResultRecorder => async (payload) => {
  const response = await server.inject({
    method: "POST",
    url: "/v1/tool-result",
    payload,
  })

  if (response.statusCode >= 400) {
    server.log.error(
      {
        statusCode: response.statusCode,
        body: response.body,
        decisionId: payload.decision_id,
      },
      "Failed to record MCP tool result",
    )
    throw new Error(`tool-result rejected with status ${response.statusCode}`)
  }
}

export function registerMcpGateway(server: FastifyInstance, interceptService?: InterceptService) {
  const sessions = new Map<string, GatewaySession>()
  const gatewayConfig = getGatewayConfig()

  server.get("/v1/mcp/sse", async (request, reply) => {
    const transport = new SSEServerTransport("/v1/mcp/message", reply.raw)
    const sessionId = transport.sessionId
    const context = createGatewayRequestContext(request)
    const mcpServer = new Server(
      {
        name: "actantos-gateway",
        version: "0.1.0",
      },
      {
        capabilities: { tools: {} },
      },
    )
    const upstreamTransport = new SSEClientTransport(new URL(gatewayConfig.upstreamUrl))
    const upstreamClient = new Client(
      {
        name: "actantos-gateway-client",
        version: "0.1.0",
      },
      {
        capabilities: {},
      },
    )
    const toolCache = new Map<string, Tool>()
    const recordToolResult = createToolResultRecorder(server)

    const session: GatewaySession = {
      transport,
      mcpServer,
      upstreamClient: {
        listTools: (params) => upstreamClient.listTools(params),
        callTool: (params) => upstreamClient.callTool(params, CallToolResultSchema),
      },
      context,
      config: gatewayConfig,
      toolCache,
    }

    sessions.set(sessionId, session)

    mcpServer.setRequestHandler(ListToolsRequestSchema, async (mcpRequest) => {
      const response = await session.upstreamClient.listTools(mcpRequest.params)

      toolCache.clear()
      for (const tool of response.tools) {
        toolCache.set(tool.name, tool)
      }

      const filteredTools = await filterGatewayTools({
        tools: response.tools,
        interceptService,
        context,
        config: gatewayConfig,
      })

      return {
        ...response,
        tools: filteredTools,
      }
    })

    mcpServer.setRequestHandler(CallToolRequestSchema, async (mcpRequest) =>
      executeGatewayToolCall({
        params: mcpRequest.params,
        upstreamClient: session.upstreamClient,
        interceptService,
        context,
        config: gatewayConfig,
        toolCache,
        recordToolResult,
      }),
    )

    try {
      await upstreamClient.connect(upstreamTransport)
      await mcpServer.connect(transport)
    } catch (error) {
      sessions.delete(sessionId)
      server.log.error(error, "Failed to initialize MCP gateway session")
      return reply.code(502).send({ error: "Failed to connect to upstream MCP server" })
    }

    reply.raw.on("close", () => {
      sessions.delete(sessionId)
    })

    reply.hijack()
  })

  server.post("/v1/mcp/message", async (request, reply) => {
    const sessionId =
      request.query !== undefined &&
      request.query !== null &&
      typeof request.query === "object" &&
      "sessionId" in request.query
        ? String((request.query as { readonly sessionId?: string }).sessionId ?? "")
        : ""

    if (sessionId.length === 0) {
      return reply.code(400).send({ error: "Missing sessionId" })
    }

    const session = sessions.get(sessionId)
    if (session === undefined) {
      return reply.code(404).send({ error: "Session not found" })
    }

    await session.transport.handlePostMessage(request.raw, reply.raw, request.body)
    reply.hijack()
  })
}
