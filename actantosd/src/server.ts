import Fastify from "fastify"
import { z, ZodError } from "zod"
import { existsSync } from "node:fs"
import { dirname, resolve } from "node:path"
import { fileURLToPath } from "node:url"
import fastifyStatic from "@fastify/static"

import { registerApprovalRoutes } from "./approval-routes.ts"
import { registerAgentsRoutes } from "./agents-routes.ts"
import { registerBudgetRoutes } from "./budget-routes.ts"
import { PostgresBudgetProvider } from "./budget-provider.ts"
import {
  createConfiguredCedarPolicyValidator,
  createConfiguredCedarProvider,
  type CedarPolicyValidator,
} from "./cedar-provider.ts"
import { toolCallInterceptionRequestSchema } from "./contracts.ts"
import { registerDecisionsRoutes } from "./decisions-routes.ts";
import { registerPolicySimulateRoutes } from "./policy-simulate-routes.ts";
import { registerEvidenceExportRoutes } from "./evidence-export-routes.ts"
import { registerExecutionRoutes } from "./execution-routes.ts"
import type { DecisionExecutionService } from "./decision-execution.ts"
import { createInterceptService } from "./intercept-service.ts"
import { registerKillSwitchRoutes } from "./kill-switch-routes.ts"
import { registerDashboardRoutes } from "./dashboard-routes.ts"
import { PostgresMcpManifestGuard } from "./mcp-manifest-guard.ts"
import { registerMcpToolVersionRoutes } from "./mcp-tool-version-routes.ts"
import { registerPolicyBundleRoutes } from "./policy-bundle-routes.ts"
import { PostgresRateLimitProvider } from "./rate-limit-provider.ts"
import { registerRateLimitRoutes } from "./rate-limit-routes.ts"
import { RiskEngine } from "./risk-engine.ts"
import { registerRiskRulesRoutes } from "./risk-rules-routes.ts"
import { listSessionEvents } from "./session-events.ts"
import { registerSessionsRoutes } from "./sessions-routes.ts"
import { recordToolResult } from "./tool-result-service.ts"
import { registerUsageMetricsRoutes } from "./usage-metrics-routes.ts"
import {
  InMemoryToolCallRepository,
  type ToolCallRepository,
} from "./tool-call-repository.ts"
import type { CedarProvider } from "./fake-cedar-provider.ts"
import { tenantLocalStorage, type Database } from "./database.ts"
import { registerMcpGateway } from "./mcp-gateway.ts"
import { registerMetricsDashboardRoutes } from "./metrics-dashboard-routes.ts"
import { registerWebhookRoutes } from "./webhook-routes.ts"
import fastifyCookie from "@fastify/cookie"
import fastifySession from "@fastify/session"
import { registerOidcRoutes, type OidcConfig } from "./oidc-routes.ts"
import { registerSseRoutes } from "./sse-routes.ts"
import type { FabricGate } from "./v2/fabric.ts"
import type { EgressCellMode } from "./v2/egress-cell.ts"

type BuildServerOptions = {
  readonly apiKey?: string
  readonly hmacSecret?: string
  readonly repository?: ToolCallRepository
  readonly cedarProvider?: CedarProvider
  readonly policyValidator?: CedarPolicyValidator
  readonly riskEngine?: RiskEngine
  readonly database?: Database
  readonly oidcConfig?: OidcConfig
  readonly serviceRole?: "control_plane" | "data_plane" | "standalone"
  /**
   * The v2 security fabric. When absent the fabric is not consulted at all, which is the
   * `v1_compat` behaviour and the reason this is optional rather than required.
   */
  readonly fabricGate?: FabricGate
  /**
   * The operator's egress cell mode. Defaults to `none`, which leaves every decision path exactly
   * as v1 behaved.
   */
  readonly egressCellMode?: EgressCellMode
  /**
   * The decision-token executor, present only when the operator set `ACTANTOS_DECISION_EXECUTION=1`.
   *
   * When absent there is no `/v1/executions` route registered at all, so the default deployment is
   * unchanged rather than newly-refusing requests it never handled.
   */
  readonly executionService?: DecisionExecutionService
  /**
   * Signs decision tokens with Ed25519. Absent means HMAC, which is unchanged existing behaviour.
   */
  readonly decisionTokenSigner?: (payload: string) => string
  /** Test affordance. Defaults to the production logger. */
  readonly logger?: boolean
}

// ---------------------------------------------------------------------------
// Zod schemas for additional endpoints
// ---------------------------------------------------------------------------

const toolResultBodySchema = z.object({
  request_id: z.string().min(8).max(128),
  decision_id: z.string().uuid(),
  decision_token: z.string().optional(),
  tool_kind: z.enum(["file", "shell", "http", "github", "mcp", "db", "custom"]),
  status: z.enum(["executed", "failed", "timeout", "blocked"]),
  started_at: z.string(),
  finished_at: z.string(),
  result: z.object({
    exit_code: z.number().int().min(-1).optional(),
    stdout_hash: z.string().nullable().optional(),
    stderr_hash: z.string().nullable().optional(),
    redacted_preview: z.string().optional(),
    error_message: z.string().optional(),
  }).optional().default({}),
})

// ---------------------------------------------------------------------------
// Server builder
// ---------------------------------------------------------------------------

export const buildServer = (options: BuildServerOptions = {}) => {
  const server = Fastify({ logger: options.logger ?? true })
  const apiKey = options.apiKey
  const repository = options.repository ?? new InMemoryToolCallRepository()
  const cedarProvider = options.cedarProvider ?? createConfiguredCedarProvider()
  const policyValidator = options.policyValidator ?? createConfiguredCedarPolicyValidator()
  const hmacSecret = options.hmacSecret ?? "actantos-dev-secret"
  const database = options.database
  const riskEngine = options.riskEngine ?? new RiskEngine(
    { database, rulesPath: undefined },
  )
  const serviceRole = options.serviceRole ?? "standalone"

  const service = createInterceptService({
    repository,
    cedarProvider,
    riskEngine,
    hmacSecret,
    ...(options.fabricGate === undefined ? {} : { fabricGate: options.fabricGate }),
    ...(options.egressCellMode === undefined ? {} : { egressCellMode: options.egressCellMode }),
    ...(options.decisionTokenSigner === undefined
      ? {}
      : { decisionTokenSigner: options.decisionTokenSigner }),
    ...(database === undefined
      ? {}
      : {
          budgetProvider: new PostgresBudgetProvider(database),
          mcpManifestGuard: new PostgresMcpManifestGuard(database),
          rateLimitProvider: new PostgresRateLimitProvider(database),
        }),
  })

  server.addHook("onRequest", (request, reply, done) => {
    const requestUrl = new URL(request.raw.url ?? request.url, "http://localhost")
    const headerTenantId = request.headers["x-actantos-tenant-id"]
    const tenantId = typeof headerTenantId === "string"
      ? headerTenantId
      : (requestUrl.searchParams.get("tenant_id") ?? "t_demo")

    tenantLocalStorage.run(tenantId, () => {
      done()
    })
  })

  if (apiKey !== undefined) {
    server.addHook("onRequest", async (request, reply) => {
      const requestUrl = new URL(request.raw.url ?? request.url, "http://localhost")
      const pathname = requestUrl.pathname

      if (
        pathname === "/health/live" ||
        pathname === "/health/ready" ||
        pathname === "/v1/intercept/tool-call" ||
        pathname === "/v1/tool-result" ||
        pathname === "/v1/mcp/sse" ||
        pathname === "/v1/mcp/message"
      ) {
        return
      }

      const headerApiKey = request.headers["x-actantos-api-key"]
      const providedApiKey = typeof headerApiKey === "string"
        ? headerApiKey
        : requestUrl.searchParams.get("api_key")

      if (providedApiKey === apiKey) {
        return
      }

      return reply.code(401).send({
        error: "unauthorized",
        message: "valid API key required",
      })
    })
  }

  if (options.oidcConfig !== undefined) {
    server.register(fastifyCookie)
    server.register(fastifySession, {
      cookieName: "actantos_session",
      secret: (hmacSecret + hmacSecret).padEnd(32, "a").slice(0, 32),
      cookie: { secure: false }, // use secure: true in prod with https
    })
    server.register(async (instance) => {
      await registerOidcRoutes(instance, { oidcConfig: options.oidcConfig! })
    })

    // Protect /dashboard
    if (serviceRole !== "data_plane") {
      server.addHook("onRequest", async (request, reply) => {
        const requestUrl = new URL(request.raw.url ?? request.url, "http://localhost")
        if (requestUrl.pathname.startsWith("/dashboard")) {
          // If not authenticated via session, redirect to login
          if (request.session && !request.session.user) {
            // Check for API key as fallback, though milestone says require OIDC for HTML dashboard if OIDC is configured.
            // The exact requirement: "Unauthenticated requests to `/dashboard` redirect to the OIDC identity provider (if configured)."
            return reply.redirect("/auth/login")
          }
        }
      })
    }
  }

  server.get("/health/live", async (_request, reply) =>
    reply.code(200).send({ status: "ok" }),
  )

  server.get("/health/ready", async (_request, reply) => {
    if (database === undefined) {
      return reply.code(200).send({
        status: "ready",
        database: "not_configured",
      })
    }

    try {
      await database.query("select 1 as ok")
      return reply.code(200).send({
        status: "ready",
        database: "connected",
      })
    } catch (error) {
      server.log.warn(error, "Readiness database probe failed")
      return reply.code(503).send({
        status: "not_ready",
        database: "unreachable",
      })
    }
  })

  // Register MCP Gateway
  if (serviceRole !== "control_plane") {
    registerMcpGateway(server, service, { ...(apiKey !== undefined ? { apiKey } : {}) })
    registerWebhookRoutes(server, { ...(database === undefined ? {} : { database }), hmacSecret })
  }

  if (serviceRole !== "data_plane") {
    registerAgentsRoutes(server, { ...(database === undefined ? {} : { database }) })
    registerApprovalRoutes(server, { repository, ...(database === undefined ? {} : { database }) })
    registerDashboardRoutes(server, { ...(database === undefined ? {} : { database }) })
    registerDecisionsRoutes(server, { ...(database === undefined ? {} : { database }) })
    registerEvidenceExportRoutes(server, { hmacSecret, ...(database === undefined ? {} : { database }) })
    registerKillSwitchRoutes(server, { repository, ...(database === undefined ? {} : { database }) })
    registerSessionsRoutes(server, { ...(database === undefined ? {} : { database }) })
    registerSseRoutes(server)
  }

  if (database !== undefined) {
    if (serviceRole !== "data_plane") {
      registerBudgetRoutes(server, { database })
      registerMcpToolVersionRoutes(server, { database })
      registerPolicyBundleRoutes(server, { database, policyValidator, cedarProvider })
      registerPolicySimulateRoutes(server, { cedarProvider })
      registerRateLimitRoutes(server, { database })
      registerRiskRulesRoutes(server, { database })
      registerMetricsDashboardRoutes(server, { database })
      registerUsageMetricsRoutes(server, { database })
    }

    if (cedarProvider.reloadPolicy) {
      server.addHook("onReady", async () => {
        try {
          const rows = await database.query<{ source_text: string }>(
            `
              SELECT source_text
              FROM policy_bundles
              WHERE active = true
              ORDER BY created_at DESC
              LIMIT 1
            `
          )
          const activeBundle = rows[0]
          if (activeBundle !== undefined) {
            cedarProvider.reloadPolicy!(activeBundle.source_text)
          }
        } catch (error) {
          server.log.error(error, "Failed to load active policy bundle on startup")
        }
      })
    }
  }

  if (serviceRole !== "control_plane") {
    // POST /v1/intercept/tool-call
    server.post("/v1/intercept/tool-call", async (request, reply) => {
      try {
        const parsedRequest = toolCallInterceptionRequestSchema.parse(request.body)
        const response = await service.intercept(parsedRequest)
        return reply.code(200).send(response)
      } catch (error) {
        if (error instanceof ZodError) {
          return reply.code(400).send({
            error: "invalid_request",
            issues: error.issues,
          })
        }
        throw error
      }
    })
  }

  if (serviceRole !== "control_plane") {
    // POST /v1/tool-result
    server.post("/v1/tool-result", async (request, reply) => {
      try {
        // T11: check decision_token before full parse, so we return our custom error
        const rawBody = request.body as Record<string, unknown>
        if (
          typeof rawBody === "object" &&
          rawBody !== null &&
          ["executed", "failed", "timeout"].includes(String(rawBody["status"] ?? "")) &&
          (rawBody["decision_token"] === undefined || String(rawBody["decision_token"]).length === 0)
        ) {
          return reply.code(400).send({
            error: "decision_token_required",
            message: "decision_token is required for executed/failed/timeout status",
          })
        }

        const body = toolResultBodySchema.parse(request.body)

        if (database !== undefined) {
          const parsedResult: {
            exit_code?: number
            stdout_hash?: string | null
            stderr_hash?: string | null
            redacted_preview?: string
            error_message?: string
          } = {}

          if (body.result.exit_code !== undefined) {
            parsedResult.exit_code = body.result.exit_code
          }
          if (body.result.stdout_hash !== undefined) {
            parsedResult.stdout_hash = body.result.stdout_hash
          }
          if (body.result.stderr_hash !== undefined) {
            parsedResult.stderr_hash = body.result.stderr_hash
          }
          if (body.result.redacted_preview !== undefined) {
            parsedResult.redacted_preview = body.result.redacted_preview
          }
          if (body.result.error_message !== undefined) {
            parsedResult.error_message = body.result.error_message
          }

          const toolResultPayload: {
            request_id: string
            decision_id: string
            decision_token?: string
            tool_kind: "file" | "shell" | "http" | "github" | "mcp" | "db" | "custom"
            status: "executed" | "failed" | "timeout" | "blocked"
            started_at: string
            finished_at: string
            result: typeof parsedResult
          } = {
            request_id: body.request_id,
            decision_id: body.decision_id,
            tool_kind: body.tool_kind,
            status: body.status,
            started_at: body.started_at,
            finished_at: body.finished_at,
            result: parsedResult,
          }

          if (body.decision_token !== undefined) {
            toolResultPayload.decision_token = body.decision_token
          }

          await recordToolResult(database, toolResultPayload, hmacSecret)
        }

        return reply.code(200).send({
          request_id: body.request_id,
          decision_id: body.decision_id,
          status: body.status,
          recorded_at: new Date().toISOString(),
        })
      } catch (error) {
        if (error instanceof ZodError) {
          return reply.code(400).send({ error: "invalid_request", issues: error.issues })
        }
        if (error instanceof Error && error.message === "invalid_decision_token") {
          return reply.code(403).send({
            error: "invalid_decision_token",
            message: "decision_token verification failed",
          })
        }
        if (error instanceof Error && error.message === "decision_token_required") {
          return reply.code(400).send({
            error: "decision_token_required",
            message: "decision_token is required for executed/failed/timeout status",
          })
        }
        throw error
      }
    })
  }

  if (options.executionService !== undefined && serviceRole !== "control_plane") {
    registerExecutionRoutes(server, { execution: options.executionService })
  }

  if (serviceRole !== "data_plane") {
    // GET /v1/sessions/:session_id/events
    server.get<{ Params: { session_id: string } }>(
      "/v1/sessions/:session_id/events",
      async (request, reply) => {
        const { session_id } = request.params

        if (database !== undefined) {
          const events = await listSessionEvents(database, "t_demo", session_id)
          return reply.code(200).send({ session_id, events })
        }

        // In-memory: no events to return (test scaffolding)
        return reply.code(200).send({ session_id, events: [] })
      },
    )
  }

  // ---------------------------------------------------------------------------
  // Dashboard SPA — serve the pre-built React app from packages/dashboard/dist
  // Uses synchronous existsSync so buildServer can remain a regular function.
  // We use 'wildcard: true' (default) which lets @fastify/static handle the
  // HEAD+GET /dashboard/* routes itself — we do NOT add our own wildcard route.
  // ---------------------------------------------------------------------------
  const thisDir = dirname(fileURLToPath(import.meta.url))
  const distDir = resolve(thisDir, "../../packages/dashboard/dist")

  if (existsSync(distDir)) {
    server.register(fastifyStatic, {
      root: distDir,
      prefix: "/dashboard",
      decorateReply: false,
    })
  }

  return server
}
