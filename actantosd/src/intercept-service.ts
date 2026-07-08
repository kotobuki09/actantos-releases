import { randomUUID } from "node:crypto"

import {
  type ToolCallContext,
  type ToolCallInterceptionRequest,
  type ToolCallInterceptionResponse,
  toolCallInterceptionRequestSchema,
} from "./contracts.ts"
import { AllowAllBudgetProvider, type BudgetProvider } from "./budget-provider.ts"
import { type CedarProvider, FakeCedarProvider } from "./fake-cedar-provider.ts"
import { createDecisionConstraints } from "./decision-constraints.ts"
import {
  createAllowResponse,
  createApprovalRequiredResponse,
  createDecisionToken,
  createDenyResponse,
  createToolCallContext,
  mapForbidReason,
} from "./intercept-response.ts"
import { persistFailClosedDecision } from "./intercept-fail-closed.ts"
import { AllowAllMcpManifestGuard, type McpManifestGuard } from "./mcp-manifest-guard.ts"
import { AllowAllRateLimitProvider, type RateLimitProvider } from "./rate-limit-provider.ts"
import { RiskEngine } from "./risk-engine.ts"
import type { ToolCallRepository } from "./tool-call-repository.ts"
import { DefaultUrlTargetGuard, type UrlTargetGuard } from "./url-target-guard.ts"

type InterceptServiceDependencies = {
  readonly repository: ToolCallRepository
  readonly hmacSecret: string
  readonly cedarProvider?: CedarProvider
  readonly riskEngine?: RiskEngine
  readonly budgetProvider?: BudgetProvider
  readonly rateLimitProvider?: RateLimitProvider
  readonly mcpManifestGuard?: McpManifestGuard
  readonly urlTargetGuard?: UrlTargetGuard
  readonly auditEventIdFactory?: () => string
}

type InterceptService = {
  readonly intercept: (
    request: ToolCallInterceptionRequest,
  ) => Promise<ToolCallInterceptionResponse>
}

export const createInterceptService = (
  dependencies: InterceptServiceDependencies,
): InterceptService => {
  const cedarProvider = dependencies.cedarProvider ?? new FakeCedarProvider()
  const riskEngine = dependencies.riskEngine ?? new RiskEngine({
    database: undefined,
    rulesPath: undefined,
  })
  const budgetProvider = dependencies.budgetProvider ?? new AllowAllBudgetProvider()
  const rateLimitProvider = dependencies.rateLimitProvider ?? new AllowAllRateLimitProvider()
  const mcpManifestGuard =
    dependencies.mcpManifestGuard ?? new AllowAllMcpManifestGuard()
  const urlTargetGuard = dependencies.urlTargetGuard ?? new DefaultUrlTargetGuard()
  const createAuditEventId = dependencies.auditEventIdFactory ?? randomUUID
  const decisionTokenTtlSeconds = 10 * 60

  return {
    async intercept(
      request: ToolCallInterceptionRequest,
    ): Promise<ToolCallInterceptionResponse> {
      const parsedRequest = toolCallInterceptionRequestSchema.parse(request)
      const context = createToolCallContext(parsedRequest)
      const decisionMode = parsedRequest.dry_run ? "dry_run" : "enforce"
      const failClosed = (options: {
        readonly reason: string
        readonly reasonCode: string
        readonly riskClass: string
        readonly priorDecisionId?: string
      }) =>
        persistFailClosedDecision({
          repository: dependencies.repository,
          request: parsedRequest,
          context,
          decisionMode,
          reason: options.reason,
          reasonCode: options.reasonCode,
          riskClass: options.riskClass,
          ...(options.priorDecisionId === undefined
            ? {}
            : { priorDecisionId: options.priorDecisionId }),
        })

      // Step 0: Idempotency — return existing decision if request_id already exists
      let existingDecision
      try {
        existingDecision = await dependencies.repository.findByRequestId(
          parsedRequest.tenant_id,
          parsedRequest.request_id,
        )
      } catch {
        return failClosed({
          reason: "request lookup failed; denying fail-closed",
          reasonCode: "dependency_failure.request_lookup",
          riskClass: parsedRequest.normalized.risk_class ?? "high",
        })
      }

      if (existingDecision !== null) {
        return existingDecision.response
      }

      // Step 1: Kill switch check
      let killSwitchActive
      try {
        killSwitchActive = await dependencies.repository.isKillSwitchActive(
          parsedRequest.tenant_id,
          parsedRequest.agent.id,
          parsedRequest.session.id,
          parsedRequest.tool.name,
        )
      } catch {
        return failClosed({
          reason: "kill-switch verification failed; denying fail-closed",
          reasonCode: "dependency_failure.kill_switch",
          riskClass: parsedRequest.normalized.risk_class ?? "high",
        })
      }

      if (killSwitchActive) {
        const decisionId = randomUUID()
        const response = createDenyResponse({
          decisionId,
          decisionMode,
          reason: "kill switch is active",
          reasonCode: "kill_switch_active",
          auditEventId: createAuditEventId(),
        })
        await dependencies.repository.saveDecision({
          request: parsedRequest,
          response,
          context,
          cedarResult: "forbid",
          riskClass: "low",
        })
        return response
      }

      let budget
      try {
        budget = await budgetProvider.checkAndConsume({
          tenantId: parsedRequest.tenant_id,
          agentId: parsedRequest.agent.id,
          sessionId: parsedRequest.session.id,
          toolName: parsedRequest.tool.name,
          consume: !parsedRequest.dry_run,
        })
      } catch {
        return failClosed({
          reason: "budget verification failed; denying fail-closed",
          reasonCode: "dependency_failure.budget_check",
          riskClass: parsedRequest.normalized.risk_class ?? "high",
        })
      }

      if (!budget.allowed) {
        const decisionId = randomUUID()
        const response = createDenyResponse({
          decisionId,
          decisionMode,
          reason: "budget exceeded",
          reasonCode: "budget_exceeded",
          auditEventId: createAuditEventId(),
        })
        await dependencies.repository.saveDecision({
          request: parsedRequest,
          response,
          context,
          cedarResult: "forbid",
          riskClass: "low",
        })
        return response
      }

      let manifestResult
      try {
        manifestResult = await mcpManifestGuard.evaluate(parsedRequest)
      } catch {
        return failClosed({
          reason: "MCP manifest verification failed; denying fail-closed",
          reasonCode: "dependency_failure.mcp_manifest_guard",
          riskClass: "high",
        })
      }

      if (!manifestResult.allowed) {
        const decisionId = randomUUID()
        const response = createDenyResponse({
          decisionId,
          decisionMode,
          reason: manifestResult.reason,
          reasonCode: manifestResult.reasonCode,
          auditEventId: createAuditEventId(),
        })
        await dependencies.repository.saveDecision({
          request: parsedRequest,
          response,
          context,
          cedarResult: "forbid",
          riskClass: "low",
        })
        return response
      }

      let urlTargetResult
      try {
        urlTargetResult = await urlTargetGuard.evaluate(parsedRequest)
      } catch {
        return failClosed({
          reason: "URL target verification failed; denying fail-closed",
          reasonCode: "dependency_failure.url_target_guard",
          riskClass: "high",
        })
      }

      if (!urlTargetResult.allowed) {
        const decisionId = randomUUID()
        const response = createDenyResponse({
          decisionId,
          decisionMode,
          reason: urlTargetResult.reason,
          reasonCode: urlTargetResult.reasonCode,
          auditEventId: createAuditEventId(),
        })
        await dependencies.repository.saveDecision({
          request: parsedRequest,
          response,
          context,
          cedarResult: "forbid",
          riskClass: "high",
        })
        return response
      }

      if (parsedRequest.authorization !== undefined) {
        let risk
        try {
          risk = await riskEngine.evaluate(context)
        } catch {
          return failClosed({
            reason: "risk evaluation failed; denying fail-closed",
            reasonCode: "dependency_failure.risk_evaluation",
            riskClass: parsedRequest.normalized.risk_class ?? "high",
            priorDecisionId: parsedRequest.authorization.prior_decision_id,
          })
        }
        const { prior_decision_id, approval_id, approval_token } = parsedRequest.authorization
        let approvalResult
        try {
          approvalResult = await dependencies.repository.verifyAndConsumeApproval({
            tenantId: parsedRequest.tenant_id,
            approvalId: approval_id,
            approvalToken: approval_token,
            scopeHash: context.scope_hash,
            requestId: parsedRequest.request_id,
            consume: !parsedRequest.dry_run,
          })
        } catch {
          return failClosed({
            reason: "approval verification failed; denying fail-closed",
            reasonCode: "dependency_failure.approval_verification",
            riskClass: risk.risk_class,
            priorDecisionId: prior_decision_id,
          })
        }

        if (!approvalResult.valid) {
          const decisionId = randomUUID()
          const response = createDenyResponse({
            decisionId,
            decisionMode,
            reason: approvalResult.reason ?? "invalid approval token",
            reasonCode: "invalid_approval",
            auditEventId: createAuditEventId(),
          })
          await dependencies.repository.saveDecision({
            request: parsedRequest,
            response,
            context,
            cedarResult: "permit",
            riskClass: risk.risk_class,
            priorDecisionId: prior_decision_id,
          })
        return response
      }

      const rateLimit = await rateLimitProvider.checkAndConsume({
        tenantId: parsedRequest.tenant_id,
        agentId: parsedRequest.agent.id,
        sessionId: parsedRequest.session.id,
        toolName: parsedRequest.tool.name,
        risk,
        consume: !parsedRequest.dry_run,
      })

      if (!rateLimit.allowed) {
        const decisionId = randomUUID()
        const response = createDenyResponse({
          decisionId,
          decisionMode,
          reason: "rate limit exceeded",
          reasonCode: "rate_limited",
          auditEventId: createAuditEventId(),
        })
        await dependencies.repository.saveDecision({
          request: parsedRequest,
          response,
          context,
          cedarResult: "permit",
          riskClass: risk.risk_class,
          priorDecisionId: prior_decision_id,
        })
        return response
      }

        const decisionId = randomUUID()
        if (parsedRequest.dry_run) {
          const response = createAllowResponse({
            decisionId,
            decisionMode: "dry_run",
            reason: "dry run — approval verified, no execution",
            reasonCode: "allowed",
            auditEventId: createAuditEventId(),
          })
          await dependencies.repository.saveDecision({
            request: parsedRequest,
            response,
            context,
            cedarResult: "permit",
            riskClass: risk.risk_class,
            priorDecisionId: prior_decision_id,
          })
          return response
        }

        const networkMode = context.normalized.network ? "egress_proxy" : "none"
        const constraints = createDecisionConstraints({ networkMode })
        const toolCallId = randomUUID()
        const decisionToken = createDecisionToken({
          decisionId,
          toolCallId,
          request: parsedRequest,
          scopeHash: context.scope_hash,
          constraints,
          expiresAtEpochSeconds: Math.floor(Date.now() / 1_000) + decisionTokenTtlSeconds,
          hmacSecret: dependencies.hmacSecret,
          approved: true,
        })

        const response = createAllowResponse({
          decisionId,
          decisionMode: "enforce",
          reason: "approval verified — action permitted",
          reasonCode: "allowed",
          auditEventId: createAuditEventId(),
          decisionToken,
          constraints,
        })
        await dependencies.repository.saveDecision({
          toolCallId,
          request: parsedRequest,
          response,
          context,
          cedarResult: "permit",
          riskClass: risk.risk_class,
          priorDecisionId: prior_decision_id,
          approvalConsumed: true,
        })
        return response
      }

      // Step 3: Cedar PDP evaluation
      let cedarDecision
      try {
        cedarDecision = await cedarProvider.evaluate(context)
      } catch {
        return failClosed({
          reason: "policy evaluation failed; denying fail-closed",
          reasonCode: "dependency_failure.policy_evaluation",
          riskClass: parsedRequest.normalized.risk_class ?? "high",
        })
      }

      if (cedarDecision === "forbid") {
        const reasonCode = mapForbidReason(context)
        const decisionId = randomUUID()
        const response = createDenyResponse({
          decisionId,
          decisionMode,
          reason: "blocked by policy",
          reasonCode,
          auditEventId: createAuditEventId(),
        })
        await dependencies.repository.saveDecision({
          request: parsedRequest,
          response,
          context,
          cedarResult: "forbid",
          riskClass: context.normalized.credential_access ? "critical" : "low",
        })
        return response
      }

      // Step 4: Risk classifier
      let risk
      try {
        risk = await riskEngine.evaluate(context)
      } catch {
        return failClosed({
          reason: "risk evaluation failed; denying fail-closed",
          reasonCode: "dependency_failure.risk_evaluation",
          riskClass: parsedRequest.normalized.risk_class ?? "high",
        })
      }

      let rateLimit
      try {
        rateLimit = await rateLimitProvider.checkAndConsume({
          tenantId: parsedRequest.tenant_id,
          agentId: parsedRequest.agent.id,
          sessionId: parsedRequest.session.id,
          toolName: parsedRequest.tool.name,
          risk,
          consume: !parsedRequest.dry_run && !risk.approval_required,
        })
      } catch {
        return failClosed({
          reason: "rate-limit verification failed; denying fail-closed",
          reasonCode: "dependency_failure.rate_limit",
          riskClass: risk.risk_class,
        })
      }

      if (!rateLimit.allowed) {
        const decisionId = randomUUID()
        const response = createDenyResponse({
          decisionId,
          decisionMode,
          reason: "rate limit exceeded",
          reasonCode: "rate_limited",
          auditEventId: createAuditEventId(),
        })
        await dependencies.repository.saveDecision({
          request: parsedRequest,
          response,
          context,
          cedarResult: "permit",
          riskClass: risk.risk_class,
        })
        return response
      }

      // Step 5: Approval state resolution
      if (parsedRequest.dry_run) {
        if (risk.approval_required) {
          const decisionId = randomUUID()
          const response = createApprovalRequiredResponse({
            decisionId,
            decisionMode: "dry_run",
            reason: `${risk.matched_rule_id ?? "risk rule"} — approval required`,
            auditEventId: createAuditEventId(),
            approvalId: randomUUID(),
            expiresAt: new Date(Date.now() + 10 * 60 * 1000).toISOString(),
          })
          await dependencies.repository.saveDecision({
            request: parsedRequest,
            response,
            context,
            cedarResult: "permit",
            riskClass: risk.risk_class,
          })
          return response
        }

        const decisionId = randomUUID()
        const response = createAllowResponse({
          decisionId,
          decisionMode: "dry_run",
          reason: "dry run — policy permit, no enforcement",
          reasonCode: "allowed",
          auditEventId: createAuditEventId(),
        })
        await dependencies.repository.saveDecision({
          request: parsedRequest,
          response,
          context,
          cedarResult: "permit",
          riskClass: risk.risk_class,
        })
        return response
      }

      if (!risk.approval_required) {
        // Cedar permit + no approval needed → allow
        const constraints = createDecisionConstraints({ networkMode: "none" })
        const decisionId = randomUUID()
        const toolCallId = randomUUID()
        const decisionToken = createDecisionToken({
          decisionId,
          toolCallId,
          request: parsedRequest,
          scopeHash: context.scope_hash,
          constraints,
          expiresAtEpochSeconds: Math.floor(Date.now() / 1_000) + decisionTokenTtlSeconds,
          hmacSecret: dependencies.hmacSecret,
        })

        const response = createAllowResponse({
          decisionId,
          decisionMode: "enforce",
          reason: "permitted by policy",
          reasonCode: "allowed",
          auditEventId: createAuditEventId(),
          decisionToken,
          constraints,
        })
        await dependencies.repository.saveDecision({
          toolCallId,
          request: parsedRequest,
          response,
          context,
          cedarResult: "permit",
          riskClass: risk.risk_class,
        })
        return response
      }

      // Cedar permit + approval_required
      if (parsedRequest.authorization === undefined) {
        // First submission — create approval record
        const decisionId = randomUUID()
        const approvalId = randomUUID()
        const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString() // 10 min TTL

        const response = createApprovalRequiredResponse({
          decisionId,
          decisionMode: "enforce",
          reason: `${risk.matched_rule_id ?? "risk rule"} — approval required`,
          auditEventId: createAuditEventId(),
          approvalId,
          expiresAt,
        })
        await dependencies.repository.saveDecision({
          request: parsedRequest,
          response,
          context,
          cedarResult: "permit",
          riskClass: risk.risk_class,
          approvalId,
          approvalExpiresAt: expiresAt,
        })
        return response
      }

      throw new Error("approval_required response must not include authorization")
    },
  }
}
