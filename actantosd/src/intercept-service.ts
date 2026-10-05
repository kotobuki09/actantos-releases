import { randomUUID } from "node:crypto"

import {
  type ToolCallContext,
  type ToolCallInterceptionRequest,
  type ToolCallInterceptionResponse,
  toolCallInterceptionRequestSchema,
} from "./contracts.ts"
import { AllowAllBudgetProvider, type BudgetProvider } from "./budget-provider.ts"
import { type CedarProvider } from "./fake-cedar-provider.ts"
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
import type { Database, DatabaseClient } from "./database.ts"
import {
  createFabricGate,
  fabricDenial,
  toFabricActionRequest,
  type FabricGate,
} from "./v2/fabric.ts"
import {
  DEFAULT_EGRESS_CELL_MODE,
  EGRESS_BROKER_REQUIRED,
  egressCellTopology,
  type EgressCellMode,
} from "./v2/egress-cell.ts"

type InterceptServiceDependencies = {
  readonly repository: ToolCallRepository
  readonly hmacSecret: string
  readonly cedarProvider: CedarProvider
  readonly riskEngine?: RiskEngine
  readonly budgetProvider?: BudgetProvider
  readonly rateLimitProvider?: RateLimitProvider
  readonly mcpManifestGuard?: McpManifestGuard
  readonly urlTargetGuard?: UrlTargetGuard
  readonly auditEventIdFactory?: () => string
  readonly database?: Database
  /**
   * The v2 security fabric. Optional so that every existing construction site keeps working
   * unchanged; when absent the fabric is not consulted, which is the `v1_compat` behaviour.
   */
  readonly fabricGate?: FabricGate
  /**
   * The operator's egress cell mode. Defaults to `none`, which is the v1 behaviour: the workload
   * gets no network and nothing about the decision path changes.
   */
  readonly egressCellMode?: EgressCellMode
  /**
   * Signs decision tokens. Absent means HMAC with `hmacSecret`, which is the existing behaviour and
   * remains the default so that no deployment changes scheme without asking.
   *
   * Configuring an Ed25519 signer is what makes a decision token executable: the executor refuses
   * HMAC tokens precisely because a party that can verify HMAC can also mint, and the executor must
   * not be able to authorize itself.
   */
  readonly decisionTokenSigner?: (payload: string) => string
}

type InterceptService = {
  readonly intercept: (
    request: ToolCallInterceptionRequest,
  ) => Promise<ToolCallInterceptionResponse>
}

export const createInterceptService = (
  dependencies: InterceptServiceDependencies,
): InterceptService => {
  const cedarProvider = dependencies.cedarProvider
  const riskEngine = dependencies.riskEngine ?? new RiskEngine({
    database: undefined,
    rulesPath: undefined,
  })
  const budgetProvider = dependencies.budgetProvider ?? new AllowAllBudgetProvider()
  const rateLimitProvider = dependencies.rateLimitProvider ?? new AllowAllRateLimitProvider()
  const mcpManifestGuard =
    dependencies.mcpManifestGuard ?? new AllowAllMcpManifestGuard()
  const urlTargetGuard = dependencies.urlTargetGuard ?? new DefaultUrlTargetGuard()
  const fabricGate = dependencies.fabricGate
  const egressCellMode = dependencies.egressCellMode ?? DEFAULT_EGRESS_CELL_MODE
  const createAuditEventId = dependencies.auditEventIdFactory ?? randomUUID
  const decisionTokenTtlSeconds = 10 * 60

  return {
    async intercept(
      request: ToolCallInterceptionRequest,
    ): Promise<ToolCallInterceptionResponse> {
      const parsedRequest = toolCallInterceptionRequestSchema.parse(request)
      const context = createToolCallContext(parsedRequest)
      const decisionMode = parsedRequest.dry_run ? "dry_run" : "enforce"

      const executeLogic = async (client?: DatabaseClient): Promise<ToolCallInterceptionResponse> => {
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
          }, client)

      // Step 0: Idempotency — return existing decision if request_id already exists
      let existingDecision
      try {
        existingDecision = await dependencies.repository.findByRequestId(
          parsedRequest.tenant_id,
          parsedRequest.request_id,
          client,
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
          client,
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
          cedarResult: { decision: "forbid" },
          riskClass: "low",
        }, client)
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
        }, client)
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
          cedarResult: { decision: "forbid" },
          riskClass: "low",
        }, client)
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
          cedarResult: { decision: "forbid" },
          riskClass: "low",
        }, client)
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
          cedarResult: { decision: "forbid" },
          riskClass: "high",
        }, client)
        return response
      }

      // The v2 security fabric. Placed after every v1 guard and before authorization so that it
      // sees the same request the rest of the pipeline sees, and so a fabric denial is recorded
      // as itself rather than as a downstream symptom.
      //
      // In observe mode this runs and its verdict is recorded but changes nothing; in enforce
      // mode a denial — or an unreachable fabric — stops the request here. `fabricDenial` is
      // the only thing that can turn an assessment into a denial, so the observe-mode guarantee
      // cannot be undone by a caller that forgets to check the mode.
      if (fabricGate?.evaluates === true) {
        const assessment = await fabricGate.evaluate(
          toFabricActionRequest(parsedRequest),
        )
        const denial = fabricDenial(assessment)

        if (denial !== null) {
          const decisionId = randomUUID()
          const response = createDenyResponse({
            decisionId,
            decisionMode,
            reason: denial.reason,
            reasonCode: denial.reasonCode,
            auditEventId: createAuditEventId(),
          })
          await dependencies.repository.saveDecision({
            request: parsedRequest,
            response,
            context,
            cedarResult: { decision: "forbid" },
            riskClass: "high",
          }, client)
          return response
        }
      }

      // Controlled egress cell, `broker_only` mode (S2).
      //
      // Under `broker_only` the workload has no network, exactly as under `none`. The difference is
      // that here the agent is told so, at decision time, with a reason code an operator can count.
      // Under `none` the same call is also impossible, but it fails later as `ENETUNREACH` inside
      // the workload — invisible to the operator and indistinguishable from a bug.
      //
      // The check sits here, after the fabric gate and before any allow path can produce
      // constraints, because a network grant produced by either allow path would otherwise be the
      // way this mode quietly stopped meaning anything.
      if (egressCellTopology(egressCellMode).brokerRequired && context.normalized.network === true) {
        const decisionId = randomUUID()
        const response = createDenyResponse({
          decisionId,
          decisionMode,
          reason:
            "this deployment runs its egress cell in broker_only mode: the workload has no network, " +
            "and this call needs one. Route it through the capability broker instead of executing " +
            "it inside the workload.",
          reasonCode: EGRESS_BROKER_REQUIRED,
          auditEventId: createAuditEventId(),
        })
        await dependencies.repository.saveDecision({
          request: parsedRequest,
          response,
          context,
          cedarResult: { decision: "forbid" },
          riskClass: "high",
        }, client)
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
            priorDecisionId: parsedRequest.authorization?.prior_decision_id,
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
          }, client)
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
            cedarResult: { decision: "permit" },
            riskClass: risk.risk_class,
            priorDecisionId: prior_decision_id,
          }, client)
        return response
      }

      const rateLimit = await rateLimitProvider.checkAndConsume({
        tenantId: parsedRequest.tenant_id,
        agentId: parsedRequest.agent.id,
        sessionId: parsedRequest.session.id,
        toolName: parsedRequest.tool.name,
        risk,
        consume: !parsedRequest.dry_run,
      }, client)

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
          cedarResult: { decision: "permit" },
          riskClass: risk.risk_class,
          priorDecisionId: prior_decision_id,
        }, client)
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
            cedarResult: { decision: "permit" },
            riskClass: risk.risk_class,
            priorDecisionId: prior_decision_id,
          }, client)
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
          ...(dependencies.decisionTokenSigner === undefined
            ? {}
            : { sign: dependencies.decisionTokenSigner }),
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
          cedarResult: { decision: "permit" },
          riskClass: risk.risk_class,
          priorDecisionId: prior_decision_id,
          approvalConsumed: true,
        }, client)
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

      if (cedarDecision.decision === "forbid") {
        const reasonCode = cedarDecision.reasonCode ?? mapForbidReason(context)
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
          cedarResult: { decision: "forbid" },
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
          cedarResult: { decision: "permit" },
          riskClass: risk.risk_class,
        }, client)
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
            cedarResult: { decision: "permit" },
            riskClass: risk.risk_class,
          }, client)
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
          cedarResult: { decision: "permit" },
          riskClass: risk.risk_class,
        }, client)
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
          ...(dependencies.decisionTokenSigner === undefined
            ? {}
            : { sign: dependencies.decisionTokenSigner }),
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
          cedarResult: { decision: "permit" },
          riskClass: risk.risk_class,
        }, client)
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
          cedarResult: { decision: "permit" },
          riskClass: risk.risk_class,
          approvalId,
          approvalExpiresAt: expiresAt,
        }, client)
        return response
      }

      throw new Error("approval_required response must not include authorization")
    }

    if (dependencies.database !== undefined) {
      return dependencies.database.transaction(executeLogic)
    }
    return executeLogic()
  },
}
}
