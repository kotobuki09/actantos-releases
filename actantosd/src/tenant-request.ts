import { z } from "zod"

/** Explicit tenant id — never falls back to t_demo in production code paths. */
export const tenantIdSchema = z.string().min(1)

export class TenantRequiredError extends Error {
  readonly code = "tenant_required" as const

  constructor(message = "tenant_id is required") {
    super(message)
    this.name = "TenantRequiredError"
  }
}

export class TenantMismatchError extends Error {
  readonly code = "tenant_forbidden" as const

  constructor(message = "principal is not a member of tenant") {
    super(message)
    this.name = "TenantMismatchError"
  }
}

/**
 * Resolve the effective tenant for an operator/control-plane request.
 * Priority: explicit query/header/body → authenticated principal → never demo default.
 */
export const resolveRequestTenantId = (input: {
  readonly explicitTenantId?: string | undefined
  readonly principalTenantId?: string | undefined
}): string => {
  const explicit = input.explicitTenantId?.trim()
  if (explicit !== undefined && explicit.length > 0) {
    if (
      input.principalTenantId !== undefined &&
      input.principalTenantId.length > 0 &&
      explicit !== input.principalTenantId
    ) {
      throw new TenantMismatchError()
    }
    return explicit
  }

  const principal = input.principalTenantId?.trim()
  if (principal !== undefined && principal.length > 0) {
    return principal
  }

  throw new TenantRequiredError()
}

/** Inventory of tenant-scoped control-plane surfaces (T5). */
export const tenantScopedSurfaces = [
  { id: "agents", path: "/v1/agents", methods: ["GET"] },
  { id: "sessions", path: "/v1/sessions", methods: ["GET"] },
  { id: "decisions", path: "/v1/decisions", methods: ["GET"] },
  { id: "approvals", path: "/v1/approvals/pending", methods: ["GET"] },
  { id: "budgets", path: "/v1/budgets", methods: ["GET", "POST", "DELETE"] },
  { id: "kill_switches", path: "/v1/kill-switches", methods: ["GET", "POST"] },
  { id: "rate_limits", path: "/v1/rate-limits", methods: ["GET", "POST"] },
  { id: "risk_rules", path: "/v1/risk-rules", methods: ["GET", "PUT"] },
  { id: "policy_bundles", path: "/v1/policy-bundles", methods: ["GET", "POST"] },
  { id: "policy_dashboard", path: "/dashboard/policy", methods: ["GET"] },
  { id: "ops_dashboard", path: "/dashboard", methods: ["GET"] },
  { id: "metrics", path: "/v1/metrics/usage", methods: ["GET"] },
  { id: "evidence_export", path: "/v1/evidence/export", methods: ["GET"] },
  { id: "mcp_tool_versions", path: "/v1/mcp/tool-versions", methods: ["GET"] },
  { id: "session_events", path: "/v1/sessions/:id/events", methods: ["GET"] },
] as const

export type TenantScopedSurface = (typeof tenantScopedSurfaces)[number]
