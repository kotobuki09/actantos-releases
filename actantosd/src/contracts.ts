import { z } from "zod"

const runtimeTypeSchema = z.enum(["pi", "mcp", "langgraph", "custom"])
const environmentSchema = z.enum(["dev", "staging", "prod"])
const riskTierSchema = z.enum(["low", "medium", "high"])
const decisionModeSchema = z.enum(["enforce", "dry_run"])
const verbSchema = z.enum(["read", "write", "execute", "delete", "list", "create", "network"])
const riskClassSchema = z.enum(["low", "medium", "high", "critical"])

const jsonObjectSchema = z.record(z.string(), z.unknown())

export const toolCallInterceptionRequestSchema = z.object({
  request_id: z.string().min(8).max(128),
  tenant_id: z.string().min(1),
  agent: z.object({
    id: z.string().min(1),
    runtime_type: runtimeTypeSchema,
    environment: environmentSchema,
    risk_tier: riskTierSchema,
  }),
  subject: z.object({
    user_id: z.string().min(1),
    role: z.string().min(1).optional(),
  }),
  session: z.object({
    id: z.string().min(1),
    cwd: z.string().min(1).optional(),
    purpose: z.string().optional(),
    budget_remaining_cents: z.number().int().min(0).optional(),
  }),
  tool: z.object({
    kind: z.enum(["file", "shell", "http", "github", "mcp", "db", "custom"]),
    name: z.string().min(1),
    operation: z.string().min(1),
    schema_hash: z.string().optional(),
  }),
  action: z.object({
    operation: z.string().min(1).optional(),
    args: jsonObjectSchema.optional(),
  }).and(jsonObjectSchema),
  resource: z.object({
    id: z.string().optional(),
    kind: z.string().optional(),
    path: z.string().optional(),
    url: z.string().optional(),
    database: z.string().optional(),
    table: z.string().optional(),
  }),
  normalized: z.object({
    verb: verbSchema.optional(),
    mutation: z.boolean().optional(),
    destructive: z.boolean().optional(),
    network: z.boolean().optional(),
    credential_access: z.boolean(),
    risk_class: riskClassSchema.optional(),
    command_family: z.string().optional(),
    subcommand: z.string().optional(),
    target_type: z.string().optional(),
    recursive_delete: z.boolean().optional(),
    force: z.boolean().optional(),
  }),
  mcp: z.object({
    server_id: z.string().min(1),
    server_identity_hash: z.string().optional(),
    tool_name: z.string().min(1),
    tool_schema_hash: z.string().min(1),
    tool_description_hash: z.string().min(1),
    transport: z.enum(["stdio", "sse", "http"]).optional(),
  }).optional(),
  authorization: z.object({
    prior_decision_id: z.string().min(8).max(128),
    approval_id: z.string().uuid(),
    approval_token: z.string().min(1),
  }).optional(),
  dry_run: z.boolean().optional(),
})

export const toolCallInterceptionResponseSchema = z.discriminatedUnion("decision", [
  z.object({
    decision: z.literal("allow"),
    decision_mode: decisionModeSchema,
    decision_id: z.string().uuid(),
    reason: z.string().min(1),
    reason_code: z.string().min(1),
    audit_event_id: z.string().uuid(),
    decision_token: z.string().min(1).optional(),
    constraints: z.object({
      timeout_ms: z.number().int().optional(),
      max_output_bytes: z.number().int().optional(),
      network_mode: z.enum(["none", "egress_proxy"]).optional(),
      network_allowlist: z.array(z.string()).optional(),
    }).optional(),
  }),
  z.object({
    decision: z.literal("deny"),
    decision_mode: decisionModeSchema,
    decision_id: z.string().uuid(),
    reason: z.string().min(1),
    reason_code: z.string().min(1),
    audit_event_id: z.string().uuid(),
  }),
  z.object({
    decision: z.literal("approval_required"),
    decision_mode: decisionModeSchema,
    decision_id: z.string().uuid(),
    reason: z.string().min(1),
    reason_code: z.string().min(1),
    audit_event_id: z.string().uuid(),
    approval: z.object({
      approval_id: z.string().uuid(),
      status: z.literal("pending"),
      expires_at: z.string(),
    }),
  }),
])

export type ToolCallInterceptionRequest = z.infer<typeof toolCallInterceptionRequestSchema>
export type ToolCallInterceptionResponse = z.infer<typeof toolCallInterceptionResponseSchema>

export type ToolCallContext = ToolCallInterceptionRequest & {
  readonly scope_hash: string
}

export const riskRuleSchema = z.object({
  rule_id: z.string().min(1),
  description: z.string().min(1),
  when: jsonObjectSchema,
  approval_required: z.boolean(),
  risk_class: riskClassSchema,
})

export const riskRulesSchema = z.array(riskRuleSchema)

// Risk rule types
export type RiskRule = z.infer<typeof riskRuleSchema>

export type RiskEvaluation = {
  readonly approval_required: boolean
  readonly risk_class: "low" | "medium" | "high" | "critical"
  readonly matched_rule_id?: string
}
