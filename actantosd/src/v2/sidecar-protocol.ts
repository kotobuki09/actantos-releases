import { z } from "zod"

/**
 * Versioned sidecar protocol (Phase 1).
 *
 * The protected agent speaks this protocol over a Unix domain socket. It is deliberately
 * separate from sidecar internals so the sidecar can be replaced, moved, or reimplemented
 * without breaking agents. An agent that does not understand `PROTOCOL_VERSION` must fail
 * closed rather than guess.
 */

export const PROTOCOL_VERSION = "v2.1"

export const DENY_REASONS = [
  "policy_expired",
  "no_valid_policy",
  "protocol_version_unsupported",
  "identity_invalid",
  "not_in_grant_scope",
  "network_rule_denied",
  "tool_not_in_manifest",
  "approval_required",
  "ifc_violation",
  "effect_permit_required",
  "sidecar_policy_denied",
  "identity_revoked",
] as const

export const denyReasonSchema = z.enum(DENY_REASONS)

export type DenyReason = z.infer<typeof denyReasonSchema>

export const REQUEST_TYPES = [
  "CheckAction",
  "CheckMessage",
  "ResolveGrant",
  "RequestEffectPermit",
  "CommitEffect",
  "GetSecurityContext",
] as const

export const requestTypeSchema = z.enum(REQUEST_TYPES)

export type RequestType = z.infer<typeof requestTypeSchema>

const baseRequestSchema = z.object({
  protocol_version: z.string().min(1),
  request_id: z.string().min(1),
  request_type: requestTypeSchema,
  identity_token: z.unknown(),
})

export const checkActionRequestSchema = baseRequestSchema.extend({
  request_type: z.literal("CheckAction"),
  tool: z.string().min(1),
  resource: z.string().min(1),
  args: z.record(z.string(), z.unknown()),
})

export const checkMessageRequestSchema = baseRequestSchema.extend({
  request_type: z.literal("CheckMessage"),
  target_agent_id: z.string().min(1),
  labels: z.array(z.string()),
})

export const resolveGrantRequestSchema = baseRequestSchema.extend({
  request_type: z.literal("ResolveGrant"),
  grant_uri: z.string().min(1),
})

export const requestEffectPermitRequestSchema = baseRequestSchema.extend({
  request_type: z.literal("RequestEffectPermit"),
  tool: z.string().min(1),
  resource: z.string().min(1),
  args: z.record(z.string(), z.unknown()),
  sink_type: z.string().min(1),
  data_labels: z.array(z.string()),
})

export const commitEffectRequestSchema = baseRequestSchema.extend({
  request_type: z.literal("CommitEffect"),
  permit_id: z.string().min(1),
  result_digest: z.string().min(1),
})

export const getSecurityContextRequestSchema = baseRequestSchema.extend({
  request_type: z.literal("GetSecurityContext"),
})

export const sidecarRequestSchema = z.discriminatedUnion("request_type", [
  checkActionRequestSchema,
  checkMessageRequestSchema,
  resolveGrantRequestSchema,
  requestEffectPermitRequestSchema,
  commitEffectRequestSchema,
  getSecurityContextRequestSchema,
])

export type SidecarRequest = z.infer<typeof sidecarRequestSchema>

export type SecurityContext = {
  readonly tenant_id: string
  readonly agent_id: string
  readonly spiffe_id: string
  readonly policy_bundle_id: string
  readonly policy_bundle_version: number
  readonly policy_expires_at: string
  readonly data_clearance: string
  readonly grants: readonly string[]
}

export type SidecarDecision =
  | {
      readonly allowed: true
      readonly request_id: string
      readonly reason: string
      /** Present only for RequestEffectPermit. */
      readonly permit?: unknown
    }
  | {
      readonly allowed: false
      readonly request_id: string
      readonly reason: DenyReason
      readonly detail?: string
    }

/**
 * Transport-level decode. An unparseable request or an unsupported version is a denial,
 * never a default-allow.
 */
export const decodeSidecarRequest = (
  raw: unknown,
  supportedVersions: readonly string[] = [PROTOCOL_VERSION],
): SidecarRequest | { readonly unsupported: true; readonly reason: DenyReason } => {
  const parsed = sidecarRequestSchema.safeParse(raw)

  if (!parsed.success) {
    return { unsupported: true, reason: "protocol_version_unsupported" }
  }

  if (!supportedVersions.includes(parsed.data.protocol_version)) {
    return { unsupported: true, reason: "protocol_version_unsupported" }
  }

  return parsed.data
}