import { z } from "zod"

import { canonicalStringify, toJsonValue } from "../hash.ts"
import { scopeIsNarrowerThan } from "./delegation.ts"
import {
  getSignatureAlgorithm,
  type SignatureAlgorithmName,
  type SigningKeyPair,
} from "./signature.ts"
import {
  DATA_LABELS,
  type DataLabel,
  type PolicyBundleBody,
} from "./signed-policy-bundle.ts"

/**
 * Security context envelope.
 *
 * Everything else in the fabric tells the *enforcement point* what an agent may do. This is
 * the one artefact that tells the *agent* what it may do, in a form the agent cannot forge
 * and the enforcement point can check.
 *
 * The problem it addresses is that an agent's self-description is otherwise ambient text. An
 * agent told "you may read these issues" is told it by whatever wrote that text — the prompt,
 * the conversation history, a tool description. A compromised agent can believe anything. So a
 * description of authority is only worth carrying if it is signed by something the agent does
 * not control, bound to the specific workload execution it was issued for, and short enough
 * that a stolen copy stops working quickly.
 *
 * Three properties do the work:
 *
 *   1. **Nonce-bound.** The envelope names the nonce of the workload identity it was issued
 *      against. Phase H made that nonce per-execution, so an envelope taken from agent A and
 *      presented by agent B is refused — the two cannot be swapped.
 *
 *   2. **Narrowing-only.** A valid signature is necessary and not sufficient. Every grant,
 *      tool, host, clearance and depth in the envelope is checked against the authority in
 *      the signed policy lease. An envelope signed by the control plane itself can still be
 *      refused for widening, because it is agent-supplied data and the lease is the ceiling.
 *      This is invariant S6 in the same form the delegation chain enforces it.
 *
 *   3. **Monotonic.** `version` is strictly increasing per agent, so a genuinely signed but
 *      older envelope — the one a rollback attacker actually has — cannot be replayed over a
 *      newer narrowing.
 */

const securityContextSchema = z.object({
  data_clearance: z.enum(DATA_LABELS),
  grants: z.array(z.string().min(1)),
  tools: z.array(z.string().min(1)),
  network_hosts: z.array(z.string().min(1)),
  max_delegation_depth: z.number().int().min(0),
})

export const securityContextEnvelopeBodySchema = z.object({
  envelope_id: z.string().min(1),
  tenant_id: z.string().min(1),
  /** The agent this describes. */
  spiffe_id: z.string().min(1),
  /**
   * The nonce of the workload identity this envelope was issued against. Verification
   * refuses an envelope whose nonce does not match the identity presented with it.
   */
  nonce: z.string().min(1),
  /** Strictly increasing per agent. Refuses a replay of an older genuine envelope. */
  version: z.number().int().positive(),
  issued_at: z.string().min(1),
  expires_at: z.string().min(1),
  context: securityContextSchema,
})

export type SecurityContext = z.infer<typeof securityContextSchema>
export type SecurityContextEnvelopeBody = z.infer<typeof securityContextEnvelopeBodySchema>

export const envelopeSignatureSchema = z.object({
  algorithm: z.string().min(1),
  issuer_id: z.string().min(1),
  /** base64 Ed25519 signature over the canonical body. */
  value: z.string().min(1),
})

export const securityContextEnvelopeSchema = z.object({
  body: securityContextEnvelopeBodySchema,
  signature: envelopeSignatureSchema,
})

export type SecurityContextEnvelope = z.infer<typeof securityContextEnvelopeSchema>

export const canonicalEnvelopeBytes = (body: SecurityContextEnvelopeBody): Uint8Array =>
  Buffer.from(canonicalStringify(toJsonValue(body)), "utf8")

export const signSecurityContextEnvelope = (
  body: SecurityContextEnvelopeBody,
  signature: { readonly algorithm: string; readonly issuer_id: string },
  keyPair: SigningKeyPair,
): SecurityContextEnvelope => {
  const algorithm = getSignatureAlgorithm(signature.algorithm as SignatureAlgorithmName)

  if (algorithm === undefined) {
    throw new Error(
      `Cannot sign security context envelope: unsupported algorithm "${signature.algorithm}"`,
    )
  }

  return {
    body,
    signature: {
      ...signature,
      value: Buffer.from(
        algorithm.sign(canonicalEnvelopeBytes(body), keyPair.privateKeyPem),
      ).toString("base64"),
    },
  }
}

export type EnvelopeRejectionReason =
  | "malformed_envelope"
  | "unsupported_algorithm"
  | "untrusted_issuer"
  | "invalid_signature"
  | "tenant_mismatch"
  | "expired"
  | "not_yet_valid"
  | "invalid_expiry_window"
  | "version_rollback"
  | "nonce_mismatch"
  | "identity_mismatch"

export type EnvelopeVerification =
  | { readonly accepted: true; readonly body: SecurityContextEnvelopeBody }
  | { readonly accepted: false; readonly reason: EnvelopeRejectionReason }

export type VerifySecurityContextEnvelopeOptions = {
  readonly expectedTenantId: string
  readonly trustedIssuerKeys: ReadonlyMap<string, string>
  readonly now?: Date
  readonly minimumVersion?: number
  /**
   * The nonce of the workload identity presented alongside the envelope. When supplied, an
   * envelope that does not carry it is refused — this is the binding that stops an envelope
   * being lifted from one agent's execution and replayed by another.
   */
  readonly expectedNonce?: string
  /** The spiffe id of the caller. Must match the envelope's subject. */
  readonly expectedSpiffeId?: string
}

export const verifySecurityContextEnvelope = (
  candidate: unknown,
  options: VerifySecurityContextEnvelopeOptions,
): EnvelopeVerification => {
  const now = options.now ?? new Date()
  const parsed = securityContextEnvelopeSchema.safeParse(candidate)

  if (!parsed.success) {
    return { accepted: false, reason: "malformed_envelope" }
  }

  const { body, signature } = parsed.data
  const algorithm = getSignatureAlgorithm(
    signature.algorithm as SignatureAlgorithmName,
  )

  if (algorithm === undefined) {
    return { accepted: false, reason: "unsupported_algorithm" }
  }

  const issuerKey = options.trustedIssuerKeys.get(signature.issuer_id)

  if (issuerKey === undefined) {
    return { accepted: false, reason: "untrusted_issuer" }
  }

  if (
    !algorithm.verify(
      canonicalEnvelopeBytes(body),
      Buffer.from(signature.value, "base64"),
      issuerKey,
    )
  ) {
    return { accepted: false, reason: "invalid_signature" }
  }

  if (body.tenant_id !== options.expectedTenantId) {
    return { accepted: false, reason: "tenant_mismatch" }
  }

  if (
    options.expectedSpiffeId !== undefined &&
    body.spiffe_id !== options.expectedSpiffeId
  ) {
    return { accepted: false, reason: "identity_mismatch" }
  }

  if (
    options.expectedNonce !== undefined &&
    body.nonce !== options.expectedNonce
  ) {
    return { accepted: false, reason: "nonce_mismatch" }
  }

  const issuedAt = Date.parse(body.issued_at)
  const expiresAt = Date.parse(body.expires_at)

  if (Number.isNaN(issuedAt) || Number.isNaN(expiresAt)) {
    return { accepted: false, reason: "invalid_expiry_window" }
  }

  if (expiresAt <= issuedAt) {
    return { accepted: false, reason: "invalid_expiry_window" }
  }

  if (now.getTime() < issuedAt) {
    return { accepted: false, reason: "not_yet_valid" }
  }

  if (now.getTime() >= expiresAt) {
    return { accepted: false, reason: "expired" }
  }

  if (options.minimumVersion !== undefined && body.version <= options.minimumVersion) {
    return { accepted: false, reason: "version_rollback" }
  }

  return { accepted: true, body }
}

// --- Narrowing only ---------------------------------------------------------------------------

/** `DATA_LABELS` is declared least- to most-sensitive, so the index is the ordering. */
const clearanceRank = (label: DataLabel): number => DATA_LABELS.indexOf(label)

export type AuthorityCeiling = {
  readonly grants: readonly string[]
  readonly tools: readonly string[]
  readonly networkHosts: readonly string[]
  readonly dataClearance: DataLabel
  readonly maxDelegationDepth: number
}

/**
 * The authority in force, read from the signed policy bundle.
 *
 * Nothing else is accepted as a ceiling. An envelope cannot be compared against another
 * envelope, and it cannot be compared against a value the agent supplied — otherwise the
 * ceiling would be exactly the thing being constrained.
 */
export const authorityFromBundle = (
  bundle: PolicyBundleBody,
  agentId: string,
): AuthorityCeiling => {
  const profile = bundle.agent_profile

  return {
    grants: bundle.tool_manifest.map((entry) => entry.grant),
    tools:
      profile.agent_id === agentId
        ? profile.allowed_tools
        : // A bundle for one agent grants nothing to another. Reading another agent's
          // allowed_tools here would hand out authority the bundle never gave this agent.
          [],
    networkHosts: bundle.network_rules
      .filter((rule) => rule.action === "allow_via_egress_gateway")
      .map((rule) => rule.host),
    dataClearance: bundle.data_clearance,
    maxDelegationDepth: profile.max_delegation_depth ?? 0,
  }
}

export type EnvelopeAuthorityViolation =
  | "grant_widened"
  | "tool_widened"
  | "host_widened"
  | "clearance_widened"
  | "depth_widened"

export type EnvelopeAuthorityAssessment =
  | { readonly accepted: true }
  | { readonly accepted: false; readonly reason: EnvelopeAuthorityViolation }

/**
 * Decide whether a verified envelope narrows, rather than widens, the authority in force.
 *
 * This runs after signature verification and is not redundant with it. A signature says the
 * control plane issued *some* envelope; it says nothing about whether that envelope is still
 * inside the policy currently in force. An envelope issued ten minutes ago under a wider
 * bundle is genuinely signed and genuinely stale, and treating "genuinely signed" as "allowed"
 * would make policy narrowing revocable by waiting.
 */
export const assessEnvelopeAuthority = (
  context: SecurityContext,
  ceiling: AuthorityCeiling,
): EnvelopeAuthorityAssessment => {
  if (!scopeIsNarrowerThan(context.grants, ceiling.grants)) {
    return { accepted: false, reason: "grant_widened" }
  }

  if (!context.tools.every((tool) => ceiling.tools.includes(tool))) {
    return { accepted: false, reason: "tool_widened" }
  }

  if (!context.network_hosts.every((host) => ceiling.networkHosts.includes(host))) {
    return { accepted: false, reason: "host_widened" }
  }

  if (clearanceRank(context.data_clearance) > clearanceRank(ceiling.dataClearance)) {
    return { accepted: false, reason: "clearance_widened" }
  }

  if (context.max_delegation_depth > ceiling.maxDelegationDepth) {
    return { accepted: false, reason: "depth_widened" }
  }

  return { accepted: true }
}

/**
 * Track the highest envelope version accepted for an agent.
 *
 * Separate from the policy lease on purpose. The lease and the envelope describe different
 * things and are signed by different issuers, so folding them into one counter would let an
 * envelope advance the policy version or a policy bundle retire an envelope.
 */
export class EnvelopeVersionTracker {
  readonly #highest = new Map<string, number>()

  highestFor(agentSpiffeId: string): number | undefined {
    return this.#highest.get(agentSpiffeId)
  }

  /** Record an accepted envelope. Returns false if it is at or below what was already seen. */
  record(agentSpiffeId: string, version: number): boolean {
    const current = this.#highest.get(agentSpiffeId)

    if (current !== undefined && version <= current) {
      return false
    }

    this.#highest.set(agentSpiffeId, version)
    return true
  }
}