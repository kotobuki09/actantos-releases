import { z } from "zod"

import { canonicalStringify, toJsonValue } from "../hash.ts"
import {
  getSignatureAlgorithm,
  type SignatureAlgorithmName,
} from "./signature.ts"

/**
 * Workload identity (invariant S4): every agent execution holds a distinct, short-lived,
 * cryptographically attested identity.
 *
 * Identity is a signed attestation from the control plane, not a shared API key. A shared
 * secret cannot distinguish which agent performed an action; an attacker holding it can
 * impersonate every agent at once. v1's OIDC support (`oidc-routes.ts`) authenticates
 * *users*, not workloads, and is not a substitute.
 *
 * The logical form follows the SPIFFE naming convention so a SPIFFE/SPIRE backend can be
 * dropped in behind `WorkloadIdentityAuthority` without changing consumers.
 */

const TRUST_DOMAIN = "actantos.local"
const TENANT_SEGMENT = /^tenant\/([A-Za-z0-9._-]+)$/
const AGENT_SEGMENT = /^agent\/([A-Za-z0-9._-]+)$/

/** `spiffe://<trust-domain>/tenant/<tenant>/agent/<agent-id>` */
export const spiffeIdPattern = new RegExp(
  `^spiffe://${TRUST_DOMAIN.replace(/\./g, "\\.")}/tenant/[A-Za-z0-9._-]+/agent/[A-Za-z0-9._-]+$`,
)

export const workloadIdentitySchema = z.object({
  spiffe_id: z.string().regex(spiffeIdPattern),
  trust_domain: z.string().min(1),
  tenant_id: z.string().min(1),
  agent_id: z.string().min(1),
  /** Unique per issuance. Two executions never share an identity value. */
  nonce: z.string().min(1),
  issued_at: z.string().min(1),
  expires_at: z.string().min(1),
})

export type WorkloadIdentity = z.infer<typeof workloadIdentitySchema>

export const signedIdentitySchema = z.object({
  identity: workloadIdentitySchema,
  signature: z.object({
    algorithm: z.string().min(1),
    issuer_id: z.string().min(1),
    value: z.string().min(1),
  }),
})

export type SignedWorkloadIdentity = z.infer<typeof signedIdentitySchema>

export const buildSpiffeId = (
  tenantId: string,
  agentId: string,
): string => `spiffe://${TRUST_DOMAIN}/tenant/${tenantId}/agent/${agentId}`

/**
 * The SPFIE ID is derived, not asserted. If the caller supplies inconsistent parts the
 * parts win and the ID is recomputed, so a mismatched ID can never be smuggled through.
 */
export const parseSpiffeId = (
  spiffeId: string,
): { tenantId: string; agentId: string } | undefined => {
  const prefix = `spiffe://${TRUST_DOMAIN}/`

  if (!spiffeId.startsWith(prefix)) {
    return undefined
  }

  // The path is exactly `tenant/<tenant>/agent/<agent>`, i.e. four segments.
  const segments = spiffeId.slice(prefix.length).split("/")

  if (segments.length !== 4) {
    return undefined
  }

  const tenantMatch = TENANT_SEGMENT.exec(`${segments[0]}/${segments[1]}`)
  const agentMatch = AGENT_SEGMENT.exec(`${segments[2]}/${segments[3]}`)

  if (tenantMatch === null || agentMatch === null) {
    return undefined
  }

  return {
    tenantId: tenantMatch[1] as string,
    agentId: agentMatch[1] as string,
  }
}

export type MintWorkloadIdentityOptions = {
  readonly tenantId: string
  readonly agentId: string
  readonly issuedAt: Date
  /** Short-lived by construction. Defaults to 15 minutes. */
  readonly ttlMs?: number
  readonly nonce?: string
}

export const DEFAULT_IDENTITY_TTL_MS = 15 * 60 * 1000

export const mintWorkloadIdentity = (
  options: MintWorkloadIdentityOptions,
): WorkloadIdentity => {
  const ttlMs = options.ttlMs ?? DEFAULT_IDENTITY_TTL_MS
  const expiresAt = new Date(options.issuedAt.getTime() + ttlMs)

  return {
    spiffe_id: buildSpiffeId(options.tenantId, options.agentId),
    trust_domain: TRUST_DOMAIN,
    tenant_id: options.tenantId,
    agent_id: options.agentId,
    nonce: options.nonce ?? crypto.randomUUID(),
    issued_at: options.issuedAt.toISOString(),
    expires_at: expiresAt.toISOString(),
  }
}

export const signWorkloadIdentity = (
  identity: WorkloadIdentity,
  signature: SignedWorkloadIdentity["signature"],
  keyPair: { privateKeyPem: string },
): SignedWorkloadIdentity => {
  const algorithm = getSignatureAlgorithm(
    signature.algorithm as SignatureAlgorithmName,
  )

  if (algorithm === undefined) {
    throw new Error(
      `Cannot sign workload identity: unsupported algorithm "${signature.algorithm}"`,
    )
  }

  const payload = Buffer.from(
    canonicalStringify(toJsonValue(identity)),
    "utf8",
  )

  return {
    identity,
    signature: {
      ...signature,
      value: Buffer.from(algorithm.sign(payload, keyPair.privateKeyPem)).toString(
        "base64",
      ),
    },
  }
}

export type IdentityRejectionReason =
  | "malformed_identity"
  | "unsupported_algorithm"
  | "untrusted_issuer"
  | "invalid_signature"
  | "tenant_mismatch"
  | "spiffe_mismatch"
  | "expired"
  | "not_yet_valid"
  | "revoked"

export type IdentityVerification =
  | { readonly accepted: true; readonly identity: WorkloadIdentity }
  | { readonly accepted: false; readonly reason: IdentityRejectionReason }

export type VerifyWorkloadIdentityOptions = {
  readonly trustedIssuerKeys: ReadonlyMap<string, string>
  readonly expectedTenantId: string
  readonly now?: Date | undefined
  /** Agents or nonces explicitly revoked by the control plane. */
  readonly revokedAgentIds?: ReadonlySet<string> | undefined
  readonly revokedNonces?: ReadonlySet<string> | undefined
}

/**
 * Verify a workload identity for use at an enforcement point.
 *
 * Revocation is checked here rather than by contacting the control plane, so a revoked
 * identity stops working immediately even if the issuer is unreachable (invariant S12).
 */
export const verifyWorkloadIdentity = (
  candidate: unknown,
  options: VerifyWorkloadIdentityOptions,
): IdentityVerification => {
  const now = options.now ?? new Date()
  const parsed = signedIdentitySchema.safeParse(candidate)

  if (!parsed.success) {
    return { accepted: false, reason: "malformed_identity" }
  }

  const { identity, signature } = parsed.data

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

  const payload = Buffer.from(
    canonicalStringify(toJsonValue(identity)),
    "utf8",
  )

  const signatureValid = algorithm.verify(
    payload,
    Buffer.from(signature.value, "base64"),
    issuerKey,
  )

  if (!signatureValid) {
    return { accepted: false, reason: "invalid_signature" }
  }

  // The ID must agree with the claims it carries. Otherwise a valid identity for agent A
  // could be presented while claiming to be agent B.
  const parsedId = parseSpiffeId(identity.spiffe_id)

  if (
    parsedId === undefined ||
    parsedId.tenantId !== identity.tenant_id ||
    parsedId.agentId !== identity.agent_id ||
    identity.trust_domain !== TRUST_DOMAIN
  ) {
    return { accepted: false, reason: "spiffe_mismatch" }
  }

  if (identity.tenant_id !== options.expectedTenantId) {
    return { accepted: false, reason: "tenant_mismatch" }
  }

  const issuedAt = Date.parse(identity.issued_at)
  const expiresAt = Date.parse(identity.expires_at)

  if (Number.isNaN(issuedAt) || Number.isNaN(expiresAt) || expiresAt <= issuedAt) {
    return { accepted: false, reason: "malformed_identity" }
  }

  if (now.getTime() < issuedAt) {
    return { accepted: false, reason: "not_yet_valid" }
  }

  if (now.getTime() >= expiresAt) {
    return { accepted: false, reason: "expired" }
  }

  if (options.revokedAgentIds?.has(identity.agent_id) === true) {
    return { accepted: false, reason: "revoked" }
  }

  if (options.revokedNonces?.has(identity.nonce) === true) {
    return { accepted: false, reason: "revoked" }
  }

  return { accepted: true, identity }
}