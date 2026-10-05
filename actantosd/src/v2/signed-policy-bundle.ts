import { z } from "zod"

import { canonicalStringify, toJsonValue } from "../hash.ts"
import { resolveIssuerKeys, type TrustedKeySource } from "./keyring.ts"
import {
  getSignatureAlgorithm,
  type SignatureAlgorithmName,
  type SigningKeyPair,
} from "./signature.ts"

/**
 * Signed policy bundle: the unit of local enforcement state in v2.
 *
 * v1 stored bundles as a database row carrying `source_hash` (SHA-256) and an `active`
 * flag. A hash detects corruption; it does not establish authenticity, because anyone who
 * can write the row can recompute the digest. A sidecar cannot distinguish an authentic
 * control-plane bundle from a forged one without a signature, so v1 state cannot support
 * the local enforcement lease required by invariant S11.
 *
 * This module adds the missing property: an asymmetric signature over a canonical
 * serialization of the bundle body.
 */

export const DATA_LABELS = [
  "PUBLIC",
  "INTERNAL",
  "CONFIDENTIAL",
  "PII",
  "SECRET",
  "CREDENTIAL",
] as const

export const dataLabelSchema = z.enum(DATA_LABELS)

export type DataLabel = z.infer<typeof dataLabelSchema>

const networkRuleSchema = z.object({
  host: z.string().min(1),
  port: z.number().int().positive().optional(),
  action: z.enum(["deny", "allow_via_egress_gateway"]),
})

const toolManifestEntrySchema = z.object({
  tool: z.string().min(1),
  grant: z.string().min(1),
})

const agentProfileSchema = z.object({
  agent_id: z.string().min(1),
  allowed_tools: z.array(z.string().min(1)),
  max_delegation_depth: z.number().int().min(0).optional(),
})

const riskProfileSchema = z.object({
  risk_level: z.enum(["low", "medium", "high"]),
  requires_effect_permit: z.array(z.string().min(1)),
})

/**
 * The signed body. Deliberately excludes the signature envelope: the signature covers
 * this object and nothing else.
 */
export const policyBundleBodySchema = z.object({
  bundle_id: z.string().min(1),
  tenant_id: z.string().min(1),
  /**
   * Monotonic integer sequence, strictly increasing per tenant. An integer rather than a
   * free-form string so rollback to a previously valid bundle is detectable, which a
   * hash and a signature alone would not catch.
   */
  version: z.number().int().positive(),
  issued_at: z.string().min(1),
  expires_at: z.string().min(1),
  policies: z.array(
    z.object({
      policy_id: z.string().min(1),
      cedar: z.string().min(1),
    }),
  ),
  agent_profile: agentProfileSchema,
  tool_manifest: z.array(toolManifestEntrySchema),
  network_rules: z.array(networkRuleSchema),
  data_clearance: dataLabelSchema,
  risk_profile: riskProfileSchema,
  trusted_issuers: z.array(z.string().min(1)).min(1),
})

export type PolicyBundleBody = z.infer<typeof policyBundleBodySchema>

export const bundleSignatureSchema = z.object({
  algorithm: z.string().min(1),
  issuer_id: z.string().min(1),
  /** base64 Ed25519 signature over the canonical body. */
  value: z.string().min(1),
})

export type BundleSignature = z.infer<typeof bundleSignatureSchema>

export const signedPolicyBundleSchema = z.object({
  body: policyBundleBodySchema,
  signature: bundleSignatureSchema,
})

export type SignedPolicyBundle = z.infer<typeof signedPolicyBundleSchema>

/**
 * Canonical bytes that get signed. Key order is fixed by `canonicalStringify`, so two
 * structurally equal bodies always produce identical bytes regardless of property order.
 */
export const canonicalBundleBytes = (body: PolicyBundleBody): Uint8Array =>
  Buffer.from(canonicalStringify(toJsonValue(body)), "utf8")

export const signPolicyBundle = (
  body: PolicyBundleBody,
  signature: BundleSignature,
  keyPair: SigningKeyPair,
): SignedPolicyBundle => {
  const algorithm = getSignatureAlgorithm(signature.algorithm as SignatureAlgorithmName)

  if (algorithm === undefined) {
    throw new Error(
      `Cannot sign policy bundle: unsupported algorithm "${signature.algorithm}"`,
    )
  }

  const value = Buffer.from(
    algorithm.sign(canonicalBundleBytes(body), keyPair.privateKeyPem),
  ).toString("base64")

  return { body, signature: { ...signature, value } }
}

export type BundleRejectionReason =
  | "malformed_bundle"
  | "unsupported_algorithm"
  | "untrusted_issuer"
  | "issuer_not_listed"
  | "invalid_signature"
  | "tenant_mismatch"
  | "expired"
  | "not_yet_valid"
  | "invalid_expiry_window"
  | "version_rollback"

export type BundleVerification =
  | { readonly accepted: true; readonly body: PolicyBundleBody }
  | { readonly accepted: false; readonly reason: BundleRejectionReason }

export type VerifyPolicyBundleOptions = {
  /** Tenant this sidecar serves. A bundle for any other tenant is refused. */
  readonly expectedTenantId: string
  /**
   * Issuer public keys the sidecar trusts, keyed by issuer id.
   *
   * Either one PEM per issuer — the historical shape, unchanged — or a keyring holding several
   * keys per issuer with validity windows, which is what makes rotation possible. See
   * `keyring.ts`.
   */
  readonly trustedIssuerKeys: TrustedKeySource
  readonly now?: Date
  /**
   * Highest version already activated for this tenant. A bundle at or below this version
   * is refused, so an attacker replaying an older but genuinely signed bundle cannot
   * reinstate revoked policy.
   */
  readonly minimumVersion?: number
}

/**
 * Verify a bundle for local enforcement.
 *
 * Order matters. The signature is checked before any claim in the body is acted on, and
 * tenant is checked before the bundle can be attributed to this sidecar. A bundle that
 * cannot be verified is refused rather than degraded.
 *
 * The issuer must be trusted *and* hold a key valid at `now`. An issuer whose only key has
 * passed its `notAfter` is reported as `untrusted_issuer`: from here that is indistinguishable
 * from an issuer that was never trusted, and a second reason meaning the same thing would only
 * give an operator a false distinction to act on.
 */
export const verifyPolicyBundle = (
  candidate: unknown,
  options: VerifyPolicyBundleOptions,
): BundleVerification => {
  const now = options.now ?? new Date()

  const parsed = signedPolicyBundleSchema.safeParse(candidate)

  if (!parsed.success) {
    return { accepted: false, reason: "malformed_bundle" }
  }

  const { body, signature } = parsed.data

  const algorithm = getSignatureAlgorithm(
    signature.algorithm as SignatureAlgorithmName,
  )

  if (algorithm === undefined) {
    return { accepted: false, reason: "unsupported_algorithm" }
  }

  const issuerKeys = resolveIssuerKeys(
    options.trustedIssuerKeys,
    signature.issuer_id,
    now,
  )

  if (issuerKeys.length === 0) {
    return { accepted: false, reason: "untrusted_issuer" }
  }

  // The bundle must name its own issuer as trusted, and the sidecar's issuer list must
  // actually contain that issuer. Both must hold; either alone is insufficient.
  if (!body.trusted_issuers.includes(signature.issuer_id)) {
    return { accepted: false, reason: "issuer_not_listed" }
  }

  const signatureBytes = Buffer.from(signature.value, "base64")

  // Every key currently valid for this issuer is tried. During a rotation there are two of them
  // and one signed this document, which is exactly the window that made rotation impossible
  // while an issuer could hold only a single key.
  const signatureValid = issuerKeys.some((key) =>
    algorithm.verify(canonicalBundleBytes(body), signatureBytes, key.publicKeyPem),
  )

  if (!signatureValid) {
    return { accepted: false, reason: "invalid_signature" }
  }

  if (body.tenant_id !== options.expectedTenantId) {
    return { accepted: false, reason: "tenant_mismatch" }
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

  if (
    options.minimumVersion !== undefined &&
    body.version <= options.minimumVersion
  ) {
    return { accepted: false, reason: "version_rollback" }
  }

  return { accepted: true, body }
}