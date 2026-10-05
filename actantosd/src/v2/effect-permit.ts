import { z } from "zod"

import { canonicalHash, canonicalStringify, toJsonValue } from "../hash.ts"
import {
  getSignatureAlgorithm,
  type SignatureAlgorithmName,
} from "./signature.ts"
import { DATA_LABELS } from "./signed-policy-bundle.ts"

/**
 * Effect permit (invariants S7, S8, S9).
 *
 * S7: a sensitive external effect requires authorization bound to the exact canonical action.
 * S8: changing the target or parameters after authorization invalidates it.
 * S9: the authorization is short-lived, single-use, nonce-bound and replay-resistant.
 *
 * The permit binds a digest of the canonical action rather than a reference to it. A
 * reference would let the caller swap the target after the fact; a digest cannot, because
 * any change to the tool, resource or arguments produces a different digest.
 */

export type CanonicalAction = {
  readonly tool: string
  readonly resource: string
  readonly args: Readonly<Record<string, unknown>>
}

/**
 * Stable digest of an action. Key order in `args` is irrelevant because the canonical
 * form sorts keys, but any change to a *value* changes the digest.
 */
export const canonicalActionDigest = (action: CanonicalAction): string =>
  canonicalHash({
    tool: action.tool,
    resource: action.resource,
    args: action.args,
  })

export const policyBundleDigest = (canonicalBundleText: string): string =>
  canonicalHash(canonicalBundleText)

export const effectPermitSchema = z.object({
  permit_id: z.string().min(1),
  /** SPIFFE id of the workload the permit is bound to. */
  principal_spiffe_id: z.string().min(1),
  tenant_id: z.string().min(1),
  execution_id: z.string().min(1),
  /** Digest over the delegation chain in force when the permit was issued. */
  delegation_digest: z.string().min(1),
  tool: z.string().min(1),
  resource: z.string().min(1),
  /** Digest of the canonical action. This is what makes S8 hold. */
  action_digest: z.string().min(1),
  /** Digest of the policy bundle that authorized the effect. */
  policy_bundle_digest: z.string().min(1),
  /** Highest data label flowing into the effect. Checked against sink clearance. */
  data_labels: z.array(z.enum(DATA_LABELS)),
  nonce: z.string().min(1),
  issued_at: z.string().min(1),
  expires_at: z.string().min(1),
  signature: z.object({
    algorithm: z.string().min(1),
    issuer_id: z.string().min(1),
    value: z.string().min(1),
  }),
})

export type EffectPermit = z.infer<typeof effectPermitSchema>

export const signEffectPermit = (
  permit: EffectPermit,
  keyPair: { privateKeyPem: string },
): EffectPermit => {
  const algorithm = getSignatureAlgorithm(
    permit.signature.algorithm as SignatureAlgorithmName,
  )

  if (algorithm === undefined) {
    throw new Error(
      `Cannot sign effect permit: unsupported algorithm "${permit.signature.algorithm}"`,
    )
  }

  const { signature, ...unsigned } = permit
  const payload = Buffer.from(
    canonicalStringify(toJsonValue(unsigned)),
    "utf8",
  )

  return {
    ...permit,
    signature: {
      ...signature,
      value: Buffer.from(algorithm.sign(payload, keyPair.privateKeyPem)).toString(
        "base64",
      ),
    },
  }
}

export type IssueEffectPermitOptions = {
  readonly principalSpiffeId: string
  readonly tenantId: string
  readonly executionId: string
  readonly delegationDigest: string
  readonly action: CanonicalAction
  readonly policyBundleDigest: string
  readonly dataLabels: EffectPermit["data_labels"]
  readonly issuedAt: Date
  /** Short-lived by construction. Defaults to 60 seconds. */
  readonly ttlMs?: number
  readonly nonce?: string
  readonly issuerId: string
  readonly keyPair: { privateKeyPem: string }
}

export const DEFAULT_PERMIT_TTL_MS = 60 * 1000

export const issueEffectPermit = (
  options: IssueEffectPermitOptions,
): EffectPermit => {
  const ttlMs = options.ttlMs ?? DEFAULT_PERMIT_TTL_MS

  return signEffectPermit(
    {
      permit_id: crypto.randomUUID(),
      principal_spiffe_id: options.principalSpiffeId,
      tenant_id: options.tenantId,
      execution_id: options.executionId,
      delegation_digest: options.delegationDigest,
      tool: options.action.tool,
      resource: options.action.resource,
      action_digest: canonicalActionDigest(options.action),
      policy_bundle_digest: options.policyBundleDigest,
      data_labels: options.dataLabels,
      nonce: options.nonce ?? crypto.randomUUID(),
      issued_at: options.issuedAt.toISOString(),
      expires_at: new Date(options.issuedAt.getTime() + ttlMs).toISOString(),
      signature: { algorithm: "ed25519", issuer_id: options.issuerId, value: "" },
    },
    options.keyPair,
  )
}

/**
 * Single-use nonce store.
 *
 * Lives in the effect gateway, never in the agent. `consume` is deliberately synchronous:
 * in a single-threaded runtime a synchronous check-and-mark cannot interleave with another
 * caller, so two concurrent uses of one permit cannot both succeed.
 */
export class NonceStore {
  readonly #consumed = new Set<string>()

  /** Returns true only for the first caller. Every later call returns false. */
  consume(nonce: string): boolean {
    if (this.#consumed.has(nonce)) {
      return false
    }

    this.#consumed.add(nonce)
    return true
  }

  isConsumed(nonce: string): boolean {
    return this.#consumed.has(nonce)
  }

  get size(): number {
    return this.#consumed.size
  }
}

export type PermitRejectionReason =
  | "malformed_permit"
  | "unsupported_algorithm"
  | "untrusted_issuer"
  | "invalid_signature"
  | "tenant_mismatch"
  | "identity_mismatch"
  | "execution_mismatch"
  | "action_mismatch"
  | "policy_mismatch"
  | "expired"
  | "not_yet_valid"
  | "already_used"
  | "revoked"

export type PermitVerification =
  | { readonly accepted: true; readonly permit: EffectPermit }
  | { readonly accepted: false; readonly reason: PermitRejectionReason }

export type VerifyEffectPermitOptions = {
  readonly trustedIssuerKeys: ReadonlyMap<string, string>
  readonly expectedTenantId: string
  readonly expectedPrincipalSpiffeId: string
  readonly expectedExecutionId: string
  /** The action the caller is about to perform. Bound and compared, not trusted. */
  readonly action: CanonicalAction
  readonly expectedPolicyBundleDigest?: string | undefined
  readonly nonces?: NonceStore | undefined
  readonly now?: Date | undefined
  readonly revokedPermitIds?: ReadonlySet<string> | undefined
  /**
   * When true the nonce is consumed as part of verification. The effect gateway sets this
   * so a permit cannot be replayed even if verification and execution are separate steps.
   */
  readonly consumeNonce?: boolean | undefined
}

/**
 * Verify a permit at the point of effect.
 *
 * Every check is performed against values the *gateway* supplies, never against values the
 * agent asserts. The agent can present a permit but cannot influence what it is compared to.
 */
export const verifyEffectPermit = (
  candidate: unknown,
  options: VerifyEffectPermitOptions,
): PermitVerification => {
  const now = options.now ?? new Date()
  const parsed = effectPermitSchema.safeParse(candidate)

  if (!parsed.success) {
    return { accepted: false, reason: "malformed_permit" }
  }

  const permit = parsed.data

  const algorithm = getSignatureAlgorithm(
    permit.signature.algorithm as SignatureAlgorithmName,
  )

  if (algorithm === undefined) {
    return { accepted: false, reason: "unsupported_algorithm" }
  }

  const issuerKey = options.trustedIssuerKeys.get(permit.signature.issuer_id)

  if (issuerKey === undefined) {
    return { accepted: false, reason: "untrusted_issuer" }
  }

  const { signature, ...unsigned } = permit
  const payload = Buffer.from(
    canonicalStringify(toJsonValue(unsigned)),
    "utf8",
  )

  if (
    !algorithm.verify(
      payload,
      Buffer.from(signature.value, "base64"),
      issuerKey,
    )
  ) {
    return { accepted: false, reason: "invalid_signature" }
  }

  if (permit.tenant_id !== options.expectedTenantId) {
    return { accepted: false, reason: "tenant_mismatch" }
  }

  if (permit.principal_spiffe_id !== options.expectedPrincipalSpiffeId) {
    return { accepted: false, reason: "identity_mismatch" }
  }

  if (permit.execution_id !== options.expectedExecutionId) {
    return { accepted: false, reason: "execution_mismatch" }
  }

  // The decisive S8 check: the permit must describe the action actually being performed.
  if (permit.action_digest !== canonicalActionDigest(options.action)) {
    return { accepted: false, reason: "action_mismatch" }
  }

  if (
    options.expectedPolicyBundleDigest !== undefined &&
    permit.policy_bundle_digest !== options.expectedPolicyBundleDigest
  ) {
    return { accepted: false, reason: "policy_mismatch" }
  }

  const issuedAt = Date.parse(permit.issued_at)
  const expiresAt = Date.parse(permit.expires_at)

  if (Number.isNaN(issuedAt) || Number.isNaN(expiresAt)) {
    return { accepted: false, reason: "malformed_permit" }
  }

  if (now.getTime() < issuedAt) {
    return { accepted: false, reason: "not_yet_valid" }
  }

  if (now.getTime() >= expiresAt) {
    return { accepted: false, reason: "expired" }
  }

  if (options.revokedPermitIds?.has(permit.permit_id) === true) {
    return { accepted: false, reason: "revoked" }
  }

  if (options.nonces !== undefined) {
    if (options.nonces.isConsumed(permit.nonce)) {
      return { accepted: false, reason: "already_used" }
    }

    if (options.consumeNonce === true && !options.nonces.consume(permit.nonce)) {
      return { accepted: false, reason: "already_used" }
    }
  }

  return { accepted: true, permit }
}