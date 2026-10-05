import { z } from "zod"

import { canonicalStringify, toJsonValue } from "../hash.ts"
import {
  getSignatureAlgorithm,
  type SignatureAlgorithmName,
} from "./signature.ts"

/**
 * Delegation (invariants S5 and S6).
 *
 * S6: delegation may narrow authority but never increase it.
 * S5: agent-to-agent trust is never implicitly transitive.
 *
 * Both are enforced here structurally, before any policy evaluation. A delegated scope that
 * cannot be *proven* to be a subset of the delegator's scope is rejected, never rounded
 * up to "probably fine".
 */

export const GRANT_SCHEME = "grant:"

/** The full URI prefix, including the authority marker. */
const GRANT_URI_PREFIX = "grant://"

export type CapabilityGrant = {
  readonly provider: string
  /** Path segments after the provider. `*` matches one segment, `**` matches the rest. */
  readonly segments: readonly string[]
}

export const parseGrant = (uri: string): CapabilityGrant | undefined => {
  if (!uri.startsWith(GRANT_URI_PREFIX)) {
    return undefined
  }

  const [provider, ...segments] = uri.slice(GRANT_URI_PREFIX.length).split("/")

  if (provider === undefined || provider.length === 0) {
    return undefined
  }

  return { provider, segments }
}

export const formatGrant = (grant: CapabilityGrant): string =>
  `${GRANT_SCHEME}${grant.provider}/${grant.segments.join("/")}`

/**
 * True when every capability matching `child` also matches `parent`.
 *
 * This is the sound direction: we require positive proof of narrowing. Where proof is not
 * obvious — notably a child `**` under a literal parent segment — the answer is `false`,
 * because assuming permissiveness there is exactly the widening bug S6 forbids.
 */
export const grantSubsumes = (
  parent: CapabilityGrant,
  child: CapabilityGrant,
): boolean => {
  if (parent.provider !== child.provider) {
    return false
  }

  const parentSegments = parent.segments
  const childSegments = child.segments

  for (let index = 0; index < parentSegments.length; index += 1) {
    const parentSegment = parentSegments[index] as string

    // `**` absorbs whatever remains of the child.
    if (parentSegment === "**") {
      return true
    }

    // Parent ran out but the child has more depth. Only `**` could cover this, and it
    // would have been caught above.
    if (index >= childSegments.length) {
      return false
    }

    const childSegment = childSegments[index] as string

    // A child `**` matches arbitrary depth. Only a parent `**` (handled above) covers
    // that, so a child `**` under a parent `*` or a literal is a widening, not a narrowing.
    if (childSegment === "**") {
      return false
    }

    // A parent `*` covers exactly one child segment, whatever that segment is.
    if (parentSegment === "*") {
      continue
    }

    // The parent is a literal here. A child `*` cannot be proven to be covered by it.
    if (childSegment === "*") {
      return false
    }

    // Both segments are literals, so they must actually be equal. Comparing wildcards only
    // would let `.../issues/read` appear to cover `.../pull-request/merge`.
    if (parentSegment !== childSegment) {
      return false
    }
  }

  // Child is narrower only if the parent also stops here.
  return childSegments.length <= parentSegments.length
}

/** True when every grant in `child` is covered by some grant in `parent`. */
export const scopeIsNarrowerThan = (
  child: readonly string[],
  parent: readonly string[],
): boolean => {
  const parsedParent = parent
    .map(parseGrant)
    .filter((grant): grant is CapabilityGrant => grant !== undefined)

  // An unparseable parent pattern cannot be used to justify authority.
  if (parsedParent.length !== parent.length) {
    return false
  }

  return child.every((childUri) => {
    const parsedChild = parseGrant(childUri)

    if (parsedChild === undefined) {
      return false
    }

    return parsedParent.some((parentGrant) =>
      grantSubsumes(parentGrant, parsedChild),
    )
  })
}

export type DelegationScopeViolation =
  | "unparseable_scope"
  | "scope_widened"
  | "root_scope_exceeded"
  | "depth_exceeded"
  | "self_delegation"
  | "tenant_mismatch"
  | "expired"
  | "invalid_signature"
  | "malformed"

export type DelegationLink = {
  readonly delegation_id: string
  readonly tenant_id: string
  readonly delegator_spiffe_id: string
  readonly delegatee_spiffe_id: string
  readonly scope: string[]
  readonly depth: number
  readonly issued_at: string
  readonly expires_at: string
}

export const delegationLinkSchema = z.object({
  delegation_id: z.string().min(1),
  tenant_id: z.string().min(1),
  delegator_spiffe_id: z.string().min(1),
  delegatee_spiffe_id: z.string().min(1),
  scope: z.array(z.string().min(1)).min(1),
  depth: z.number().int().min(1),
  issued_at: z.string().min(1),
  expires_at: z.string().min(1),
  signature: z.object({
    algorithm: z.string().min(1),
    issuer_id: z.string().min(1),
    value: z.string().min(1),
  }),
})

export const signedDelegationLinkSchema = z.object({
  link: delegationLinkSchema,
})

export type SignedDelegationLink = z.infer<typeof signedDelegationLinkSchema>

export const signDelegationLink = (
  link: DelegationLink,
  signature: SignedDelegationLink["link"]["signature"],
  keyPair: { privateKeyPem: string },
): SignedDelegationLink => {
  const algorithm = getSignatureAlgorithm(
    signature.algorithm as SignatureAlgorithmName,
  )

  if (algorithm === undefined) {
    throw new Error(
      `Cannot sign delegation: unsupported algorithm "${signature.algorithm}"`,
    )
  }

  const payload = Buffer.from(canonicalStringify(toJsonValue(link)), "utf8")

  return {
    link: {
      ...link,
      signature: {
        ...signature,
        value: Buffer.from(
          algorithm.sign(payload, keyPair.privateKeyPem),
        ).toString("base64"),
      },
    },
  }
}

export const DEFAULT_MAX_DELEGATION_DEPTH = 3

export type ResolveDelegationOptions = {
  readonly tenantId: string
  /** Authority the root delegator holds, from the policy bundle. */
  readonly rootScope: readonly string[]
  readonly maxDepth?: number
  readonly now?: Date
  readonly trustedIssuerKeys: ReadonlyMap<string, string>
}

export type DelegationResolution =
  | {
      readonly accepted: true
      readonly effectiveScope: readonly string[]
      readonly delegateeSpiffeId: string
    }
  | { readonly accepted: false; readonly reason: DelegationScopeViolation }

/**
 * Resolve a delegation chain into an effective scope.
 *
 * `chain` is ordered root-first: `chain[0]` is the original delegator delegating to the
 * next agent, and the last element is the delegation that reaches the current caller.
 *
 * Non-transitivity (S5) is enforced by re-checking the *final* scope against the root
 * scope on every hop, rather than trusting that each hop only narrowed. A middle agent that
 * legitimately delegates to C still cannot make C's authority exceed the root's.
 */
export const resolveDelegation = (
  chain: readonly unknown[],
  options: ResolveDelegationOptions,
): DelegationResolution => {
  const now = options.now ?? new Date()
  const maxDepth = options.maxDepth ?? DEFAULT_MAX_DELEGATION_DEPTH

  if (chain.length === 0) {
    return { accepted: false, reason: "malformed" }
  }

  const links: DelegationLink[] = []

  for (const entry of chain) {
    const parsed = signedDelegationLinkSchema.safeParse(entry)

    if (!parsed.success) {
      return { accepted: false, reason: "malformed" }
    }

    const { link } = parsed.data
    const algorithm = getSignatureAlgorithm(
      link.signature.algorithm as SignatureAlgorithmName,
    )

    if (algorithm === undefined) {
      return { accepted: false, reason: "malformed" }
    }

    const issuerKey = options.trustedIssuerKeys.get(link.signature.issuer_id)

    if (issuerKey === undefined) {
      return { accepted: false, reason: "invalid_signature" }
    }

    // The signature is nested inside the signed object, so it must be excluded from the
    // payload. At signing time the link had no signature field; including it here would
    // hash a different payload and reject every valid delegation.
    const { signature, ...linkWithoutSignature } = link

    const payload = Buffer.from(
      canonicalStringify(toJsonValue(linkWithoutSignature)),
      "utf8",
    )

    if (
      !algorithm.verify(
        payload,
        Buffer.from(link.signature.value, "base64"),
        issuerKey,
      )
    ) {
      return { accepted: false, reason: "invalid_signature" }
    }

    if (link.tenant_id !== options.tenantId) {
      return { accepted: false, reason: "tenant_mismatch" }
    }

    const expiresAt = Date.parse(link.expires_at)

    if (Number.isNaN(expiresAt) || now.getTime() >= expiresAt) {
      return { accepted: false, reason: "expired" }
    }

    if (link.delegator_spiffe_id === link.delegatee_spiffe_id) {
      return { accepted: false, reason: "self_delegation" }
    }

    links.push(link)
  }

  // Each hop must hand over to the next hop's delegator, otherwise the chain is not a
  // chain and non-transitivity cannot be reasoned about.
  for (let index = 0; index < links.length - 1; index += 1) {
    const current = links[index] as DelegationLink
    const next = links[index + 1] as DelegationLink

    if (current.delegatee_spiffe_id !== next.delegator_spiffe_id) {
      return { accepted: false, reason: "malformed" }
    }
  }

  const finalLink = links[links.length - 1] as DelegationLink

  if (finalLink.depth > maxDepth || finalLink.depth !== links.length) {
    return { accepted: false, reason: "depth_exceeded" }
  }

  for (const link of links) {
    if (!scopeIsNarrowerThan(link.scope, link.scope)) {
      return { accepted: false, reason: "unparseable_scope" }
    }
  }

  // The decisive check: the authority the callee ends up with must still fit inside the
  // authority the root delegator started with.
  if (!scopeIsNarrowerThan(finalLink.scope, options.rootScope)) {
    return { accepted: false, reason: "root_scope_exceeded" }
  }

  // Every intermediate hop must also stay inside the root, so a widening at any depth is
  // caught even if a later hop narrows it back.
  for (const link of links) {
    if (!scopeIsNarrowerThan(link.scope, options.rootScope)) {
      return { accepted: false, reason: "scope_widened" }
    }
  }

  return {
    accepted: true,
    effectiveScope: finalLink.scope,
    delegateeSpiffeId: finalLink.delegatee_spiffe_id,
  }
}