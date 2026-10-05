import { parseGrant, scopeIsNarrowerThan, type CapabilityGrant } from "./delegation.ts"
import { EvidenceChain } from "./evidence.ts"
import { verifyWorkloadIdentity } from "./workload-identity.ts"

/**
 * Secretless capability broker (invariant S1).
 *
 * The agent holds grants, never credentials. The broker authenticates the calling
 * workload, checks scope, obtains a short-lived downstream credential if the provider
 * needs one, performs the operation, destroys the credential, and returns only the
 * result.
 *
 * The structural guarantee is `assertNoCredentialsInResult`: a provider that tries to
 * return a token to the agent is rejected at the boundary rather than trusted to behave.
 */

const CREDENTIAL_KEY = /pass|secret|token|api[_-]?key|private[_-]?key|authorization|credential|bearer|session[_-]?key/i

export type DownstreamCredential = {
  readonly value: string
  readonly expiresAt: Date
  /**
   * An opaque, non-secret handle the credential provider can use to release the exact
   * external resource it created — a Vault lease id, an AWS session name.
   *
   * This exists because `destroy()` is called with a credential, and a provider holding
   * only one slot for "the thing to release" cannot tell two concurrent grants apart. It
   * must never contain secret material: it is carried alongside a credential, and a handle
   * that leaked would be evidence of the credential's identity.
   */
  readonly handle?: string | undefined
}

/**
 * Who is asking for a credential.
 *
 * `obtain()` used to receive only the grant, so a provider could not bind the credential
 * it minted to the agent that asked. An AWS session therefore had to be named from a
 * constant, which removed the caller's identity from CloudTrail — the one place the audit
 * trail records who caused an effect. The broker has already authenticated the caller at
 * this point, so passing the verified identity down is not a new trust decision; it is the
 * existing one being made available to the provider.
 */
export type CredentialRequestContext = {
  readonly tenantId: string
  readonly agentSpiffeId: string
  readonly at: Date
}

export interface CredentialProvider {
  readonly id: string
  obtain(
    grant: CapabilityGrant,
    context: CredentialRequestContext,
  ): Promise<DownstreamCredential>
  /** Release the material. Called in a `finally` so a failed effect cannot leak one. */
  destroy(credential: DownstreamCredential): Promise<void>
}

export type CapabilityExecuteArgs = {
  readonly grant: CapabilityGrant
  readonly grantUri: string
  readonly args: Readonly<Record<string, unknown>>
  readonly tenantId: string
  readonly agentSpiffeId: string
  /**
   * Present only when the provider declared it needs one. The broker supplies it; the
   * agent never sees it and cannot influence it.
   */
  readonly credential?: DownstreamCredential | undefined
}

export interface CapabilityProvider {
  readonly provider: string
  supports(grant: CapabilityGrant): boolean
  /** True when this provider needs a downstream credential to operate. */
  readonly requiresCredential: boolean
  execute(args: CapabilityExecuteArgs): Promise<unknown>
}

export type CredentialLeakError = Error & {
  readonly path: string
}

const leakError = (path: string, what: string): CredentialLeakError => {
  const error = new Error(
    `Capability provider returned ${what} at "${path}". Refusing to pass it to the agent.`,
  ) as CredentialLeakError
  error.name = "CredentialLeakError"
  return Object.assign(error, { path })
}

/**
 * Recursively reject credential-shaped fields in a provider result.
 *
 * This is the S1 enforcement point at the broker boundary. Deny by default: an unexpected
 * shape is treated as a leak rather than assumed safe.
 */
export const assertNoCredentialsInResult = (value: unknown, path = "result"): void => {
  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      assertNoCredentialsInResult(item, `${path}[${index}]`)
    })
    return
  }

  if (value !== null && typeof value === "object") {
    for (const [key, nested] of Object.entries(value)) {
      if (CREDENTIAL_KEY.test(key)) {
        throw leakError(`${path}.${key}`, "a credential-shaped field")
      }

      assertNoCredentialsInResult(nested, `${path}.${key}`)
    }
  }
}

/**
 * The distinct secrets inside a credential.
 *
 * A provider that assembles a JSON blob — as the STS and database providers both do —
 * hands the broker one string, but the secret is the `secretAccessKey` inside it. Matching
 * only the whole blob would miss a provider that returns the component, and matching only
 * components would miss a provider that returns a raw token, so both are returned.
 *
 * Fragments shorter than the floor are dropped. Without a floor, a credential component
 * like a username or a scope name would match unrelated text in an ordinary API response
 * and refuse legitimate work, which is how a security control gets switched off.
 */
const MARKER_FLOOR = 8

export const credentialMarkers = (credential: string): readonly string[] => {
  const markers = new Set<string>()
  const add = (candidate: unknown): void => {
    if (typeof candidate === "string" && candidate.trim().length >= MARKER_FLOOR) {
      markers.add(candidate)
    }
  }

  add(credential)

  // A JSON credential is only treated as such if every value in it is a string. Anything
  // else is opaque material the broker does not attempt to take apart.
  try {
    const parsed: unknown = JSON.parse(credential)
    if (parsed !== null && typeof parsed === "object" && !Array.isArray(parsed)) {
      for (const nested of Object.values(parsed as Record<string, unknown>)) {
        add(nested)
      }
    }
  } catch {
    // Not JSON. The whole value is the secret, and it was already added.
  }

  return [...markers]
}

/**
 * Reject a result that echoes the credential the broker is holding.
 *
 * The key-name check above is necessary and not sufficient. A provider under
 * misconfiguration or compromise can return the material it was handed under any key it
 * likes — `{ data: "<token>" }` passes a key-name check cleanly. Because the broker already
 * knows the exact value it issued, it can check for that value instead of inferring from
 * the shape, which is a stronger statement than "no field is named suspiciously".
 *
 * Keys are checked as well as values: a provider that renames the field to the secret is
 * leaking just as surely as one that returns it under a neutral name.
 */
export const assertCredentialNotEchoed = (
  value: unknown,
  markers: readonly string[],
  path = "result",
): void => {
  if (markers.length === 0) return

  if (typeof value === "string") {
    for (const marker of markers) {
      if (value.includes(marker)) {
        throw leakError(path, "the credential the broker issued")
      }
    }
    return
  }

  if (Array.isArray(value)) {
    value.forEach((item, index) => {
      assertCredentialNotEchoed(item, markers, `${path}[${index}]`)
    })
    return
  }

  if (value !== null && typeof value === "object") {
    for (const [key, nested] of Object.entries(value)) {
      assertCredentialNotEchoed(key, markers, `${path}.${key}` as string)
      assertCredentialNotEchoed(nested, markers, `${path}.${key}`)
    }
  }
}

export type BrokerRejectionReason =
  | "invalid_identity"
  | "identity_denied"
  | "unknown_grant"
  | "grant_not_in_scope"
  | "credential_unavailable"
  | "provider_failed"
  | "credential_leak"

export type BrokerOutcome =
  | { readonly granted: true; readonly result: unknown }
  | {
      readonly granted: false
      readonly reason: BrokerRejectionReason
      readonly detail?: string
    }

export type BrokerRequest = {
  readonly identityToken: unknown
  readonly grantUri: string
  readonly args: Readonly<Record<string, unknown>>
}

export class CapabilityBroker {
  readonly #options: {
    readonly tenantId: string
    readonly trustedIssuerKeys: ReadonlyMap<string, string>
    readonly evidenceChain: EvidenceChain
    readonly providers: readonly CapabilityProvider[]
    readonly credentialProviders: ReadonlyMap<string, CredentialProvider>
    readonly revokedAgentIds?: ReadonlySet<string> | undefined
    readonly now?: (() => Date) | undefined
  }

  constructor(options: {
    readonly tenantId: string
    readonly trustedIssuerKeys: ReadonlyMap<string, string>
    readonly evidenceChain: EvidenceChain
    readonly providers: readonly CapabilityProvider[]
    readonly credentialProviders?: ReadonlyMap<string, CredentialProvider> | undefined
    readonly revokedAgentIds?: ReadonlySet<string> | undefined
    readonly now?: (() => Date) | undefined
  }) {
    this.#options = {
      ...options,
      credentialProviders: options.credentialProviders ?? new Map(),
    }
  }

  async grant(request: BrokerRequest): Promise<BrokerOutcome> {
    const now = this.#options.now?.() ?? new Date()

    // 1. Authenticate the calling workload.
    const identity = verifyWorkloadIdentity(request.identityToken, {
      trustedIssuerKeys: this.#options.trustedIssuerKeys,
      expectedTenantId: this.#options.tenantId,
      revokedAgentIds: this.#options.revokedAgentIds,
      now,
    })

    if (!identity.accepted) {
      this.#options.evidenceChain.append("security_violation", {
        reason: identity.reason,
        grant: request.grantUri,
        occurred_at: now.toISOString(),
      })

      return { granted: false, reason: "identity_denied" }
    }

    const agentSpiffeId = identity.identity.spiffe_id

    // 2. Resolve the grant and find a provider.
    const grant = parseGrant(request.grantUri)

    if (grant === undefined) {
      return { granted: false, reason: "unknown_grant" }
    }

    const provider = this.#options.providers.find((candidate) =>
      candidate.supports(grant as CapabilityGrant),
    )

    if (provider === undefined) {
      return { granted: false, reason: "unknown_grant" }
    }

    // 3. Check the grant is inside the authority in force for this agent. The authority
    //    comes from the agent profile in the signed policy bundle, not from the request.
    const effectiveScope = this.#authorityFor(agentSpiffeId)

    if (
      effectiveScope === undefined ||
      !scopeIsNarrowerThan([request.grantUri], effectiveScope)
    ) {
      this.#options.evidenceChain.append("security_violation", {
        reason: "grant_not_in_scope",
        grant: request.grantUri,
        agent: agentSpiffeId,
        occurred_at: now.toISOString(),
      })

      return { granted: false, reason: "grant_not_in_scope" }
    }

    this.#options.evidenceChain.append("data_access", {
      agent: agentSpiffeId,
      grant: request.grantUri,
      occurred_at: now.toISOString(),
    })

    // 4-6. Obtain a short-lived credential, perform the operation, destroy the credential.
    let credential: DownstreamCredential | undefined

    if (provider.requiresCredential) {
      const credentialProvider =
        this.#options.credentialProviders.get(provider.provider)

      if (credentialProvider === undefined) {
        return { granted: false, reason: "credential_unavailable" }
      }

      try {
        credential = await credentialProvider.obtain(grant, {
          tenantId: this.#options.tenantId,
          agentSpiffeId,
          at: now,
        })
      } catch {
        return { granted: false, reason: "credential_unavailable" }
      }

      // An already-expired or undatable credential is refused rather than handed on. A
      // provider that returned an invalid `expiresAt` has failed closed, not open: the
      // agent gets nothing rather than an unbounded credential.
      if (
        credential === undefined ||
        !Number.isFinite(credential.expiresAt.getTime()) ||
        now.getTime() >= credential.expiresAt.getTime()
      ) {
        if (credential !== undefined) {
          await this.#options.credentialProviders
            .get(provider.provider)
            ?.destroy(credential)
        }
        return { granted: false, reason: "credential_unavailable" }
      }
    }

    // Secrets the broker is holding, used to detect a provider echoing them back below.
    const markers = credential === undefined ? [] : credentialMarkers(credential.value)

    try {
      const result = await provider.execute({
        grant,
        grantUri: request.grantUri,
        args: request.args,
        tenantId: this.#options.tenantId,
        agentSpiffeId,
        credential,
      })

      // 7. Refuse to pass credential-shaped data to the agent, whatever the provider did.
      //    Two independent checks: the field *names* look like credentials, or the value
      //    the broker itself issued reappears anywhere in the result.
      try {
        assertNoCredentialsInResult(result)
        assertCredentialNotEchoed(result, markers)
      } catch (error) {
        this.#options.evidenceChain.append("security_violation", {
          reason: "credential_leak",
          grant: request.grantUri,
          detail: error instanceof Error ? error.message : "unknown",
          occurred_at: now.toISOString(),
        })

        return { granted: false, reason: "credential_leak" }
      }

      return { granted: true, result }
    } catch {
      return { granted: false, reason: "provider_failed" }
    } finally {
      // 6. Always release, including when execution or the leak check threw.
      if (credential !== undefined) {
        const credentialProvider =
          this.#options.credentialProviders.get(provider.provider)

        await credentialProvider?.destroy(credential)
      }
    }
  }

  /**
   * Authority for an agent. Supplied by the signed policy bundle in a real deployment;
   * injected here so the broker never reads policy from an unauthenticated source.
   */
  #authorityFor(agentSpiffeId: string): readonly string[] | undefined {
    return this.#authorityResolver?.(agentSpiffeId)
  }

  #authorityResolver: ((agentSpiffeId: string) => readonly string[] | undefined) | undefined

  setAuthorityResolver(
    resolver: (agentSpiffeId: string) => readonly string[] | undefined,
  ): void {
    this.#authorityResolver = resolver
  }
}