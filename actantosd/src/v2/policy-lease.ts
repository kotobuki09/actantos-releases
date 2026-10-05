import { resolveIssuerKeys, type TrustedKeySource } from "./keyring.ts"
import {
  verifyPolicyBundle,
  type PolicyBundleBody,
  type SignedPolicyBundle,
} from "./signed-policy-bundle.ts"

/**
 * Policy lease (invariant S11).
 *
 * The sidecar keeps the last validly signed policy bundle so it can keep enforcing while
 * the control plane is unreachable. The lease is not a licence to invent: it carries only
 * what the control plane already signed, and it expires. When it expires, or when no valid
 * bundle has ever been accepted, enforcement fails closed (invariant S12).
 */

export type LeaseState =
  | {
      readonly kind: "active"
      readonly body: PolicyBundleBody
      /**
       * The trusted key that signed the bundle currently being enforced.
       *
       * Reported rather than acted on. An active lease keeps enforcing until it expires even if
       * every one of its issuer's keys is later withdrawn — refusing mid-lease would let anyone
       * who can push a key update deny service to a sidecar that is otherwise enforcing
       * correctly, which is a stronger attack than the one key withdrawal prevents. Expiry is
       * the bound, and that is a property of the signed body rather than of the keyring.
       *
       * It exists so a rotation is *observable*: "policy v9 activated under key 3f2a" is a
       * statement an operator can act on, where before there was no way to tell a rotation from
       * a forgery because both surfaced as `invalid_signature` under one issuer id.
       */
      readonly signingKeyId: string | undefined
    }
  | { readonly kind: "expired" }
  | { readonly kind: "empty" }

export class PolicyLease {
  readonly #tenantId: string
  #trustedIssuerKeys: TrustedKeySource
  #body: PolicyBundleBody | undefined
  #signingKeyId: string | undefined
  #highestActivatedVersion = 0

  constructor(options: {
    readonly tenantId: string
    readonly trustedIssuerKeys: TrustedKeySource
  }) {
    this.#tenantId = options.tenantId
    this.#trustedIssuerKeys = options.trustedIssuerKeys
  }

  /**
   * Replace the trusted keys.
   *
   * The only way an issuer's key rotation takes effect on a running sidecar. It is deliberately
   * not a constructor-only concern: before this, swapping the map meant constructing a new lease,
   * which reset the anti-rollback floor and re-opened the replay of an older signed bundle.
   *
   * An activated lease is *not* torn down here. See `LeaseState.signingKeyId` for why.
   */
  setTrustedKeys(trustedIssuerKeys: TrustedKeySource): void {
    this.#trustedIssuerKeys = trustedIssuerKeys
  }

  /**
   * Offer a bundle to the lease.
   *
   * An unverifiable bundle is refused and the previous bundle is left in place. A refusal
   * never clears a still-valid lease, and an accepted bundle never lowers the activated
   * version.
   */
  offer(candidate: unknown, now: Date = new Date()): { readonly accepted: boolean; readonly reason?: string } {
    const result = verifyPolicyBundle(candidate, {
      expectedTenantId: this.#tenantId,
      trustedIssuerKeys: this.#trustedIssuerKeys,
      minimumVersion: this.#highestActivatedVersion,
      now,
    })

    if (!result.accepted) {
      return { accepted: false, reason: result.reason }
    }

    this.#body = result.body
    this.#signingKeyId = this.#keyIdFor(candidate, now)
    this.#highestActivatedVersion = Math.max(
      this.#highestActivatedVersion,
      result.body.version,
    )

    return { accepted: true }
  }

  /**
   * Which trusted key signed an already-verified document, for reporting only.
   *
   * The document is known good at this point, so this re-runs the same candidate resolution the
   * verifier used and reads off the first key that checks out. It cannot change the outcome.
   */
  #keyIdFor(candidate: unknown, now: Date): string | undefined {
    const signed = candidate as {
      readonly signature?: { readonly issuer_id?: unknown }
    } | null
    const issuerId = signed?.signature?.issuer_id

    if (typeof issuerId !== "string") return undefined

    const keys = resolveIssuerKeys(this.#trustedIssuerKeys, issuerId, now)
    return keys[0]?.keyId
  }

  state(now: Date = new Date()): LeaseState {
    if (this.#body === undefined) {
      return { kind: "empty" }
    }

    if (now.getTime() >= Date.parse(this.#body.expires_at)) {
      return { kind: "expired" }
    }

    return { kind: "active", body: this.#body, signingKeyId: this.#signingKeyId }
  }

  get activatedVersion(): number {
    return this.#highestActivatedVersion
  }

  /** Grants and tools the currently valid policy allows, or empty when not enforceable. */
  currentProfile(now: Date = new Date()): {
    grants: readonly string[]
    tools: readonly string[]
    dataClearance: string
    networkHosts: readonly string[]
    bundle: PolicyBundleBody | undefined
  } {
    const state = this.state(now)

    if (state.kind !== "active") {
      return {
        grants: [],
        tools: [],
        dataClearance: "PUBLIC",
        networkHosts: [],
        bundle: undefined,
      }
    }

    return {
      grants: state.body.tool_manifest.map((entry) => entry.grant),
      tools: state.body.agent_profile.allowed_tools,
      dataClearance: state.body.data_clearance,
      networkHosts: state.body.network_rules
        .filter((rule) => rule.action === "allow_via_egress_gateway")
        .map((rule) => rule.host),
      bundle: state.body,
    }
  }
}

export type SignedBundleOffer = SignedPolicyBundle