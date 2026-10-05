import { scopeIsNarrowerThan } from "./delegation.ts"
import { PolicyLease } from "./policy-lease.ts"
import {
  decodeSidecarRequest,
  type DenyReason,
  type SecurityContext,
  type SidecarDecision,
  type SidecarRequest,
} from "./sidecar-protocol.ts"
import { evaluateIfc, type SinkType } from "./ifc.ts"
import { checkNetworkTargets } from "./network-target-guard.ts"
import { verifyIdentityToken } from "./workload-identity-provider.ts"
import type { RevocationStore } from "./revocation-snapshot.ts"
import { DATA_LABELS, type DataLabel } from "./signed-policy-bundle.ts"

/**
 * Local Actant sidecar (Phase 1).
 *
 * The sidecar is the local security boundary. It answers protocol requests from the
 * protected agent using the signed policy lease, with no round-trip to the control plane.
 *
 * Two structural rules matter more than anything else here:
 *
 * 1. No valid lease means no external effect. The lease is checked before any other
 *    evaluation, so an unreachable control plane never turns into an open boundary.
 * 2. The agent supplies no value that is trusted. Grants, tools and labels are compared
 *    against the signed bundle, which only the control plane can write.
 */

export type DecisionTelemetry = {
  readonly request_id: string
  readonly request_type: string
  readonly allowed: boolean
  readonly reason: string
  readonly at: string
}

export type SidecarOptions = {
  readonly tenantId: string
  readonly trustedIssuerKeys: ReadonlyMap<string, string>
  /**
   * SPIFFE trust domain keys, when this sidecar accepts JWT-SVIDs as workload identities.
   *
   * Absent — the default — means only a locally-signed envelope is accepted, and a JWT-SVID is
   * refused rather than reinterpreted. This is what a deployment with no SPIRE wants.
   *
   * The sidecar verifies the SVID itself. It does not ask the control plane whether the SVID is
   * good, because that would put the control plane back on the request path and reintroduce the
   * round trip that the policy lease exists to avoid (S11).
   */
  readonly spire?: {
    readonly keys: readonly import("./workload-identity-provider.ts").Jwk[]
    readonly trustDomain: string
    readonly audience?: string | undefined
  } | undefined
  readonly lease: PolicyLease
  /**
   * Signed revocation snapshots, consulted on every decision (phase I).
   *
   * Optional so a deployment without a revocation feed keeps working, and it is the empty store
   * in that case — which revokes nothing rather than refusing everything. When present, entries are
   * read from a signature the sidecar verified itself, so a compromised caller cannot clear them
   * by passing an empty set.
   */
  readonly revocations?: RevocationStore | undefined
  /**
   * Authority in force for an agent. In production this is the delegation resolution
   * result; injected so the sidecar stays free of transport concerns.
   */
  readonly authorityFor: (spiffeId: string) => readonly string[]
  readonly permitIssuer?: (args: {
    action: { tool: string; resource: string; args: Record<string, unknown> }
    spiffeId: string
    executionId: string
    dataLabels: DataLabel[]
    policyBundleDigest: string
  }) => unknown
  readonly now?: () => Date
}

const deny = (
  requestId: string,
  reason: DenyReason,
  detail?: string,
): SidecarDecision => ({
  allowed: false,
  request_id: requestId,
  reason,
  ...(detail === undefined ? {} : { detail }),
})

export class ActantSidecar {
  readonly #options: SidecarOptions
  readonly #telemetry: DecisionTelemetry[] = []

  constructor(options: SidecarOptions) {
    this.#options = options
  }

  get telemetry(): readonly DecisionTelemetry[] {
    return this.#telemetry
  }

  #record(
    requestId: string,
    requestType: string,
    decision: SidecarDecision,
    now: Date,
  ): SidecarDecision {
    this.#telemetry.push({
      request_id: requestId,
      request_type: requestType,
      allowed: decision.allowed,
      reason: decision.allowed ? decision.reason : decision.reason,
      at: now.toISOString(),
    })

    return decision
  }

  /** Decode and handle one protocol request. */
  handle(raw: unknown): SidecarDecision {
    const now = this.#options.now?.() ?? new Date()
    const decoded = decodeSidecarRequest(raw)

    if ("unsupported" in decoded) {
      return deny("unknown", decoded.reason)
    }

    return this.#handleDecoded(decoded, now)
  }

  #handleDecoded(request: SidecarRequest, now: Date): SidecarDecision {
    const state = this.#options.lease.state(now)

    // Fail closed before anything else when policy is not enforceable.
    if (state.kind === "empty") {
      return this.#record(request.request_id, request.request_type, deny(request.request_id, "no_valid_policy"), now)
    }

    if (state.kind === "expired") {
      return this.#record(request.request_id, request.request_type, deny(request.request_id, "policy_expired"), now)
    }

    const bundle = state.body

    const identity = verifyIdentityToken(request.identity_token, {
      trustedIssuerKeys: this.#options.trustedIssuerKeys,
      expectedTenantId: this.#options.tenantId,
      spire: this.#options.spire,
      now,
    })

    if (!identity.accepted) {
      return this.#record(request.request_id, request.request_type, deny(request.request_id, "identity_invalid"), now)
    }

    const spiffeId = identity.identity.spiffe_id

    // Revocation is checked after the identity is verified and before any policy is applied. Order
    // matters in one direction only: a revoked agent must not be able to act even if its policy is
    // valid, and an unverifiable identity must never reach the revocation lookup, because a lookup
    // keyed on unverified input is a lookup an attacker chooses.
    const revoked =
      this.#options.revocations?.isAgentRevoked(identity.identity.agent_id, now).revoked === true ||
      this.#options.revocations?.isNonceRevoked(identity.identity.nonce, now).revoked === true

    if (revoked) {
      return this.#record(request.request_id, request.request_type, deny(request.request_id, "identity_revoked"), now)
    }

    const authority = this.#options.authorityFor(spiffeId)

    switch (request.request_type) {
      case "GetSecurityContext": {
        const context: SecurityContext = {
          tenant_id: bundle.tenant_id,
          agent_id: identity.identity.agent_id,
          spiffe_id: spiffeId,
          policy_bundle_id: bundle.bundle_id,
          policy_bundle_version: bundle.version,
          policy_expires_at: bundle.expires_at,
          data_clearance: bundle.data_clearance,
          grants: authority,
        }

        return this.#record(
          request.request_id,
          request.request_type,
          { allowed: true, request_id: request.request_id, reason: "context_returned" },
          now,
        )
      }

      case "ResolveGrant": {
        if (!scopeIsNarrowerThan([request.grant_uri], authority)) {
          return this.#record(
            request.request_id,
            request.request_type,
            deny(request.request_id, "not_in_grant_scope"),
            now,
          )
        }

        return this.#record(
          request.request_id,
          request.request_type,
          { allowed: true, request_id: request.request_id, reason: "grant_resolved" },
          now,
        )
      }

      case "CheckMessage": {
        const labels = request.labels.filter((label): label is DataLabel =>
          (DATA_LABELS as readonly string[]).includes(label),
        )

        const ifc = evaluateIfc(labels, "another_agent")

        if (!ifc.allowed) {
          return this.#record(
            request.request_id,
            request.request_type,
            deny(request.request_id, "ifc_violation"),
            now,
          )
        }

        return this.#record(
          request.request_id,
          request.request_type,
          { allowed: true, request_id: request.request_id, reason: "message_allowed" },
          now,
        )
      }

      case "CheckAction":
        return this.#record(
          request.request_id,
          request.request_type,
          this.#checkAction(request, bundle, authority),
          now,
        )

      case "RequestEffectPermit":
        return this.#record(
          request.request_id,
          request.request_type,
          this.#requestPermit(request, bundle, spiffeId, now),
          now,
        )

      case "CommitEffect":
        return this.#record(
          request.request_id,
          request.request_type,
          { allowed: true, request_id: request.request_id, reason: "effect_committed" },
          now,
        )
    }
  }

  #checkAction(
    request: Extract<SidecarRequest, { request_type: "CheckAction" }>,
    bundle: {
      agent_profile: { allowed_tools: string[] }
      tool_manifest: readonly { tool: string; grant: string }[]
      network_rules: readonly { host: string; action: "deny" | "allow_via_egress_gateway" }[]
    },
    authority: readonly string[],
  ): SidecarDecision {
    if (!bundle.agent_profile.allowed_tools.includes(request.tool)) {
      return deny(request.request_id, "tool_not_in_manifest")
    }

    // The signed bundle states which grant a tool consumes. The delegation authority in
    // force must cover that grant; the request cannot name its own grant.
    const manifestEntry = bundle.tool_manifest.find(
      (entry) => entry.tool === request.tool,
    )

    if (manifestEntry === undefined) {
      return deny(request.request_id, "tool_not_in_manifest")
    }

    if (!scopeIsNarrowerThan([manifestEntry.grant], authority)) {
      return deny(request.request_id, "not_in_grant_scope")
    }

    // The tool being in the manifest says nothing about *where* it points. A manifest tool
    // handed an arbitrary URL, IP literal or IPv6 address is the same egress as curl, so the
    // destination is checked against the signed network rules before the action is allowed.
    const target = checkNetworkTargets(
      { resource: request.resource, args: request.args },
      { rules: bundle.network_rules },
    )

    if (!target.allowed) {
      return deny(
        request.request_id,
        "network_rule_denied",
        `target not permitted by policy: ${target.host}`,
      )
    }

    return { allowed: true, request_id: request.request_id, reason: "action_allowed" }
  }

  #requestPermit(
    request: Extract<SidecarRequest, { request_type: "RequestEffectPermit" }>,
    bundle: {
      risk_profile: { requires_effect_permit: string[] }
      network_rules: readonly { host: string; action: "deny" | "allow_via_egress_gateway" }[]
    },
    spiffeId: string,
    now: Date,
  ): SidecarDecision {
    if (!bundle.risk_profile.requires_effect_permit.includes(request.tool)) {
      return deny(request.request_id, "sidecar_policy_denied", "tool does not require a permit")
    }

    if (this.#options.permitIssuer === undefined) {
      return deny(request.request_id, "sidecar_policy_denied", "no permit issuer configured")
    }

    // Authorizing an effect is the last point before it happens, so the destination is
    // re-checked here too rather than trusting that CheckAction was called first.
    const target = checkNetworkTargets(
      { resource: request.resource, args: request.args },
      { rules: bundle.network_rules },
    )

    if (!target.allowed) {
      return deny(
        request.request_id,
        "network_rule_denied",
        `target not permitted by policy: ${target.host}`,
      )
    }

    const dataLabels = request.data_labels.filter((label): label is DataLabel =>
      (DATA_LABELS as readonly string[]).includes(label),
    )

    const ifc = evaluateIfc(dataLabels, request.sink_type as SinkType)

    if (!ifc.allowed) {
      return deny(request.request_id, "ifc_violation")
    }

    const permit = this.#options.permitIssuer({
      action: { tool: request.tool, resource: request.resource, args: request.args },
      spiffeId,
      executionId: request.request_id,
      dataLabels,
      policyBundleDigest: "policy-bundle-digest",
    })

    return {
      allowed: true,
      request_id: request.request_id,
      reason: "effect_permit_issued",
      permit,
    }
  }
}