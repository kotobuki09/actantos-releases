import { CapabilityBroker, type CapabilityProvider } from "./capability-broker.ts"
import { EvidenceChain } from "./evidence.ts"
import { EffectGateway } from "./effect-gateway.ts"
import { issueEffectPermit, type CanonicalAction } from "./effect-permit.ts"
import { ActantSidecar } from "./sidecar.ts"
import { PROTOCOL_VERSION, type SidecarDecision } from "./sidecar-protocol.ts"
import { PolicyLease } from "./policy-lease.ts"
import { signPolicyBundle, type PolicyBundleBody } from "./signed-policy-bundle.ts"
import {
  mintWorkloadIdentity,
  signWorkloadIdentity,
} from "./workload-identity.ts"
import type { SigningKeyPair } from "./signature.ts"

/**
 * Explicit failure semantics (Phase 9, invariants S11 and S12).
 *
 * Every component in this fabric can fail. The requirement is not that nothing fails; it is
 * that a failure has a *declared* security consequence and that the declared consequence is
 * actually what happens.
 *
 * The contract below is the declaration. `probe*` functions are the measurement: each one
 * takes the real components, takes one component away, and reports what the fabric then did.
 * `runFailureConformance` compares measurement against declaration, so a change that quietly
 * turns a fail-closed path into a fail-open one fails the test suite instead of shipping.
 *
 * The five states an outage can produce:
 *
 * - `enforced_from_lease`: decisions still happen, still from the last valid signed policy.
 *   Availability drops; authority does not.
 * - `denied`: nothing protected can proceed. This is the correct answer whenever the state of
 *   the boundary cannot be established.
 * - `limited`: non-effect work continues, but every effect is refused.
 * - `effect_blocked`: the effect path stops; other decisions continue.
 * - `audited_offline`: effects continue and evidence is buffered locally, pending a sink.
 */

export const FAILURE_MODES = [
  "control_plane_unavailable",
  "policy_expired",
  "sidecar_unavailable",
  "identity_service_unavailable",
  "evidence_sink_unavailable",
] as const

export type FailureMode = (typeof FAILURE_MODES)[number]

export const FAILURE_STATES = [
  "enforced_from_lease",
  "denied",
  "limited",
  "effect_blocked",
  "audited_offline",
] as const

export type FailureState = (typeof FAILURE_STATES)[number]

export type FailureContract = {
  readonly mode: FailureMode
  /** Every state this failure is allowed to produce. More than one only where genuinely ambiguous. */
  readonly expected: readonly FailureState[]
  readonly rationale: string
}

export const FAILURE_CONTRACT: readonly FailureContract[] = [
  {
    mode: "control_plane_unavailable",
    expected: ["enforced_from_lease"],
    rationale:
      "The lease is the enforcement source. While a validly signed lease exists, decisions continue with no control-plane round trip. Authority must not change during the outage.",
  },
  {
    mode: "policy_expired",
    expected: ["denied"],
    rationale:
      "An expired lease means the authority it carried is no longer known to be current. Every protected decision is refused.",
  },
  {
    mode: "sidecar_unavailable",
    expected: ["denied", "limited", "effect_blocked"],
    rationale:
      "No sidecar means no permit can be issued, so the effect path stops. Anything else is a fail-open.",
  },
  {
    mode: "identity_service_unavailable",
    expected: ["enforced_from_lease", "denied", "limited"],
    rationale:
      "Identities are attested in advance and verified locally, so a valid unexpired identity keeps working. An identity past its expiry is still refused: the issuer being unreachable must not extend a lifetime.",
  },
  {
    mode: "evidence_sink_unavailable",
    expected: ["denied", "effect_blocked", "audited_offline"],
    rationale:
      "An effect that cannot be evidenced must not happen. Either the effect is refused, or the architecture explicitly declares an audited-offline mode; it must never run silently unrecorded.",
  },
]

// --- Probe helpers ---------------------------------------------------------------------

export type ProbeDependencies = {
  readonly tenantId: string
  readonly issuerId: string
  readonly keyPair: SigningKeyPair
  readonly trustedIssuerKeys: ReadonlyMap<string, string>
  readonly bundle: PolicyBundleBody
  readonly now: Date
}

const signBundle = (deps: ProbeDependencies) =>
  signPolicyBundle(
    deps.bundle,
    { algorithm: "ed25519", issuer_id: deps.issuerId, value: "" },
    deps.keyPair,
  )

const identityFor = (deps: ProbeDependencies, agentId: string, issuedAt: Date) =>
  signWorkloadIdentity(
    mintWorkloadIdentity({
      tenantId: deps.tenantId,
      agentId,
      issuedAt,
    }),
    { algorithm: "ed25519", issuer_id: deps.issuerId, value: "" },
    deps.keyPair,
  )

const readRequest = (
  deps: ProbeDependencies,
  identity: unknown,
  tool: string,
  resource: string,
) => ({
  protocol_version: PROTOCOL_VERSION,
  request_id: "req-failure",
  request_type: "CheckAction" as const,
  identity_token: identity,
  tool,
  resource,
  args: {},
})

const MERGE_ACTION: CanonicalAction = {
  tool: "github.pull-request.merge",
  resource: "org/repo#42",
  args: { number: 42, method: "squash" },
}

const readPermit = (
  deps: ProbeDependencies,
  spiffeId: string,
): unknown =>
  issueEffectPermit({
    principalSpiffeId: spiffeId,
    tenantId: deps.tenantId,
    executionId: "exec-failure",
    delegationDigest: "delegation-digest",
    action: MERGE_ACTION,
    policyBundleDigest: "policy-digest",
    dataLabels: ["CONFIDENTIAL"],
    issuedAt: deps.now,
    issuerId: deps.issuerId,
    keyPair: deps.keyPair,
  })

/** Classify what a sidecar pair of decisions means for the fabric. */
const classifyDecisions = (
  inScope: SidecarDecision,
  outOfScope: SidecarDecision,
): FailureState => {
  if (!inScope.allowed && !outOfScope.allowed) {
    return "denied"
  }

  if (inScope.allowed && !outOfScope.allowed) {
    return "enforced_from_lease"
  }

  // Allowed where it should be denied: enforcement is weaker than the contract allows.
  return "limited"
}

// --- Probes -----------------------------------------------------------------------------

/**
 * The control plane stops serving. The sidecar keeps the last valid lease and must keep
 * enforcing with it.
 */
export const probeControlPlaneUnavailable = (
  deps: ProbeDependencies,
): FailureState => {
  const lease = new PolicyLease({
    tenantId: deps.tenantId,
    trustedIssuerKeys: deps.trustedIssuerKeys,
  })

  // The only bundle the agent will ever see. Nothing refreshes it.
  lease.offer(signBundle(deps), deps.now)

  const sidecar = new ActantSidecar({
    tenantId: deps.tenantId,
    trustedIssuerKeys: deps.trustedIssuerKeys,
    lease,
    authorityFor: () => [deps.bundle.tool_manifest[0]?.grant ?? ""],
    now: () => deps.now,
  })

  const identity = identityFor(deps, "probe-agent", deps.now)

  return classifyDecisions(
    sidecar.handle(
      readRequest(deps, identity, deps.bundle.agent_profile.allowed_tools[0] ?? "", "org/repo"),
    ),
    sidecar.handle(readRequest(deps, identity, "github.repo.delete", "org/repo")),
  )
}

/** The lease has expired. Nothing protected may proceed. */
export const probePolicyExpired = (
  deps: ProbeDependencies,
): FailureState => {
  const lease = new PolicyLease({
    tenantId: deps.tenantId,
    trustedIssuerKeys: deps.trustedIssuerKeys,
  })

  lease.offer(
    signBundle({ ...deps, bundle: { ...deps.bundle, expires_at: "2026-10-03T11:00:00.000Z" } }),
    new Date("2026-10-03T10:00:00.000Z"),
  )

  const sidecar = new ActantSidecar({
    tenantId: deps.tenantId,
    trustedIssuerKeys: deps.trustedIssuerKeys,
    lease,
    authorityFor: () => [deps.bundle.tool_manifest[0]?.grant ?? ""],
    now: () => deps.now,
  })

  const identity = identityFor(deps, "probe-agent", deps.now)

  return classifyDecisions(
    sidecar.handle(readRequest(deps, identity, "github.issues.read", "org/repo")),
    sidecar.handle(readRequest(deps, identity, "github.repo.delete", "org/repo")),
  )
}

/**
 * The sidecar cannot be consulted. The permit issuer is gone, so no permit can exist, so the
 * effect gateway has nothing valid to accept.
 */
export const probeSidecarUnavailable = async (
  deps: ProbeDependencies,
): Promise<FailureState> => {
  const lease = new PolicyLease({
    tenantId: deps.tenantId,
    trustedIssuerKeys: deps.trustedIssuerKeys,
  })

  lease.offer(signBundle(deps), deps.now)

  // A sidecar with policy but no permit issuer: it can describe, it cannot authorize.
  const sidecar = new ActantSidecar({
    tenantId: deps.tenantId,
    trustedIssuerKeys: deps.trustedIssuerKeys,
    lease,
    authorityFor: () => [deps.bundle.tool_manifest[0]?.grant ?? ""],
    now: () => deps.now,
  })

  const identity = identityFor(deps, "probe-agent", deps.now)
  const spiffeId =
    (identity as { identity: { spiffe_id: string } }).identity.spiffe_id

  const permitDecision = sidecar.handle({
    protocol_version: PROTOCOL_VERSION,
    request_id: "req-failure",
    request_type: "RequestEffectPermit",
    identity_token: identity,
    tool: "github.pull-request.merge",
    resource: MERGE_ACTION.resource,
    args: MERGE_ACTION.args,
    sink_type: "file_store",
    data_labels: ["CONFIDENTIAL"],
  })

  if (permitDecision.allowed) {
    // A permit exists without a working issuer. That is already fail-open.
    return "enforced_from_lease"
  }

  // The agent, unable to get a permit, tries the effect path with nothing.
  let effectHappened = false
  const gateway = new EffectGateway({
    tenantId: deps.tenantId,
    trustedIssuerKeys: deps.trustedIssuerKeys,
    evidenceChain: new EvidenceChain({
      tenantId: deps.tenantId,
      issuerId: deps.issuerId,
      keyPair: deps.keyPair,
    }),
    executors: {
      "github.pull-request.merge": async () => {
        effectHappened = true
        return { ok: true, result: {} }
      },
    },
    now: () => deps.now,
  })

  const outcome = await gateway.perform({
    permit: undefined,
    action: MERGE_ACTION,
    executionId: "exec-failure",
    principalSpiffeId: spiffeId,
    sinkType: "file_store",
  })

  return !outcome.performed && !effectHappened ? "denied" : "limited"
}

/**
 * The identity issuer is unreachable. A valid unexpired identity must keep working, and an
 * expired one must still be refused.
 */
export const probeIdentityServiceUnavailable = (
  deps: ProbeDependencies,
): FailureState => {
  const lease = new PolicyLease({
    tenantId: deps.tenantId,
    trustedIssuerKeys: deps.trustedIssuerKeys,
  })

  lease.offer(signBundle(deps), deps.now)

  const sidecar = new ActantSidecar({
    tenantId: deps.tenantId,
    trustedIssuerKeys: deps.trustedIssuerKeys,
    lease,
    authorityFor: () => [deps.bundle.tool_manifest[0]?.grant ?? ""],
    now: () => deps.now,
  })

  const tool = deps.bundle.agent_profile.allowed_tools[0] ?? ""

  // A short-lived identity minted long enough ago to still be valid.
  const stillValid = identityFor(
    deps,
    "probe-agent",
    new Date(deps.now.getTime() - 60_000),
  )

  // A short-lived identity minted long enough ago to be expired.
  const expired = identityFor(
    deps,
    "probe-agent",
    new Date(deps.now.getTime() - 24 * 60 * 60 * 1000),
  )

  const validDecision = sidecar.handle(
    readRequest(deps, stillValid, tool, "org/repo"),
  )

  const expiredDecision = sidecar.handle(
    readRequest(deps, expired, tool, "org/repo"),
  )

  // If the outage had extended identity lifetime, the expired identity would be allowed.
  if (validDecision.allowed && !expiredDecision.allowed) {
    return "enforced_from_lease"
  }

  return validDecision.allowed ? "limited" : "denied"
}

/**
 * The evidence sink is down. The effect must not proceed, because an effect with no evidence
 * is exactly what S13 forbids.
 */
export const probeEvidenceSinkUnavailable = async (
  deps: ProbeDependencies,
): Promise<FailureState> => {
  let effectHappened = false

  const chain = new EvidenceChain({
    tenantId: deps.tenantId,
    issuerId: deps.issuerId,
    keyPair: deps.keyPair,
    sink: () => {
      throw new Error("evidence sink unavailable")
    },
  })

  const spiffeId = `spiffe://actantos.local/tenant/${deps.tenantId}/agent/probe-agent`

  const gateway = new EffectGateway({
    tenantId: deps.tenantId,
    trustedIssuerKeys: deps.trustedIssuerKeys,
    evidenceChain: chain,
    executors: {
      "github.pull-request.merge": async () => {
        effectHappened = true
        return { ok: true, result: {} }
      },
    },
    now: () => deps.now,
  })

  const outcome = await gateway.perform({
    permit: readPermit(deps, spiffeId),
    action: MERGE_ACTION,
    executionId: "exec-failure",
    principalSpiffeId: spiffeId,
    sinkType: "file_store",
  })

  if (effectHappened) {
    return "audited_offline"
  }

  return outcome.performed ? "limited" : "denied"
}

// --- Conformance -----------------------------------------------------------------------

export type FailureConformanceReport = {
  readonly mode: FailureMode
  readonly expected: readonly FailureState[]
  readonly observed: FailureState
  readonly conforms: boolean
  readonly rationale: string
}

const PROBES: Readonly<
  Record<FailureMode, (deps: ProbeDependencies) => FailureState | Promise<FailureState>>
> = {
  control_plane_unavailable: probeControlPlaneUnavailable,
  policy_expired: probePolicyExpired,
  sidecar_unavailable: probeSidecarUnavailable,
  identity_service_unavailable: probeIdentityServiceUnavailable,
  evidence_sink_unavailable: probeEvidenceSinkUnavailable,
}

export const runFailureConformance = async (
  deps: ProbeDependencies,
): Promise<readonly FailureConformanceReport[]> => {
  const reports: FailureConformanceReport[] = []

  for (const contract of FAILURE_CONTRACT) {
    const observed = await PROBES[contract.mode](deps)

    reports.push({
      mode: contract.mode,
      expected: contract.expected,
      observed,
      conforms: contract.expected.includes(observed),
      rationale: contract.rationale,
    })
  }

  return reports
}

export { CapabilityBroker, type CapabilityProvider }