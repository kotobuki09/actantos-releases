import { CapabilityBroker, type CapabilityProvider } from "../../actantosd/src/v2/capability-broker.ts"
import { EvidenceChain } from "../../actantosd/src/v2/evidence.ts"
import { EffectGateway, type EffectExecutor } from "../../actantosd/src/v2/effect-gateway.ts"
import {
  issueEffectPermit,
  type CanonicalAction,
} from "../../actantosd/src/v2/effect-permit.ts"
import { PolicyLease } from "../../actantosd/src/v2/policy-lease.ts"
import { createGitHubCapabilityProvider } from "../../actantosd/src/v2/providers.ts"
import { ed25519, type SigningKeyPair } from "../../actantosd/src/v2/signature.ts"
import { ActantSidecar } from "../../actantosd/src/v2/sidecar.ts"
import { PROTOCOL_VERSION } from "../../actantosd/src/v2/sidecar-protocol.ts"
import {
  signPolicyBundle,
  type PolicyBundleBody,
} from "../../actantosd/src/v2/signed-policy-bundle.ts"
import {
  buildSpiffeId,
  mintWorkloadIdentity,
  signWorkloadIdentity,
  type SignedWorkloadIdentity,
} from "../../actantosd/src/v2/workload-identity.ts"

/** Shared deterministic fixtures. No network, no credentials, no live services. */

export const ISSUER_ID = "issuer-primary"
export const TENANT = "t_demo"

export const keyPair: SigningKeyPair = ed25519.generateKeyPair()
export const trustedIssuerKeys = new Map([[ISSUER_ID, keyPair.publicKeyPem]])

export const BENCH_NOW = new Date("2026-10-03T12:00:00.000Z")

export const GRANT_READ = "grant://github/org/repo/issues/read"
export const GRANT_MERGE = "grant://github/org/repo/pull-request/merge"
export const GRANT_ADMIN = "grant://github/org/repo/admin/**"

export const policyBody = (
  overrides: Partial<PolicyBundleBody> = {},
): PolicyBundleBody => ({
  bundle_id: "bundle-100",
  tenant_id: TENANT,
  version: 100,
  issued_at: "2026-10-03T00:00:00.000Z",
  expires_at: "2026-10-04T00:00:00.000Z",
  policies: [{ policy_id: "p1", cedar: "permit(principal, action, resource);" }],
  agent_profile: {
    agent_id: "reviewer-1",
    allowed_tools: ["github.issues.read", "github.pull-request.merge"],
    max_delegation_depth: 2,
  },
  tool_manifest: [
    { tool: "github.issues.read", grant: GRANT_READ },
    { tool: "github.pull-request.merge", grant: GRANT_MERGE },
  ],
  network_rules: [{ host: "api.github.com", action: "allow_via_egress_gateway" }],
  data_clearance: "CONFIDENTIAL",
  risk_profile: {
    risk_level: "medium",
    requires_effect_permit: ["github.pull-request.merge"],
  },
  trusted_issuers: [ISSUER_ID],
  ...overrides,
})

export const signedPolicyBundle = (
  overrides: Partial<PolicyBundleBody> = {},
) =>
  signPolicyBundle(
    policyBody(overrides),
    { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
    keyPair,
  )

export const identityFor = (
  agentId: string,
  overrides: {
    readonly tenantId?: string
    readonly ttlMs?: number
    /** Mint this long before `BENCH_NOW`, so a short TTL is already expired. */
    readonly issuedAgoMs?: number
  } = {},
): SignedWorkloadIdentity =>
  signWorkloadIdentity(
    mintWorkloadIdentity({
      tenantId: overrides.tenantId ?? TENANT,
      agentId,
      issuedAt: new Date(BENCH_NOW.getTime() - (overrides.issuedAgoMs ?? 0)),
      ...(overrides.ttlMs === undefined ? {} : { ttlMs: overrides.ttlMs }),
    }),
    { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
    keyPair,
  )

export const spiffe = (agentId: string): string => buildSpiffeId(TENANT, agentId)

export const evidenceChain = (): EvidenceChain =>
  new EvidenceChain({ tenantId: TENANT, issuerId: ISSUER_ID, keyPair })

export const leaseWith = (bundle: unknown): PolicyLease => {
  const lease = new PolicyLease({ tenantId: TENANT, trustedIssuerKeys })
  lease.offer(bundle, BENCH_NOW)
  return lease
}

export const sidecarWith = (
  options: {
    readonly bundle?: unknown
    readonly authority?: readonly string[]
    readonly now?: Date
  } = {},
) => {
  const lease =
    options.bundle === undefined
      ? new PolicyLease({ tenantId: TENANT, trustedIssuerKeys })
      : leaseWith(options.bundle)

  const sidecar = new ActantSidecar({
    tenantId: TENANT,
    trustedIssuerKeys,
    lease,
    authorityFor: () => options.authority ?? [GRANT_READ],
    now: () => options.now ?? BENCH_NOW,
  })

  return { sidecar, lease }
}

export const request = (overrides: Record<string, unknown>) => ({
  protocol_version: PROTOCOL_VERSION,
  request_id: "req-1",
  identity_token: identityFor("reviewer-1"),
  ...overrides,
})

export const MERGE_ACTION: CanonicalAction = {
  tool: "github.pull-request.merge",
  resource: "org/repo#42",
  args: { number: 42, method: "squash" },
}

export const mergePermit = (overrides: Record<string, unknown> = {}) =>
  issueEffectPermit({
    principalSpiffeId: spiffe("reviewer-1"),
    tenantId: TENANT,
    executionId: "exec-1",
    delegationDigest: "delegation-digest",
    action: MERGE_ACTION,
    policyBundleDigest: "policy-digest",
    dataLabels: ["CONFIDENTIAL"],
    issuedAt: BENCH_NOW,
    issuerId: ISSUER_ID,
    keyPair,
    ...overrides,
  })

export const gatewayWith = (
  effects: { performed: string[] },
  options: { readonly now?: Date } = {},
) => {
  const chain = evidenceChain()

  // The gateway takes a plain executor, not a broker provider: the gateway is the path for
  // effects the agent is already authorized to perform.
  const executor: EffectExecutor = async (action) => {
    effects.performed.push(`${action.tool} ${action.resource}`)
    return { ok: true, result: { merged: true } }
  }

  const gateway = new EffectGateway({
    tenantId: TENANT,
    trustedIssuerKeys,
    evidenceChain: chain,
    executors: { "github.pull-request.merge": executor },
    now: () => options.now ?? BENCH_NOW,
  })

  return { gateway, chain }
}

/**
 * A provider that tries to hand a credential back to the agent.
 *
 * This is the S1 test at its strongest: the broker must refuse the result on shape, without
 * trusting the provider to behave. The token here is a literal, not a real secret.
 */
export const leakyProvider: CapabilityProvider = {
  provider: "github",
  requiresCredential: false,
  supports: () => true,
  async execute() {
    return { issues: [], auth: { access_token: "ghp_fixture_not_a_real_token" } }
  },
}

export const brokerWith = (
  options: {
    readonly scope?: readonly string[]
    readonly provider?: CapabilityProvider
    readonly revokedAgentIds?: ReadonlySet<string>
  } = {},
) => {
  const chain = evidenceChain()

  const provider =
    options.provider ??
    createGitHubCapabilityProvider({
      async listIssues() {
        return { issues: [] }
      },
      async mergePullRequest() {
        return { merged: true }
      },
    })

  const broker = new CapabilityBroker({
    tenantId: TENANT,
    trustedIssuerKeys,
    evidenceChain: chain,
    providers: [provider],
    revokedAgentIds: options.revokedAgentIds,
    now: () => BENCH_NOW,
  })

  broker.setAuthorityResolver(() => options.scope ?? [GRANT_READ])

  return { broker, chain }
}