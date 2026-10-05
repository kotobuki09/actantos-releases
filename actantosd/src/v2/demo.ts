import { CapabilityBroker, type CapabilityProvider } from "./capability-broker.ts"
import { EvidenceChain, verifyEvidenceBundle, type EvidenceBundle } from "./evidence.ts"
import { EffectGateway } from "./effect-gateway.ts"
import { issueEffectPermit } from "./effect-permit.ts"
import { resolveDelegation, signDelegationLink, type DelegationLink } from "./delegation.ts"
import { PolicyLease } from "./policy-lease.ts"
import { ActantSidecar } from "./sidecar.ts"
import { PROTOCOL_VERSION } from "./sidecar-protocol.ts"
import { signPolicyBundle, type PolicyBundleBody } from "./signed-policy-bundle.ts"
import { ed25519, type SigningKeyPair } from "./signature.ts"
import {
  buildSpiffeId,
  mintWorkloadIdentity,
  signWorkloadIdentity,
} from "./workload-identity.ts"

/**
 * End-to-end reference demonstration (§21).
 *
 * One Orchestrator, one Reviewer, one repository, and every attack the specification names.
 * Nothing here talks to a network or needs a real credential: the GitHub client is a stub and
 * the "token" is a literal string.
 *
 * The point of the demo is the *ordering*. The agent asks, the sidecar decides, the gateway
 * performs. The agent never decides anything, and never holds anything it could replay.
 */

const NOW = new Date("2026-10-03T12:00:00.000Z")
const TENANT = "t_demo"
const ISSUER = "issuer-demo"

const GRANT_READ = "grant://github/org/repo/issues/read"
const GRANT_MERGE = "grant://github/org/repo/pull-request/merge"

export type DemoStep = {
  readonly label: string
  readonly detail: string
  readonly blocked: boolean
}

export type DemoResult = {
  readonly steps: readonly DemoStep[]
  readonly evidenceValid: boolean
  readonly evidenceRecordCount: number
  readonly evidence: EvidenceBundle
  readonly orchestratorTokenSeenByAgent: boolean
  readonly fileReadWithValidPermit: boolean
}

/** A stand-in GitHub client. It records what it was asked to do and holds no secret. */
const createDemoWorld = () => {
  const keyPair: SigningKeyPair = ed25519.generateKeyPair()
  const trustedIssuerKeys = new Map([[ISSUER, keyPair.publicKeyPem]])

  const calls: string[] = []

  const githubProvider: CapabilityProvider = {
    provider: "github",
    // The broker would mint a short-lived credential here and destroy it afterwards. The demo
    // uses the credential-free path so there is nothing to leak even by accident.
    requiresCredential: false,
    supports: (grant) => grant.provider === "github",
    async execute(args) {
      calls.push(`${args.grantUri} ${JSON.stringify(args.args)}`)

      return {
        issues: [
          { number: 1, title: "Fix the retry loop", labels: ["bug"] },
          { number: 2, title: "Document the sidecar protocol", labels: [] },
        ],
      }
    },
  }

  return { keyPair, trustedIssuerKeys, githubProvider, calls }
}

const policyBody = (): PolicyBundleBody => ({
  bundle_id: "bundle-demo-7",
  tenant_id: TENANT,
  version: 7,
  issued_at: "2026-10-03T00:00:00.000Z",
  expires_at: "2026-10-04T00:00:00.000Z",
  policies: [{ policy_id: "p-review", cedar: "permit(principal, action, resource);" }],
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
  trusted_issuers: [ISSUER],
})

export const runDemo = async (): Promise<DemoResult> => {
  const world = createDemoWorld()
  const steps: DemoStep[] = []

  const orchestratorId = buildSpiffeId(TENANT, "orchestrator")
  const reviewerId = buildSpiffeId(TENANT, "reviewer-1")

  const identityFor = (agentId: string, issuedAt = NOW) =>
    signWorkloadIdentity(
      mintWorkloadIdentity({ tenantId: TENANT, agentId, issuedAt }),
      { algorithm: "ed25519", issuer_id: ISSUER, value: "" },
      world.keyPair,
    )

  const orchestratorIdentity = identityFor("orchestrator")
  const reviewerIdentity = identityFor("reviewer-1")

  // --- 1. The control plane signs a policy bundle, and the sidecar leases it ---------------

  const bundle = signPolicyBundle(
    policyBody(),
    { algorithm: "ed25519", issuer_id: ISSUER, value: "" },
    world.keyPair,
  )

  const lease = new PolicyLease({
    tenantId: TENANT,
    trustedIssuerKeys: world.trustedIssuerKeys,
  })

  const leaseOffer = lease.offer(bundle, NOW)

  steps.push({
    label: "control plane signs policy",
    detail: `bundle ${bundle.body.bundle_id} v${bundle.body.version}, lease ${leaseOffer.accepted ? "accepted" : `refused (${leaseOffer.reason})`}`,
    blocked: false,
  })

  // --- 2. The Orchestrator delegates a narrowed scope to the Reviewer -----------------------

  const delegationLink: DelegationLink = {
    delegation_id: "del-demo-1",
    tenant_id: TENANT,
    delegator_spiffe_id: orchestratorId,
    delegatee_spiffe_id: reviewerId,
    // Narrower than the Orchestrator holds: read, not merge.
    scope: [GRANT_READ],
    depth: 1,
    issued_at: new Date(NOW.getTime() - 60_000).toISOString(),
    expires_at: new Date(NOW.getTime() + 3_600_000).toISOString(),
  }

  const signedDelegation = signDelegationLink(
    delegationLink,
    { algorithm: "ed25519", issuer_id: ISSUER, value: "" },
    world.keyPair,
  )

  const delegation = resolveDelegation([signedDelegation], {
    tenantId: TENANT,
    rootScope: [GRANT_READ, GRANT_MERGE],
    trustedIssuerKeys: world.trustedIssuerKeys,
    now: NOW,
  })

  const reviewerScope = delegation.accepted ? delegation.effectiveScope : []

  steps.push({
    label: "orchestrator delegates to reviewer",
    detail: delegation.accepted
      ? `accepted with narrowed scope: ${reviewerScope.join(", ")}`
      : `refused (${delegation.reason})`,
    blocked: !delegation.accepted,
  })

  // --- 3. The sidecar enforces locally from the lease ---------------------------------------

  const sidecar = new ActantSidecar({
    tenantId: TENANT,
    trustedIssuerKeys: world.trustedIssuerKeys,
    lease,
    authorityFor: (spiffeId) => (spiffeId === reviewerId ? reviewerScope : [GRANT_READ, GRANT_MERGE]),
    now: () => NOW,
  })

  const check = (
    tool: string,
    resource: string,
    args: Record<string, unknown>,
    identity: unknown = reviewerIdentity,
  ) =>
    sidecar.handle({
      protocol_version: PROTOCOL_VERSION,
      request_id: `req-${tool}`,
      request_type: "CheckAction",
      identity_token: identity,
      tool,
      resource,
      args,
    })

  // --- 4. Legitimate work still works ------------------------------------------------------

  const evidenceChain = new EvidenceChain({
    tenantId: TENANT,
    issuerId: ISSUER,
    keyPair: world.keyPair,
  })

  const broker = new CapabilityBroker({
    tenantId: TENANT,
    trustedIssuerKeys: world.trustedIssuerKeys,
    evidenceChain,
    providers: [world.githubProvider],
    now: () => NOW,
  })

  broker.setAuthorityResolver((spiffeId) =>
    spiffeId === reviewerId ? reviewerScope : [GRANT_READ, GRANT_MERGE],
  )

  const readOutcome = await broker.grant({
    identityToken: reviewerIdentity,
    grantUri: GRANT_READ,
    args: {},
  })

  steps.push({
    label: "reviewer reads issues through the broker",
    detail: readOutcome.granted
      ? `granted; result contains no credential (${JSON.stringify(readOutcome.result).length} bytes returned)`
      : `refused (${readOutcome.reason})`,
    blocked: !readOutcome.granted,
  })

  // --- 5. Attack: prompt injection asks for the token ---------------------------------------

  const injectionOutcome = await broker.grant({
    identityToken: reviewerIdentity,
    grantUri: "grant://github/org/repo/token",
    args: {},
  })

  steps.push({
    label: "ATTACK injection asks the broker for the token",
    detail: injectionOutcome.granted
      ? "TOKEN REACHED THE AGENT"
      : `refused (${injectionOutcome.reason}); the agent holds a grant, not a secret`,
    blocked: !injectionOutcome.granted,
  })

  // --- 6. Attack: direct network from Python -----------------------------------------------

  const pythonSocket = check("python.socket.connect", "93.184.216.34:443", {})

  steps.push({
    label: "ATTACK reviewer opens a raw Python socket",
    detail: pythonSocket.allowed
      ? "RAW EGRESS ALLOWED"
      : `refused (${pythonSocket.reason})`,
    blocked: !pythonSocket.allowed,
  })

  // --- 7. Attack: child process curl -------------------------------------------------------

  const childCurl = check("shell.exec.curl", "https://evil.example.com/collect", {})

  steps.push({
    label: "ATTACK reviewer spawns a child shell running curl",
    detail: childCurl.allowed
      ? "CHILD EGRESS ALLOWED"
      : `refused (${childCurl.reason})`,
    blocked: !childCurl.allowed,
  })

  // --- 8. Attack: argument mutation after authorization -------------------------------------

  const mergeAction = {
    tool: "github.pull-request.merge",
    resource: "org/repo#42",
    args: { number: 42, method: "squash" },
  }

  // The Orchestrator authorizes the merge. The Reviewer is *not* allowed to hold that
  // authority, so the permit is issued to the Orchestrator, as it must be.
  const mergePermit = issueEffectPermit({
    principalSpiffeId: orchestratorId,
    tenantId: TENANT,
    executionId: "exec-demo-1",
    delegationDigest: "delegation-digest-demo",
    action: mergeAction,
    policyBundleDigest: "policy-bundle-digest-demo",
    dataLabels: ["CONFIDENTIAL"],
    issuedAt: NOW,
    issuerId: ISSUER,
    keyPair: world.keyPair,
  })

  const merged: string[] = []

  const gateway = new EffectGateway({
    tenantId: TENANT,
    trustedIssuerKeys: world.trustedIssuerKeys,
    evidenceChain,
    executors: {
      "github.pull-request.merge": async (action) => {
        merged.push(`${action.resource} ${JSON.stringify(action.args)}`)
        return { ok: true, result: { merged: true } }
      },
    },
    now: () => NOW,
  })

// The permit says `squash`. The Reviewer swaps it to `merge` after authorization.
  const mutated = await runEffect(
    gateway,
    mergePermit,
    { ...mergeAction, args: { ...mergeAction.args, method: "merge" } },
    orchestratorId,
  )

  steps.push({
    label: "ATTACK reviewer changes the merge method after authorization",
    detail: mutated.performed
      ? "MUTATED EFFECT EXECUTED"
      : `refused (${mutated.reason}); the permit binds a digest of the whole action`,
    blocked: !mutated.performed,
  })

  // --- 9. Attack: permit replay ------------------------------------------------------------

  const first = await runEffect(gateway, mergePermit, mergeAction, orchestratorId)
  const replay = await runEffect(gateway, mergePermit, mergeAction, orchestratorId)

  steps.push({
    label: "ATTACK reviewer replays the permit",
    detail: replay.performed
      ? "REPLAY SUCCEEDED"
      : `first use ${first.performed ? "succeeded" : "failed"}, replay refused (${replay.reason})`,
    blocked: !replay.performed,
  })

  // --- 10. Attack: confidential data into an external sink ----------------------------------

  // A fresh permit, so this is refused by the information-flow check and not by the spent
  // nonce of the previous step. Confusing the two would hide whether IFC actually works.
  const exfiltrationPermit = issueEffectPermit({
    principalSpiffeId: orchestratorId,
    tenantId: TENANT,
    executionId: "exec-demo-2",
    delegationDigest: "delegation-digest-demo",
    action: mergeAction,
    policyBundleDigest: "policy-bundle-digest-demo",
    dataLabels: ["CONFIDENTIAL"],
    issuedAt: NOW,
    issuerId: ISSUER,
    keyPair: world.keyPair,
  })

  const sinkOutcome = await runEffect(
    gateway,
    exfiltrationPermit,
    mergeAction,
    orchestratorId,
    { executionId: "exec-demo-2", sinkType: "external_http" },
  )

  steps.push({
    label: "ATTACK confidential data is sent to an external sink",
    detail: sinkOutcome.performed
      ? "DATA EXFILTRATED"
      : `refused (${sinkOutcome.reason}); external_http clearance is PUBLIC, the data is CONFIDENTIAL`,
    blocked: !sinkOutcome.performed,
  })

  // --- 11. The control plane goes away; the sidecar keeps enforcing -------------------------

  const afterOutage = check("github.issues.read", "org/repo", {})
  const outOfScope = check("github.pull-request.merge", "org/repo#42", {})

  steps.push({
    label: "control plane outage",
    detail: `no new bundles arrive; in-scope read ${afterOutage.allowed ? "still allowed" : `refused (${afterOutage.reason})`}, out-of-scope merge ${outOfScope.allowed ? "STILL ALLOWED" : `refused (${outOfScope.reason})`}`,
    blocked: afterOutage.allowed && !outOfScope.allowed,
  })

  // --- 12. Evidence verifies offline --------------------------------------------------------

  const bundleExport = evidenceChain.export()
  const verification = verifyEvidenceBundle(bundleExport, world.trustedIssuerKeys)

  return {
    steps,
    evidenceValid: verification.valid,
    evidenceRecordCount: verification.valid ? verification.recordCount : 0,
    evidence: bundleExport,
    orchestratorTokenSeenByAgent: injectionOutcome.granted,
    fileReadWithValidPermit: readOutcome.granted && first.performed,
  }
}

const runEffect = async (
  gateway: EffectGateway,
  permit: unknown,
  action: { tool: string; resource: string; args: Record<string, unknown> },
  principalSpiffeId: string,
  overrides: {
    readonly executionId?: string
    readonly sinkType?: "file_store" | "external_http"
    readonly dataLabels?: readonly ("CONFIDENTIAL" | "SECRET")[]
  } = {},
) =>
  gateway.perform({
    permit,
    action,
    executionId: overrides.executionId ?? "exec-demo-1",
    principalSpiffeId,
    sinkType: overrides.sinkType ?? "file_store",
    ...(overrides.dataLabels === undefined ? {} : { dataLabels: overrides.dataLabels }),
  })

/** Human-readable trace of the demo. */
export const formatDemo = (result: DemoResult): string => {
  const lines: string[] = []

  lines.push("ActantOS v2 — end-to-end reference demonstration")
  lines.push("=".repeat(64))
  lines.push("")

  for (const [index, step] of result.steps.entries()) {
    const status = step.blocked ? "blocked" : "      "
    lines.push(`${String(index + 1).padStart(2)}. [${status}] ${step.label}`)
    lines.push(`       ${step.detail}`)
  }

  lines.push("")
  lines.push(
    `evidence: ${result.evidenceValid ? "VERIFIED" : "FAILED"} (${result.evidenceRecordCount} records, hash chain + per-record signatures)`,
  )
  lines.push(
    `production credential in agent context: ${result.orchestratorTokenSeenByAgent ? "YES (FAIL)" : "no"}`,
  )

  return lines.join("\n")
}