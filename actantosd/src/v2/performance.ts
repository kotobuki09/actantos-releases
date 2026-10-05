import { CapabilityBroker, type CapabilityProvider } from "./capability-broker.ts"
import { EvidenceChain } from "./evidence.ts"
import { EffectGateway } from "./effect-gateway.ts"
import { issueEffectPermit, type CanonicalAction } from "./effect-permit.ts"
import { PolicyLease } from "./policy-lease.ts"
import { ActantSidecar } from "./sidecar.ts"
import { PROTOCOL_VERSION } from "./sidecar-protocol.ts"
import { signPolicyBundle, type PolicyBundleBody } from "./signed-policy-bundle.ts"
import { ed25519 } from "./signature.ts"
import {
  mintWorkloadIdentity,
  signWorkloadIdentity,
  verifyWorkloadIdentity,
} from "./workload-identity.ts"

/**
 * Latency measurement for the local security fabric.
 *
 * Every enforcement path in v2 adds work to an agent request, so the honest question is not
 * "is enforcement fast" but "what does it cost". These numbers are the answer for the
 * in-process fabric. They are *not* a claim about a deployment: a sidecar over a Unix domain
 * socket adds transport cost this harness does not model, and that is stated in the report
 * rather than hidden.
 */

export type LatencySummary = {
  readonly name: string
  readonly unit: string
  readonly samples: number
  readonly p50: number
  readonly p95: number
  readonly p99: number
  readonly max: number
  readonly mean: number
}

const percentile = (sorted: readonly number[], fraction: number): number => {
  if (sorted.length === 0) {
    return 0
  }

  // Nearest-rank. No interpolation: a reported latency should be one that was actually seen.
  const rank = Math.ceil(fraction * sorted.length)
  return sorted[Math.min(sorted.length - 1, Math.max(0, rank - 1))] as number
}

export const summarize = (
  name: string,
  unit: string,
  durationsMs: readonly number[],
): LatencySummary => {
  const sorted = [...durationsMs].sort((a, b) => a - b)
  const total = sorted.reduce((sum, value) => sum + value, 0)

  return {
    name,
    unit,
    samples: sorted.length,
    p50: percentile(sorted, 0.5),
    p95: percentile(sorted, 0.95),
    p99: percentile(sorted, 0.99),
    max: sorted.at(-1) ?? 0,
    mean: sorted.length === 0 ? 0 : total / sorted.length,
  }
}

const measure = async (
  name: string,
  unit: string,
  iterations: number,
  body: (index: number) => void | Promise<void>,
): Promise<LatencySummary> => {
  const durations: number[] = []

  // Warm up so the first-call JIT and key-generation costs are not attributed to the loop.
  for (let index = 0; index < 50; index += 1) {
    await body(index)
  }

  for (let index = 0; index < iterations; index += 1) {
    const startedAt = performance.now()
    await body(index)
    durations.push(performance.now() - startedAt)
  }

  return summarize(name, unit, durations)
}

const NOW = new Date("2026-10-03T12:00:00.000Z")
const TENANT = "t_perf"
const ISSUER = "issuer-perf"
const GRANT_READ = "grant://github/org/repo/issues/read"
const GRANT_MERGE = "grant://github/org/repo/pull-request/merge"

export type PerformanceReport = {
  readonly summaries: readonly LatencySummary[]
  readonly notes: readonly string[]
}

export const runPerformance = async (
  iterations = 2000,
): Promise<PerformanceReport> => {
  const keyPair = ed25519.generateKeyPair()
  const trustedIssuerKeys = new Map([[ISSUER, keyPair.publicKeyPem]])

  const bundleBody: PolicyBundleBody = {
    bundle_id: "bundle-perf",
    tenant_id: TENANT,
    version: 1,
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
    trusted_issuers: [ISSUER],
  }

  const bundle = signPolicyBundle(
    bundleBody,
    { algorithm: "ed25519", issuer_id: ISSUER, value: "" },
    keyPair,
  )

  const lease = new PolicyLease({ tenantId: TENANT, trustedIssuerKeys })
  lease.offer(bundle, NOW)

  const sidecar = new ActantSidecar({
    tenantId: TENANT,
    trustedIssuerKeys,
    lease,
    authorityFor: () => [GRANT_READ],
    now: () => NOW,
  })

  const reviewerIdentity = signWorkloadIdentity(
    mintWorkloadIdentity({ tenantId: TENANT, agentId: "reviewer-1", issuedAt: NOW }),
    { algorithm: "ed25519", issuer_id: ISSUER, value: "" },
    keyPair,
  )

  const summaries: LatencySummary[] = []

  summaries.push(
    await measure("sidecar CheckAction (allow)", "ms", iterations, () => {
      sidecar.handle({
        protocol_version: PROTOCOL_VERSION,
        request_id: "req-perf",
        request_type: "CheckAction",
        identity_token: reviewerIdentity,
        tool: "github.issues.read",
        resource: "org/repo",
        args: {},
      })
    }),
  )

  summaries.push(
    await measure("sidecar CheckAction (deny)", "ms", iterations, () => {
      sidecar.handle({
        protocol_version: PROTOCOL_VERSION,
        request_id: "req-perf",
        request_type: "CheckAction",
        identity_token: reviewerIdentity,
        tool: "github.repo.delete",
        resource: "org/repo",
        args: {},
      })
    }),
  )

  summaries.push(
    await measure("workload identity verify", "ms", iterations, () => {
      verifyWorkloadIdentity(reviewerIdentity, {
        trustedIssuerKeys,
        expectedTenantId: TENANT,
        now: NOW,
      })
    }),
  )

  summaries.push(
    await measure("effect permit issuance (sign)", "ms", iterations, () => {
      issueEffectPermit({
        principalSpiffeId: `spiffe://actantos.local/tenant/${TENANT}/agent/reviewer-1`,
        tenantId: TENANT,
        executionId: "exec-perf",
        delegationDigest: "delegation-digest",
        action: {
          tool: "github.pull-request.merge",
          resource: "org/repo#42",
          args: { number: 42, method: "squash" },
        } satisfies CanonicalAction,
        policyBundleDigest: "policy-digest",
        dataLabels: ["CONFIDENTIAL"],
        issuedAt: NOW,
        issuerId: ISSUER,
        keyPair,
      })
    }),
  )

  const chain = new EvidenceChain({
    tenantId: TENANT,
    issuerId: ISSUER,
    keyPair,
  })

  summaries.push(
    await measure("evidence append (hash + sign)", "ms", iterations, (index) => {
      chain.append("data_access", { agent: "reviewer-1", index })
    }),
  )

  // Broker overhead measured against a no-op provider, so the number is the fabric's cost and
  // not the cost of whatever the real tool would have done.
  const provider: CapabilityProvider = {
    provider: "github",
    requiresCredential: false,
    supports: (grant) => grant.provider === "github",
    async execute() {
      return { issues: [] }
    },
  }

  const brokerChain = new EvidenceChain({
    tenantId: TENANT,
    issuerId: ISSUER,
    keyPair,
  })

  const broker = new CapabilityBroker({
    tenantId: TENANT,
    trustedIssuerKeys,
    evidenceChain: brokerChain,
    providers: [provider],
    now: () => NOW,
  })

  broker.setAuthorityResolver(() => [GRANT_READ])

  summaries.push(
    await measure("broker grant (no-op tool)", "ms", iterations, async () => {
      await broker.grant({
        identityToken: reviewerIdentity,
        grantUri: GRANT_READ,
        args: {},
      })
    }),
  )

  const gatewayChain = new EvidenceChain({
    tenantId: TENANT,
    issuerId: ISSUER,
    keyPair,
  })

  const gateway = new EffectGateway({
    tenantId: TENANT,
    trustedIssuerKeys,
    evidenceChain: gatewayChain,
    executors: {
      "github.pull-request.merge": async () => ({ ok: true, result: { merged: true } }),
    },
    now: () => NOW,
  })

  summaries.push(
    await measure(
      "effect through gateway (sign + verify + execute)",
      "ms",
      Math.max(200, Math.floor(iterations / 4)),
      async () => {
        await gateway.perform({
          permit: issueEffectPermit({
            principalSpiffeId: `spiffe://actantos.local/tenant/${TENANT}/agent/reviewer-1`,
            tenantId: TENANT,
            executionId: "exec-perf-gw",
            delegationDigest: "delegation-digest",
            action: {
              tool: "github.pull-request.merge",
              resource: "org/repo#42",
              args: { number: 42, method: "squash" },
            },
            policyBundleDigest: "policy-digest",
            dataLabels: ["CONFIDENTIAL"],
            issuedAt: NOW,
            issuerId: ISSUER,
            keyPair,
          }),
          action: {
            tool: "github.pull-request.merge",
            resource: "org/repo#42",
            args: { number: 42, method: "squash" },
          },
          executionId: "exec-perf-gw",
          principalSpiffeId: `spiffe://actantos.local/tenant/${TENANT}/agent/reviewer-1`,
          sinkType: "file_store",
        })
      },
    ),
  )

  return {
    summaries,
    notes: [
      "Measured in-process, on the host, with no transport.",
      "A production sidecar adds Unix domain socket round-trip on top of these numbers; that cost is not included here.",
      "Ed25519 dominates identity verification, permit issuance and evidence appends. This is the price of not trusting the network or the process.",
      "Evidence append cost grows with chain length because the export is recomputed on write; see the sink design note in evidence.ts.",
    ],
  }
}

export const formatPerformance = (report: PerformanceReport): string => {
  const lines: string[] = []

  lines.push("ActantOS v2 — enforcement path latency")
  lines.push("=".repeat(78))
  lines.push("")
  lines.push(
    "path".padEnd(48) + "p50".padStart(8) + "p95".padStart(8) + "p99".padStart(8) + "max".padStart(9),
  )
  lines.push("-".repeat(78))

  for (const summary of report.summaries) {
    lines.push(
      summary.name.slice(0, 47).padEnd(48) +
        summary.p50.toFixed(3).padStart(8) +
        summary.p95.toFixed(3).padStart(8) +
        summary.p99.toFixed(3).padStart(8) +
        summary.max.toFixed(3).padStart(9),
    )
  }

  lines.push("")
  for (const note of report.notes) {
    lines.push(`- ${note}`)
  }

  return lines.join("\n")
}