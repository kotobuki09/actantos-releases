import assert from "node:assert/strict"
import { test } from "node:test"

import { EvidenceChain } from "./evidence.ts"
import { EffectGateway } from "./effect-gateway.ts"
import {
  FAILURE_CONTRACT,
  FAILURE_MODES,
  runFailureConformance,
  type ProbeDependencies,
} from "./failure-semantics.ts"
import { ed25519 } from "./signature.ts"
import type { PolicyBundleBody } from "./signed-policy-bundle.ts"

/**
 * Phase 9 conformance.
 *
 * These tests measure what the fabric actually does when a component is taken away, and check
 * the result against the declared contract. They are the tests that would catch a silent
 * change from fail-closed to fail-open.
 */

const NOW = new Date("2026-10-03T12:00:00.000Z")

const buildDeps = (): ProbeDependencies => {
  const keyPair = ed25519.generateKeyPair()
  const issuerId = "issuer-primary"
  const tenantId = "t_failure"

  const bundle: PolicyBundleBody = {
    bundle_id: "bundle-failure",
    tenant_id: tenantId,
    version: 1,
    issued_at: "2026-10-03T00:00:00.000Z",
    expires_at: "2026-10-04T00:00:00.000Z",
    policies: [{ policy_id: "p1", cedar: "permit(principal, action, resource);" }],
    agent_profile: {
      agent_id: "probe-agent",
      allowed_tools: ["github.issues.read", "github.pull-request.merge"],
      max_delegation_depth: 2,
    },
    tool_manifest: [
      { tool: "github.issues.read", grant: "grant://github/org/repo/issues/read" },
      {
        tool: "github.pull-request.merge",
        grant: "grant://github/org/repo/pull-request/merge",
      },
    ],
    network_rules: [
      { host: "api.github.com", action: "allow_via_egress_gateway" },
    ],
    data_clearance: "CONFIDENTIAL",
    risk_profile: {
      risk_level: "medium",
      requires_effect_permit: ["github.pull-request.merge"],
    },
    trusted_issuers: [issuerId],
  }

  return {
    tenantId,
    issuerId,
    keyPair,
    trustedIssuerKeys: new Map([[issuerId, keyPair.publicKeyPem]]),
    bundle,
    now: NOW,
  }
}

test("S11/S12: every declared failure mode conforms to its contract", async () => {
  const reports = await runFailureConformance(buildDeps())

  const nonConforming = reports
    .filter((report) => !report.conforms)
    .map(
      (report) =>
        `${report.mode}: expected one of [${report.expected.join(", ")}], observed ${report.observed}`,
    )

  assert.deepEqual(nonConforming, [], nonConforming.join("\n"))
})

test("S12: the contract covers every failure mode exactly once", () => {
  assert.deepEqual(
    FAILURE_CONTRACT.map((contract) => contract.mode),
    [...FAILURE_MODES],
  )
})

test("S11: a control-plane outage keeps enforcement, not just availability", async () => {
  const [report] = (await runFailureConformance(buildDeps())).filter(
    (entry) => entry.mode === "control_plane_unavailable",
  )

  assert.equal(report?.observed, "enforced_from_lease")
})

test("S12: an expired policy denies everything", async () => {
  const [report] = (await runFailureConformance(buildDeps())).filter(
    (entry) => entry.mode === "policy_expired",
  )

  assert.equal(report?.observed, "denied")
})

test("S12: an unreachable sidecar cannot be turned into an effect", async () => {
  const [report] = (await runFailureConformance(buildDeps())).filter(
    (entry) => entry.mode === "sidecar_unavailable",
  )

  assert.notEqual(report?.observed, "enforced_from_lease")
  assert.equal(report?.conforms, true)
})

test("S12: an unreachable issuer does not extend an identity's lifetime", async () => {
  const [report] = (await runFailureConformance(buildDeps())).filter(
    (entry) => entry.mode === "identity_service_unavailable",
  )

  // The probe distinguishes these two outcomes; if the expired identity had been allowed the
  // probe would report `limited` instead.
  assert.equal(report?.observed, "enforced_from_lease")
})

test("S13: an unrecordable effect does not happen", async () => {
  const deps = buildDeps()
  const spiffeId = `spiffe://actantos.local/tenant/${deps.tenantId}/agent/probe-agent`

  let effectHappened = false

  const gateway = new EffectGateway({
    tenantId: deps.tenantId,
    trustedIssuerKeys: deps.trustedIssuerKeys,
    evidenceChain: new EvidenceChain({
      tenantId: deps.tenantId,
      issuerId: deps.issuerId,
      keyPair: deps.keyPair,
      sink: () => {
        throw new Error("evidence sink unavailable")
      },
    }),
    executors: {
      "github.pull-request.merge": async () => {
        effectHappened = true
        return { ok: true, result: {} }
      },
    },
    now: () => NOW,
  })

  const { issueEffectPermit } = await import("./effect-permit.ts")

  const outcome = await gateway.perform({
    permit: issueEffectPermit({
      principalSpiffeId: spiffeId,
      tenantId: deps.tenantId,
      executionId: "exec-sink",
      delegationDigest: "delegation-digest",
      action: {
        tool: "github.pull-request.merge",
        resource: "org/repo#42",
        args: { number: 42, method: "squash" },
      },
      policyBundleDigest: "policy-digest",
      dataLabels: ["CONFIDENTIAL"],
      issuedAt: NOW,
      issuerId: deps.issuerId,
      keyPair: deps.keyPair,
    }),
    action: {
      tool: "github.pull-request.merge",
      resource: "org/repo#42",
      args: { number: 42, method: "squash" },
    },
    executionId: "exec-sink",
    principalSpiffeId: spiffeId,
    sinkType: "file_store",
  })

  assert.equal(outcome.performed, false)
  assert.equal(outcome.performed === false && outcome.reason, "evidence_unavailable")
  assert.equal(effectHappened, false)
})

test("S13: a working sink still records the authorization before the effect", async () => {
  const deps = buildDeps()
  const spiffeId = `spiffe://actantos.local/tenant/${deps.tenantId}/agent/probe-agent`
  const persisted: unknown[] = []

  const chain = new EvidenceChain({
    tenantId: deps.tenantId,
    issuerId: deps.issuerId,
    keyPair: deps.keyPair,
    sink: (bundle) => persisted.push(bundle),
  })

  const gateway = new EffectGateway({
    tenantId: deps.tenantId,
    trustedIssuerKeys: deps.trustedIssuerKeys,
    evidenceChain: chain,
    executors: {
      "github.pull-request.merge": async () => ({ ok: true, result: { merged: true } }),
    },
    now: () => NOW,
  })

  const { issueEffectPermit } = await import("./effect-permit.ts")

  const outcome = await gateway.perform({
    permit: issueEffectPermit({
      principalSpiffeId: spiffeId,
      tenantId: deps.tenantId,
      executionId: "exec-ok",
      delegationDigest: "delegation-digest",
      action: {
        tool: "github.pull-request.merge",
        resource: "org/repo#42",
        args: { number: 42, method: "squash" },
      },
      policyBundleDigest: "policy-digest",
      dataLabels: ["CONFIDENTIAL"],
      issuedAt: NOW,
      issuerId: deps.issuerId,
      keyPair: deps.keyPair,
    }),
    action: {
      tool: "github.pull-request.merge",
      resource: "org/repo#42",
      args: { number: 42, method: "squash" },
    },
    executionId: "exec-ok",
    principalSpiffeId: spiffeId,
    sinkType: "file_store",
  })

  assert.equal(outcome.performed, true)
  // authorization, execution, result commitment
  assert.equal(chain.length, 3)
  assert.equal(persisted.length, 3)
})