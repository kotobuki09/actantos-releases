import assert from "node:assert/strict"
import test from "node:test"

import { EffectGateway } from "./effect-gateway.ts"
import {
  canonicalActionDigest,
  issueEffectPermit,
  NonceStore,
  verifyEffectPermit,
  type CanonicalAction,
} from "./effect-permit.ts"
import { EvidenceChain, verifyEvidenceBundle } from "./evidence.ts"
import { evaluateIfc } from "./ifc.ts"
import { ed25519 } from "./signature.ts"

/**
 * Conformance tests for S7 (exact-action binding), S8 (post-authorization mutation
 * invalidates), S9 (short-lived, single-use, nonce-bound) and S10 (information flow).
 */

const ISSUER_ID = "issuer-primary"
const keyPair = ed25519.generateKeyPair()
const trustedIssuerKeys = new Map([[ISSUER_ID, keyPair.publicKeyPem]])

const now = new Date("2026-10-03T12:00:00.000Z")
const TENANT = "t_demo"
const PRINCIPAL = "spiffe://actantos.local/tenant/t_demo/agent/reviewer-1"
const EXECUTION = "exec-1"
const POLICY_DIGEST = "policy-digest-v7"

const action: CanonicalAction = {
  tool: "github.pull-request.merge",
  resource: "org/repo#42",
  args: { method: "squash", commit: "abc123" },
}

const permitFor = (
  overrides: Partial<Parameters<typeof issueEffectPermit>[0]> = {},
) =>
  issueEffectPermit({
    principalSpiffeId: PRINCIPAL,
    tenantId: TENANT,
    executionId: EXECUTION,
    delegationDigest: "delegation-digest",
    action,
    policyBundleDigest: POLICY_DIGEST,
    dataLabels: ["CONFIDENTIAL"],
    issuedAt: now,
    issuerId: ISSUER_ID,
    keyPair,
    ...overrides,
  })

const verifyWith = (
  permit: unknown,
  overrides: Partial<Parameters<typeof verifyEffectPermit>[1]> = {},
) =>
  verifyEffectPermit(permit, {
    trustedIssuerKeys,
    expectedTenantId: TENANT,
    expectedPrincipalSpiffeId: PRINCIPAL,
    expectedExecutionId: EXECUTION,
    action,
    expectedPolicyBundleDigest: POLICY_DIGEST,
    now,
    ...overrides,
  })

// --- Canonical action binding -------------------------------------------------------

test("S8 allow: the digest is stable under key reordering but changes with values", () => {
  const reordered: CanonicalAction = {
    tool: action.tool,
    resource: action.resource,
    args: { commit: "abc123", method: "squash" },
  }

  assert.equal(canonicalActionDigest(action), canonicalActionDigest(reordered))
  assert.notEqual(
    canonicalActionDigest(action),
    canonicalActionDigest({ ...action, args: { ...action.args, commit: "def456" } }),
  )
})

// --- Allow path ---------------------------------------------------------------------

test("S7 allow: an exact match verifies", () => {
  const result = verifyWith(permitFor())

  assert.equal(result.accepted, true)
})

// --- Required negative tests --------------------------------------------------------

test("S8 deny: changing one argument after authorization invalidates the permit", () => {
  const permit = permitFor()

  const result = verifyWith(permit, {
    action: { ...action, args: { ...action.args, method: "merge" } },
  })

  assert.deepEqual(result, { accepted: false, reason: "action_mismatch" })
})

test("S8 deny: changing the resource after authorization invalidates the permit", () => {
  const result = verifyWith(permitFor(), {
    action: { ...action, resource: "org/other-repo#1" },
  })

  assert.deepEqual(result, { accepted: false, reason: "action_mismatch" })
})

test("S8 deny: using the permit for another tool is refused", () => {
  const result = verifyWith(permitFor(), {
    action: { ...action, tool: "github.repo.delete" },
  })

  assert.deepEqual(result, { accepted: false, reason: "action_mismatch" })
})

test("S7 deny: a permit from another tenant is refused", () => {
  const result = verifyWith(permitFor({ tenantId: "t_other" }))

  assert.deepEqual(result, { accepted: false, reason: "tenant_mismatch" })
})

test("S7 deny: a permit bound to another identity is refused", () => {
  const result = verifyWith(permitFor({ principalSpiffeId: "spiffe://actantos.local/tenant/t_demo/agent/attacker" }))

  assert.deepEqual(result, { accepted: false, reason: "identity_mismatch" })
})

test("S7 deny: a permit bound to another execution or session is refused", () => {
  const result = verifyWith(permitFor({ executionId: "exec-other" }))

  assert.deepEqual(result, { accepted: false, reason: "execution_mismatch" })
})

test("S9 deny: a permit issued under a different policy bundle is refused", () => {
  const result = verifyWith(permitFor({ policyBundleDigest: "policy-digest-v6" }))

  assert.deepEqual(result, { accepted: false, reason: "policy_mismatch" })
})

test("S9 deny: replaying an already-consumed permit is refused", () => {
  const nonces = new NonceStore()
  const permit = permitFor()

  const first = verifyWith(permit, { nonces, consumeNonce: true })
  const second = verifyWith(permit, { nonces, consumeNonce: true })

  assert.equal(first.accepted, true)
  assert.deepEqual(second, { accepted: false, reason: "already_used" })
})

test("S9 deny: an expired permit is refused", () => {
  const result = verifyWith(permitFor({ issuedAt: now, ttlMs: 1000 }), {
    now: new Date(now.getTime() + 2000),
  })

  assert.deepEqual(result, { accepted: false, reason: "expired" })
})

test("S9 deny: a revoked permit is refused", () => {
  const permit = permitFor()

  const result = verifyWith(permit, {
    revokedPermitIds: new Set([permit.permit_id]),
  })

  assert.deepEqual(result, { accepted: false, reason: "revoked" })
})

test("S7 deny: a tampered permit fails signature verification", () => {
  const permit = permitFor()
  const tampered = { ...permit, resource: "org/attacker#1" }

  assert.equal(verifyWith(tampered).accepted, false)
})

test("S9 deny: a permit signed by an untrusted issuer is refused", () => {
  const rogue = ed25519.generateKeyPair()

  const permit = issueEffectPermit({
    principalSpiffeId: PRINCIPAL,
    tenantId: TENANT,
    executionId: EXECUTION,
    delegationDigest: "d",
    action,
    policyBundleDigest: POLICY_DIGEST,
    dataLabels: ["CONFIDENTIAL"],
    issuedAt: now,
    issuerId: ISSUER_ID,
    keyPair: rogue,
  })

  assert.equal(verifyWith(permit).accepted, false)
})

// --- Nonce store semantics ----------------------------------------------------------

test("S9 allow: a nonce is consumable exactly once", () => {
  const nonces = new NonceStore()

  assert.equal(nonces.consume("n1"), true)
  assert.equal(nonces.consume("n1"), false)
  assert.equal(nonces.consume("n2"), true)
})

// --- Effect gateway -----------------------------------------------------------------

const gatewayFixture = (executorCalls: string[] = []) => {
  const evidenceChain = new EvidenceChain({
    tenantId: TENANT,
    issuerId: ISSUER_ID,
    keyPair,
  })

  const gateway = new EffectGateway({
    tenantId: TENANT,
    trustedIssuerKeys,
    evidenceChain,
    nonces: new NonceStore(),
    now: () => now,
    executors: {
      "github.pull-request.merge": async (requested) => {
        executorCalls.push(requested.resource)
        return { ok: true, result: { merged: true } }
      },
    },
  })

  return { gateway, evidenceChain, executorCalls }
}

test("S13 allow: an authorized effect executes and produces verifiable evidence", async () => {
  const { gateway, evidenceChain } = gatewayFixture()

  const outcome = await gateway.perform({
    permit: permitFor(),
    action,
    executionId: EXECUTION,
    principalSpiffeId: PRINCIPAL,
    // The permit carries a CONFIDENTIAL label, so the sink must have CONFIDENTIAL
    // clearance. `file_store` does; `internal_http` would be (correctly) denied by IFC.
    sinkType: "file_store",
  })

  assert.equal(outcome.performed, true)

  const verification = verifyEvidenceBundle(evidenceChain.export(), trustedIssuerKeys)

  assert.equal(verification.valid, true)
  assert.equal(
    verification.valid && verification.recordCount,
    3,
    "expected effect_permit, effect_execution and tool_result_commitment records",
  )

  // The authorization is recorded before the effect, so an unrecordable effect cannot happen.
  assert.deepEqual(
    evidenceChain.export().records.map((record) => record.evidence_type),
    ["effect_permit", "effect_execution", "tool_result_commitment"],
  )
})

test("S9 deny: the gateway performs an effect at most once for one permit", async () => {
  const { gateway, executorCalls } = gatewayFixture()
  const permit = permitFor()

  const first = await gateway.perform({
    permit,
    action,
    executionId: EXECUTION,
    principalSpiffeId: PRINCIPAL,
    // The permit carries a CONFIDENTIAL label, so the sink must have CONFIDENTIAL
    // clearance. `file_store` does; `internal_http` would be (correctly) denied by IFC.
    sinkType: "file_store",
  })

  const second = await gateway.perform({
    permit,
    action,
    executionId: EXECUTION,
    principalSpiffeId: PRINCIPAL,
    // The permit carries a CONFIDENTIAL label, so the sink must have CONFIDENTIAL
    // clearance. `file_store` does; `internal_http` would be (correctly) denied by IFC.
    sinkType: "file_store",
  })

  assert.equal(first.performed, true)
  assert.equal(second.performed, false)
  assert.deepEqual(executorCalls, ["org/repo#42"])
})

test("S9 deny: concurrent double-use performs the effect exactly once", async () => {
  const { gateway, executorCalls } = gatewayFixture()
  const permit = permitFor()

  const results = await Promise.all([
    gateway.perform({
      permit,
      action,
      executionId: EXECUTION,
      principalSpiffeId: PRINCIPAL,
      // The permit carries a CONFIDENTIAL label, so the sink must have CONFIDENTIAL
    // clearance. `file_store` does; `internal_http` would be (correctly) denied by IFC.
    sinkType: "file_store",
    }),
    gateway.perform({
      permit,
      action,
      executionId: EXECUTION,
      principalSpiffeId: PRINCIPAL,
      // The permit carries a CONFIDENTIAL label, so the sink must have CONFIDENTIAL
    // clearance. `file_store` does; `internal_http` would be (correctly) denied by IFC.
    sinkType: "file_store",
    }),
  ])

  const performedCount = results.filter((r) => r.performed).length

  assert.equal(performedCount, 1)
  assert.equal(executorCalls.length, 1)
})

test("S8 deny: the gateway refuses a mutated action and records a violation", async () => {
  const { gateway, executorCalls, evidenceChain } = gatewayFixture()
  const permit = permitFor()

  const outcome = await gateway.perform({
    permit,
    action: { ...action, args: { ...action.args, method: "merge" } },
    executionId: EXECUTION,
    principalSpiffeId: PRINCIPAL,
    // The permit carries a CONFIDENTIAL label, so the sink must have CONFIDENTIAL
    // clearance. `file_store` does; `internal_http` would be (correctly) denied by IFC.
    sinkType: "file_store",
  })

  assert.equal(outcome.performed, false)
  assert.equal(executorCalls.length, 0)

  const verification = verifyEvidenceBundle(evidenceChain.export(), trustedIssuerKeys)

  assert.equal(verification.valid, true)
  assert.equal(
    evidenceChain.export().records[0]?.evidence_type,
    "security_violation",
  )
})

// --- Information flow --------------------------------------------------------------

test("S10 allow: INTERNAL data may flow to an internal sink", () => {
  assert.equal(evaluateIfc(["INTERNAL"], "internal_http").allowed, true)
})

test("S10 deny: SECRET data may not flow to an external sink", () => {
  const decision = evaluateIfc(["SECRET"], "external_http")

  assert.equal(decision.allowed, false)
  assert.equal(decision.allowed === false && decision.reason, "clearance_violation")
})

test("S10 deny: CREDENTIAL data may not flow to a model provider", () => {
  assert.equal(evaluateIfc(["CREDENTIAL"], "model_provider").allowed, false)
})

test("S10 deny: the highest label governs a mixed set", () => {
  assert.equal(evaluateIfc(["PUBLIC", "PII"], "external_http").allowed, false)
  assert.equal(evaluateIfc(["PUBLIC", "INTERNAL"], "internal_http").allowed, true)
})

test("S10 allow: an explicit declassification rule permits the flow", () => {
  const decision = evaluateIfc(["SECRET"], "external_http", {
    declassificationRules: [
      {
        rule_id: "rule-1",
        sink_type: "external_http",
        permitted_labels: ["SECRET"],
        justification: "vendor endpoint under DPA",
        approved_by: "security-owner",
      },
    ],
  })

  assert.equal(decision.allowed, true)
})

test("S10 deny: a rule for a different sink does not apply", () => {
  const decision = evaluateIfc(["SECRET"], "external_http", {
    declassificationRules: [
      {
        rule_id: "rule-1",
        sink_type: "file_store",
        permitted_labels: ["SECRET"],
        justification: "archive",
        approved_by: "security-owner",
      },
    ],
  })

  assert.equal(decision.allowed, false)
})

test("S10 deny: the gateway blocks an over-classified effect before executing it", async () => {
  const { gateway, executorCalls } = gatewayFixture()

  const outcome = await gateway.perform({
    permit: permitFor({ dataLabels: ["CREDENTIAL"] }),
    action,
    executionId: EXECUTION,
    principalSpiffeId: PRINCIPAL,
    sinkType: "external_http",
  })

  assert.equal(outcome.performed, false)
  assert.equal(outcome.performed === false && outcome.reason, "ifc_denied")
  assert.equal(executorCalls.length, 0)
})

// --- Evidence tamper detection ------------------------------------------------------

test("S13 deny: a modified evidence payload breaks the chain", () => {
  const chain = new EvidenceChain({ tenantId: TENANT, issuerId: ISSUER_ID, keyPair })

  chain.append("root_authorization", { principal: "user-1" })
  chain.append("agent_identity", { spiffe_id: PRINCIPAL })

  const bundle = chain.export()
  const tampered = structuredClone(bundle)
  ;(tampered.records[0] as { payload: unknown }).payload = { principal: "attacker" }

  const verification = verifyEvidenceBundle(tampered, trustedIssuerKeys)

  assert.equal(verification.valid, false)
  assert.ok(
    verification.valid === false &&
      verification.issues.some((issue) => issue.problem === "record_hash_mismatch"),
  )
})

test("S13 deny: a deleted evidence record breaks linkage", () => {
  const chain = new EvidenceChain({ tenantId: TENANT, issuerId: ISSUER_ID, keyPair })

  chain.append("root_authorization", { principal: "user-1" })
  chain.append("agent_identity", { spiffe_id: PRINCIPAL })
  chain.append("policy_decision", { effect: "allow" })

  const bundle = chain.export()
  const tampered = structuredClone(bundle)
  tampered.records.splice(1, 1)

  const verification = verifyEvidenceBundle(tampered, trustedIssuerKeys)

  assert.equal(verification.valid, false)
  assert.ok(
    verification.valid === false &&
      verification.issues.some((issue) => issue.problem === "broken_chain_linkage"),
  )
})

test("S13 deny: evidence cannot be verified by an untrusted issuer key", () => {
  const chain = new EvidenceChain({ tenantId: TENANT, issuerId: ISSUER_ID, keyPair })
  chain.append("root_authorization", { principal: "user-1" })

  const verification = verifyEvidenceBundle(chain.export(), new Map())

  assert.equal(verification.valid, false)
  assert.ok(
    verification.valid === false &&
      verification.issues.some((issue) => issue.problem === "untrusted_issuer"),
  )
})

test("S13 allow: credentials are redacted from evidence payloads", () => {
  const chain = new EvidenceChain({ tenantId: TENANT, issuerId: ISSUER_ID, keyPair })
  chain.append("root_authorization", { api_key: "ghp_secret_value", user: "user-1" })

  const record = chain.export().records[0]

  assert.deepEqual(record?.payload, { api_key: "[redacted]", user: "user-1" })
})