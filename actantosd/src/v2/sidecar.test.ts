import assert from "node:assert/strict"
import test from "node:test"

import { PolicyLease } from "./policy-lease.ts"
import { ed25519 } from "./signature.ts"
import { ActantSidecar } from "./sidecar.ts"
import { PROTOCOL_VERSION } from "./sidecar-protocol.ts"
import { signPolicyBundle, type PolicyBundleBody } from "./signed-policy-bundle.ts"
import {
  mintWorkloadIdentity,
  signWorkloadIdentity,
} from "./workload-identity.ts"

/**
 * Conformance tests for S11 (local enforcement under a signed lease) and S12 (fail closed
 * when security state is expired or unverifiable).
 */

const ISSUER_ID = "issuer-primary"
const keyPair = ed25519.generateKeyPair()
const trustedIssuerKeys = new Map([[ISSUER_ID, keyPair.publicKeyPem]])

const TENANT = "t_demo"
const AGENT = "reviewer-1"
const now = new Date("2026-10-03T12:00:00.000Z")

const GRANT_READ = "grant://github/org/repo/issues/read"

const bundleBody = (overrides: Partial<PolicyBundleBody> = {}): PolicyBundleBody => ({
  bundle_id: "bundle-100",
  tenant_id: TENANT,
  version: 100,
  issued_at: "2026-10-03T00:00:00.000Z",
  expires_at: "2026-10-04T00:00:00.000Z",
  policies: [{ policy_id: "p1", cedar: "permit(principal, action, resource);" }],
  agent_profile: {
    agent_id: AGENT,
    allowed_tools: ["github.issues.read", "github.pull-request.merge"],
    max_delegation_depth: 2,
  },
  tool_manifest: [{ tool: "github.issues.read", grant: GRANT_READ }],
  network_rules: [{ host: "api.github.com", action: "allow_via_egress_gateway" }],
  data_clearance: "CONFIDENTIAL",
  risk_profile: {
    risk_level: "medium",
    requires_effect_permit: ["github.pull-request.merge"],
  },
  trusted_issuers: [ISSUER_ID],
  ...overrides,
})

const signedBundle = (overrides: Partial<PolicyBundleBody> = {}) =>
  signPolicyBundle(
    bundleBody(overrides),
    { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
    keyPair,
  )

const identityToken = () =>
  signWorkloadIdentity(
    mintWorkloadIdentity({ tenantId: TENANT, agentId: AGENT, issuedAt: now }),
    { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
    keyPair,
  )

const request = (overrides: Record<string, unknown>) => ({
  protocol_version: PROTOCOL_VERSION,
  request_id: "req-1",
  identity_token: identityToken(),
  ...overrides,
})

const setup = (
  options: {
    readonly bundle?: unknown
    readonly authority?: readonly string[]
    readonly now?: Date
    /** Time at which the bundle is offered. Defaults to `now`. */
    readonly offerAt?: Date
    readonly withPermitIssuer?: boolean
  } = {},
) => {
  const lease = new PolicyLease({ tenantId: TENANT, trustedIssuerKeys })

  if (options.bundle !== undefined) {
    lease.offer(options.bundle, options.offerAt ?? options.now ?? now)
  }

  const sidecar = new ActantSidecar({
    tenantId: TENANT,
    trustedIssuerKeys,
    lease,
    authorityFor: () => options.authority ?? [GRANT_READ],
    ...(options.withPermitIssuer === true
      ? {
          permitIssuer: () => ({ permit_id: "permit-1", nonce: "nonce-1" }),
        }
      : {}),
    now: () => options.now ?? now,
  })

  return { sidecar, lease }
}

// --- Allow path ---------------------------------------------------------------------

test("S11 allow: a scoped action is permitted while the lease is valid", () => {
  const { sidecar } = setup({ bundle: signedBundle() })

  const decision = sidecar.handle(
    request({
      request_type: "CheckAction",
      tool: "github.issues.read",
      resource: "org/repo",
      args: {},
    }),
  )

  assert.equal(decision.allowed, true)
})

test("S11 allow: the security context is returned from local state", () => {
  const { sidecar } = setup({ bundle: signedBundle() })

  const decision = sidecar.handle(request({ request_type: "GetSecurityContext" }))

  assert.equal(decision.allowed, true)
})

// --- S11: control-plane outage ------------------------------------------------------

test("S11 allow: enforcement continues after the control plane stops responding", () => {
  // The lease is loaded once. Nothing further is offered to it, simulating an outage.
  const { sidecar } = setup({ bundle: signedBundle() })

  const first = sidecar.handle(
    request({
      request_type: "CheckAction",
      tool: "github.issues.read",
      resource: "org/repo",
      args: {},
    }),
  )

  const second = sidecar.handle(
    request({
      request_type: "CheckAction",
      tool: "github.issues.read",
      resource: "org/repo",
      args: {},
    }),
  )

  assert.equal(first.allowed, true)
  assert.equal(second.allowed, true)
})

test("S11 allow: a tool outside the manifest is refused during an outage", () => {
  const { sidecar } = setup({ bundle: signedBundle() })

  const decision = sidecar.handle(
    request({
      request_type: "CheckAction",
      tool: "github.repo.delete",
      resource: "org/repo",
      args: {},
    }),
  )

  assert.equal(decision.allowed, false)
  assert.equal(decision.allowed === false && decision.reason, "tool_not_in_manifest")
})

// --- S12: fail closed ---------------------------------------------------------------

test("S12 deny: with no bundle ever loaded, every action is refused", () => {
  const { sidecar } = setup({})

  const decision = sidecar.handle(
    request({
      request_type: "CheckAction",
      tool: "github.issues.read",
      resource: "org/repo",
      args: {},
    }),
  )

  assert.deepEqual(
    { allowed: decision.allowed, reason: decision.allowed === false && decision.reason },
    { allowed: false, reason: "no_valid_policy" },
  )
})

test("S12 deny: an expired lease refuses every action", () => {
  // Offered while valid, then the clock advances past expiry. This is the realistic
  // outage case: the lease was good until it was not.
  const { sidecar } = setup({
    bundle: signedBundle({ expires_at: "2026-10-03T13:00:00.000Z" }),
    offerAt: new Date("2026-10-03T12:30:00.000Z"),
    now: new Date("2026-10-03T14:00:00.000Z"),
  })

  const decision = sidecar.handle(
    request({
      request_type: "CheckAction",
      tool: "github.issues.read",
      resource: "org/repo",
      args: {},
    }),
  )

  assert.equal(decision.allowed, false)
  assert.equal(decision.allowed === false && decision.reason, "policy_expired")
})

test("S12 deny: a tampered bundle never replaces a valid lease", () => {
  const { lease } = setup({ bundle: signedBundle() })

  const tampered = structuredClone(signedBundle())
  tampered.body.tool_manifest[0] = {
    tool: "github.repo.delete",
    grant: "grant://github/org/repo/**",
  }

  const outcome = lease.offer(tampered, now)

  assert.equal(outcome.accepted, false)
  assert.equal(lease.state(now).kind, "active")
})

test("S12 deny: an older signed bundle cannot roll the lease back", () => {
  const { lease } = setup({ bundle: signedBundle({ version: 200 }) })

  const outcome = lease.offer(signedBundle({ version: 150 }), now)

  assert.equal(outcome.accepted, false)
  assert.equal(outcome.reason, "version_rollback")
  assert.equal(lease.activatedVersion, 200)
})

test("S12 deny: a bundle for another tenant is refused by the lease", () => {
  const { lease } = setup({})

  const outcome = lease.offer(signedBundle({ tenant_id: "t_other" }), now)

  assert.equal(outcome.accepted, false)
  assert.equal(lease.state(now).kind, "empty")
})

test("S12 deny: an unsupported protocol version is refused", () => {
  const { sidecar } = setup({ bundle: signedBundle() })

  const decision = sidecar.handle(
    request({
      protocol_version: "v99.0",
      request_type: "CheckAction",
      tool: "github.issues.read",
      resource: "org/repo",
      args: {},
    }),
  )

  assert.equal(decision.allowed, false)
  assert.equal(
    decision.allowed === false && decision.reason,
    "protocol_version_unsupported",
  )
})

test("S12 deny: a malformed request is refused rather than default-allowed", () => {
  const { sidecar } = setup({ bundle: signedBundle() })

  const decision = sidecar.handle({ nonsense: true })

  assert.equal(decision.allowed, false)
})

test("S12 deny: an invalid identity token is refused", () => {
  const { sidecar } = setup({ bundle: signedBundle() })

  const decision = sidecar.handle(
    request({
      identity_token: { garbage: true },
      request_type: "CheckAction",
      tool: "github.issues.read",
      resource: "org/repo",
      args: {},
    }),
  )

  assert.equal(decision.allowed, false)
  assert.equal(decision.allowed === false && decision.reason, "identity_invalid")
})

// --- Grants, messages and permits ----------------------------------------------------

test("S6 deny: a grant outside the agent authority is refused", () => {
  const { sidecar } = setup({ bundle: signedBundle() })

  const decision = sidecar.handle(
    request({ request_type: "ResolveGrant", grant_uri: "grant://github/org/repo/**" }),
  )

  assert.equal(decision.allowed, false)
  assert.equal(decision.allowed === false && decision.reason, "not_in_grant_scope")
})

test("S6 allow: a grant inside the agent authority resolves", () => {
  const { sidecar } = setup({ bundle: signedBundle() })

  const decision = sidecar.handle(
    request({ request_type: "ResolveGrant", grant_uri: GRANT_READ }),
  )

  assert.equal(decision.allowed, true)
})

test("S10 deny: a secret message to another agent is refused", () => {
  const { sidecar } = setup({ bundle: signedBundle() })

  const decision = sidecar.handle(
    request({
      request_type: "CheckMessage",
      target_agent_id: "worker-1",
      labels: ["SECRET"],
    }),
  )

  assert.equal(decision.allowed, false)
  assert.equal(decision.allowed === false && decision.reason, "ifc_violation")
})

test("S10 allow: an internal message to another agent is permitted", () => {
  const { sidecar } = setup({ bundle: signedBundle() })

  const decision = sidecar.handle(
    request({
      request_type: "CheckMessage",
      target_agent_id: "worker-1",
      labels: ["INTERNAL"],
    }),
  )

  assert.equal(decision.allowed, true)
})

test("S7 allow: a permit is issued for a tool that requires one", () => {
  const { sidecar } = setup({ bundle: signedBundle(), withPermitIssuer: true })

  const decision = sidecar.handle(
    request({
      request_type: "RequestEffectPermit",
      tool: "github.pull-request.merge",
      resource: "org/repo#42",
      args: { number: 42, method: "squash" },
      sink_type: "file_store",
      data_labels: ["CONFIDENTIAL"],
    }),
  )

  assert.equal(decision.allowed, true)
  assert.ok(decision.allowed && decision.permit !== undefined)
})

test("S7 deny: no permit is issued when the sidecar has no issuer configured", () => {
  const { sidecar } = setup({ bundle: signedBundle(), withPermitIssuer: false })

  const decision = sidecar.handle(
    request({
      request_type: "RequestEffectPermit",
      tool: "github.pull-request.merge",
      resource: "org/repo#42",
      args: { number: 42, method: "squash" },
      sink_type: "file_store",
      data_labels: ["CONFIDENTIAL"],
    }),
  )

  assert.equal(decision.allowed, false)
  // The request is well formed and the tool does require a permit, so the refusal must
  // come from the missing issuer rather than from an earlier check.
  assert.equal(decision.reason, "sidecar_policy_denied")
  if (decision.allowed === false) {
    assert.equal(decision.detail, "no permit issuer configured")
  }
})

// --- Telemetry ----------------------------------------------------------------------

test("S11 allow: every decision emits telemetry", () => {
  const { sidecar } = setup({ bundle: signedBundle() })

  sidecar.handle(
    request({
      request_type: "CheckAction",
      tool: "github.issues.read",
      resource: "org/repo",
      args: {},
    }),
  )

  sidecar.handle(
    request({
      request_type: "CheckAction",
      tool: "github.repo.delete",
      resource: "org/repo",
      args: {},
    }),
  )

  assert.equal(sidecar.telemetry.length, 2)
  assert.equal(sidecar.telemetry[0]?.allowed, true)
  assert.equal(sidecar.telemetry[1]?.allowed, false)
})