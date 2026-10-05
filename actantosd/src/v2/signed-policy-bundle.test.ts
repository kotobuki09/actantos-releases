import assert from "node:assert/strict"
import test from "node:test"

import {
  ed25519,
  type SigningKeyPair,
} from "./signature.ts"
import {
  signPolicyBundle,
  verifyPolicyBundle,
  type PolicyBundleBody,
} from "./signed-policy-bundle.ts"

/**
 * Conformance tests for invariant S11 (local enforcement under a valid signed policy
 * lease) and S12 (fail closed on unverifiable security state).
 *
 * Each test states an invariant, exercises the deny or bypass path, and checks the
 * resulting outcome rather than an internal detail.
 */

const ISSUER_ID = "issuer-primary"

const keyPair: SigningKeyPair = ed25519.generateKeyPair()

const trustedIssuerKeys = new Map([[ISSUER_ID, keyPair.publicKeyPem]])

const issuedAt = "2026-10-03T00:00:00.000Z"
const expiresAt = "2026-10-04T00:00:00.000Z"
const withinWindow = new Date("2026-10-03T12:00:00.000Z")

const baseBody = (): PolicyBundleBody => ({
  bundle_id: "bundle-100",
  tenant_id: "t_demo",
  version: 100,
  issued_at: issuedAt,
  expires_at: expiresAt,
  policies: [
    { policy_id: "p1", cedar: 'permit(principal, action, resource);' },
  ],
  agent_profile: {
    agent_id: "reviewer-1",
    allowed_tools: ["code.search", "code.read"],
    max_delegation_depth: 2,
  },
  tool_manifest: [
    { tool: "github.issues.read", grant: "grant://github/org/repo/issues/read" },
  ],
  network_rules: [{ host: "api.github.com", action: "allow_via_egress_gateway" }],
  data_clearance: "CONFIDENTIAL",
  risk_profile: {
    risk_level: "medium",
    requires_effect_permit: ["github.pull-request.merge"],
  },
  trusted_issuers: [ISSUER_ID],
})

const signedBundle = (body: PolicyBundleBody = baseBody()) =>
  signPolicyBundle(
    body,
    { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
    keyPair,
  )

// --- Allow path -------------------------------------------------------------------

test("S11 allow: a correctly signed, in-window, correct-tenant bundle is accepted", () => {
  const result = verifyPolicyBundle(signedBundle(), {
    expectedTenantId: "t_demo",
    trustedIssuerKeys,
    now: withinWindow,
  })

  assert.equal(result.accepted, true)
  assert.equal(
    result.accepted && result.body.bundle_id,
    "bundle-100",
  )
})

test("S11 allow: canonical signing is stable under property reordering", () => {
  const body = baseBody()
  const reordered = Object.fromEntries(
    Object.entries(body).reverse(),
  ) as unknown as PolicyBundleBody

  const first = signedBundle(body)
  const second = signPolicyBundle(
    reordered,
    { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
    keyPair,
  )

  assert.equal(first.signature.value, second.signature.value)
})

// --- Deny / bypass paths -----------------------------------------------------------

test("S12 deny: a bundle signed by an untrusted issuer is refused", () => {
  const rogue = ed25519.generateKeyPair()

  const result = verifyPolicyBundle(signedBundle(), {
    expectedTenantId: "t_demo",
    trustedIssuerKeys: new Map([[ISSUER_ID, rogue.publicKeyPem]]),
    now: withinWindow,
  })

  assert.deepEqual(result, { accepted: false, reason: "invalid_signature" })
})

test("S12 deny: an issuer absent from the sidecar trust store is refused", () => {
  const result = verifyPolicyBundle(signedBundle(), {
    expectedTenantId: "t_demo",
    trustedIssuerKeys: new Map(),
    now: withinWindow,
  })

  assert.deepEqual(result, { accepted: false, reason: "untrusted_issuer" })
})

test("S12 deny: an issuer omitted from the bundle's own trusted_issuers list is refused", () => {
  const body = baseBody()
  body.trusted_issuers = ["some-other-issuer"]

  const result = verifyPolicyBundle(
    signPolicyBundle(
      body,
      { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
      keyPair,
    ),
    { expectedTenantId: "t_demo", trustedIssuerKeys, now: withinWindow },
  )

  assert.deepEqual(result, { accepted: false, reason: "issuer_not_listed" })
})

test("S12 deny: tampering with the signed body invalidates the signature", () => {
  const bundle = signedBundle()

  // Attacker widens the grant after the control plane signed the bundle.
  const tampered = structuredClone(bundle)
  tampered.body.tool_manifest[0]!.grant = "grant://github/org/repo/pull-request/merge"

  const result = verifyPolicyBundle(tampered, {
    expectedTenantId: "t_demo",
    trustedIssuerKeys,
    now: withinWindow,
  })

  assert.deepEqual(result, { accepted: false, reason: "invalid_signature" })
})

test("S12 deny: tampering with the signature value is refused", () => {
  const bundle = signedBundle()
  const tampered = structuredClone(bundle)
  tampered.signature.value = Buffer.from("not-a-signature").toString("base64")

  const result = verifyPolicyBundle(tampered, {
    expectedTenantId: "t_demo",
    trustedIssuerKeys,
    now: withinWindow,
  })

  assert.deepEqual(result, { accepted: false, reason: "invalid_signature" })
})

test("S12 deny: a malformed bundle is refused without throwing", () => {
  const result = verifyPolicyBundle(
    { body: { bundle_id: "x" }, signature: { algorithm: "ed25519" } },
    { expectedTenantId: "t_demo", trustedIssuerKeys, now: withinWindow },
  )

  assert.deepEqual(result, { accepted: false, reason: "malformed_bundle" })
})

test("S12 deny: an unknown signature algorithm is refused, never downgraded", () => {
  const bundle = signedBundle()
  const downgraded = {
    body: bundle.body,
    signature: { ...bundle.signature, algorithm: "none" },
  }

  const result = verifyPolicyBundle(downgraded, {
    expectedTenantId: "t_demo",
    trustedIssuerKeys,
    now: withinWindow,
  })

  assert.deepEqual(result, { accepted: false, reason: "unsupported_algorithm" })
})

test("S10 deny: a bundle for another tenant is refused for this sidecar", () => {
  const result = verifyPolicyBundle(signedBundle(), {
    expectedTenantId: "t_other",
    trustedIssuerKeys,
    now: withinWindow,
  })

  assert.deepEqual(result, { accepted: false, reason: "tenant_mismatch" })
})

test("S12 deny: an expired bundle is refused", () => {
  const result = verifyPolicyBundle(signedBundle(), {
    expectedTenantId: "t_demo",
    trustedIssuerKeys,
    now: new Date("2026-10-05T00:00:00.000Z"),
  })

  assert.deepEqual(result, { accepted: false, reason: "expired" })
})

test("S12 deny: a bundle whose issued_at is in the future is refused", () => {
  const result = verifyPolicyBundle(signedBundle(), {
    expectedTenantId: "t_demo",
    trustedIssuerKeys,
    now: new Date("2026-09-01T00:00:00.000Z"),
  })

  assert.deepEqual(result, { accepted: false, reason: "not_yet_valid" })
})

test("S12 deny: an expiry window that ends before it starts is refused", () => {
  const body = baseBody()
  body.expires_at = body.issued_at

  const result = verifyPolicyBundle(
    signPolicyBundle(
      body,
      { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
      keyPair,
    ),
    { expectedTenantId: "t_demo", trustedIssuerKeys, now: withinWindow },
  )

  assert.deepEqual(result, { accepted: false, reason: "invalid_expiry_window" })
})

test("S9 deny: replaying an older genuinely signed bundle is refused", () => {
  // The bundle is authentic and unexpired, but it is older than what the sidecar
  // already activated. A signature alone would not catch this.
  const result = verifyPolicyBundle(signedBundle(), {
    expectedTenantId: "t_demo",
    trustedIssuerKeys,
    now: withinWindow,
    minimumVersion: 100,
  })

  assert.deepEqual(result, { accepted: false, reason: "version_rollback" })
})

test("S9 allow: a strictly newer bundle supersedes the activated one", () => {
  const body = baseBody()
  body.version = 101

  const result = verifyPolicyBundle(
    signPolicyBundle(
      body,
      { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
      keyPair,
    ),
    {
      expectedTenantId: "t_demo",
      trustedIssuerKeys,
      now: withinWindow,
      minimumVersion: 100,
    },
  )

  assert.equal(result.accepted, true)
  assert.equal(result.accepted && result.body.version, 101)
})