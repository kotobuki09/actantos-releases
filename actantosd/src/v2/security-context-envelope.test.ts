import assert from "node:assert/strict"
import test from "node:test"

import {
  EnvelopeVersionTracker,
  assessEnvelopeAuthority,
  authorityFromBundle,
  canonicalEnvelopeBytes,
  signSecurityContextEnvelope,
  verifySecurityContextEnvelope,
  type SecurityContext,
  type SecurityContextEnvelopeBody,
} from "./security-context-envelope.ts"
import { ed25519 } from "./signature.ts"
import { policyBundleBodySchema, type PolicyBundleBody } from "./signed-policy-bundle.ts"

/**
 * Conformance tests for the security context envelope.
 *
 * The load-bearing claim is not that a forged envelope is refused — that is the easy half and
 * any signature check gets it. It is that a **genuinely signed** envelope which widens
 * authority is refused anyway. The signing key here belongs to the same "control plane" that
 * signs the policy bundle, so every widening case below is a document the control plane
 * really did issue. Only the narrowing check stops them.
 */

const ISSUER_ID = "issuer-primary"
const keyPair = ed25519.generateKeyPair()
const trustedIssuerKeys = new Map([[ISSUER_ID, keyPair.publicKeyPem]])

const TENANT = "t_demo"
const AGENT = "reviewer-1"
const AGENT_SPIFFE = `spiffe://${TENANT}/${AGENT}`
const NONCE = "nonce-abc123"

const NOW = new Date("2026-10-04T12:00:00.000Z")
const WITHIN = (offsetMs: number): string =>
  new Date(NOW.getTime() + offsetMs).toISOString()

const baseContext = (): SecurityContext => ({
  data_clearance: "CONFIDENTIAL",
  grants: ["grant://github/org/repo/issues/read"],
  tools: ["github.issues.read"],
  network_hosts: ["api.github.com"],
  max_delegation_depth: 1,
})

const baseBody = (
  overrides: Partial<SecurityContextEnvelopeBody> = {},
): SecurityContextEnvelopeBody => ({
  envelope_id: "env-0001",
  tenant_id: TENANT,
  spiffe_id: AGENT_SPIFFE,
  nonce: NONCE,
  version: 1,
  issued_at: WITHIN(-60_000),
  expires_at: WITHIN(300_000),
  context: baseContext(),
  ...overrides,
})

const signedEnvelope = (
  overrides: Partial<SecurityContextEnvelopeBody> = {},
) =>
  signSecurityContextEnvelope(
    baseBody(overrides),
    { algorithm: "ed25519", issuer_id: ISSUER_ID },
    keyPair,
  )

const verify = (candidate: unknown, options: Record<string, unknown> = {}) =>
  verifySecurityContextEnvelope(candidate, {
    expectedTenantId: TENANT,
    trustedIssuerKeys,
    now: NOW,
    ...options,
  })

// --- The ceiling, read only from the signed bundle ------------------------------------------

const bundle = (overrides: Partial<PolicyBundleBody> = {}): PolicyBundleBody =>
  policyBundleBodySchema.parse({
    bundle_id: "bundle-1",
    tenant_id: TENANT,
    version: 1,
    issued_at: WITHIN(-60_000),
    expires_at: WITHIN(3_600_000),
    policies: [{ policy_id: "p1", cedar: 'permit(principal, action, resource);' }],
    agent_profile: {
      agent_id: AGENT,
      allowed_tools: ["github.issues.read", "github.pull-request.merge"],
      max_delegation_depth: 2,
    },
    tool_manifest: [
      { tool: "github.issues.read", grant: "grant://github/org/repo/issues/read" },
      { tool: "github.pull-request.merge", grant: "grant://github/org/repo/pull-request/merge" },
    ],
    network_rules: [{ host: "api.github.com", action: "allow_via_egress_gateway" }],
    data_clearance: "CONFIDENTIAL",
    risk_profile: { risk_level: "medium", requires_effect_permit: ["github.pull-request.merge"] },
    trusted_issuers: [ISSUER_ID],
    ...overrides,
  })

const ceiling = authorityFromBundle(bundle(), AGENT)

// --- Allow path ------------------------------------------------------------------------------

test("S6 allow: a correctly signed, in-window, correctly-bound envelope is accepted", () => {
  const result = verify(signedEnvelope(), { expectedNonce: NONCE, expectedSpiffeId: AGENT_SPIFFE })

  assert.equal(result.accepted, true)
})

test("S6 allow: a narrowing envelope is accepted against the ceiling", () => {
  const narrowed = baseContext()

  const assessment = assessEnvelopeAuthority(
    {
      data_clearance: "INTERNAL",
      grants: narrowed.grants,
      tools: ["github.issues.read"],
      network_hosts: [],
      max_delegation_depth: 0,
    },
    ceiling,
  )

  assert.equal(assessment.accepted, true)
})

test("S6 allow: an empty context narrows everything and is accepted", () => {
  const assessment = assessEnvelopeAuthority(
    { data_clearance: "PUBLIC", grants: [], tools: [], network_hosts: [], max_delegation_depth: 0 },
    ceiling,
  )

  assert.equal(assessment.accepted, true)
})

// --- A genuine signature is not sufficient ---------------------------------------------------

test("S6 deny: a genuinely signed envelope that widens grants is refused", () => {
  // A repository the bundle's manifest does not name. This document was really signed by
  // the trusted control-plane key, so only the narrowing check refuses it.
  const widened: SecurityContext = {
    ...baseContext(),
    grants: ["grant://github/org/other-repo/issues/read"],
  }

  const result = verify(signedEnvelope({ context: widened }))
  assert.equal(result.accepted, true, "the signature itself is valid")

  const assessment = assessEnvelopeAuthority(widened, ceiling)

  assert.equal(assessment.accepted, false)
  assert.equal(assessment.accepted === false && assessment.reason, "grant_widened")
})

test("S6 allow: a grant the ceiling does list is not a widening", () => {
  // The merge grant is in the bundle's manifest, so naming it narrows nothing. If this were
  // reported as `grant_widened` the control would be refusing legitimate work.
  const assessment = assessEnvelopeAuthority(
    { ...baseContext(), grants: ["grant://github/org/repo/pull-request/merge"] },
    ceiling,
  )

  assert.equal(assessment.accepted, true)
})

test("S6 deny: a genuinely signed envelope that widens tools is refused", () => {
  const assessment = assessEnvelopeAuthority(
    { ...baseContext(), tools: ["github.issues.write", "shell.exec"] },
    ceiling,
  )

  assert.equal(assessment.accepted, false)
  assert.equal(assessment.accepted === false && assessment.reason, "tool_widened")
})

test("S6 deny: a genuinely signed envelope naming an unlisted host is refused", () => {
  const assessment = assessEnvelopeAuthority(
    { ...baseContext(), network_hosts: ["api.github.com", "exfil.attacker.test"] },
    ceiling,
  )

  assert.equal(assessment.accepted, false)
  assert.equal(assessment.accepted === false && assessment.reason, "host_widened")
})

test("S10 deny: a genuinely signed envelope that raises its own clearance is refused", () => {
  const assessment = assessEnvelopeAuthority({ ...baseContext(), data_clearance: "SECRET" }, ceiling)

  assert.equal(assessment.accepted, false)
  assert.equal(assessment.accepted === false && assessment.reason, "clearance_widened")
})

test("S6 deny: a genuinely signed envelope that raises its own delegation depth is refused", () => {
  const assessment = assessEnvelopeAuthority({ ...baseContext(), max_delegation_depth: 5 }, ceiling)

  assert.equal(assessment.accepted, false)
  assert.equal(assessment.accepted === false && assessment.reason, "depth_widened")
})

test("clearance is ordered, so an equal clearance narrows nothing and is still accepted", () => {
  assert.equal(assessEnvelopeAuthority({ ...baseContext(), data_clearance: "CONFIDENTIAL" }, ceiling).accepted, true)
  assert.equal(assessEnvelopeAuthority({ ...baseContext(), data_clearance: "PII" }, ceiling).accepted, false)
})

test("the ceiling for another agent grants nothing, so any envelope is a widening", () => {
  // Reading the bundle's allowed_tools regardless of which agent the bundle names would
  // hand one agent the tools of another. The bundle is for reviewer-1; asking as
  // reviewer-2 must find an empty ceiling rather than reviewer-1's tools.
  const otherCeiling = authorityFromBundle(bundle(), "someone-else")

  assert.deepEqual(otherCeiling.tools, [])
  const assessment = assessEnvelopeAuthority(baseContext(), otherCeiling)

  assert.equal(assessment.accepted, false)
  assert.equal(assessment.accepted === false && assessment.reason, "tool_widened")
})

// --- Binding to the execution ---------------------------------------------------------------

test("S4 deny: an envelope from an earlier execution of the same agent is refused", () => {
  // The real shape of this attack. An agent reuses an envelope from a previous run of itself:
  // same identity, so the spiffe check passes, but a different execution's nonce. Phase H
  // made the nonce per-execution precisely so this copy stops working.
  const result = verify(signedEnvelope(), {
    expectedNonce: "nonce-of-a-different-execution",
    expectedSpiffeId: AGENT_SPIFFE,
  })

  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "nonce_mismatch")
})

test("S4 deny: when both agent and nonce differ, the agent mismatch is what is reported", () => {
  // Both checks refuse; only the reason differs. Identity is checked first because it is the
  // more useful thing to tell an operator — the envelope is for a different agent entirely.
  const result = verify(signedEnvelope(), {
    expectedNonce: "nonce-of-reviewer-2",
    expectedSpiffeId: `spiffe://${TENANT}/reviewer-2`,
  })

  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "identity_mismatch")
})

test("S4 deny: an envelope for a different agent is refused even with a matching nonce", () => {
  const result = verify(signedEnvelope(), { expectedSpiffeId: `spiffe://${TENANT}/reviewer-2` })

  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "identity_mismatch")
})

test("S9 deny: an older genuine envelope is refused as a version rollback", () => {
  const result = verify(signedEnvelope(), { minimumVersion: 1 })

  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "version_rollback")
})

test("EnvelopeVersionTracker only accepts strictly increasing versions, per agent", () => {
  const tracker = new EnvelopeVersionTracker()

  assert.equal(tracker.record(AGENT_SPIFFE, 1), true)
  assert.equal(tracker.record(AGENT_SPIFFE, 1), false, "the same version twice is a rollback")
  assert.equal(tracker.record(AGENT_SPIFFE, 0), false)
  assert.equal(tracker.record(AGENT_SPIFFE, 2), true)
  assert.equal(tracker.highestFor(AGENT_SPIFFE), 2)

  // A different agent is tracked separately, so one agent's version cannot retire another's.
  assert.equal(tracker.record(`spiffe://${TENANT}/reviewer-2`, 1), true)
  assert.equal(tracker.highestFor(`spiffe://${TENANT}/reviewer-2`), 1)
  assert.equal(tracker.highestFor(AGENT_SPIFFE), 2)
})

// --- Forgery and shape -----------------------------------------------------------------------

test("S12 deny: a tampered body is refused", () => {
  const envelope = signedEnvelope()
  const tampered = structuredClone(envelope) as unknown as {
    body: SecurityContextEnvelopeBody
  }
  tampered.body.context.grants = ["grant://github/org/repo/pull-request/merge"]

  const result = verify(tampered)

  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "invalid_signature")
})

test("S12 deny: a signature from an untrusted key is refused", () => {
  const otherKeys = ed25519.generateKeyPair()
  const forged = signSecurityContextEnvelope(
    baseBody(),
    { algorithm: "ed25519", issuer_id: ISSUER_ID },
    otherKeys,
  )

  const result = verify(forged)

  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "invalid_signature")
})

test("S12 deny: an unknown issuer id is refused before the key is looked up", () => {
  const forged = signSecurityContextEnvelope(
    baseBody(),
    { algorithm: "ed25519", issuer_id: "issuer-unknown" },
    keyPair,
  )

  const result = verify(forged)

  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "untrusted_issuer")
})

test("S12 deny: an unsupported algorithm is refused", () => {
  const result = verify({
    body: baseBody(),
    signature: { algorithm: "ml-dsa-44", issuer_id: ISSUER_ID, value: "AAAA" },
  })

  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "unsupported_algorithm")
})

test("S12 deny: another tenant's envelope is refused", () => {
  const result = verify(signedEnvelope({ tenant_id: "t_other" }))

  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "tenant_mismatch")
})

test("S12 deny: an expired envelope is refused", () => {
  const result = verify(
    signedEnvelope({ issued_at: WITHIN(-600_000), expires_at: WITHIN(-300_000) }),
  )

  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "expired")
})

test("S12 deny: an envelope that is not yet valid is refused", () => {
  const result = verify(
    signedEnvelope({ issued_at: WITHIN(60_000), expires_at: WITHIN(360_000) }),
  )

  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "not_yet_valid")
})

test("S12 deny: an expiry window that does not advance is refused", () => {
  const result = verify(
    signedEnvelope({ issued_at: WITHIN(60_000), expires_at: WITHIN(60_000) }),
  )

  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "invalid_expiry_window")
})

test("S12 deny: an unparseable date is refused", () => {
  const result = verify(signedEnvelope({ expires_at: "never" }))

  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "invalid_expiry_window")
})

test("S12 deny: a structurally wrong envelope is refused", () => {
  for (const candidate of [
    undefined,
    null,
    "not-an-envelope",
    {},
    { body: baseBody() },
    { body: { ...baseBody(), version: 0 }, signature: { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "AA" } },
    { body: { ...baseBody(), nonce: "" }, signature: { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "AA" } },
  ]) {
    const result = verify(candidate)

    assert.equal(result.accepted, false, `${JSON.stringify(candidate)} must be refused`)
    assert.equal(result.accepted === false && result.reason, "malformed_envelope")
  }
})

// --- Canonical bytes ---------------------------------------------------------------------------

test("canonical envelope bytes do not depend on property order", () => {
  const ordered = baseBody()
  const shuffled = {
    context: ordered.context,
    expires_at: ordered.expires_at,
    issued_at: ordered.issued_at,
    version: ordered.version,
    nonce: ordered.nonce,
    spiffe_id: ordered.spiffe_id,
    tenant_id: ordered.tenant_id,
    envelope_id: ordered.envelope_id,
  } as SecurityContextEnvelopeBody

  assert.deepEqual(canonicalEnvelopeBytes(ordered), canonicalEnvelopeBytes(shuffled))
})

test("a reordered body still verifies, because the signature covers canonical bytes", () => {
  const envelope = signedEnvelope()
  const reordered = {
    signature: envelope.signature,
    body: {
      context: envelope.body.context,
      expires_at: envelope.body.expires_at,
      issued_at: envelope.body.issued_at,
      version: envelope.body.version,
      nonce: envelope.body.nonce,
      spiffe_id: envelope.body.spiffe_id,
      tenant_id: envelope.body.tenant_id,
      envelope_id: envelope.body.envelope_id,
    },
  }

  assert.equal(verify(reordered).accepted, true)
})

test("two envelopes with different content do not share canonical bytes", () => {
  assert.notDeepEqual(
    canonicalEnvelopeBytes(baseBody()),
    canonicalEnvelopeBytes(baseBody({ nonce: "nonce-different" })),
  )
})