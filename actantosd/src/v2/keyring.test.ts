import assert from "node:assert/strict"
import { test } from "node:test"

import {
  activeKeyIds,
  keyFingerprint,
  resolveIssuerKeys,
  toKeyring,
  verifyAgainstIssuerKeys,
  type TrustedKeyring,
} from "./keyring.ts"
import { ed25519 } from "./signature.ts"
import { signPolicyBundle, policyBundleBodySchema, verifyPolicyBundle } from "./signed-policy-bundle.ts"
import { PolicyLease } from "./policy-lease.ts"
import { signRevocationSnapshot, verifyRevocationSnapshot, RevocationStore, MAX_REVOCATION_ENTRIES } from "./revocation-snapshot.ts"

/**
 * Key rotation (phase O).
 *
 * Before this, `trustedIssuerKeys` was `Map<issuerId, pem>`: one key per issuer, no validity
 * window, captured at construction and never reassigned. An issuer therefore could not rotate at
 * all — it either kept the old key and had every new document refused, or swapped the map and had
 * every document signed by the previous key stop verifying. Both failures looked identical:
 * `invalid_signature` under one unchanging issuer id.
 *
 * These tests pin the rotation lifecycle, and pin the two things it must *not* do.
 */

const ISSUER = "issuer-primary"
const TENANT = "t_demo"
const NOW = new Date("2026-10-04T12:00:00.000Z")
const at = (offsetMs: number): string => new Date(NOW.getTime() + offsetMs).toISOString()

const oldKeys = ed25519.generateKeyPair()
const newKeys = ed25519.generateKeyPair()
const rogueKeys = ed25519.generateKeyPair()

const bundleBody = (version: number) =>
  policyBundleBodySchema.parse({
    bundle_id: "bundle-1",
    tenant_id: TENANT,
    version,
    issued_at: at(-60_000),
    expires_at: at(3_600_000),
    policies: [{ policy_id: "p1", cedar: "permit(principal, action, resource);" }],
    agent_profile: { agent_id: "reviewer-1", allowed_tools: ["github.issues.read"], max_delegation_depth: 1 },
    tool_manifest: [{ tool: "github.issues.read", grant: "grant://github/org/repo/issues/read" }],
    network_rules: [{ host: "api.github.com", action: "allow_via_egress_gateway" }],
    data_clearance: "CONFIDENTIAL",
    risk_profile: { risk_level: "medium", requires_effect_permit: ["github.pull-request.merge"] },
    trusted_issuers: [ISSUER],
  })

const signedBy = (keyPair: { privateKeyPem: string }, version: number) =>
  signPolicyBundle(bundleBody(version), { algorithm: "ed25519", issuer_id: ISSUER, value: "" }, keyPair as never)

const key = (keyId: string, pem: string, window: { notBefore?: Date; notAfter?: Date } = {}) => ({
  keyId,
  publicKeyPem: pem,
  ...(window.notBefore === undefined ? {} : { notBefore: window.notBefore }),
  ...(window.notAfter === undefined ? {} : { notAfter: window.notAfter }),
})

// --- The plain map still means exactly what it always meant ---------------------------------------

test("Phase O: the historical single-key map is accepted and unchanged", () => {
  const trusted = new Map([[ISSUER, oldKeys.publicKeyPem]])
  const bundle = signedBy(oldKeys, 1)

  assert.equal(
    verifyPolicyBundle(bundle, { expectedTenantId: TENANT, trustedIssuerKeys: trusted, now: NOW }).accepted,
    true,
  )
  assert.equal(
    verifyPolicyBundle(signedBy(newKeys, 1), { expectedTenantId: TENANT, trustedIssuerKeys: trusted, now: NOW })
      .accepted,
    false,
  )
})

test("Phase O: toKeyring round-trips a single-key map", () => {
  const pem = oldKeys.publicKeyPem
  const resolved = resolveIssuerKeys(toKeyring(new Map([[ISSUER, pem]])), ISSUER, NOW)

  assert.deepEqual(resolved.map((entry) => entry.publicKeyPem), [pem])
  // The key id is derived, so a plain map has no operator-chosen id to report.
  assert.equal(resolved[0]?.keyId, keyFingerprint(pem))
})

// --- Rotation, with an overlap window -----------------------------------------------------------

/**
 * The old key's window closes well before the bundle's own expiry, so a test can observe the
 * key boundary without the document's own expiry being the reason for the refusal. Getting this
 * wrong makes the test pass for the wrong reason, which is why it is a named constant.
 */
const OLD_KEY_RETIRES_AT = new Date(NOW.getTime() + 60_000)

const overlapping: TrustedKeyring = new Map([
  [
    ISSUER,
    [
      key("old", oldKeys.publicKeyPem, { notAfter: OLD_KEY_RETIRES_AT }),
      key("new", newKeys.publicKeyPem, { notBefore: new Date(NOW.getTime() - 3_600_000) }),
    ],
  ],
])

test("Phase O: during the overlap window a document from either key is accepted", () => {
  const options = { expectedTenantId: TENANT, trustedIssuerKeys: overlapping, now: NOW }

  assert.equal(verifyPolicyBundle(signedBy(oldKeys, 1), options).accepted, true, "old key must still work")
  assert.equal(verifyPolicyBundle(signedBy(newKeys, 1), options).accepted, true, "new key must work too")
})

test("Phase O: a document from an untrusted key is still refused during the overlap", () => {
  // The overlap widens who can *verify*, never who is trusted. An issuer is not made more
  // powerful by rotating.
  const result = verifyPolicyBundle(signedBy(rogueKeys, 1), {
    expectedTenantId: TENANT,
    trustedIssuerKeys: overlapping,
    now: NOW,
  })

  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "invalid_signature")
})

test("Phase O: once the old key's window closes, documents signed by it are refused", () => {
  const afterRetirement = new Date(OLD_KEY_RETIRES_AT.getTime() + 1)
  const options = { expectedTenantId: TENANT, trustedIssuerKeys: overlapping, now: afterRetirement }

  assert.equal(verifyPolicyBundle(signedBy(oldKeys, 1), options).accepted, false)
  assert.equal(verifyPolicyBundle(signedBy(newKeys, 1), options).accepted, true)
})

test("Phase O: a key whose window has not opened is refused", () => {
  const future = new Date(NOW.getTime() + 7_200_000)
  const ring: TrustedKeyring = new Map([
    [ISSUER, [key("future", newKeys.publicKeyPem, { notBefore: future })]],
  ])

  const result = verifyPolicyBundle(signedBy(newKeys, 1), {
    expectedTenantId: TENANT,
    trustedIssuerKeys: ring,
    now: NOW,
  })

  // No key is valid, which is reported as an untrusted issuer rather than a new reason.
  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "untrusted_issuer")
})

test("Phase O: an unusable clock does not make a bounded key current", () => {
  // Fail closed: a clock that cannot be read is not evidence that a key is inside its window.
  const ring: TrustedKeyring = new Map([
    [ISSUER, [key("bad", oldKeys.publicKeyPem, { notAfter: new Date(Number.NaN) })]],
  ])

  assert.deepEqual(resolveIssuerKeys(ring, ISSUER, NOW), [])
})

test("Phase O: activeKeyIds reports the overlap, so a rotation is observable", () => {
  assert.deepEqual(activeKeyIds(overlapping, ISSUER, NOW), ["old", "new"])
  assert.deepEqual(
    activeKeyIds(overlapping, ISSUER, new Date(OLD_KEY_RETIRES_AT.getTime() + 1)),
    ["new"],
  )
})

test("Phase O: verifyAgainstIssuerKeys names the key that verified", () => {
  const message = Buffer.from("canonical bytes")
  const signature = Buffer.from(ed25519.sign(message, newKeys.privateKeyPem))

  const verified = verifyAgainstIssuerKeys({
    trustedKeys: overlapping,
    issuerId: ISSUER,
    signedBytes: message,
    signature,
    algorithm: ed25519,
    now: NOW,
  })

  assert.equal(verified.verified, true)
  assert.equal(verified.verified === true && verified.keyId, "new")
})

test("Phase O: an unknown issuer resolves to no keys at all", () => {
  assert.deepEqual(resolveIssuerKeys(overlapping, "issuer-unknown", NOW), [])
})

// --- The fingerprint is a fingerprint -------------------------------------------------------------

test("Phase O: the key fingerprint is stable across PEM rewrapping", () => {
  const pem = oldKeys.publicKeyPem
  const rewrapped = pem
    .split("\n")
    .map((line) => `  ${line}`)
    .join("\n")

  assert.equal(keyFingerprint(rewrapped), keyFingerprint(pem))
})

test("Phase O: two different keys have different fingerprints", () => {
  assert.notEqual(keyFingerprint(oldKeys.publicKeyPem), keyFingerprint(newKeys.publicKeyPem))
})

// --- A running lease can actually rotate ---------------------------------------------------------

test("Phase O: a lease accepts a new key mid-flight without losing its rollback floor", () => {
  // The old failure mode: swapping keys meant constructing a new lease, which reset
  // #highestActivatedVersion to 0 and re-opened the replay of an older signed bundle.
  const lease = new PolicyLease({
    tenantId: TENANT,
    trustedIssuerKeys: new Map([[ISSUER, oldKeys.publicKeyPem]]),
  })

  assert.equal(lease.offer(signedBy(oldKeys, 5), NOW).accepted, true)

  lease.setTrustedKeys(overlapping)

  assert.equal(lease.offer(signedBy(newKeys, 6), NOW).accepted, true, "the rotated key must work")
  assert.equal(lease.activatedVersion, 6)

  // The floor survived the rotation, so replaying v5 is still refused.
  const replay = lease.offer(signedBy(newKeys, 5), NOW)
  assert.equal(replay.accepted, false)
  assert.equal(replay.reason, "version_rollback")
})

test("Phase O: an active lease reports the key that signed it", () => {
  const lease = new PolicyLease({
    tenantId: TENANT,
    trustedIssuerKeys: new Map([[ISSUER, oldKeys.publicKeyPem]]),
  })

  lease.offer(signedBy(oldKeys, 1), NOW)

  const state = lease.state(NOW)
  assert.equal(state.kind, "active")
  assert.equal(state.kind === "active" && state.signingKeyId, keyFingerprint(oldKeys.publicKeyPem))
})

test("Phase O: withdrawing every key does not tear down an active lease", () => {
  // Deliberate, and the reason is written down in the type. Refusing mid-lease would let anyone
  // who can push a key update deny service to a sidecar that is enforcing correctly, which is a
  // stronger attack than the withdrawal prevents. Expiry is the bound, and expiry is a property
  // of the signed body rather than of the keyring.
  const lease = new PolicyLease({
    tenantId: TENANT,
    trustedIssuerKeys: new Map([[ISSUER, oldKeys.publicKeyPem]]),
  })

  lease.offer(signedBy(oldKeys, 1), NOW)
  lease.setTrustedKeys(new Map())

  assert.equal(lease.state(NOW).kind, "active")
  // But a *new* document from that now-untrusted issuer is refused.
  assert.equal(lease.offer(signedBy(oldKeys, 2), NOW).accepted, false)
})

// --- Revocation rotates the same way -------------------------------------------------------------

const revocationBody = (version: number, count = 1) => ({
  snapshot_id: "snap-1",
  tenant_id: TENANT,
  version,
  issued_at: at(-60_000),
  expires_at: at(3_600_000),
  entries: Array.from({ length: count }, (_unused, index) => ({
    agent_id: `agent-${index}`,
    reason: "credential_compromised" as const,
    revoked_at: at(-30_000),
  })),
})

test("Phase O: a revocation snapshot verifies under either key during the overlap", () => {
  const options = { expectedTenantId: TENANT, trustedIssuerKeys: overlapping, now: NOW }

  assert.equal(
    verifyRevocationSnapshot(signRevocationSnapshot(revocationBody(1), { algorithm: "ed25519", issuer_id: ISSUER, value: "" }, oldKeys), options)
      .accepted,
    true,
  )
  assert.equal(
    verifyRevocationSnapshot(signRevocationSnapshot(revocationBody(1), { algorithm: "ed25519", issuer_id: ISSUER, value: "" }, newKeys), options)
      .accepted,
    true,
  )
})

test("Phase O: an applied revocation list is not cleared by a key withdrawal", () => {
  // The un-revocation rule, applied to rotation. A list that went empty when keys were
  // withdrawn would turn a rotation into a mass un-revocation.
  const store = new RevocationStore({
    tenantId: TENANT,
    trustedIssuerKeys: new Map([[ISSUER, oldKeys.publicKeyPem]]),
  })

  store.offer(
    signRevocationSnapshot(revocationBody(1), { algorithm: "ed25519", issuer_id: ISSUER, value: "" }, oldKeys),
    NOW,
  )
  store.setTrustedKeys(new Map())

  assert.equal(store.isAgentRevoked("agent-0", NOW).revoked, true)
})

// --- The size bound ------------------------------------------------------------------------------

test("Phase O: an oversized snapshot is refused as too_many_entries, not malformed", () => {
  const oversized = signRevocationSnapshot(
    revocationBody(1, MAX_REVOCATION_ENTRIES + 1),
    { algorithm: "ed25519", issuer_id: ISSUER, value: "" },
    oldKeys,
  )

  const result = verifyRevocationSnapshot(oversized, {
    expectedTenantId: TENANT,
    trustedIssuerKeys: new Map([[ISSUER, oldKeys.publicKeyPem]]),
    now: NOW,
  })

  // The reason names the cause. Before this the same document arrived as a frame-decoder
  // `overflowed`, which says the transport gave up and not why.
  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "too_many_entries")
})

test("Phase O: a snapshot at exactly the limit is accepted", () => {
  const atLimit = signRevocationSnapshot(
    revocationBody(1, MAX_REVOCATION_ENTRIES),
    { algorithm: "ed25519", issuer_id: ISSUER, value: "" },
    oldKeys,
  )

  assert.equal(
    verifyRevocationSnapshot(atLimit, {
      expectedTenantId: TENANT,
      trustedIssuerKeys: new Map([[ISSUER, oldKeys.publicKeyPem]]),
      now: NOW,
    }).accepted,
    true,
  )
})
