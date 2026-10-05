import assert from "node:assert/strict"
import test from "node:test"

import {
  resolveDelegation,
  scopeIsNarrowerThan,
  signDelegationLink,
  type DelegationLink,
} from "./delegation.ts"
import { ed25519 } from "./signature.ts"
import {
  buildSpiffeId,
  mintWorkloadIdentity,
  signWorkloadIdentity,
  verifyWorkloadIdentity,
} from "./workload-identity.ts"

/**
 * Conformance tests for S4 (distinct short-lived workload identity), S5 (non-transitive
 * trust) and S6 (delegation may narrow but never increase authority).
 */

const ISSUER_ID = "issuer-primary"
const keyPair = ed25519.generateKeyPair()
const trustedIssuerKeys = new Map([[ISSUER_ID, keyPair.publicKeyPem]])

const now = new Date("2026-10-03T12:00:00.000Z")

// --- Workload identity --------------------------------------------------------------

test("S4 allow: a freshly minted identity verifies and carries the expected SPIFFE id", () => {
  const identity = mintWorkloadIdentity({
    tenantId: "t_demo",
    agentId: "reviewer-1",
    issuedAt: now,
  })

  const token = signWorkloadIdentity(
    identity,
    { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
    keyPair,
  )

  const result = verifyWorkloadIdentity(token, {
    trustedIssuerKeys,
    expectedTenantId: "t_demo",
    now,
  })

  assert.equal(result.accepted, true)
  assert.equal(
    result.accepted && result.identity.spiffe_id,
    "spiffe://actantos.local/tenant/t_demo/agent/reviewer-1",
  )
})

test("S4 allow: each minting produces a distinct identity", () => {
  const first = mintWorkloadIdentity({ tenantId: "t_demo", agentId: "a", issuedAt: now })
  const second = mintWorkloadIdentity({ tenantId: "t_demo", agentId: "a", issuedAt: now })

  assert.notEqual(first.nonce, second.nonce)
})

test("S4 deny: an expired identity is refused", () => {
  const identity = mintWorkloadIdentity({
    tenantId: "t_demo",
    agentId: "reviewer-1",
    issuedAt: now,
    ttlMs: 60_000,
  })

  const token = signWorkloadIdentity(
    identity,
    { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
    keyPair,
  )

  const result = verifyWorkloadIdentity(token, {
    trustedIssuerKeys,
    expectedTenantId: "t_demo",
    now: new Date("2026-10-03T13:00:00.000Z"),
  })

  assert.deepEqual(result, { accepted: false, reason: "expired" })
})

test("S4 deny: a revoked agent is refused even while its identity is unexpired", () => {
  const identity = mintWorkloadIdentity({ tenantId: "t_demo", agentId: "rogue", issuedAt: now })

  const token = signWorkloadIdentity(
    identity,
    { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
    keyPair,
  )

  const result = verifyWorkloadIdentity(token, {
    trustedIssuerKeys,
    expectedTenantId: "t_demo",
    now,
    revokedAgentIds: new Set(["rogue"]),
  })

  assert.deepEqual(result, { accepted: false, reason: "revoked" })
})

test("S4 deny: an identity for another tenant is refused", () => {
  const identity = mintWorkloadIdentity({ tenantId: "t_other", agentId: "a", issuedAt: now })

  const token = signWorkloadIdentity(
    identity,
    { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
    keyPair,
  )

  const result = verifyWorkloadIdentity(token, {
    trustedIssuerKeys,
    expectedTenantId: "t_demo",
    now,
  })

  assert.deepEqual(result, { accepted: false, reason: "tenant_mismatch" })
})

test("S4 deny: swapping the claimed agent id breaks the SPIFFE id binding", () => {
  const identity = mintWorkloadIdentity({ tenantId: "t_demo", agentId: "reviewer-1", issuedAt: now })

  const token = signWorkloadIdentity(
    identity,
    { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
    keyPair,
  )

  // Attacker repoints the SPIFFE id at another agent while keeping the signed claims.
  const forged = {
    ...token,
    identity: { ...token.identity, spiffe_id: buildSpiffeId("t_demo", "reviewer-2") },
  }

  const result = verifyWorkloadIdentity(forged, {
    trustedIssuerKeys,
    expectedTenantId: "t_demo",
    now,
  })

  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "invalid_signature")
})

test("S4 deny: an identity signed by an untrusted issuer is refused", () => {
  const rogue = ed25519.generateKeyPair()
  const identity = mintWorkloadIdentity({ tenantId: "t_demo", agentId: "a", issuedAt: now })

  const token = signWorkloadIdentity(
    identity,
    { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
    rogue,
  )

  const result = verifyWorkloadIdentity(token, {
    trustedIssuerKeys,
    expectedTenantId: "t_demo",
    now,
  })

  assert.deepEqual(result, { accepted: false, reason: "invalid_signature" })
})

// --- Scope subset algebra -----------------------------------------------------------

const covers = (parent: string, child: string): boolean =>
  scopeIsNarrowerThan([child], [parent])

test("S6 allow: identical scopes are a subset", () => {
  assert.equal(covers("grant://github/org/repo/issues/read", "grant://github/org/repo/issues/read"), true)
})

test("S6 allow: a trailing ** parent covers deeper literal children", () => {
  assert.equal(covers("grant://github/org/repo/**", "grant://github/org/repo/issues/read"), true)
  assert.equal(covers("grant://github/org/**", "grant://github/org/repo/pull-request/merge"), true)
})

test("S6 allow: a * parent segment covers one literal child segment", () => {
  assert.equal(covers("grant://github/org/repo/*", "grant://github/org/repo/issues"), true)
  assert.equal(covers("grant://github/org/*/**", "grant://github/org/repo/**"), true)
})

test("S6 allow: a child shorter than the parent is narrower", () => {
  assert.equal(covers("grant://github/org/repo/**", "grant://github/org/repo"), true)
})

test("S6 deny: a literal parent segment cannot cover a child * ", () => {
  assert.equal(covers("grant://github/org/repo/issues", "grant://github/org/repo/*"), false)
})

test("S6 deny: a child ** under a parent * is a widening, not a narrowing", () => {
  // `grant://github/org/repo/**` matches arbitrarily deep paths; the parent `*` matches
  // exactly one segment. Treating this as a subset would widen authority silently.
  assert.equal(covers("grant://github/org/repo/*", "grant://github/org/repo/**"), false)
})

test("S6 deny: a child ** under a literal parent is refused", () => {
  assert.equal(covers("grant://github/org/repo/issues", "grant://github/org/repo/**"), false)
})

test("S6 deny: a child deeper than a non-** parent is refused", () => {
  assert.equal(covers("grant://github/org/repo", "grant://github/org/repo/issues/read"), false)
})

test("S6 deny: differing literal segments are not covered even at equal depth", () => {
  // Regression: a subset test that only compared wildcards would treat
  // `issues/read` as covering `pull-request/merge` because both paths are four segments.
  assert.equal(
    covers("grant://github/org/repo/issues/read", "grant://github/org/repo/pull-request/merge"),
    false,
  )
  assert.equal(
    covers("grant://github/org/repo/issues/read", "grant://github/org/repo/issues/write"),
    false,
  )
})

test("S6 deny: a different provider is never covered", () => {
  assert.equal(covers("grant://github/**", "grant://aws/s3/project-a/read"), false)
})

test("S6 deny: an unparseable parent pattern grants nothing", () => {
  assert.equal(scopeIsNarrowerThan(["grant://github/org/repo/issues/read"], ["not-a-grant"]), false)
})

test("S6 deny: an unparseable child pattern is refused", () => {
  assert.equal(scopeIsNarrowerThan(["https://example.com/"], ["grant://github/**"]), false)
})

/**
 * A mixed parent list must fail closed as a whole, not merely drop the malformed entry.
 *
 * Mutation testing found this gap. Removing the guard
 * `parsedParent.length !== parent.length` changed no test, because a parent list that is
 * *entirely* unparseable still denies — `parsedParent` becomes empty and `.some()` is false.
 * The guard only decides the outcome when a list mixes a valid grant with a malformed one.
 * In that case dropping the guard silently returns true: authority derived from a scope
 * entry that was never a valid grant.
 */
test("S6 deny: a malformed entry poisons an otherwise-valid parent scope", () => {
  assert.equal(
    scopeIsNarrowerThan(
      ["grant://github/org/repo/issues/read"],
      ["grant://github/org/repo/**", "not-a-grant"],
    ),
    false,
    "a mixed parent list must not be narrowed by ignoring its malformed entries",
  )
})

test("S6 deny: every malformed-parent shape fails closed, not just a non-grant scheme", () => {
  const malformedParents = [
    ["not-a-grant"],
    ["grant://"],
    ["grant://github/**", "not-a-grant"],
    ["grant://github/**", "https://example.com/"],
    ["grant://github/**", ""],
    ["grant://github/**", "**"],
  ]

  for (const parent of malformedParents) {
    assert.equal(
      scopeIsNarrowerThan(["grant://github/org/repo/issues/read"], parent),
      false,
      `parent scope ${JSON.stringify(parent)} must not confer authority`,
    )
  }
})

// --- Delegation chains -------------------------------------------------------------

const link = (
  overrides: Partial<DelegationLink>,
): DelegationLink => ({
  delegation_id: "d-1",
  tenant_id: "t_demo",
  delegator_spiffe_id: buildSpiffeId("t_demo", "orchestrator"),
  delegatee_spiffe_id: buildSpiffeId("t_demo", "reviewer"),
  scope: ["grant://github/org/repo/issues/read"],
  depth: 1,
  issued_at: "2026-10-03T11:00:00.000Z",
  expires_at: "2026-10-03T13:00:00.000Z",
  ...overrides,
})

const signLink = (overrides: Partial<DelegationLink>) =>
  signDelegationLink(
    link(overrides),
    { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
    keyPair,
  )

test("S6 allow: a single narrowing delegation inside the root scope is accepted", () => {
  const result = resolveDelegation([signLink({})], {
    tenantId: "t_demo",
    rootScope: ["grant://github/org/repo/**"],
    trustedIssuerKeys,
    now,
  })

  assert.equal(result.accepted, true)
  assert.deepEqual(
    result.accepted && result.effectiveScope,
    ["grant://github/org/repo/issues/read"],
  )
})

test("S6 deny: a delegation that exceeds the root delegator authority is refused", () => {
  const result = resolveDelegation(
    [signLink({ scope: ["grant://github/org/repo/**"] })],
    {
      tenantId: "t_demo",
      rootScope: ["grant://github/org/repo/issues/read"],
      trustedIssuerKeys,
      now,
    },
  )

  assert.deepEqual(result, { accepted: false, reason: "root_scope_exceeded" })
})

test("S5 deny: a chain cannot widen authority at an intermediate hop", () => {
  // orchestrator -> reviewer is narrow; reviewer -> worker then tries to claim a wider
  // scope. Checking only the final hop against the previous hop would pass this.
  const hop1 = signLink({
    delegation_id: "d-1",
    delegatee_spiffe_id: buildSpiffeId("t_demo", "reviewer"),
    scope: ["grant://github/org/repo/issues/read"],
    depth: 1,
  })

  const hop2 = signLink({
    delegation_id: "d-2",
    delegator_spiffe_id: buildSpiffeId("t_demo", "reviewer"),
    delegatee_spiffe_id: buildSpiffeId("t_demo", "worker"),
    scope: ["grant://github/org/repo/**"],
    depth: 2,
  })

  const result = resolveDelegation([hop1, hop2], {
    tenantId: "t_demo",
    rootScope: ["grant://github/org/repo/issues/read"],
    trustedIssuerKeys,
    now,
  })

  assert.equal(result.accepted, false)
})

test("S5 deny: a broken chain linkage is refused", () => {
  const hop1 = signLink({
    delegation_id: "d-1",
    delegatee_spiffe_id: buildSpiffeId("t_demo", "reviewer"),
    depth: 1,
  })

  const hop2 = signLink({
    delegation_id: "d-2",
    delegator_spiffe_id: buildSpiffeId("t_demo", "someone-else"),
    delegatee_spiffe_id: buildSpiffeId("t_demo", "worker"),
    depth: 2,
  })

  const result = resolveDelegation([hop1, hop2], {
    tenantId: "t_demo",
    rootScope: ["grant://github/org/repo/**"],
    trustedIssuerKeys,
    now,
  })

  assert.deepEqual(result, { accepted: false, reason: "malformed" })
})

test("S5 deny: self-delegation is refused", () => {
  const self = buildSpiffeId("t_demo", "reviewer")

  const result = resolveDelegation(
    [
      signLink({
        delegator_spiffe_id: self,
        delegatee_spiffe_id: self,
      }),
    ],
    {
      tenantId: "t_demo",
      rootScope: ["grant://github/org/repo/**"],
      trustedIssuerKeys,
      now,
    },
  )

  assert.deepEqual(result, { accepted: false, reason: "self_delegation" })
})

test("S6 deny: excessive delegation depth is refused", () => {
  const result = resolveDelegation(
    [signLink({ delegation_id: "d-1", depth: 9 })],
    {
      tenantId: "t_demo",
      rootScope: ["grant://github/org/repo/**"],
      trustedIssuerKeys,
      now,
      maxDepth: 3,
    },
  )

  assert.deepEqual(result, { accepted: false, reason: "depth_exceeded" })
})

test("S6 deny: an expired delegation is refused", () => {
  const result = resolveDelegation(
    [signLink({ expires_at: "2026-10-03T11:30:00.000Z" })],
    {
      tenantId: "t_demo",
      rootScope: ["grant://github/org/repo/**"],
      trustedIssuerKeys,
      now,
    },
  )

  assert.deepEqual(result, { accepted: false, reason: "expired" })
})

test("S6 deny: a cross-tenant delegation is refused", () => {
  const result = resolveDelegation([signLink({ tenant_id: "t_other" })], {
    tenantId: "t_demo",
    rootScope: ["grant://github/org/repo/**"],
    trustedIssuerKeys,
    now,
  })

  assert.deepEqual(result, { accepted: false, reason: "tenant_mismatch" })
})

test("S6 deny: a tampered delegation scope invalidates the signature", () => {
  const signed = signLink({})
  const tampered = {
    link: {
      ...signed.link,
      scope: ["grant://github/org/repo/pull-request/merge"],
    },
  }

  const result = resolveDelegation([tampered], {
    tenantId: "t_demo",
    rootScope: ["grant://github/org/repo/**"],
    trustedIssuerKeys,
    now,
  })

  assert.deepEqual(result, { accepted: false, reason: "invalid_signature" })
})

test("S5 allow: a two-hop chain that only narrows is accepted", () => {
  const hop1 = signLink({
    delegation_id: "d-1",
    delegatee_spiffe_id: buildSpiffeId("t_demo", "reviewer"),
    scope: ["grant://github/org/repo/**"],
    depth: 1,
  })

  const hop2 = signLink({
    delegation_id: "d-2",
    delegator_spiffe_id: buildSpiffeId("t_demo", "reviewer"),
    delegatee_spiffe_id: buildSpiffeId("t_demo", "worker"),
    scope: ["grant://github/org/repo/issues/read"],
    depth: 2,
  })

  const result = resolveDelegation([hop1, hop2], {
    tenantId: "t_demo",
    rootScope: ["grant://github/org/repo/**"],
    trustedIssuerKeys,
    now,
  })

  assert.equal(result.accepted, true)
  assert.deepEqual(
    result.accepted && result.effectiveScope,
    ["grant://github/org/repo/issues/read"],
  )
})