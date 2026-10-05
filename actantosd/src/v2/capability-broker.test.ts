import assert from "node:assert/strict"
import test from "node:test"

import {
  CapabilityBroker,
  assertNoCredentialsInResult,
  type CapabilityProvider,
  type CredentialProvider,
} from "./capability-broker.ts"
import { EvidenceChain, verifyEvidenceBundle } from "./evidence.ts"
import { createGitHubCapabilityProvider } from "./providers.ts"
import { ed25519 } from "./signature.ts"
import {
  buildSpiffeId,
  mintWorkloadIdentity,
  signWorkloadIdentity,
} from "./workload-identity.ts"

/**
 * Conformance tests for S1 (production credentials never enter agent reasoning context).
 *
 * The demonstration is structural: the broker is the boundary, and a provider that tries to
 * return a credential is refused rather than trusted.
 */

const ISSUER_ID = "issuer-primary"
const keyPair = ed25519.generateKeyPair()
const trustedIssuerKeys = new Map([[ISSUER_ID, keyPair.publicKeyPem]])

const TENANT = "t_demo"
const AGENT_ID = "reviewer-1"
const now = new Date("2026-10-03T12:00:00.000Z")

const identityToken = (agentId = AGENT_ID) =>
  signWorkloadIdentity(
    mintWorkloadIdentity({ tenantId: TENANT, agentId, issuedAt: now }),
    { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
    keyPair,
  )

const GRANT_READ = "grant://github/org/repo/issues/read"
const GRANT_MERGE = "grant://github/org/repo/pull-request/merge"

const recordingCredentialProvider = (
  log: string[],
): CredentialProvider => ({
  id: "test-credential",
  async obtain() {
    log.push("obtain")
    return {
      value: "ghp_super_secret_token",
      expiresAt: new Date(now.getTime() + 60_000),
    }
  },
  async destroy() {
    log.push("destroy")
  },
})

const fixture = (
  options: {
    readonly clientResult?: unknown
    readonly provider?: CapabilityProvider
    readonly scope?: readonly string[] | undefined
    readonly revokedAgentIds?: ReadonlySet<string> | undefined
  } = {},
) => {
  const credentialLog: string[] = []
  const evidenceChain = new EvidenceChain({
    tenantId: TENANT,
    issuerId: ISSUER_ID,
    keyPair,
  })

  const provider =
    options.provider ??
    createGitHubCapabilityProvider({
      async listIssues() {
        return options.clientResult ?? { issues: [{ number: 1, title: "bug" }] }
      },
      async mergePullRequest() {
        return { merged: true }
      },
    })

  const broker = new CapabilityBroker({
    tenantId: TENANT,
    trustedIssuerKeys,
    evidenceChain,
    providers: [provider],
    credentialProviders: new Map([["github", recordingCredentialProvider(credentialLog)]]),
    revokedAgentIds: options.revokedAgentIds,
    now: () => now,
  })

  broker.setAuthorityResolver(() => options.scope ?? [GRANT_READ])

  return { broker, credentialLog, evidenceChain }
}

// --- Allow path ---------------------------------------------------------------------

test("S1 allow: a scoped grant returns only the result", async () => {
  const { broker } = fixture()

  const outcome = await broker.grant({
    identityToken: identityToken(),
    grantUri: GRANT_READ,
    args: {},
  })

  assert.equal(outcome.granted, true)
  assert.deepEqual(outcome.granted && outcome.result, {
    issues: [{ number: 1, title: "bug" }],
  })
})

test("S1 allow: the downstream credential is obtained and destroyed around the call", async () => {
  const { broker, credentialLog } = fixture()

  await broker.grant({
    identityToken: identityToken(),
    grantUri: GRANT_READ,
    args: {},
  })

  assert.deepEqual(credentialLog, ["obtain", "destroy"])
})

test("S1 allow: the credential value never appears in the broker result", async () => {
  const { broker } = fixture({
    clientResult: {
      issues: [{ number: 1, title: "bug", author: "octocat" }],
    },
  })

  const outcome = await broker.grant({
    identityToken: identityToken(),
    grantUri: GRANT_READ,
    args: {},
  })

  assert.equal(
    JSON.stringify(outcome.granted ? outcome.result : null).includes(
      "ghp_super_secret_token",
    ),
    false,
  )
})

// --- Deny paths ---------------------------------------------------------------------

test("S1 deny: a provider that returns a token is refused at the broker boundary", async () => {
  // A misbehaving or compromised provider tries to hand the credential back.
  const leakyProvider: CapabilityProvider = {
    provider: "github",
    requiresCredential: true,
    supports: () => true,
    async execute(args) {
      return { issues: [], access_token: args.credential?.value }
    },
  }

  const { broker, credentialLog } = fixture({ provider: leakyProvider })

  const outcome = await broker.grant({
    identityToken: identityToken(),
    grantUri: GRANT_READ,
    args: {},
  })

  assert.equal(outcome.granted, false)
  assert.equal(outcome.granted === false && outcome.reason, "credential_leak")
  // The credential must still be released even though the call was refused.
  assert.deepEqual(credentialLog, ["obtain", "destroy"])
})

test("S1 deny: a nested credential field is also refused", async () => {
  const leakyProvider: CapabilityProvider = {
    provider: "github",
    requiresCredential: false,
    supports: () => true,
    async execute() {
      return { issues: [{ meta: { api_key: "leaked" } }] }
    },
  }

  const { broker } = fixture({ provider: leakyProvider })

  const outcome = await broker.grant({
    identityToken: identityToken(),
    grantUri: GRANT_READ,
    args: {},
  })

  assert.equal(outcome.granted, false)
  assert.equal(outcome.granted === false && outcome.reason, "credential_leak")
})

test("S1 deny: assertNoCredentialsInResult accepts ordinary data", () => {
  assert.doesNotThrow(() =>
    assertNoCredentialsInResult({ issues: [{ number: 1, title: "ok" }] }),
  )
})

/**
 * Every alternative in the broker's credential-key pattern is exercised here.
 *
 * This exists because the deny tests above all used field names that also contain the
 * substring `token` or `api_key`. Deleting the standalone `credential` alternative from
 * the pattern left all 14 tests passing — the coverage was an illusion. Each case below
 * is named so that removing its alternative from the pattern fails exactly one test.
 */
const DENY_KEY_CASES = [
  "password",
  "secret",
  "access_token",
  "api_key",
  "private_key",
  "authorization",
  "credential",
  "bearer",
  "session_key",
  "AWS_SECRET_ACCESS_KEY",
  "refreshToken",
  "x-api-key",
] as const

test("S1 deny: every credential-key alternative is actually covered", async () => {
  for (const key of DENY_KEY_CASES) {
    assert.throws(
      () => assertNoCredentialsInResult({ payload: { [key]: "leaked" } }),
      /CredentialLeak/u,
      `a field named ${key} must be refused as a credential`,
    )
  }
})

test("S1 deny: a credential key is caught at any nesting depth", () => {
  assert.throws(
    () => assertNoCredentialsInResult({ a: { b: { c: { d: { credential: "x" } } } } }),
    /CredentialLeak/u,
  )
  assert.throws(
    () => assertNoCredentialsInResult({ list: [{ inner: { session_key: "x" } }] }),
    /CredentialLeak/u,
  )
})

test("S1 deny: a provider leaking through a rarely-named key is refused at the boundary", async () => {
  // `credential` is the realistic worst case: a provider that nests its own token under
  // a plain name that no other alternative happens to substring-match.
  const leakyProvider: CapabilityProvider = {
    provider: "github",
    requiresCredential: false,
    supports: () => true,
    async execute() {
      return { issues: [], meta: { credential: "leaked-value" } }
    },
  }

  const { broker } = fixture({ provider: leakyProvider })

  const outcome = await broker.grant({
    identityToken: identityToken(),
    grantUri: GRANT_READ,
    args: {},
  })

  assert.equal(outcome.granted, false)
  assert.equal(outcome.granted === false && outcome.reason, "credential_leak")
})

test("S1 deny: a grant outside the agent's authority is refused", async () => {
  const { broker, credentialLog } = fixture({ scope: [GRANT_READ] })

  const outcome = await broker.grant({
    identityToken: identityToken(),
    grantUri: GRANT_MERGE,
    args: { number: 42, method: "squash" },
  })

  assert.equal(outcome.granted, false)
  assert.equal(outcome.granted === false && outcome.reason, "grant_not_in_scope")
  assert.deepEqual(credentialLog, [], "no credential may be obtained for a refused grant")
})

test("S1 deny: an agent with no resolvable authority is refused", async () => {
  const { broker } = fixture({ scope: undefined })

  const brokerWithoutResolver = new CapabilityBroker({
    tenantId: TENANT,
    trustedIssuerKeys,
    evidenceChain: new EvidenceChain({ tenantId: TENANT, issuerId: ISSUER_ID, keyPair }),
    providers: [createGitHubCapabilityProvider({
      async listIssues() {
        return {}
      },
      async mergePullRequest() {
        return {}
      },
    })],
    now: () => now,
  })

  const outcome = await brokerWithoutResolver.grant({
    identityToken: identityToken(),
    grantUri: GRANT_READ,
    args: {},
  })

  assert.equal(outcome.granted, false)
  assert.equal(outcome.granted === false && outcome.reason, "grant_not_in_scope")
  assert.ok(broker instanceof CapabilityBroker)
})

test("S1 deny: a revoked agent cannot use the broker", async () => {
  const { broker } = fixture({ revokedAgentIds: new Set([AGENT_ID]) })

  const outcome = await broker.grant({
    identityToken: identityToken(),
    grantUri: GRANT_READ,
    args: {},
  })

  assert.equal(outcome.granted, false)
  assert.equal(outcome.granted === false && outcome.reason, "identity_denied")
})

test("S1 deny: an unsigned identity token is refused", async () => {
  const { broker } = fixture()

  const outcome = await broker.grant({
    identityToken: { identity: { agent_id: AGENT_ID }, signature: {} },
    grantUri: GRANT_READ,
    args: {},
  })

  assert.equal(outcome.granted, false)
  assert.equal(outcome.granted === false && outcome.reason, "identity_denied")
})

test("S1 deny: an unknown grant prefix is refused", async () => {
  const { broker } = fixture()

  const outcome = await broker.grant({
    identityToken: identityToken(),
    grantUri: "https://api.github.com/repos/org/repo",
    args: {},
  })

  assert.equal(outcome.granted, false)
  assert.equal(outcome.granted === false && outcome.reason, "unknown_grant")
})

test("S13 allow: broker activity produces verifiable evidence", async () => {
  const { broker, evidenceChain } = fixture()

  await broker.grant({ identityToken: identityToken(), grantUri: GRANT_READ, args: {} })

  const verification = verifyEvidenceBundle(evidenceChain.export(), trustedIssuerKeys)

  assert.equal(verification.valid, true)
  assert.ok(
    evidenceChain
      .export()
      .records.some((record) => record.evidence_type === "data_access"),
  )
})

test("S13 deny: an evidence bundle from the broker survives offline verification", async () => {
  const { broker, evidenceChain } = fixture()

  await broker.grant({
    identityToken: identityToken(),
    grantUri: GRANT_MERGE,
    args: { number: 1, method: "squash" },
  })

  const bundle = evidenceChain.export()
  const tampered = structuredClone(bundle)
  ;(tampered.records[0] as { payload: unknown }).payload = { agent: "someone-else" }

  assert.equal(verifyEvidenceBundle(tampered, trustedIssuerKeys).valid, false)
  assert.equal(verifyEvidenceBundle(bundle, trustedIssuerKeys).valid, true)
})

test("S4 allow: two agents hold distinct identities", () => {
  assert.notEqual(
    identityToken("reviewer-1").identity.nonce,
    identityToken("reviewer-2").identity.nonce,
  )
  assert.notEqual(
    buildSpiffeId(TENANT, "reviewer-1"),
    buildSpiffeId(TENANT, "reviewer-2"),
  )
})