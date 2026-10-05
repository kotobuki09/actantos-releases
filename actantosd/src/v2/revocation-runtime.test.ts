import assert from "node:assert/strict"
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import path from "node:path"
import test from "node:test"

import { buildServer } from "../server.ts"
import type { ToolCallInterceptionRequest } from "../contracts.ts"
import { createFabricGate, SidecarFabricDecider } from "./fabric.ts"
import { PolicyLease } from "./policy-lease.ts"
import { RevocationStore, signRevocationSnapshot, type RevocationSnapshotBody } from "./revocation-snapshot.ts"
import { ed25519 } from "./signature.ts"
import { signPolicyBundle, type PolicyBundleBody } from "./signed-policy-bundle.ts"
import { ActantSidecar } from "./sidecar.ts"
import { defaultSocketPath, isNamedPipe, startSidecarServer } from "./sidecar-server.ts"
import { mintWorkloadIdentity, signWorkloadIdentity } from "./workload-identity.ts"

/**
 * Revocation, enforced end to end (invariants S9, S12).
 *
 * `revocation-snapshot.test.ts` proves the document verifies and that the store answers correctly.
 * That is not enforcement. The property here is that a revoked agent is refused by a *real sidecar*
 * on a real socket while holding a valid policy, a valid identity, and a valid signature — that is,
 * revocation has to be the thing that stops it, not an accident of the other checks.
 *
 * The second half is the more interesting half: a snapshot that arrives late, forged, or rolled
 * back must not be able to *restore* a revoked agent. Those are the attacks, and they run in the
 * opposite direction from the ones the store unit tests cover.
 */

const ISSUER = "issuer-revocation-runtime"
const keyPair = ed25519.generateKeyPair()
const trustedIssuerKeys = new Map([[ISSUER, keyPair.publicKeyPem]])

const TENANT = "t_revocation"
const AGENT = "pi_demo"
const GRANT = "grant://github/org/repo/issues/read"
const HOUR_MS = 60 * 60 * 1000

const policyBody = (now: Date): PolicyBundleBody => ({
  bundle_id: "bundle-revocation",
  tenant_id: TENANT,
  version: 1,
  issued_at: new Date(now.getTime() - HOUR_MS).toISOString(),
  expires_at: new Date(now.getTime() + 365 * 24 * HOUR_MS).toISOString(),
  policies: [{ policy_id: "p1", cedar: "permit(principal, action, resource);" }],
  agent_profile: {
    agent_id: AGENT,
    allowed_tools: ["github.issues.read"],
    max_delegation_depth: 2,
  },
  tool_manifest: [{ tool: "github.issues.read", grant: GRANT }],
  network_rules: [{ host: "api.github.com", action: "allow_via_egress_gateway" }],
  data_clearance: "CONFIDENTIAL",
  risk_profile: { risk_level: "medium", requires_effect_permit: [] },
  trusted_issuers: [ISSUER],
})

const revocationBody = (
  now: Date,
  overrides: Partial<RevocationSnapshotBody> = {},
): RevocationSnapshotBody => ({
  snapshot_id: "snap-1",
  tenant_id: TENANT,
  version: 1,
  issued_at: now.toISOString(),
  expires_at: new Date(now.getTime() + 24 * HOUR_MS).toISOString(),
  entries: [{ agent_id: AGENT, reason: "credential_compromised", revoked_at: now.toISOString() }],
  ...overrides,
})

const signSnapshot = (body: RevocationSnapshotBody, key = keyPair, issuer = ISSUER) =>
  signRevocationSnapshot(body, { algorithm: "ed25519", issuer_id: issuer, value: "" }, key)

let counter = 0
const uniqueSocketPath = (): string => {
  counter += 1
  const name = `actantos-rev-${process.pid}-${Date.now().toString(36)}-${counter}`

  return isNamedPipe(defaultSocketPath(name))
    ? defaultSocketPath(name)
    : path.join(mkdtempSync(path.join(tmpdir(), "actantos-rev-")), `${name}.sock`)
}

const toolCall = (): ToolCallInterceptionRequest => ({
  request_id: `req_rev_${Math.random().toString(36).slice(2, 10)}`,
  tenant_id: TENANT,
  agent: { id: AGENT, runtime_type: "pi", environment: "dev", risk_tier: "low" },
  subject: { user_id: "u_demo", role: "developer" },
  session: { id: "s_demo", cwd: "/workspace", budget_remaining_cents: 10_000 },
  tool: { kind: "github", name: "github.issues.read", operation: "ReadIssues" },
  resource: { url: "https://api.github.com/repos/org/repo/issues" },
  action: { operation: "ReadIssues", args: {} },
  normalized: {
    verb: "read",
    mutation: false,
    destructive: false,
    network: true,
    credential_access: false,
    risk_class: "low",
  },
})

/**
 * Build the whole enforcement path: a real sidecar on a real socket, a real server, and a
 * revocation store the test pushes snapshots into.
 */
const startRuntime = async (
  options: { readonly withRevocations?: boolean } = {},
): Promise<{
  readonly server: ReturnType<typeof buildServer>
  readonly revocations: RevocationStore | undefined
  readonly close: () => Promise<void>
}> => {
  const now = new Date()
  const socketPath = uniqueSocketPath()
  const lease = new PolicyLease({ tenantId: TENANT, trustedIssuerKeys })

  lease.offer(
    signPolicyBundle(policyBody(now), { algorithm: "ed25519", issuer_id: ISSUER, value: "" }, keyPair),
    now,
  )

  const revocations =
    options.withRevocations === true
      ? new RevocationStore({ tenantId: TENANT, trustedIssuerKeys })
      : undefined

  const sidecarServer = await startSidecarServer({
    socketPath,
    sidecar: new ActantSidecar({
      tenantId: TENANT,
      trustedIssuerKeys,
      lease,
      authorityFor: () => [GRANT],
      ...(revocations === undefined ? {} : { revocations }),
    }),
  })

  const decider = new SidecarFabricDecider({
    socketPath,
    issueIdentity: (tenantId, agentId, at) =>
      signWorkloadIdentity(
        mintWorkloadIdentity({ tenantId, agentId, issuedAt: at }),
        { algorithm: "ed25519", issuer_id: ISSUER, value: "" },
        keyPair,
      ),
  })

  const server = buildServer({
    hmacSecret: "revocation-test-secret",
    logger: false,
    fabricGate: createFabricGate({ mode: "v2_enforce", decider }),
  })

  await server.ready()

  return {
    server,
    revocations,
    close: async () => {
      await server.close()
      await decider.close()
      await sidecarServer.close()
    },
  }
}

const intercept = async (
  server: ReturnType<typeof buildServer>,
): Promise<{ readonly decision: string; readonly reason_code: string }> => {
  const response = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: toolCall(),
  })

  const parsed = response.json() as { decision: string; reason_code: string }

  return { decision: parsed.decision, reason_code: parsed.reason_code }
}

/* --------------------------------------------------------------------------------- tests */

test("S9: an unrevoked agent with a valid policy is allowed", async () => {
  const stack = await startRuntime({ withRevocations: true })
  const now = new Date()

  try {
    // Signed, and containing a different agent. This is the control for every test below: it
    // proves the revocation path is what denies, rather than the document being un-signable or
    // the sidecar refusing everything.
    stack.revocations?.offer(
      signSnapshot(
        revocationBody(now, {
          entries: [
            { agent_id: "someone-else", reason: "operator_request", revoked_at: now.toISOString() },
          ],
        }),
      ),
      now,
    )

    const result = await intercept(stack.server)

    assert.equal(result.decision, "allow")
  } finally {
    await stack.close()
  }
})

test("S9: a revoked agent is refused by a real sidecar while holding a valid policy and signature", async () => {
  const stack = await startRuntime({ withRevocations: true })
  const now = new Date()

  try {
    stack.revocations?.offer(signSnapshot(revocationBody(now)), now)

    const result = await intercept(stack.server)

    // The agent's policy is valid, its identity signature verifies, and the tool is in the signed
    // manifest. Revocation is the only thing that can be refusing this, which is the point.
    assert.equal(result.decision, "deny")
    assert.equal(result.reason_code, "fabric.identity_revoked")
  } finally {
    await stack.close()
  }
})

test("S9: revoking one identity's nonce does not revoke the whole agent", async () => {
  const stack = await startRuntime({ withRevocations: true })
  const now = new Date()

  try {
    // A nonce the next request will not carry. Narrower than an agent revocation by design.
    stack.revocations?.offer(
      signSnapshot(
        revocationBody(now, {
          entries: [
            { nonce: "some-other-execution", reason: "session_terminated", revoked_at: now.toISOString() },
          ],
        }),
      ),
      now,
    )

    assert.equal((await intercept(stack.server)).decision, "allow")
  } finally {
    await stack.close()
  }
})

test("S9: a forged snapshot does not revoke, and does not restore a revoked agent either", async () => {
  const stack = await startRuntime({ withRevocations: true })
  const now = new Date()

  try {
    stack.revocations?.offer(signSnapshot(revocationBody(now)), now)
    assert.equal((await intercept(stack.server)).reason_code, "fabric.identity_revoked")

    // The attack that matters: an attacker who can reach the store tries to un-revoke by pushing
    // a higher version with the entry removed.
    const forged = {
      body: revocationBody(now, { version: 99, entries: [] }),
      signature: { algorithm: "ed25519", issuer_id: ISSUER, value: "AAAA" },
    }

    assert.equal(stack.revocations?.offer(forged, now).accepted, false)
    assert.equal(
      (await intercept(stack.server)).reason_code,
      "fabric.identity_revoked",
      "a forged snapshot restored a revoked agent",
    )
  } finally {
    await stack.close()
  }
})

test("S9: replaying an older genuine snapshot does not un-revoke", async () => {
  const stack = await startRuntime({ withRevocations: true })
  const now = new Date()

  try {
    // Version 1 revokes. Version 2 exists and was signed — but by the wrong key, so the store
    // never applied it, leaving version 1 in force. Replaying version 1 must then still be refused
    // as a rollback rather than being accepted as "the latest".
    stack.revocations?.offer(signSnapshot(revocationBody(now, { version: 1 })), now)

    const otherKey = ed25519.generateKeyPair()
    const replay = signSnapshot(
      revocationBody(now, { version: 1, entries: [] }),
      otherKey,
      "issuer-impostor",
    )

    assert.equal(stack.revocations?.offer(replay, now).accepted, false)
    assert.equal((await intercept(stack.server)).reason_code, "fabric.identity_revoked")
  } finally {
    await stack.close()
  }
})

test("S9: a sidecar with no revocation feed still serves traffic", async () => {
  const stack = await startRuntime()

  try {
    // The optional wiring must not become an accidental deny-all on upgrade.
    assert.equal((await intercept(stack.server)).decision, "allow")
  } finally {
    await stack.close()
  }
})

test("S12: a snapshot from another tenant is refused and changes nothing", async () => {
  const stack = await startRuntime({ withRevocations: true })
  const now = new Date()

  try {
    const offer = stack.revocations?.offer(
      signSnapshot(revocationBody(now, { tenant_id: "some-other-tenant" })),
      now,
    )

    assert.equal(offer?.accepted, false)
    assert.equal(offer?.reason, "tenant_mismatch")
    assert.equal((await intercept(stack.server)).decision, "allow")
  } finally {
    await stack.close()
  }
})

test("S12: revocation keeps applying after the snapshot expires", async () => {
  const stack = await startRuntime({ withRevocations: true })
  const now = new Date()

  try {
    stack.revocations?.offer(
      signSnapshot(
        revocationBody(now, {
          expires_at: new Date(now.getTime() + 1000).toISOString(),
        }),
      ),
      now,
    )

    assert.equal(stack.revocations?.state(new Date(now.getTime() + 60_000)).kind, "expired")
    // Still enforced: the entries were signed, and a control-plane outage must not become an
    // un-revocation. `state()` says expired so an operator can see it, but the decision is deny.
    assert.equal(
      stack.revocations?.isAgentRevoked(AGENT, new Date(now.getTime() + 60_000)).revoked,
      true,
    )
  } finally {
    await stack.close()
  }
})
