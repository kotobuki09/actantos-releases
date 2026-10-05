import assert from "node:assert/strict"
import { createServer, type Server } from "node:http"
import { mkdtempSync } from "node:fs"
import { tmpdir } from "node:os"
import path from "node:path"
import { generateKeyPairSync, sign as cryptoSign } from "node:crypto"
import test, { after } from "node:test"

import { buildServer } from "../server.ts"
import type { ToolCallInterceptionRequest } from "../contracts.ts"
import { createFabricGate, SidecarFabricDecider, toFabricActionRequest } from "./fabric.ts"
import { PolicyLease } from "./policy-lease.ts"
import { ed25519 } from "./signature.ts"
import { ActantSidecar } from "./sidecar.ts"
import { defaultSocketPath, isNamedPipe, startSidecarServer } from "./sidecar-server.ts"
import { signPolicyBundle, type PolicyBundleBody } from "./signed-policy-bundle.ts"
import {
  createSpireIdentityProvider,
  type Jwk,
} from "./workload-identity-provider.ts"
import {
  buildSpiffeId,
  mintWorkloadIdentity,
  signWorkloadIdentity,
} from "./workload-identity.ts"

/**
 * Phase H end to end: SPIRE-issued identities, enforced by a real sidecar, changing real decisions.
 *
 * `workload-identity-provider.test.ts` proves the SVD is parsed and verified correctly, in
 * isolation. That is not enforcement. The property S4 actually claims is that a *fabric* refuses an
 * identity it did not attest — so this file drives a real sidecar on a real socket, hands it a real
 * JWT-SVID signed by a real key, and asserts on the decision the caller receives.
 *
 * The Workload API is a real HTTP server. Its responses are produced by signing with a real
 * Ed25519 key, so a token that verifies here would verify against SPIRE. Nothing is stubbed at the
 * crypto layer.
 */

const TRUST_DOMAIN = "actantos.local"
const KID = "td-key-1"
const spireKeys = generateKeyPairSync("ed25519")
const spireJwks: Jwk[] = [
  { ...(spireKeys.publicKey.export({ format: "jwk" }) as Jwk), kid: KID },
]

const ISSUER_ID = "issuer-spire-runtime"
const keyPair = ed25519.generateKeyPair()
const trustedIssuerKeys = new Map([[ISSUER_ID, keyPair.publicKeyPem]])

const TENANT = "t_spire"
const AGENT = "pi_demo"
const GRANT = "grant://github/org/repo/issues/read"
const SPIFFE_ID = buildSpiffeId(TENANT, AGENT)

const b64url = (bytes: Buffer): string =>
  bytes.toString("base64").replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "")

const signSvid = (claims: Record<string, unknown>, signingKey = spireKeys.privateKey): string => {
  const header = { alg: "Ed25519", kid: KID, typ: "JWT" }
  const signingInput = `${b64url(Buffer.from(JSON.stringify(header)))}.${b64url(
    Buffer.from(JSON.stringify(claims)),
  )}`

  return `${signingInput}.${b64url(cryptoSign(null, Buffer.from(signingInput), signingKey))}`
}

const NOW_SECONDS = Math.floor(Date.now() / 1000)

const svidClaims = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
  sub: SPIFFE_ID,
  iss: `spiffe://${TRUST_DOMAIN}`,
  aud: "actantos-fabric",
  iat: NOW_SECONDS - 5,
  nbf: NOW_SECONDS - 5,
  exp: NOW_SECONDS + 600,
  ...overrides,
})

/* ------------------------------------------------------- a real Workload API over real HTTP */

const openServers: Array<Server> = []

after(async () => {
  await Promise.all(
    openServers.map(
      (server) =>
        new Promise<void>((resolve) => {
          server.close(() => resolve())
        }),
    ),
  )
})

const startWorkloadApi = async (jwtFor: () => string): Promise<string> => {
  const server = createServer((req, res) => {
    const url = new URL(req.url ?? "/", "http://127.0.0.1")

    if (url.pathname === "/workload-api/jwt-svid") {
      res.writeHead(200, { "content-type": "application/json" })
      res.end(JSON.stringify({ [SPIFFE_ID]: { svid: { jwt: jwtFor() } } }))
      return
    }

    if (url.pathname === "/jwks") {
      res.writeHead(200, { "content-type": "application/json" })
      res.end(JSON.stringify({ keys: spireJwks }))
      return
    }

    res.writeHead(404, { "content-type": "application/json" })
    res.end("{}")
  })

  openServers.push(server)

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))

  const address = server.address()

  return `http://127.0.0.1:${typeof address === "object" && address !== null ? address.port : 0}`
}

/* ------------------------------------------------------------- the rest of the real stack */

const HOUR_MS = 60 * 60 * 1000

const bundleBody = (now: Date): PolicyBundleBody => ({
  bundle_id: "bundle-spire",
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
  trusted_issuers: [ISSUER_ID],
})

let socketCounter = 0
const uniqueSocketPath = (): string => {
  socketCounter += 1
  const name = `actantos-spire-${process.pid}-${Date.now().toString(36)}-${socketCounter}`

  return isNamedPipe(defaultSocketPath(name))
    ? defaultSocketPath(name)
    : path.join(mkdtempSync(path.join(tmpdir(), "actantos-spire-")), `${name}.sock`)
}

const toolCall = (
  overrides: Partial<ToolCallInterceptionRequest> = {},
): ToolCallInterceptionRequest => ({
  request_id: `req_spire_${Math.random().toString(36).slice(2, 10)}`,
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
  ...overrides,
})

const disallowedToolCall = (): ToolCallInterceptionRequest =>
  toolCall({ resource: { url: "https://evil.example.com/collect" } })

/**
 * Build the whole enforcement path with `issueIdentity` as given.
 *
 * `spire` on the sidecar is what makes a JWT-SVID acceptable at all; leaving it off is the
 * no-SPIRE deployment, and the difference between the two is asserted below rather than assumed.
 */
const startStack = async (
  issueIdentity: SidecarFabricDeciderOptions["issueIdentity"],
  options: { readonly spire?: boolean } = {},
): Promise<{
  readonly server: ReturnType<typeof buildServer>
  readonly close: () => Promise<void>
}> => {
  const socketPath = uniqueSocketPath()
  const now = new Date()
  const lease = new PolicyLease({ tenantId: TENANT, trustedIssuerKeys })

  lease.offer(
    signPolicyBundle(
      bundleBody(now),
      { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
      keyPair,
    ),
    now,
  )

  const sidecar = new ActantSidecar({
    tenantId: TENANT,
    trustedIssuerKeys,
    lease,
    authorityFor: () => [GRANT],
    ...(options.spire === true
      ? { spire: { keys: spireJwks, trustDomain: TRUST_DOMAIN, audience: "actantos-fabric" } }
      : {}),
  })

  const sidecarServer = await startSidecarServer({ socketPath, sidecar })
  const decider = new SidecarFabricDecider({ socketPath, issueIdentity })
  const server = buildServer({
    hmacSecret: "spire-test-secret",
    logger: false,
    fabricGate: createFabricGate({ mode: "v2_enforce", decider }),
  })

  await server.ready()

  return {
    server,
    close: async () => {
      await server.close()
      await decider.close()
      await sidecarServer.close()
    },
  }
}

type SidecarFabricDeciderOptions = ConstructorParameters<typeof SidecarFabricDecider>[0]

const intercept = async (
  server: ReturnType<typeof buildServer>,
  body: ToolCallInterceptionRequest,
): Promise<{ readonly decision: string; readonly reason_code: string }> => {
  const response = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: body,
  })

  const parsed = response.json() as { decision: string; reason_code: string }

  return { decision: parsed.decision, reason_code: parsed.reason_code }
}

/* --------------------------------------------------------------------------------- tests */

test("S4: an SVID from the trust domain is accepted by a real sidecar, and enforces policy", async () => {
  const api = await startWorkloadApi(() => signSvid(svidClaims()))

  const provider = createSpireIdentityProvider({
    workloadApi: api,
    spiffeId: SPIFFE_ID,
    trustDomain: TRUST_DOMAIN,
    jwksUri: `${api}/jwks`,
    expectedAudience: "actantos-fabric",
  })

  const stack = await startStack(
    async (tenantId, agentId) => (await provider.issue(tenantId, agentId)).token,
    { spire: true },
  )

  try {
    const allowed = await intercept(stack.server, toolCall())

    // This is the whole point of the phase: the sidecar made an enforcement decision using an
    // identity it attested itself, with no signing key in this process.
    assert.equal(allowed.decision, "allow")

    const denied = await intercept(stack.server, disallowedToolCall())

    // And the identity did not become a rubber stamp — the signed policy still governs.
    assert.equal(denied.decision, "deny")
    assert.equal(denied.reason_code, "fabric.network_rule_denied")
  } finally {
    await stack.close()
  }
})

test("S4: a sidecar with no SPIRE keys refuses an SVID rather than accepting it unchecked", async () => {
  const api = await startWorkloadApi(() => signSvid(svidClaims()))
  const provider = createSpireIdentityProvider({
    workloadApi: api,
    spiffeId: SPIFFE_ID,
    trustDomain: TRUST_DOMAIN,
    jwksUri: `${api}/jwks`,
    expectedAudience: "actantos-fabric",
  })

  // `spire: true` omitted: this is a deployment that has not been given a trust domain. If a
  // JWT-SVID were accepted here without keys, "not configured" would silently mean "trusted".
  const stack = await startStack(
    async (tenantId, agentId) => (await provider.issue(tenantId, agentId)).token,
  )

  try {
    const result = await intercept(stack.server, toolCall())

    // `identity_invalid`, not `unavailable`: the sidecar was reached and did decide. The two are
    // different incidents for an operator — this one means "this deployment was sent a token it
    // has no keys to check", the other means "the fabric is down".
    assert.equal(result.decision, "deny")
    assert.equal(result.reason_code, "fabric.identity_invalid")
  } finally {
    await stack.close()
  }
})

test("S4: an SVID signed by a key the trust domain does not publish is refused", async () => {
  const impostor = generateKeyPairSync("ed25519")
  const api = await startWorkloadApi(() => signSvid(svidClaims(), impostor.privateKey))

  const provider = createSpireIdentityProvider({
    workloadApi: api,
    spiffeId: SPIFFE_ID,
    trustDomain: TRUST_DOMAIN,
    jwksUri: `${api}/jwks`,
    expectedAudience: "actantos-fabric",
  })

  // The provider verifies the SVID before it is ever sent, so the request fails at the control
  // plane. Asserting the refusal happens here rather than at the sidecar is deliberate: it is the
  // reason an operator sees `signature_invalid` instead of a generic identity failure.
  await assert.rejects(
    () => provider.issue(TENANT, AGENT),
    /signature_invalid/,
  )
})

test("S4: an expired SVID is refused before it reaches the fabric", async () => {
  const api = await startWorkloadApi(() =>
    signSvid(svidClaims({ exp: NOW_SECONDS - 60, nbf: NOW_SECONDS - 600 })),
  )

  const provider = createSpireIdentityProvider({
    workloadApi: api,
    spiffeId: SPIFFE_ID,
    trustDomain: TRUST_DOMAIN,
    jwksUri: `${api}/jwks`,
    expectedAudience: "actantos-fabric",
  })

  await assert.rejects(() => provider.issue(TENANT, AGENT), /expired/)
})

test("S12: when the Workload API is unreachable, v2_enforce denies rather than falling back", async () => {
  const provider = createSpireIdentityProvider({
    // Nothing listens on port 1. There is no path by which this request could succeed.
    workloadApi: "http://127.0.0.1:1",
    spiffeId: SPIFFE_ID,
    trustDomain: TRUST_DOMAIN,
    jwksUri: "http://127.0.0.1:1/jwks",
  })

  const stack = await startStack(
    async (tenantId, agentId) => (await provider.issue(tenantId, agentId)).token,
    { spire: true },
  )

  try {
    const result = await intercept(stack.server, toolCall())

    // The identity source being down must not become an allow. There is no code path here that
    // signs locally as a fallback, because a fallback is exactly the silent weakening this
    // configuration is supposed to rule out.
    assert.equal(result.decision, "deny")
    assert.equal(result.reason_code, "fabric.unavailable")
  } finally {
    await stack.close()
  }
})

test("S4: one attested client cannot obtain an identity for a different agent", async () => {
  const api = await startWorkloadApi(() => signSvid(svidClaims()))

  const provider = createSpireIdentityProvider({
    workloadApi: api,
    spiffeId: SPIFFE_ID,
    trustDomain: TRUST_DOMAIN,
    jwksUri: `${api}/jwks`,
  })

  // Even if the Workload API were to answer with a valid SVID naming another agent, the client
  // refuses before asking. Node attestation is checked here, not inferred from the response.
  await assert.rejects(() => provider.issue(TENANT, "someone-else"), /cannot issue an identity/)
  await assert.rejects(() => provider.issue("other-tenant", AGENT), /cannot issue an identity/)
})

test("S12: a locally-signed envelope still works on a sidecar that also accepts SVIDs", async () => {
  // Regression guard for the migration. A deployment that adds SPIRE must not break the existing
  // envelope path on the way, or the two cannot be run side by side during a rollout.
  const socketPath = uniqueSocketPath()
  const now = new Date()
  const lease = new PolicyLease({ tenantId: TENANT, trustedIssuerKeys })

  lease.offer(
    signPolicyBundle(
      bundleBody(now),
      { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
      keyPair,
    ),
    now,
  )

  const sidecarServer = await startSidecarServer({
    socketPath,
    sidecar: new ActantSidecar({
      tenantId: TENANT,
      trustedIssuerKeys,
      lease,
      authorityFor: () => [GRANT],
      spire: { keys: spireJwks, trustDomain: TRUST_DOMAIN, audience: "actantos-fabric" },
    }),
  })

  const decider = new SidecarFabricDecider({
    socketPath,
    issueIdentity: (tenantId, agentId, at) =>
      ed25519SignEnvelope(tenantId, agentId, at),
  })

  const server = buildServer({
    hmacSecret: "spire-test-secret",
    logger: false,
    fabricGate: createFabricGate({ mode: "v2_enforce", decider }),
  })

  await server.ready()

  try {
    assert.equal((await intercept(server, toolCall())).decision, "allow")
    assert.equal((await intercept(server, disallowedToolCall())).decision, "deny")
  } finally {
    await server.close()
    await decider.close()
    await sidecarServer.close()
  }
})

test("the action handed to the fabric still names the request's own agent", () => {
  const request = toolCall()
  const action = toFabricActionRequest(request)

  assert.equal(action.agentId, AGENT)
  assert.equal(action.resource, "https://api.github.com/repos/org/repo/issues")
})

const ed25519SignEnvelope = (tenantId: string, agentId: string, at: Date): unknown =>
  signWorkloadIdentity(
    mintWorkloadIdentity({ tenantId, agentId, issuedAt: at }),
    { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
    keyPair,
  )
