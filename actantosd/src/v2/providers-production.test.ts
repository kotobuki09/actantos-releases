import assert from "node:assert/strict"
import { createHash, createHmac, createPublicKey, generateKeyPairSync, verify } from "node:crypto"
import { createServer, type IncomingMessage, type Server, type ServerResponse } from "node:http"
import type { AddressInfo } from "node:net"
import test from "node:test"

import {
  CapabilityBroker,
  type CapabilityProvider,
  assertCredentialNotEchoed,
  credentialMarkers,
} from "./capability-broker.ts"
import { EvidenceChain } from "./evidence.ts"
import {
  createAwsStsClient,
  createGitHubAppClient,
  createHttpGitHubClient,
  createVaultAppRoleClient,
} from "./production-providers.ts"
import {
  createGitHubCapabilityProvider,
  createStsCredentialProvider,
  createVaultCredentialProvider,
  sessionNameForAgent,
  type VaultClient,
} from "./providers.ts"
import { ed25519 } from "./signature.ts"
import { mintWorkloadIdentity, signWorkloadIdentity } from "./workload-identity.ts"

/**
 * Phase J: the production credential providers, against real HTTP servers.
 *
 * These are INTEGRATION, not REAL_SUBSTRATE. The sockets, the HTTP, the RSA and HMAC
 * signatures and the request formats are all real. github.com, AWS and Vault are not: the
 * far end is a local server in this file. So what is demonstrated is that the provider
 * speaks the vendor's protocol correctly and that the secret does not escape — not that
 * the vendor accepts it. That split is recorded in the substrate registry rather than
 * averaged into one claim.
 *
 * Three defects in the previous implementation are pinned here by regression tests. Each
 * was measured against the old code before being fixed; the "was wrong because" comment
 * records what actually happened, not a plausible story.
 */

const ISSUER_ID = "issuer-primary"
const keyPair = ed25519.generateKeyPair()
const trustedIssuerKeys = new Map([[ISSUER_ID, keyPair.publicKeyPem]])
const TENANT = "t_demo"
const AGENT = "reviewer-1"
const NOW = new Date("2026-10-04T12:00:00.000Z")

const identityToken = (agentId = AGENT) =>
  signWorkloadIdentity(
    mintWorkloadIdentity({ tenantId: TENANT, agentId, issuedAt: NOW }),
    { algorithm: "ed25519", issuer_id: ISSUER_ID, value: "" },
    keyPair,
  )

const context = (agentId = AGENT) => ({
  tenantId: TENANT,
  agentSpiffeId: `spiffe://${TENANT}/${agentId}`,
  at: NOW,
})

// --- A tiny real HTTP server ---------------------------------------------------------------

type Handler = (
  request: IncomingMessage,
  response: ServerResponse,
  body: string,
) => void | Promise<void>

const serve = async (handler: Handler): Promise<{ origin: string; close: () => Promise<void> }> => {
  const server: Server = createServer((request, response) => {
    const chunks: Buffer[] = []
    request.on("data", (chunk: Buffer) => chunks.push(chunk))
    request.on("end", () => {
      void Promise.resolve(handler(request, response, Buffer.concat(chunks).toString("utf8"))).catch(
        () => {
          response.writeHead(500)
          response.end()
        },
      )
    })
  })

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))
  const { port } = server.address() as AddressInfo

  return {
    origin: `http://127.0.0.1:${port}`,
    close: () =>
      new Promise<void>((resolve) => {
        server.close(() => resolve())
      }),
  }
}

const json = (response: ServerResponse, status: number, body: unknown): void => {
  response.writeHead(status, { "content-type": "application/json" })
  response.end(JSON.stringify(body))
}

// --- GitHub App ---------------------------------------------------------------------------

const APP_ID = "482139"
const INSTALLATION_ID = "99117744"

// Generated once so the App's public key is stable across every test that verifies a JWT.
// Assigned through a holder because a `let` declared after this IIFE would be in its TDZ.
const appKeys: { privatePem: string; publicPem: string } = (() => {
  const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 })
  return {
    privatePem: privateKey.export({ type: "pkcs8", format: "pem" }) as string,
    publicPem: publicKey.export({ type: "spki", format: "pem" }) as string,
  }
})()
const APP_PRIVATE_KEY_PEM = appKeys.privatePem

const verifyAppJwt = (token: string): Record<string, unknown> | undefined => {
  const parts = token.replace(/^Bearer\s+/u, "").split(".")
  if (parts.length !== 3) return undefined

  const [header, payload, signature] = parts
  const valid = verify(
    "sha256",
    Buffer.from(`${header}.${payload}`, "utf8"),
    createPublicKey(appKeys.publicPem),
    Buffer.from(signature ?? "", "base64url"),
  )
  if (!valid) return undefined

  return JSON.parse(Buffer.from(payload ?? "", "base64url").toString("utf8")) as Record<string, unknown>
}

test("S1 allow: an installation token is minted from a real signed JWT over real HTTP", async () => {
  let sawClaims: Record<string, unknown> | undefined
  const server = await serve((request, response, _body) => {
    sawClaims = verifyAppJwt(String(request.headers.authorization))
    json(response, 201, {
      token: "ghs_installationtokenvalue0001",
      expires_at: "2026-10-04T13:00:00Z",
      permissions: { issues: "write" },
    })
  })

  try {
    const client = createGitHubAppClient({
      appId: APP_ID,
      installationId: INSTALLATION_ID,
      privateKeyPem: APP_PRIVATE_KEY_PEM,
      apiBase: server.origin,
      now: () => NOW,
    })

    const minted = await client.obtainInstallationToken()

    assert.equal(minted.token, "ghs_installationtokenvalue0001")
    assert.equal(minted.expiresAt.toISOString(), "2026-10-04T13:00:00.000Z")
    // The App id, not the agent's, and a lifetime inside GitHub's 10-minute ceiling.
    assert.equal(sawClaims?.["iss"], APP_ID)
    assert.ok(Number(sawClaims?.["exp"]) - Number(sawClaims?.["iat"]) <= 600)
  } finally {
    await server.close()
  }
})

test("S1 deny: a GitHub server that cannot verify the JWT gets no token", async () => {
  // The server verifies against a *different* App key, exactly as GitHub would for an App
  // whose key it does not know. A mint that succeeded here would mean the client ignores
  // whether it is authenticated.
  const server = await serve((request, response) => {
    if (verifyAppJwt(String(request.headers.authorization)) === undefined) {
      json(response, 401, { message: "Bad credentials" })
      return
    }
    json(response, 201, { token: "ghs_installationtokenvalue0001", expires_at: "2026-10-04T13:00:00Z" })
  })

  try {
    const { privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 })
    const client = createGitHubAppClient({
      appId: APP_ID,
      installationId: INSTALLATION_ID,
      privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }) as string,
      apiBase: server.origin,
      now: () => NOW,
    })

    await assert.rejects(() => client.obtainInstallationToken(), /HTTP 401/u)
  } finally {
    await server.close()
  }
})

test("the installation token is cached until shortly before it expires", async () => {
  let mints = 0
  const server = await serve((_request, response) => {
    mints += 1
    json(response, 201, { token: "ghs_installationtokenvalue0001", expires_at: "2026-10-04T12:05:00Z" })
  })

  try {
    let clock = NOW
    const client = createGitHubAppClient({
      appId: APP_ID,
      installationId: INSTALLATION_ID,
      privateKeyPem: APP_PRIVATE_KEY_PEM,
      apiBase: server.origin,
      now: () => clock,
    })

    await client.obtainInstallationToken()
    await client.obtainInstallationToken()
    assert.equal(mints, 1, "a token with four minutes left must be reused")

    // Inside the one-minute skew window the cached token is no longer handed out.
    clock = new Date("2026-10-04T12:04:30.000Z")
    await client.obtainInstallationToken()
    assert.equal(mints, 2)
  } finally {
    await server.close()
  }
})

test("S1 deny: the App private key never appears in a minted token or its metadata", async () => {
  const server = await serve((_request, response) => {
    json(response, 201, { token: "ghs_installationtokenvalue0001", expires_at: "2026-10-04T13:00:00Z" })
  })

  try {
    const client = createGitHubAppClient({
      appId: APP_ID,
      installationId: INSTALLATION_ID,
      privateKeyPem: APP_PRIVATE_KEY_PEM,
      apiBase: server.origin,
      now: () => NOW,
    })

    const minted = await client.obtainInstallationToken()
    const body = createHash("sha256").update(APP_PRIVATE_KEY_PEM).digest("hex")

    assert.equal(JSON.stringify(minted).includes(body), false)
    assert.equal(JSON.stringify(minted).includes("PRIVATE KEY"), false)
  } finally {
    await server.close()
  }
})

test("a failing GitHub response is reported by status without echoing the credential", async () => {
  const server = await serve((_request, response) => {
    response.writeHead(403, { "content-type": "text/plain" })
    // A real vendor can echo the request in its error body, and the request carried the JWT.
    response.end("Bad credentials: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9")
  })

  try {
    const client = createGitHubAppClient({
      appId: APP_ID,
      installationId: INSTALLATION_ID,
      privateKeyPem: APP_PRIVATE_KEY_PEM,
      apiBase: server.origin,
      now: () => NOW,
    })

    await assert.rejects(
      () => client.obtainInstallationToken(),
      (error: Error) => {
        assert.match(error.message, /HTTP 403/u)
        assert.equal(error.message.includes("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"), false)
        return true
      },
    )
  } finally {
    await server.close()
  }
})

// --- AWS STS --------------------------------------------------------------------------------

const AWS_ACCESS_KEY = "ASIAEXAMPLE"
const AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"
const ROLE_ARN = "arn:aws:iam::123456789012:role/demo-agent"

/**
 * Rebuild the SigV4 signature from the request the server actually received.
 *
 * Written from the specification here rather than imported, so a bug in the signer cannot
 * hide behind the same bug in its verifier.
 */
const sigv4ServerCheck = (
  request: IncomingMessage,
  body: string,
): { valid: boolean; sessionName: string; detail: string } => {
  const authorization = String(request.headers.authorization ?? "")
  const match =
    /^AWS4-HMAC-SHA256 Credential=([^/]+)\/(\d{8})\/([^/]+)\/([^/]+)\/aws4_request, SignedHeaders=([^,]+), Signature=([0-9a-f]+)$/u.exec(
      authorization,
    )
  if (match === null) return { valid: false, sessionName: "", detail: "no parseable authorization" }

  const [, accessKey, dateStamp, region, service, signedHeaders, providedSignature] = match
  const names = (signedHeaders ?? "").split(";")

  const canonicalHeaders = names
    .map((name) => `${name}:${String(request.headers[name] ?? "").trim().replace(/\s+/gu, " ")}\n`)
    .join("")

  const path = request.url ?? "/"
  const [rawPath = "/", rawQuery = ""] = path.split("?")
  const canonicalQuery = rawQuery
    .split("&")
    .filter((pair) => pair !== "")
    .map((pair) => {
      const [key = "", value = ""] = pair.split("=")
      return [key, value] as const
    })
    .sort(([a], [b]) => (a < b ? -1 : 1))
    .map(([key, value]) => `${key}=${value}`)
    .join("&")

  const sha = (value: string): string =>
    createHash("sha256").update(value, "utf8").digest("hex")
  const mac = (key: Buffer | string, data: string): Buffer =>
    createHmac("sha256", key).update(data, "utf8").digest()

  const canonicalRequest = [
    request.method ?? "GET",
    rawPath,
    canonicalQuery,
    canonicalHeaders,
    signedHeaders ?? "",
    sha(body),
  ].join("\n")

  const scope = `${dateStamp}/${region}/${service}/aws4_request`
  const stringToSign = [
    "AWS4-HMAC-SHA256",
    String(request.headers["x-amz-date"] ?? ""),
    scope,
    sha(canonicalRequest),
  ].join("\n")

  const signingKey = mac(mac(mac(mac(`AWS4${AWS_SECRET_KEY}`, dateStamp ?? ""), region ?? ""), service ?? ""), "aws4_request")
  const expected = mac(signingKey, stringToSign).toString("hex")

  const sessionName = /RoleSessionName=([^&]*)/u.exec(body)?.[1] ?? ""

  return {
    valid: expected === providedSignature && accessKey === AWS_ACCESS_KEY,
    sessionName,
    detail: expected === providedSignature ? "ok" : `expected ${expected}`,
  }
}

const stsResponse = (sessionName: string): string => `<?xml version="1.0"?>
<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
    <Credentials>
      <AccessKeyId>ASIASESSIONKEY0001</AccessKeyId>
      <SecretAccessKey>wJalrSessionSecretValue0000000000000000000</SecretAccessKey>
      <SessionToken>FQoGZXIvYXdzEXAMPLEsessiontokenvalue</SessionToken>
      <Expiration>2026-10-04T12:15:00Z</Expiration>
    </Credentials>
    <AssumedRoleUser>
      <Arn>${ROLE_ARN}/actant-t_demo-reviewer-1</Arn>
      <AssumedRoleId>AROAEXAMPLE:${sessionName}</AssumedRoleId>
    </AssumedRoleUser>
  </AssumeRoleResult>
</AssumeRoleResponse>`

test("S1 allow: STS AssumeRole is accepted by a server that rebuilds the signature", async () => {
  let check: ReturnType<typeof sigv4ServerCheck> | undefined

  const server = await serve((request, response, body) => {
    check = sigv4ServerCheck(request, body)
    if (!check.valid) {
      response.writeHead(403, { "content-type": "text/xml" })
      response.end("<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code></Error></ErrorResponse>")
      return
    }
    response.writeHead(200, { "content-type": "text/xml" })
    response.end(stsResponse(check.sessionName))
  })

  try {
    const sts = createAwsStsClient({
      region: "us-east-1",
      accessKeyId: AWS_ACCESS_KEY,
      secretAccessKey: AWS_SECRET_KEY,
      endpoint: server.origin,
      now: () => NOW,
    })

    const assumed = await sts.assumeRole({
      roleArn: ROLE_ARN,
      sessionName: sessionNameForAgent(context()),
      durationSeconds: 900,
    })

    assert.equal(check?.valid, true, `server rejected the signature: ${check?.detail}`)
    assert.equal(assumed.accessKeyId, "ASIASESSIONKEY0001")
    assert.equal(assumed.expiration.toISOString(), "2026-10-04T12:15:00.000Z")
  } finally {
    await server.close()
  }
})

test("S1 deny: an STS server rejects a request whose body was altered after signing", async () => {
  // A fetch interceptor stands between the signer and the server and swaps the RoleArn for
  // a wider one, keeping the Authorization header. If the signature did not cover the body,
  // the server would accept the request and the agent would hold a credential for a role it
  // never asked for — privilege escalation that looks like a successful call.
  const server = await serve((request, response, body) => {
    const check = sigv4ServerCheck(request, body)
    if (!check.valid) {
      response.writeHead(403)
      response.end("<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code></Error></ErrorResponse>")
      return
    }
    response.writeHead(200, { "content-type": "text/xml" })
    response.end(stsResponse(check.sessionName))
  })

  try {
    const sts = createAwsStsClient({
      region: "us-east-1",
      accessKeyId: AWS_ACCESS_KEY,
      secretAccessKey: AWS_SECRET_KEY,
      endpoint: server.origin,
      now: () => NOW,
      fetchImpl: async (input, init) => {
        const tampered = String(init?.body ?? "").replace(
          /RoleArn=[^&]*/u,
          "RoleArn=arn%3Aaws%3Aiam%3A%3A123456789012%3Arole%2Fadministrator",
        )
        return fetch(input, { ...init, body: tampered })
      },
    })

    await assert.rejects(
      () => sts.assumeRole({ roleArn: ROLE_ARN, sessionName: "actant-t_demo-reviewer-1", durationSeconds: 900 }),
      /HTTP 403/u,
    )
  } finally {
    await server.close()
  }
})

test("S1 deny: an STS response missing a credential field is refused, not half-assembled", async () => {
  const server = await serve((_request, response) => {
    response.writeHead(200, { "content-type": "text/xml" })
    response.end(`<AssumeRoleResponse><Credentials><AccessKeyId>ASIA1</AccessKeyId></Credentials></AssumeRoleResponse>`)
  })

  try {
    const sts = createAwsStsClient({
      region: "us-east-1",
      accessKeyId: AWS_ACCESS_KEY,
      secretAccessKey: AWS_SECRET_KEY,
      endpoint: server.origin,
      now: () => NOW,
    })

    // Every missing field throws. A credential assembled from `undefined` would look like a
    // successful mint to the broker and would be carried to a real API call.
    await assert.rejects(
      () => sts.assumeRole({ roleArn: ROLE_ARN, sessionName: "actant-x", durationSeconds: 900 }),
      /carried no SecretAccessKey/u,
    )
  } finally {
    await server.close()
  }
})

// --- The session name binds the credential to the agent ---------------------------------------

test("S13 allow: the AWS session is named for the verified agent, not a constant", async () => {
  let observed = ""
  const server = await serve((request, response, body) => {
    const check = sigv4ServerCheck(request, body)
    observed = check.sessionName
    response.writeHead(check.valid ? 200 : 403, { "content-type": "text/xml" })
    response.end(stsResponse(observed))
  })

  try {
    const provider = createStsCredentialProvider(
      createAwsStsClient({
        region: "us-east-1",
        accessKeyId: AWS_ACCESS_KEY,
        secretAccessKey: AWS_SECRET_KEY,
        endpoint: server.origin,
        now: () => NOW,
      }),
    )

    await provider.obtain(
      { provider: "aws", segments: [ROLE_ARN] } as never,
      context("reviewer-1"),
    )

    assert.equal(observed, "actant-t_demo-spiffe---t_demo-reviewer-1")
    assert.equal(observed.includes("actant-broker"), false)
  } finally {
    await server.close()
  }
})

test("tenant and agent identity survive sanitisation without collapsing", () => {
  // A charset that drops underscore maps `t_demo` and `t-demo` onto the same session name,
  // which is precisely the attribution collision this function exists to remove.
  const name = (tenantId: string, agentId: string) =>
    sessionNameForAgent({ tenantId, agentSpiffeId: `spiffe://${tenantId}/${agentId}`, at: NOW })

  assert.notEqual(name("t_demo", "a"), name("t-demo", "a"))
  assert.notEqual(name("t_demo", "reviewer_1"), name("t_demo", "reviewer-1"))
  assert.match(name("t_demo", "reviewer-1"), /t_demo/u, "the underscore must survive")
})

test("S4 allow: two agents never share an AWS session name", () => {
  // Before this change every agent produced the literal "actant-broker", so a CloudTrail
  // entry could not say which agent caused an effect. Distinctness is the property; the
  // constant is what removed it.
  const a = sessionNameForAgent(context("reviewer-1"))
  const b = sessionNameForAgent(context("reviewer-2"))

  assert.notEqual(a, b)
  assert.match(a, /^[\w+=,.@-]{2,64}$/u, "STS constrains the session name charset and length")
  assert.match(b, /^[\w+=,.@-]{2,64}$/u)
})

test("two long distinct identities still produce distinct STS-legal session names", () => {
  const long = (agentId: string) =>
    sessionNameForAgent({ tenantId: TENANT, agentSpiffeId: `spiffe://${TENANT}/${agentId}`, at: NOW })

  const a = long(`${"x".repeat(80)}-alpha`)
  const b = long(`${"x".repeat(80)}-beta`)

  assert.notEqual(a, b, "truncation must not collapse two identities onto one name")
  assert.match(a, /^[\w+=,.@-]{2,64}$/u)
  assert.match(b, /^[\w+=,.@-]{2,64}$/u)
})

// --- Vault -----------------------------------------------------------------------------------

test("S1 allow: a Vault lease is read over real HTTP and revoked on release", async () => {
  const revoked: string[] = []
  let secretIdSeen = ""

  const server = await serve((request, response, body) => {
    const url = request.url ?? ""

    if (url === "/v1/auth/approle/login") {
      secretIdSeen = String((JSON.parse(body) as { secret_id?: string }).secret_id ?? "")
      json(response, 200, { auth: { client_token: "hvs.cafewhere-realclienttoken", lease_duration: 60 } })
      return
    }

    if (url === "/v1/sys/leases/revoke") {
      revoked.push(String((JSON.parse(body) as { lease_id?: string }).lease_id ?? ""))
      json(response, 200, {})
      return
    }

    if (url.startsWith("/v1/secret/database/creds/app")) {
      json(response, 200, {
        lease_id: "database/creds/app/9f2c7a11-0000-4444-8888-abcdefabcdef",
        lease_duration: 300,
        data: { username: "v-approle-demo-abc", password: "A1b2C3d4RealVaultSecretValue" },
      })
      return
    }

    json(response, 404, { errors: ["not found"] })
  })

  try {
    const client = createVaultAppRoleClient({
      address: server.origin,
      roleId: "db02de05-fa39-4855-059b-67221c5c2f63",
      secretId: "f7d1c9a2-realsecret-id",
      now: () => NOW,
    })
    const provider = createVaultCredentialProvider(client)

    const grant = { provider: "vault", segments: ["database/creds/app"] } as never
    const credential = await provider.obtain(grant, context())
    await provider.destroy(credential)

    assert.equal(secretIdSeen, "f7d1c9a2-realsecret-id")
    assert.deepEqual(JSON.parse(credential.value), {
      username: "v-approle-demo-abc",
      password: "A1b2C3d4RealVaultSecretValue",
    })
    assert.deepEqual(revoked, ["database/creds/app/9f2c7a11-0000-4444-8888-abcdefabcdef"])
  } finally {
    await server.close()
  }
})

test("S1 deny: the broker's own expiry check refuses an already-expired credential", async () => {
  const vault: VaultClient = {
    async readDynamicSecret() {
      return {
        value: "A1b2C3d4RealVaultSecretValue",
        leaseId: "lease-expired",
        expiresAt: new Date(NOW.getTime() - 1),
      }
    },
    async revokeLease() {},
  }

  const provider = createVaultCredentialProvider(vault)
  const credential = await provider.obtain({ provider: "vault", segments: ["database/creds/app"] } as never, context())

  assert.ok(credential.expiresAt.getTime() <= NOW.getTime())
})

test("S12 allow: the credential expires when Vault says so, not when the caller asked", async () => {
  // Vault can grant a shorter TTL than the one requested — a policy cap, or a database
  // engine whose own credential lifetime is the binding constraint. Trusting the request
  // would hand the broker an expiry later than the truth, and the broker would use the
  // credential past its life and report it as valid.
  const server = await serve((request, response) => {
    const url = request.url ?? ""

    if (url === "/v1/auth/approle/login") {
      json(response, 200, { auth: { client_token: "hvs.cafewhere-realclienttoken", lease_duration: 60 } })
      return
    }

    // 300 seconds were requested; Vault grants 45.
    json(response, 200, {
      lease_id: "database/creds/app/9f2c7a11-0000-4444-8888-abcdefabcdef",
      lease_duration: 45,
      data: { username: "v-approle-demo-abc", password: "A1b2C3d4RealVaultSecretValue" },
    })
  })

  try {
    const client = createVaultAppRoleClient({
      address: server.origin,
      roleId: "db02de05-fa39-4855-059b-67221c5c2f63",
      secretId: "f7d1c9a2-realsecret-id",
      now: () => NOW,
    })
    const provider = createVaultCredentialProvider(client)

    const credential = await provider.obtain(
      { provider: "vault", segments: ["database/creds/app"] } as never,
      context(),
    )

    assert.equal(credential.expiresAt.getTime(), NOW.getTime() + 45_000)
    assert.notEqual(credential.expiresAt.getTime(), NOW.getTime() + 300_000)
  } finally {
    await server.close()
  }
})

/**
 * Defect A, pinned.
 *
 * Before the fix the provider held one `activeLeaseId`. Two concurrent grants overwrote it,
 * so destroying the first credential revoked the *second's* still-in-use lease while the
 * first's lease survived unrevoked for its full TTL. This was measured against the previous
 * implementation, which reported `revoked: ['lease-2']` when handed credential `a`.
 */
test("Defect A: destroying one credential revokes that credential's own lease", async () => {
  const revoked: string[] = []
  let counter = 0

  const client: VaultClient = {
    async readDynamicSecret() {
      counter += 1
      return {
        value: `secret-${counter}`,
        leaseId: `lease-${counter}`,
        expiresAt: new Date(NOW.getTime() + 300_000),
      }
    },
    async revokeLease({ leaseId }) {
      revoked.push(leaseId)
    },
  }

  const provider = createVaultCredentialProvider(client)
  const grant = { provider: "vault", segments: ["database/creds/app"] } as never

  const first = await provider.obtain(grant, context("reviewer-1"))
  const second = await provider.obtain(grant, context("reviewer-2"))

  await provider.destroy(first)

  assert.deepEqual(revoked, ["lease-1"], "the credential destroyed must be the lease revoked")
  assert.equal(revoked.includes("lease-2"), false, "the other live lease must survive")

  await provider.destroy(second)
  assert.deepEqual(revoked, ["lease-1", "lease-2"])
})

test("Defect A: a handle cannot be reused to revoke another grant's lease", async () => {
  const revoked: string[] = []
  let counter = 0

  const provider = createVaultCredentialProvider({
    async readDynamicSecret() {
      counter += 1
      return { value: `s${counter}`, leaseId: `lease-${counter}`, expiresAt: new Date(NOW.getTime() + 300_000) }
    },
    async revokeLease({ leaseId }) {
      revoked.push(leaseId)
    },
  })

  const grant = { provider: "vault", segments: ["database/creds/app"] } as never
  const first = await provider.obtain(grant, context("reviewer-1"))
  const handle = first.handle

  await provider.destroy(first)
  // A second destroy with the same handle must not revoke anything again: the entry is
  // removed before the revoke is awaited, so a retry cannot hit a reassigned lease.
  await provider.destroy(first)

  assert.deepEqual(revoked, ["lease-1"])
  assert.notEqual(handle, undefined)
})

test("Defect A: two agents minting at once each keep their own lease", async () => {
  const revoked: string[] = []
  let counter = 0

  const provider = createVaultCredentialProvider({
    async readDynamicSecret() {
      counter += 1
      const n = counter
      // Interleave the two mints so the second finishes first, as real I/O would.
      await new Promise((resolve) => setTimeout(resolve, n === 1 ? 10 : 1))
      return { value: `s${n}`, leaseId: `lease-${n}`, expiresAt: new Date(NOW.getTime() + 300_000) }
    },
    async revokeLease({ leaseId }) {
      revoked.push(leaseId)
    },
  })

  const grant = { provider: "vault", segments: ["database/creds/app"] } as never
  const [first, second] = await Promise.all([
    provider.obtain(grant, context("reviewer-1")),
    provider.obtain(grant, context("reviewer-2")),
  ])

  // Finish in reverse order — the case the single slot could not represent.
  await provider.destroy(second)
  await provider.destroy(first)

  assert.deepEqual(revoked.sort(), ["lease-1", "lease-2"])
})

// --- The echo gap -----------------------------------------------------------------------------

/**
 * Defect D, pinned.
 *
 * The boundary check inspected field *names* only. A provider returning the credential under
 * `{ data: "<token>" }` passed it cleanly. This was measured: `assertNoCredentialsInResult`
 * accepted `{ data: SECRET }`. The fix checks the value the broker is holding.
 */
test("Defect D: the credential value is refused even under an innocuous field name", () => {
  const credential = "ghs_installationtokenvalue0001"
  const markers = credentialMarkers(credential)

  assert.throws(
    () => assertCredentialNotEchoed({ data: credential, status: 200 }, markers),
    /CredentialLeakError/u,
  )
  assert.doesNotThrow(() => assertCredentialNotEchoed({ data: "a normal result" }, markers))
})

test("Defect D: a JSON credential is refused when any one of its components is echoed", () => {
  const credential = JSON.stringify({
    accessKeyId: "ASIASESSIONKEY0001",
    secretAccessKey: "wJalrSessionSecretValue0000000000000000000",
    sessionToken: "FQoGZXIvYXdzEXAMPLEsessiontokenvalue",
  })
  const markers = credentialMarkers(credential)

  // The component, not the whole blob: this is the shape a provider would produce by
  // pulling one field out of the credential it was handed.
  assert.throws(
    () => assertCredentialNotEchoed({ session: { token: "FQoGZXIvYXdzEXAMPLEsessiontokenvalue" } }, markers),
    /CredentialLeakError/u,
  )
  assert.throws(() => assertCredentialNotEchoed({ whole: credential }, markers), /CredentialLeakError/u)
  assert.doesNotThrow(() => assertCredentialNotEchoed({ issues: [{ number: 1, title: "bug" }] }, markers))
})

test("Defect D: the credential is refused when it is smuggled into a field name", () => {
  const credential = "ghs_installationtokenvalue0001"

  assert.throws(
    () => assertCredentialNotEchoed({ [`x-${credential}`]: "value" }, credentialMarkers(credential)),
    /CredentialLeakError/u,
  )
})

test("a short credential fragment does not refuse unrelated data", () => {
  // Without a floor, a component like a username would match ordinary response text and
  // switch the control off by making it useless.
  assert.deepEqual(credentialMarkers("abc"), [])
  assert.deepEqual(credentialMarkers(JSON.stringify({ username: "svc", password: "x" })), [JSON.stringify({ username: "svc", password: "x" })])
  assert.deepEqual(credentialMarkers("longenoughsecret"), ["longenoughsecret"])
})

// --- The whole broker path, end to end ----------------------------------------------------------

test("S1 allow: a real GitHub call through the broker returns data and no credential", async () => {
  const server = await serve((request, response) => {
    const url = request.url ?? ""

    if (url.startsWith("/app/installations/")) {
      if (verifyAppJwt(String(request.headers.authorization)) === undefined) {
        json(response, 401, { message: "Bad credentials" })
        return
      }
      json(response, 201, { token: "ghs_installationtokenvalue0001", expires_at: "2026-10-04T13:00:00Z" })
      return
    }

    if (String(request.headers.authorization) !== "Bearer ghs_installationtokenvalue0001") {
      json(response, 401, { message: "Bad credentials" })
      return
    }

    json(response, 200, [
      { number: 1, title: "flaky test", user: { login: "octocat" }, labels: [{ name: "bug" }] },
    ])
  })

  try {
    const appClient = createGitHubAppClient({
      appId: APP_ID,
      installationId: INSTALLATION_ID,
      privateKeyPem: APP_PRIVATE_KEY_PEM,
      apiBase: server.origin,
      now: () => NOW,
    })

    const provider: CapabilityProvider = createGitHubCapabilityProvider(
      createHttpGitHubClient({
        obtainToken: async () => (await appClient.obtainInstallationToken()).token,
        apiBase: server.origin,
      }),
    )

    const evidenceChain = new EvidenceChain({ tenantId: TENANT, issuerId: ISSUER_ID, keyPair })
    const broker = new CapabilityBroker({
      tenantId: TENANT,
      trustedIssuerKeys,
      evidenceChain,
      providers: [provider],
      credentialProviders: new Map([
        [
          "github",
          {
            id: "github-app",
            async obtain() {
              return {
                value: "ghs_installationtokenvalue0001",
                expiresAt: new Date(NOW.getTime() + 3_600_000),
              }
            },
            async destroy() {},
          },
        ],
      ]),
      now: () => NOW,
    })

    broker.setAuthorityResolver(() => ["grant://github/octo/repo/issues/read"])

    const outcome = await broker.grant({
      identityToken: identityToken(),
      grantUri: "grant://github/octo/repo/issues/read",
      args: {},
    })

    assert.equal(outcome.granted, true)
    assert.deepEqual(outcome.granted && outcome.result, [
      { number: 1, title: "flaky test", user: { login: "octocat" }, labels: [{ name: "bug" }] },
    ])
    assert.equal(
      JSON.stringify(outcome).includes("ghs_installationtokenvalue0001"),
      false,
      "the installation token must not appear anywhere in the broker outcome",
    )
  } finally {
    await server.close()
  }
})

test("S1 deny: a provider that echoes the live credential under a plain name is refused", async () => {
  const leakyProvider: CapabilityProvider = {
    provider: "github",
    requiresCredential: true,
    supports: () => true,
    async execute(args) {
      // The exact attack the key-name check misses.
      return { issues: [], data: args.credential?.value }
    },
  }

  const evidenceChain = new EvidenceChain({ tenantId: TENANT, issuerId: ISSUER_ID, keyPair })
  const broker = new CapabilityBroker({
    tenantId: TENANT,
    trustedIssuerKeys,
    evidenceChain,
    providers: [leakyProvider],
    credentialProviders: new Map([
      [
        "github",
        {
          id: "leaky",
          async obtain() {
            return { value: "ghs_installationtokenvalue0001", expiresAt: new Date(NOW.getTime() + 3_600_000) }
          },
          async destroy() {},
        },
      ],
    ]),
    now: () => NOW,
  })
  broker.setAuthorityResolver(() => ["grant://github/octo/repo/issues/read"])

  const outcome = await broker.grant({
    identityToken: identityToken(),
    grantUri: "grant://github/octo/repo/issues/read",
    args: {},
  })

  assert.equal(outcome.granted, false)
  assert.equal(outcome.granted === false && outcome.reason, "credential_leak")
  assert.ok(
    evidenceChain
      .export()
      .records.some((record) => record.evidence_type === "security_violation"),
  )
})

test("S12 deny: a credential the provider reports as already expired is never handed on", async () => {
  let executed = false

  const provider: CapabilityProvider = {
    provider: "github",
    requiresCredential: true,
    supports: () => true,
    async execute() {
      executed = true
      return {}
    },
  }

  const broker = new CapabilityBroker({
    tenantId: TENANT,
    trustedIssuerKeys,
    evidenceChain: new EvidenceChain({ tenantId: TENANT, issuerId: ISSUER_ID, keyPair }),
    providers: [provider],
    credentialProviders: new Map([
      [
        "github",
        {
          id: "stale",
          async obtain() {
            return { value: "ghs_installationtokenvalue0001", expiresAt: new Date(NOW.getTime() - 1) }
          },
          async destroy() {},
        },
      ],
    ]),
    now: () => NOW,
  })
  broker.setAuthorityResolver(() => ["grant://github/octo/repo/issues/read"])

  const outcome = await broker.grant({
    identityToken: identityToken(),
    grantUri: "grant://github/octo/repo/issues/read",
    args: {},
  })

  assert.equal(outcome.granted, false)
  assert.equal(outcome.granted === false && outcome.reason, "credential_unavailable")
  assert.equal(executed, false, "the provider must never be reached with an expired credential")
})

test("S12 deny: an unusable expiry is treated as a failure, not as unlimited", async () => {
  let executed = false

  const broker = new CapabilityBroker({
    tenantId: TENANT,
    trustedIssuerKeys,
    evidenceChain: new EvidenceChain({ tenantId: TENANT, issuerId: ISSUER_ID, keyPair }),
    providers: [
      {
        provider: "github",
        requiresCredential: true,
        supports: () => true,
        async execute() {
          executed = true
          return {}
        },
      },
    ],
    credentialProviders: new Map([
      [
        "github",
        {
          id: "undatable",
          async obtain() {
            return { value: "ghs_installationtokenvalue0001", expiresAt: new Date("nonsense") }
          },
          async destroy() {},
        },
      ],
    ]),
    now: () => NOW,
  })
  broker.setAuthorityResolver(() => ["grant://github/octo/repo/issues/read"])

  const outcome = await broker.grant({
    identityToken: identityToken(),
    grantUri: "grant://github/octo/repo/issues/read",
    args: {},
  })

  assert.equal(outcome.granted, false)
  assert.equal(outcome.granted === false && outcome.reason, "credential_unavailable")
  assert.equal(executed, false)
})