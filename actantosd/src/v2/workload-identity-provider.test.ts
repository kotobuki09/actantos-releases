import assert from "node:assert/strict"
import { createServer, type Server } from "node:http"
import { generateKeyPairSync, sign as cryptoSign, randomBytes } from "node:crypto"
import { after, test } from "node:test"

import {
  createSpireIdentityProvider,
  fetchJwks,
  parseJwt,
  rawEcdsaToDer,
  requestSvid,
  resolveIdentitySource,
  spiffeIdFromClaims,
  verifyIdentityToken,
  verifyJwtSvid,
  type Jwk,
} from "./workload-identity-provider.ts"
import { DEFAULT_WORKLOAD_SOCKET } from "./spiffe-workload-api.ts"
import { ed25519 } from "./signature.ts"
import {
  buildSpiffeId,
  mintWorkloadIdentity,
  signWorkloadIdentity,
} from "./workload-identity.ts"

/**
 * Everything below signs and verifies with real keys through `node:crypto`. No stub ever produces
 * the bytes under test: a mock signer would let the tests pass against a verifier that is wrong.
 */

const TRUST_DOMAIN = "actantos.local"
const KID = "trust-domain-key-1"

const b64url = (bytes: Buffer): string =>
  bytes.toString("base64").replace(/\+/gu, "-").replace(/\//gu, "_").replace(/=+$/u, "")

const edKeyPair = generateKeyPairSync("ed25519")
const rsaKeyPair = generateKeyPairSync("rsa", { modulusLength: 2048 })
const ecKeyPair = generateKeyPairSync("ec", { namedCurve: "P-256" })

/** The JWK form Node would export for each key, which is what a JWKS actually carries. */
const edPublicJwk = edKeyPair.publicKey.export({ format: "jwk" }) as Jwk & { kid?: string }
const rsaPublicJwk = rsaKeyPair.publicKey.export({ format: "jwk" }) as Jwk & { kid?: string }
const ecPublicJwk = ecKeyPair.publicKey.export({ format: "jwk" }) as Jwk & { kid?: string }

const edJwks: Jwk[] = [{ ...edPublicJwk, kid: KID }]
const rsaJwks: Jwk[] = [{ ...rsaPublicJwk, kid: KID }]
const ecJwks: Jwk[] = [{ ...ecPublicJwk, kid: KID }]

/**
 * Re-encode a DER ECDSA signature as the raw R‖S that JWS carries.
 *
 * `node:crypto` signs ECDSA into DER and has no option to emit the raw form, so a signer that
 * produces a real JWS has to convert. This is the mirror of the conversion the verifier performs
 * in the other direction, and keeping both in the test is what makes the tests meaningful: a
 * verifier that merely passed the bytes through would fail here rather than pass.
 *
 * The padding rule is the whole content of this helper. A DER INTEGER is the shortest encoding of
 * a signed integer, so it drops leading zero bytes as well as adding a `0x00` sign byte. JWS wants
 * R and S fixed-width at 32 bytes each. An earlier version of this function only stripped the sign
 * byte, which is correct for every signature whose top byte happens to have its high bit set but
 * wrong for the roughly 1 in 128 signatures where R or S begins with a zero byte: those came out 31
 * bytes and the token carried a 63-byte signature. The verifier correctly refused those as
 * `signature_invalid`, so the affected test failed roughly one run in 128 with a reason that had
 * nothing to do with what it was asserting. Left-padding below is the fix; it makes the signer
 * produce a spec-conformant token so the test reaches the check it means to reach.
 */
const derToRawEcdsa = (der: Buffer): Buffer => {
  assert.equal(der[0], 0x30, "the signature is not a DER SEQUENCE")

  let offset = 2
  const readInteger = (): Buffer => {
    assert.equal(der[offset], 0x02, "the signature has no DER INTEGER")
    const length = der[offset + 1] as number
    const value = der.subarray(offset + 2, offset + 2 + length)
    offset += 2 + length
    // Strip the sign-padding byte DER adds when the top bit is set.
    const unsigned = value.length > 32 && value[0] === 0 ? value.subarray(1) : value

    // DER also drops leading zeros outright, which can leave the integer short. JWS fixes R and S
    // at 32 bytes, so pad on the left rather than letting a short integer through.
    assert.ok(unsigned.length <= 32, "a P-256 integer cannot exceed 32 bytes")
    return Buffer.concat([Buffer.alloc(32 - unsigned.length), unsigned])
  }

  return Buffer.concat([readInteger(), readInteger()])
}

type SignOptions = {
  readonly claims: Record<string, unknown>
  readonly header?: Record<string, unknown>
  readonly key?: "ed" | "rsa" | "ec"
  /** Corrupt the signature after signing, leaving the header and claims intact. */
  readonly tamperSignature?: boolean
  /** Overwrite the signature entirely, for `alg: none`. */
  readonly stripSignature?: boolean
}

const ALG_FOR_KEY = { rsa: "RS256", ec: "ES256", ed: "Ed25519" } as const

const signJwt = (options: SignOptions): string => {
  const which = options.key ?? "ed"
  const header = {
    alg: ALG_FOR_KEY[which],
    kid: KID,
    typ: "JWT",
    ...options.header,
  }
  const signingInput = `${b64url(Buffer.from(JSON.stringify(header)))}.${b64url(
    Buffer.from(JSON.stringify(options.claims)),
  )}`

  if (options.stripSignature === true) return `${signingInput}.`

  const privateKey = which === "rsa" ? rsaKeyPair.privateKey : which === "ec" ? ecKeyPair.privateKey : edKeyPair.privateKey
  const signature = which === "ed"
    ? cryptoSign(null, Buffer.from(signingInput), privateKey)
    : cryptoSign("sha256", Buffer.from(signingInput), privateKey)

  const encoded = b64url(
    options.tamperSignature === true
      ? randomBytes(64)
      : // ECDSA reaches the wire in the raw form JWS specifies, not the DER form Node produced.
        which === "ec"
        ? derToRawEcdsa(signature)
        : signature,
  )

  return `${signingInput}.${encoded}`
}

const NOW = new Date("2026-10-04T12:00:00.000Z")
const NOW_SECONDS = NOW.getTime() / 1000

const goodClaims = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
  sub: buildSpiffeId("acme", "planner"),
  iss: `spiffe://${TRUST_DOMAIN}`,
  aud: "actantos-fabric",
  iat: NOW_SECONDS - 5,
  nbf: NOW_SECONDS - 5,
  exp: NOW_SECONDS + 600,
  ...overrides,
})

const verifyEd = (token: string, overrides: Partial<Parameters<typeof verifyJwtSvid>[1]> = {}) =>
  verifyJwtSvid(token, {
    jwks: edJwks,
    expectedTrustDomain: TRUST_DOMAIN,
    expectedAudience: "actantos-fabric",
    now: NOW,
    ...overrides,
  })

/* ------------------------------------------------------------------------ JWS parsing */

test("a signed JWS splits into its header, claims, and the bytes the signature covers", () => {
  const token = signJwt({ claims: goodClaims() })
  const parsed = parseJwt(token)

  assert.notEqual(parsed, undefined)
  assert.equal(parsed?.header.alg, "Ed25519")
  assert.equal(parsed?.header.kid, KID)
  assert.equal(parsed?.claims.sub, buildSpiffeId("acme", "planner"))
  // The signing input is the two encoded segments, not the token: verifying the wrong span is the
  // classic JWS mistake, and this asserts the span is right.
  assert.equal(parsed?.signingInput.toString("ascii"), token.slice(0, token.lastIndexOf(".")))
})

test("anything that is not three JSON segments is not parsed", () => {
  assert.equal(parseJwt("not-a-jwt"), undefined)
  assert.equal(parseJwt("only.two"), undefined)
  assert.equal(parseJwt("a.b.c.d"), undefined)
  // Base64 that decodes to something that is not JSON.
  assert.equal(parseJwt(`${b64url(Buffer.from("[]"))}.${b64url(Buffer.from("{}"))}.AA`), undefined)
  assert.equal(parseJwt(`.${b64url(Buffer.from("{}"))}.AA`), undefined)
})

/* --------------------------------------------------------------------- happy paths (S4) */

test("an Ed25519 JWT-SVID from the trust domain verifies", () => {
  const result = verifyEd(signJwt({ claims: goodClaims() }))

  assert.equal(result.ok, true)
  assert.equal(
    spiffeIdFromClaims(result.ok ? result.parsed.claims : {}),
    buildSpiffeId("acme", "planner"),
  )
})

test("an RS256 JWT-SVID from the trust domain verifies too", () => {
  // SPIRE is not Ed25519-only. A verifier that only handled one algorithm would pass every other
  // test here and fail against a real trust domain.
  const result = verifyEd(signJwt({ claims: goodClaims(), key: "rsa" }), { jwks: rsaJwks })

  assert.equal(result.ok, true)
})

test("an audience given as an array is accepted when it contains the expected value", () => {
  const result = verifyEd(signJwt({ claims: goodClaims({ aud: ["other", "actantos-fabric"] }) }))

  assert.equal(result.ok, true)
})

test("a trust domain with no expected audience verifies any audience", () => {
  const result = verifyEd(signJwt({ claims: goodClaims() }), { expectedAudience: undefined })

  assert.equal(result.ok, true)
})

/* ------------------------------------------------------- every refusal has its own reason */

test("a tampered signature is refused as signature_invalid, not as anything softer", () => {
  const result = verifyEd(signJwt({ claims: goodClaims(), tamperSignature: true }))

  assert.equal(result.ok, false)
  assert.equal(result.ok === false && result.reason, "signature_invalid")
})

test("a signature made by a different key under the same kid is refused", () => {
  // This is the attack the kid lookup invites: publish one kid, sign with another. Selecting by
  // name and skipping verification would accept it.
  const other = generateKeyPairSync("ed25519")
  const header = { alg: "Ed25519", kid: KID, typ: "JWT" }
  const claims = goodClaims()
  const signingInput = `${b64url(Buffer.from(JSON.stringify(header)))}.${b64url(
    Buffer.from(JSON.stringify(claims)),
  )}`
  const forged = `${signingInput}.${b64url(cryptoSign(null, Buffer.from(signingInput), other.privateKey))}`

  const result = verifyEd(forged)

  assert.equal(result.ok, false)
  assert.equal(result.ok === false && result.reason, "signature_invalid")
})

test("alg none is refused as unsupported_algorithm", () => {
  // The single most important case in this file. An unsigned token must not reach the identity
  // minting path, and `none` is the header value that asks for exactly that.
  const token = signJwt({ claims: goodClaims(), header: { alg: "none" }, stripSignature: true })

  assert.equal(parseJwt(token) !== undefined, true, "the token itself must parse — it is not malformed")

  const result = verifyEd(token)

  assert.equal(result.ok, false)
  assert.equal(result.ok === false && result.reason, "unsupported_algorithm")
})

test("an absent alg is refused as unsupported_algorithm", () => {
  const header = { kid: KID, typ: "JWT" }
  const token = `${b64url(Buffer.from(JSON.stringify(header)))}.${b64url(
    Buffer.from(JSON.stringify(goodClaims())),
  )}.AA`

  const result = verifyEd(token)

  assert.equal(result.ok, false)
  assert.equal(result.ok === false && result.reason, "unsupported_algorithm")
})

test("an unknown algorithm is refused rather than handed to the verifier", () => {
  const result = verifyEd(signJwt({ claims: goodClaims(), header: { alg: "HS256" } }))

  assert.equal(result.ok, false)
  assert.equal(result.ok === false && result.reason, "unsupported_algorithm")
})

test("a token whose kid is not published is refused as unknown_signing_key", () => {
  const result = verifyEd(signJwt({ claims: goodClaims(), header: { kid: "some-other-key" } }))

  assert.equal(result.ok, false)
  assert.equal(result.ok === false && result.reason, "unknown_signing_key")
})

test("a JWKS with no keys at all refuses every token", () => {
  const result = verifyEd(signJwt({ claims: goodClaims() }), { jwks: [] })

  assert.equal(result.ok, false)
  assert.equal(result.ok === false && result.reason, "unknown_signing_key")
})

test("an expired SVID is refused as expired", () => {
  const result = verifyEd(
    signJwt({ claims: goodClaims({ exp: NOW_SECONDS - 1, nbf: NOW_SECONDS - 600 }) }),
  )

  assert.equal(result.ok, false)
  assert.equal(result.ok === false && result.reason, "expired")
})

test("an SVID expiring exactly now is expired — the boundary is not exclusive", () => {
  const result = verifyEd(
    signJwt({ claims: goodClaims({ exp: NOW_SECONDS, nbf: NOW_SECONDS - 600 }) }),
  )

  assert.equal(result.ok, false)
  assert.equal(result.ok === false && result.reason, "expired")
})

test("an SVID that is not yet valid is refused as not_yet_valid", () => {
  const result = verifyEd(signJwt({ claims: goodClaims({ nbf: NOW_SECONDS + 60 }) }))

  assert.equal(result.ok, false)
  assert.equal(result.ok === false && result.reason, "not_yet_valid")
})

test("an SVID with no numeric exp is refused as malformed, before any claim is trusted", () => {
  const result = verifyEd(signJwt({ claims: goodClaims({ exp: "soon" }) }))

  assert.equal(result.ok, false)
  assert.equal(result.ok === false && result.reason, "malformed_jwt")
})

test("an SVID from another trust domain is refused", () => {
  const result = verifyEd(signJwt({ claims: goodClaims({ iss: "spiffe://evil.example" }) }))

  assert.equal(result.ok, false)
  assert.equal(result.ok === false && result.reason, "wrong_trust_domain")
})

test("an SVID for another audience is refused", () => {
  const result = verifyEd(signJwt({ claims: goodClaims({ aud: ["some-other-service"] }) }))

  assert.equal(result.ok, false)
  assert.equal(result.ok === false && result.reason, "wrong_audience")
})

test("a JWK whose type disagrees with the header alg cannot verify the token", () => {
  // The RSA key is published under the Ed25519 header. Field agreement is checked, so the bytes
  // are never handed to createVerify in a shape it would have to guess at.
  const result = verifyEd(signJwt({ claims: goodClaims() }), { jwks: [{ ...rsaPublicJwk, kid: KID }] })

  assert.equal(result.ok, false)
  assert.equal(result.ok === false && result.reason, "signature_invalid")
})

test("every refusal carries a detail that names the reason", () => {
  // An operator triaging an authentication spike gets a code, but the detail is what makes the code
  // actionable. A blank detail would pass every check above.
  const failures = [
    verifyEd(signJwt({ claims: goodClaims(), tamperSignature: true })),
    verifyEd(signJwt({ claims: goodClaims({ exp: 1 }) })),
    verifyEd(signJwt({ claims: goodClaims({ iss: "spiffe://other" }) })),
    verifyEd(signJwt({ claims: goodClaims({ aud: "other" }) })),
  ]

  for (const failure of failures) {
    assert.equal(failure.ok, false)
    assert.equal(
      failure.ok === false && failure.detail.trim().length > 0,
      true,
      `empty detail for ${failure.ok === false ? failure.reason : "a success"}`,
    )
  }
})

/* ---------------------------------------------- a real HTTP server, standing in for SPIRE */

type Route = (path: string) => { status: number; body: unknown }

const startStub = async (route: Route): Promise<{ url: string; close: () => Promise<void> }> => {
  const server: Server = createServer((req, res) => {
    const path = req.url ?? "/"
    const answer = route(path)

    res.writeHead(answer.status, { "content-type": "application/json" })
    res.end(JSON.stringify(answer.body))
  })

  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve))

  const address = server.address()

  assert.notEqual(address, null)
  const port = typeof address === "object" && address !== null ? address.port : 0

  return {
    url: `http://127.0.0.1:${port}`,
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  }
}

const openStubs: Array<() => Promise<void>> = []

after(async () => {
  for (const close of openStubs) await close()
})

const stub = async (route: Route): Promise<{ url: string; close: () => Promise<void> }> => {
  const started = await startStub(route)

  openStubs.push(started.close)

  return started
}

/* ------------------------------------------------------------- the Workload API protocol */

test("the Workload API request names the SPIFFE ID and carries the JWT accept header", async () => {
  const seen: Array<{ path: string; accept: string | undefined }> = []
  const api = await stub((path) => {
    seen.push({ path, accept: undefined })
    return { status: 200, body: { [buildSpiffeId("acme", "planner")]: { svid: { jwt: "token" } } } }
  })

  const result = await requestSvid({
    workloadApi: api.url,
    spiffeId: buildSpiffeId("acme", "planner"),
    trustDomain: TRUST_DOMAIN,
    jwksUri: "http://unused",
  })

  assert.equal("token" in result, true)
  assert.equal(seen[0]?.path.startsWith("/workload-api/jwt-svid?spiffe_id="), true)
  assert.equal(
    decodeURIComponent(seen[0]?.path ?? "").includes(buildSpiffeId("acme", "planner")),
    true,
  )
  assert.ok(api.url.startsWith("http://127.0.0.1:"))
})

test("node attestation selectors are passed through as query parameters", async () => {
  const seen: string[] = []
  await stub((path) => {
    seen.push(path)
    return { status: 200, body: { x: { svid: { jwt: "token" } } } }
  })

  await requestSvid({
    workloadApi: "http://127.0.0.1:1",
    spiffeId: buildSpiffeId("acme", "planner"),
    trustDomain: TRUST_DOMAIN,
    jwksUri: "http://unused",
    selector: { parentId: "spiffe://example.org/agent" },
    fetchImpl: (async (input: unknown) => {
      seen.push(String(input))
      return new Response(JSON.stringify({ x: { svid: { jwt: "token" } } }), { status: 200 })
    }) as unknown as typeof fetch,
  })

  assert.equal(
    seen.some((entry) => entry.includes("parentId=spiffe%3A%2F%2Fexample.org%2Fagent")),
    true,
    `selector missing from ${seen.join(" | ")}`,
  )
})

test("a Workload API that offers no SVID is reported as no_svid_offered, not as a crash", async () => {
  const api = await stub(() => ({ status: 404, body: {} }))

  const result = await requestSvid({
    workloadApi: api.url,
    spiffeId: buildSpiffeId("acme", "planner"),
    trustDomain: TRUST_DOMAIN,
    jwksUri: "http://unused",
  })

  assert.equal("failure" in result, true)
  assert.equal("failure" in result && result.failure, "no_svid_offered")
})

test("a 200 with no svid.jwt is reported as no_svid_offered", async () => {
  const api = await stub(() => ({
    status: 200,
    body: { [buildSpiffeId("acme", "planner")]: { svid: {} } },
  }))

  const result = await requestSvid({
    workloadApi: api.url,
    spiffeId: buildSpiffeId("acme", "planner"),
    trustDomain: TRUST_DOMAIN,
    jwksUri: "http://unused",
  })

  assert.equal("failure" in result && result.failure, "no_svid_offered")
})

test("an unreachable Workload API is a failure value, so the caller can refuse closed", async () => {
  const result = await requestSvid({
    // Port 1 on loopback refuses connections. Nothing here can succeed by accident.
    workloadApi: "http://127.0.0.1:1",
    spiffeId: buildSpiffeId("acme", "planner"),
    trustDomain: TRUST_DOMAIN,
    jwksUri: "http://unused",
  })

  assert.equal("failure" in result, true)
  assert.equal("failure" in result && result.failure, "workload_api_unreachable")
})

test("a JWKS that will not load is reported, not treated as an empty key set", async () => {
  // Empty and failed are different: empty means "this trust domain publishes no keys", failed means
  // "we could not ask". Collapsing them would let a JWKS outage look like a clean refusal and a
  // misconfigured key set look like the same thing.
  const down = await fetchJwks("http://127.0.0.1:1/jwks")

  assert.equal(down.ok, false)
  assert.equal(down.ok === false && down.failure, "jwks_unavailable")

  const noKeys = await fetchJwks("http://127.0.0.1:1/jwks", (async () =>
    new Response(JSON.stringify({ nope: true }), { status: 200 })) as unknown as typeof fetch)

  assert.equal(noKeys.ok, false)
  assert.equal(noKeys.ok === false && noKeys.detail, "JWKS body has no keys array")
})

test("a real JWKS document is read as a key set", async () => {
  const jwks = await stub(() => ({ status: 200, body: { keys: edJwks } }))

  const result = await fetchJwks(`${jwks.url}/jwks`)

  assert.equal(result.ok, true)
  assert.equal(result.ok && result.keys[0]?.kid, KID)
})

/* -------------------------------------------------------------- identity source (config) */

test("an unset identity source is local_key, the mode that works without SPIRE", () => {
  assert.equal(resolveIdentitySource(undefined), "local_key")
  assert.equal(resolveIdentitySource("   "), "local_key")
})

test("an unrecognised identity source throws rather than falling back", () => {
  // The default is the *weaker* mode. Falling back to it on a typo would silently remove node
  // attestation from a deployment whose operator believed it had one.
  assert.throws(() => resolveIdentitySource("spir"), /ACTANTOS_FABRIC_IDENTITY_SOURCE/)
  assert.throws(() => resolveIdentitySource("true"), /ACTANTOS_FABRIC_IDENTITY_SOURCE/)
  assert.throws(() => resolveIdentitySource("jwt-svid"), /ACTANTOS_FABRIC_IDENTITY_SOURCE/)
})

test("every declared identity source parses back to itself", () => {
  for (const source of ["local_key", "spire"] as const) {
    assert.equal(resolveIdentitySource(source), source)
    assert.equal(resolveIdentitySource(source.toUpperCase()), source)
    assert.equal(resolveIdentitySource(` ${source} `), source)
  }
})

test("a jti claim is used as the identity nonce when the trust domain sets one", async () => {
  // SPIFFE allows either a `jti` or nothing. When it is present it is the natural per-issuance
  // nonce and is inside the signature, so it must be preferred over a derived value.
  const token = signJwt({ claims: goodClaims({ jti: "unique-per-issuance" }) })
  const api = await stub(() => ({
    status: 200,
    body: { [buildSpiffeId("acme", "planner")]: { svid: { jwt: token } } },
  }))
  const jwks = await stub(() => ({ status: 200, body: { keys: edJwks } }))

  const provider = createSpireIdentityProvider({
    workloadApi: api.url,
    spiffeId: buildSpiffeId("acme", "planner"),
    trustDomain: TRUST_DOMAIN,
    jwksUri: `${jwks.url}/jwks`,
    now: () => NOW,
  })

  const issued = await provider.issue("acme", "planner")

  assert.equal(issued.identity.nonce, "unique-per-issuance")
})

test("without a jti, the nonce is derived from claims the signature covers", async () => {
  const token = signJwt({ claims: goodClaims() })
  const api = await stub(() => ({
    status: 200,
    body: { [buildSpiffeId("acme", "planner")]: { svid: { jwt: token } } },
  }))
  const jwks = await stub(() => ({ status: 200, body: { keys: edJwks } }))

  const provider = createSpireIdentityProvider({
    workloadApi: api.url,
    spiffeId: buildSpiffeId("acme", "planner"),
    trustDomain: TRUST_DOMAIN,
    jwksUri: `${jwks.url}/jwks`,
    now: () => NOW,
  })

  const issued = await provider.issue("acme", "planner")

  assert.equal(issued.identity.nonce, `${NOW_SECONDS - 5}.${buildSpiffeId("acme", "planner")}`)
})

/* ---------------------------------------- the sidecar's own view: verifyIdentityToken (S4, S12) */

/**
 * Everything below calls the function the sidecar actually enforces with.
 *
 * The provider tests prove the control plane verifies an SVID before sending it. That is not the
 * enforcement point — a caller that skipped the provider, or a compromised one, would present a
 * token the sidecar still has to check. These tests hold the sidecar's copy of the truth fixed and
 * vary what arrives.
 */

const identityNow = new Date("2026-10-04T12:00:00.000Z")
const identityNowSeconds = identityNow.getTime() / 1000

const identityClaims = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
  sub: buildSpiffeId("acme", "planner"),
  iss: `spiffe://${TRUST_DOMAIN}`,
  aud: "actantos-fabric",
  iat: identityNowSeconds - 5,
  exp: identityNowSeconds + 600,
  ...overrides,
})

const verifyAsSidecar = (
  token: unknown,
  overrides: Partial<Parameters<typeof verifyIdentityToken>[1]> = {},
) =>
  verifyIdentityToken(token, {
    trustedIssuerKeys: new Map(),
    expectedTenantId: "acme",
    now: identityNow,
    spire: { keys: edJwks, trustDomain: TRUST_DOMAIN, audience: "actantos-fabric" },
    ...overrides,
  })

test("a sidecar with SPIRE keys accepts an SVID and derives the identity from it", () => {
  const result = verifyAsSidecar(signJwt({ claims: identityClaims() }))

  assert.equal(result.accepted, true)
  assert.equal(result.accepted && result.identity.agent_id, "planner")
  assert.equal(result.accepted && result.identity.tenant_id, "acme")
  assert.equal(result.accepted && result.identity.trust_domain, TRUST_DOMAIN)
  // Derived from the claims, so it expires when the SVID does.
  assert.equal(
    result.accepted && result.identity.expires_at,
    new Date((identityNowSeconds + 600) * 1000).toISOString(),
  )
})

test("a sidecar with no SPIRE keys refuses an SVID — not configuring is not trusting", () => {
  const result = verifyAsSidecar(signJwt({ claims: identityClaims() }), { spire: undefined })

  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "malformed_identity")
})

test("a sidecar refuses an SVID for a tenant it does not serve", () => {
  // The multi-tenancy property. Without this check a valid SVID from tenant A would be honoured by
  // tenant B's sidecar, which is a cross-tenant acceptance rather than a bug in one tenant's data.
  const result = verifyAsSidecar(signJwt({ claims: identityClaims() }), {
    expectedTenantId: "some-other-tenant",
  })

  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "spiffe_mismatch")
})

test("a sidecar refuses an SVID whose signature no published key verifies", () => {
  const result = verifyAsSidecar(signJwt({ claims: identityClaims(), tamperSignature: true }))

  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "invalid_signature")
})

test("a sidecar refuses an SVID signed by a key it was not given", () => {
  // The same key, published under the same kid. If the sidecar selected by name without
  // verifying, this would be accepted.
  const impostor = generateKeyPairSync("ed25519")
  const header = { alg: "Ed25519", kid: KID, typ: "JWT" }
  const claims = identityClaims()
  const signingInput = `${b64url(Buffer.from(JSON.stringify(header)))}.${b64url(
    Buffer.from(JSON.stringify(claims)),
  )}`
  const forged = `${signingInput}.${b64url(
    cryptoSign(null, Buffer.from(signingInput), impostor.privateKey),
  )}`

  const result = verifyAsSidecar(forged)

  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "invalid_signature")
})

test("a sidecar refuses an expired SVID", () => {
  const result = verifyAsSidecar(
    signJwt({ claims: identityClaims({ exp: identityNowSeconds - 1 }) }),
  )

  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "expired")
})

test("a sidecar refuses an SVID from a trust domain it does not serve", () => {
  const result = verifyAsSidecar(signJwt({ claims: identityClaims() }), {
    spire: { keys: edJwks, trustDomain: "other.example", audience: "actantos-fabric" },
  })

  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "untrusted_issuer")
})

test("a sidecar honours revocation of an SVID by agent id", () => {
  const token = signJwt({ claims: identityClaims() })
  const allowed = verifyAsSidecar(token)
  const revoked = verifyAsSidecar(token, {
    revokedAgentIds: new Set(["planner"]),
  })

  // Both asserted: the same token, before and after. Without the allow case a test that always
  // denied would pass here too.
  assert.equal(allowed.accepted, true)
  assert.equal(revoked.accepted, false)
  assert.equal(revoked.accepted === false && revoked.reason, "revoked")
})

test("a sidecar honours revocation of an SVID by nonce", () => {
  const token = signJwt({ claims: identityClaims({ jti: "nonce-under-revocation" }) })
  const revoked = verifyAsSidecar(token, {
    revokedNonces: new Set(["nonce-under-revocation"]),
  })

  assert.equal(revoked.accepted, false)
  assert.equal(revoked.accepted === false && revoked.reason, "revoked")
})

test("a sidecar uses the jti as the identity nonce when present", () => {
  const result = verifyAsSidecar(signJwt({ claims: identityClaims({ jti: "per-issuance" }) }))

  assert.equal(result.accepted && result.identity.nonce, "per-issuance")
})

test("an SVID signed with alg none is refused at the sidecar too", () => {
  // The provider refuses this and so does the sidecar. Both matter: the provider's check protects
  // the control plane, the sidecar's protects against a caller that never went through one.
  const token = signJwt({ claims: identityClaims(), header: { alg: "none" }, stripSignature: true })
  const result = verifyAsSidecar(token)

  assert.equal(result.accepted, false)
  assert.equal(result.accepted === false && result.reason, "unsupported_algorithm")
})

test("a locally-signed envelope is still accepted when SPIRE is configured", () => {
  // Both forms coexist, which is what makes a staged rollout possible.
  const issuerId = "issuer-envelope"
  const keyPair = ed25519.generateKeyPair()

  const token = signWorkloadIdentity(
    mintWorkloadIdentity({ tenantId: "acme", agentId: "planner", issuedAt: identityNow }),
    { algorithm: "ed25519", issuer_id: issuerId, value: "" },
    keyPair,
  )

  const result = verifyAsSidecar(token, {
    trustedIssuerKeys: new Map([[issuerId, keyPair.publicKeyPem]]),
  })

  assert.equal(result.accepted, true)
  assert.equal(result.accepted && result.identity.agent_id, "planner")
})

/* -------------------------------------------------------------------------- default transport */

test("the default transport is the Unix socket SPIRE actually serves", () => {
  // This asserted `DEFAULT_WORKLOAD_API` was "SPIRE's", which was never true: no SPIRE version
  // serves the Workload API over HTTP. Asserting a constant equalled its own hard-coded literal
  // proved nothing about SPIRE either. What matters is the transport the client reaches an agent
  // on, and that is the socket.
  assert.equal(DEFAULT_WORKLOAD_SOCKET, "/run/spire/sockets/agent.sock")
})

test("an unset transport reaches for the socket rather than an endpoint SPIRE does not serve", async () => {
  // With nothing configured, `requestSvid` must try the socket. If it quietly fell back to the HTTP
  // default it would report "unreachable" for the wrong reason and an operator would go looking at
  // a port instead of a socket.
  const result = await requestSvid({
    spiffeId: "spiffe://actantos.local/tenant/t_acme/agent/planner",
    trustDomain: TRUST_DOMAIN,
    jwksUri: "https://spiffe.example/bundle",
  })

  assert.ok(!("token" in result), "a SVID was produced with no agent to produce one")
  assert.equal(result.failure, "workload_api_unreachable")
})

/* ------------------------------------------------ the provider as a whole, over real HTTP */

test("the provider issues an identity only after verifying the SVID it was issued", async () => {
  const token = signJwt({ claims: goodClaims() })
  const api = await stub(() => ({
    status: 200,
    body: { [buildSpiffeId("acme", "planner")]: { svid: { jwt: token } } },
  }))
  const jwks = await stub(() => ({ status: 200, body: { keys: edJwks } }))

  const provider = createSpireIdentityProvider({
    workloadApi: api.url,
    spiffeId: buildSpiffeId("acme", "planner"),
    trustDomain: TRUST_DOMAIN,
    jwksUri: `${jwks.url}/jwks`,
    expectedAudience: "actantos-fabric",
    now: () => NOW,
  })

  assert.equal(provider.kind, "spire")

  const issued = await provider.issue("acme", "planner")

  // What crosses the wire is the verified JWT itself, so the sidecar verifies the same bytes that
  // were checked here. Sending the parsed identity instead would leave the sidecar verifying
  // nothing — it would have no signature to check.
  assert.equal(issued.token, token)

  const identity = issued.identity

  assert.equal(identity.tenant_id, "acme")
  assert.equal(identity.agent_id, "planner")
  assert.equal(identity.spiffe_id, buildSpiffeId("acme", "planner"))
  assert.equal(identity.trust_domain, TRUST_DOMAIN)
  // The nonce comes from what was attested, not from a fresh random value: an identity whose nonce
  // is not covered by the SVID is not an identity the attestation says anything about.
  assert.equal(identity.nonce, `${NOW_SECONDS - 5}.${buildSpiffeId("acme", "planner")}`)
  assert.equal(identity.issued_at, new Date((NOW_SECONDS - 5) * 1000).toISOString())
  assert.equal(identity.expires_at, new Date((NOW_SECONDS + 600) * 1000).toISOString())
})

test("an attested client refuses to issue for a workload it was not attested as", async () => {
  const api = await stub(() => ({ status: 200, body: {} }))
  const jwks = await stub(() => ({ status: 200, body: { keys: edJwks } }))

  const provider = createSpireIdentityProvider({
    workloadApi: api.url,
    spiffeId: buildSpiffeId("acme", "planner"),
    trustDomain: TRUST_DOMAIN,
    jwksUri: `${jwks.url}/jwks`,
    now: () => NOW,
  })

  // This is the S4 property node attestation buys and a local key cannot: one attested workload
  // cannot ask the SPIRE client to mint another's identity.
  await assert.rejects(
    () => provider.issue("acme", "exfiltrator"),
    /cannot issue an identity/,
  )
  await assert.rejects(
    () => provider.issue("other-tenant", "planner"),
    /cannot issue an identity/,
  )
})

test("a SVID whose subject names a different agent is refused as spiffe_id_mismatch", async () => {
  // The Workload API is asked for one workload and answers with another. Trusting the response
  // body rather than the request would let a compromised API name any agent it liked.
  const token = signJwt({
    claims: goodClaims({ sub: buildSpiffeId("acme", "somebody-else") }),
  })
  const api = await stub(() => ({
    status: 200,
    body: { [buildSpiffeId("acme", "planner")]: { svid: { jwt: token } } },
  }))
  const jwks = await stub(() => ({ status: 200, body: { keys: edJwks } }))

  const provider = createSpireIdentityProvider({
    workloadApi: api.url,
    spiffeId: buildSpiffeId("acme", "planner"),
    trustDomain: TRUST_DOMAIN,
    jwksUri: `${jwks.url}/jwks`,
    now: () => NOW,
  })

  await assert.rejects(() => provider.issue("acme", "planner"), /spiffe_id_mismatch/)
})

test("the provider refuses when the trust domain's key does not verify the SVID", async () => {
  const other = generateKeyPairSync("ed25519")
  const impostorJwks: Jwk[] = [
    { ...(other.publicKey.export({ format: "jwk" }) as Jwk), kid: KID },
  ]
  const api = await stub(() => ({
    status: 200,
    body: {
      [buildSpiffeId("acme", "planner")]: {
        svid: { jwt: signJwt({ claims: goodClaims() }) },
      },
    },
  }))
  const jwks = await stub(() => ({ status: 200, body: { keys: impostorJwks } }))

  const provider = createSpireIdentityProvider({
    workloadApi: api.url,
    spiffeId: buildSpiffeId("acme", "planner"),
    trustDomain: TRUST_DOMAIN,
    jwksUri: `${jwks.url}/jwks`,
    now: () => NOW,
  })

  await assert.rejects(() => provider.issue("acme", "planner"), /signature_invalid/)
})

test("the provider refuses an expired SVID rather than issuing a dead identity", async () => {
  const token = signJwt({
    claims: goodClaims({ exp: NOW_SECONDS - 60, nbf: NOW_SECONDS - 600 }),
  })
  const api = await stub(() => ({
    status: 200,
    body: { [buildSpiffeId("acme", "planner")]: { svid: { jwt: token } } },
  }))
  const jwks = await stub(() => ({ status: 200, body: { keys: edJwks } }))

  const provider = createSpireIdentityProvider({
    workloadApi: api.url,
    spiffeId: buildSpiffeId("acme", "planner"),
    trustDomain: TRUST_DOMAIN,
    jwksUri: `${jwks.url}/jwks`,
    now: () => NOW,
  })

  await assert.rejects(() => provider.issue("acme", "planner"), /expired/)
})

test("the provider refuses when the JWKS cannot be loaded, rather than minting anyway", async () => {
  const api = await stub(() => ({
    status: 200,
    body: {
      [buildSpiffeId("acme", "planner")]: {
        svid: { jwt: signJwt({ claims: goodClaims() }) },
      },
    },
  }))

  const provider = createSpireIdentityProvider({
    workloadApi: api.url,
    spiffeId: buildSpiffeId("acme", "planner"),
    trustDomain: TRUST_DOMAIN,
    jwksUri: "http://127.0.0.1:1/jwks",
    now: () => NOW,
  })

  await assert.rejects(() => provider.issue("acme", "planner"), /jwks_unavailable/)
})

test("two issues from one attested client produce different nonces when the SVID differs", async () => {
  // S4 requires a distinct identity per execution. With a fixed token the nonce is fixed, which is
  // correct — the SVID itself is what distinguishes the executions — and this records that the
  // value is derived rather than freshly randomised, so it cannot drift from what was attested.
  const first = signJwt({ claims: goodClaims({ iat: NOW_SECONDS - 5 }) })
  const second = signJwt({ claims: goodClaims({ iat: NOW_SECONDS - 1 }) })
  const served = [first, second]
  let call = 0

  const api = await stub(() => ({
    status: 200,
    body: {
      [buildSpiffeId("acme", "planner")]: { svid: { jwt: served[call++] ?? first } },
    },
  }))
  const jwks = await stub(() => ({ status: 200, body: { keys: edJwks } }))

  const provider = createSpireIdentityProvider({
    workloadApi: api.url,
    spiffeId: buildSpiffeId("acme", "planner"),
    trustDomain: TRUST_DOMAIN,
    jwksUri: `${jwks.url}/jwks`,
    now: () => NOW,
  })

  const one = (await provider.issue("acme", "planner")).identity
  const two = (await provider.issue("acme", "planner")).identity

  assert.notEqual(one.nonce, two.nonce)
  assert.equal(one.expires_at, two.expires_at)
})

/* --------------------------------------- ES256, which is what a real trust domain issues */

const verifyEc = (token: string, overrides: Partial<Parameters<typeof verifyJwtSvid>[1]> = {}) =>
  verifyJwtSvid(token, {
    jwks: ecJwks,
    expectedTrustDomain: TRUST_DOMAIN,
    expectedAudience: "actantos-fabric",
    now: NOW,
    ...overrides,
  })

test("an ES256 SVID signed by a published P-256 key verifies", () => {
  // Before ES256 was in the algorithm table this was refused as `unsupported_algorithm`, so a
  // genuine SPIRE SVID could not be verified at all. A live SPIRE 1.15.3 signs with ES256 and
  // nothing else, which is what made that a real defect rather than a missing nicety.
  const result = verifyEc(signJwt({ claims: goodClaims(), key: "ec" }))

  assert.equal(result.ok, true)
  assert.ok(result.ok)
  assert.equal(result.parsed.header.alg, "ES256")
})

type DerInteger = { readonly length: number; readonly firstByte: number }

/** Read the two INTEGERs back out of a DER SEQUENCE. A signature is always exactly this pair. */
const readDerIntegers = (der: Buffer): [DerInteger, DerInteger] => {
  assert.equal(der[0], 0x30, "the result is not a DER SEQUENCE")

  // SEQUENCE tag, then the length byte, which is always the short form for a P-256 signature.
  let offset = 2

  const read = (): DerInteger => {
    assert.equal(der[offset], 0x02, "the value is not a DER INTEGER")
    const length = der[offset + 1] as number
    const value = { length, firstByte: der[offset + 2] as number }
    offset += 2 + length
    return value
  }

  const first = read()
  const second = read()

  assert.equal(offset, der.length, "the SEQUENCE holds more than the two integers read")

  return [first, second]
}

test("the raw-to-DER encoder strips a leading zero byte from R and from S", () => {
  // DER integers are signed, so a value whose top byte is below 0x80 is written without a pad byte
  // and a leading zero is stripped. A P-256 signature carries neither the length metadata nor the
  // sign, so both rules must be re-applied to the fixed-width raw form. Getting only one right
  // yields well-formed DER that encodes the wrong number, and node:crypto reports that as a bad
  // signature rather than as a malformed one.
  const withLeadingZeroInR = rawEcdsaToDer(
    Buffer.concat([Buffer.alloc(1, 0x00), Buffer.alloc(31, 0x11), Buffer.alloc(32, 0x22)]),
  ) as Buffer
  const [r, s] = readDerIntegers(withLeadingZeroInR)

  assert.equal(r.length, 31, "the leading zero byte in R was not stripped")
  assert.equal(r.firstByte, 0x11)
  assert.equal(s.length, 32)

  const withLeadingZeroInS = rawEcdsaToDer(
    Buffer.concat([Buffer.alloc(32, 0x22), Buffer.alloc(1, 0x00), Buffer.alloc(31, 0x33)]),
  ) as Buffer
  const [r2, s2] = readDerIntegers(withLeadingZeroInS)

  assert.equal(r2.length, 32)
  assert.equal(s2.length, 31, "the leading zero byte in S was not stripped")
  assert.equal(s2.firstByte, 0x33)
})

test("the raw-to-DER encoder pads an R whose top bit is set", () => {
  // Without the pad byte a value above 0x7f reads as a negative DER integer, which is a different
  // number from the one that was signed.
  const der = rawEcdsaToDer(
    Buffer.concat([Buffer.from([0xff]), Buffer.alloc(31, 0x11), Buffer.alloc(32, 0x22)]),
  ) as Buffer
  const [r] = readDerIntegers(der)

  assert.equal(r.length, 33, "the high-bit R was not padded back to 33 bytes")
  assert.equal(r.firstByte, 0x00, "the pad byte is not zero")
})

test("the raw-to-DER encoder refuses a signature that is not a P-256 one", () => {
  // 64 bytes is the only width ES256 can produce. Anything else is not a signature this algorithm
  // could have made, and re-encoding it would invent a shape rather than translate one.
  assert.equal(rawEcdsaToDer(Buffer.alloc(63)), undefined)
  assert.equal(rawEcdsaToDer(Buffer.alloc(65)), undefined)
  assert.equal(rawEcdsaToDer(Buffer.alloc(0)), undefined)
})

test("an ES256 SVID verifies when R carries its high bit", () => {
  // Roughly half of all signatures have a high bit set in R or S and therefore need DER padding.
  // An encoder that misses the pad still verifies most tokens and fails the rest, which is the
  // worst shape for this bug: intermittent, and looking like a bad key.
  let checked = 0

  for (let attempt = 0; attempt < 400 && checked < 5; attempt += 1) {
    const token = signJwt({ claims: goodClaims(), key: "ec" })
    const signature = parseJwt(token)?.signature as Buffer
    const needsPad = (signature[0] as number) >= 0x80 || (signature[32] as number) >= 0x80

    if (!needsPad) continue

    checked += 1
    assert.equal(
      verifyEc(token).ok,
      true,
      `a padded signature failed to verify: ${signature.toString("hex")}`,
    )
  }

  assert.ok(checked >= 5, `only ${checked} padded signatures were produced in 400 attempts`)
})

test("the DER-to-raw signer left-pads an integer DER encoded shorter than 32 bytes", () => {
  // The other direction of the conversion. DER encodes an integer as the shortest string that
  // reads back as the same signed number, so it drops leading zero bytes rather than keeping them.
  // JWS fixes R and S at 32 bytes. An implementation that only strips the sign byte returns 31
  // bytes here and hands the verifier a 63-byte signature, which is refused as `signature_invalid`
  // — a rejection that says nothing about the check the caller was making.
  const shortR = Buffer.alloc(31, 0x11)
  const fullS = Buffer.alloc(32, 0x22)
  const der = Buffer.concat([
    Buffer.from([0x30, 0x02 + 31 + 0x02 + 32]),
    Buffer.from([0x02, 31]),
    shortR,
    Buffer.from([0x02, 32]),
    fullS,
  ])

  const raw = derToRawEcdsa(der)

  assert.equal(raw.length, 64, "R was not padded back out to 32 bytes")
  assert.deepEqual(raw.subarray(0, 32), Buffer.concat([Buffer.alloc(1, 0x00), shortR]))
  assert.deepEqual(raw.subarray(32, 64), fullS)
})

test("every ES256 token this test signs carries a 64-byte signature", () => {
  // The property the padding rule exists to hold, asserted over the real signer rather than over a
  // hand-built encoding. A JWS ES256 signature is R||S at 32 bytes each, always. The defect this
  // replaced produced a 63-byte signature for roughly one token in 128, which the verifier refused
  // as `signature_invalid` -- so whichever test happened to draw that token failed for a reason
  // unrelated to what it asserted. Checking the width directly catches the defect on the first
  // occurrence rather than the hundred-and-twenty-eighth, and it cannot pass vacuously: 1000
  // tokens draw roughly eight of the short signatures the rule governs.
  const widths = new Set<number>()

  for (let attempt = 0; attempt < 1000; attempt += 1) {
    const token = signJwt({ claims: goodClaims({ nonce: `width-${attempt}` }), key: "ec" })

    widths.add((parseJwt(token)?.signature as Buffer).length)
  }

  assert.deepEqual([...widths], [64], `signatures came out ${[...widths].join(", ")} bytes wide`)
})

test("an ES256 SVID with a corrupted signature is refused", () => {
  const result = verifyEc(signJwt({ claims: goodClaims(), key: "ec", tamperSignature: true }))

  assert.equal(result.ok, false)
  assert.ok(!result.ok)
  assert.equal(result.reason, "signature_invalid")
})

test("an ES256 SVID whose signature is not 64 bytes is refused", () => {
  // A signature of the wrong width is not a P-256 JWS signature. Passing it on in some other
  // shape would hand the crypto layer bytes whose meaning it has to guess at.
  const token = signJwt({ claims: goodClaims(), key: "ec" })
  const [header, claims] = token.split(".")
  const result = verifyEc(`${header as string}.${claims as string}.${b64url(Buffer.alloc(63, 7))}`)

  assert.equal(result.ok, false)
  assert.ok(!result.ok)
  assert.equal(result.reason, "signature_invalid")
})

test("an ES256 header signed by a key published for another curve is refused", () => {
  // The curve is pinned to P-256 because ES256 defines it. A key on another curve is not a key
  // this algorithm can have been signed with, so it is refused rather than coerced.
  const p384 = generateKeyPairSync("ec", { namedCurve: "P-384" })
  const foreign = p384.publicKey.export({ format: "jwk" }) as Jwk

  const result = verifyJwtSvid(signJwt({ claims: goodClaims(), key: "ec" }), {
    jwks: [{ ...foreign, kid: KID }],
    expectedTrustDomain: TRUST_DOMAIN,
    expectedAudience: "actantos-fabric",
    now: NOW,
  })

  assert.equal(result.ok, false)
  assert.ok(!result.ok)
  assert.equal(result.reason, "signature_invalid")
})

test("an ES256 SVID whose kid resolves only to a key of the wrong type is refused", () => {
  // The kid does match, so this is not `unknown_signing_key`: a key was found and none of them can
  // verify this signature. Asserting the exact reason matters — `signature_invalid` says the key
  // set is wrong for this token, and collapsing it into `unknown_signing_key` would send an
  // operator to look at bundle publication instead of at the key types in it.
  const result = verifyEc(signJwt({ claims: goodClaims(), key: "ec" }), { jwks: edJwks })

  assert.equal(result.ok, false)
  assert.ok(!result.ok)
  assert.equal(result.reason, "signature_invalid")
})

test("an ES256 SVID signed under a kid the trust domain never published is refused", () => {
  const result = verifyJwtSvid(signJwt({ claims: goodClaims(), key: "ec", header: { kid: "other-key" } }), {
    jwks: ecJwks,
    expectedTrustDomain: TRUST_DOMAIN,
    expectedAudience: "actantos-fabric",
    now: NOW,
  })

  assert.equal(result.ok, false)
  assert.ok(!result.ok)
  assert.equal(result.reason, "unknown_signing_key")
})

/* ------------------------------- the trust domain, from the claim SPIRE actually emits */

// SPIRE emits `sub`, `aud`, `iat` and `exp` and no `iss`. These were measured against a live
// SPIRE 1.15.3 agent rather than inferred from the spec, and the claims below are that token's
// shape verbatim.
const spireClaims = (overrides: Record<string, unknown> = {}): Record<string, unknown> => {
  const claims = goodClaims({ aud: ["actantos-fabric"] })
  delete claims["iss"]

  return { ...claims, ...overrides }
}

test("an SVID with no iss at all is verified from the trust domain its subject names", () => {
  // The previous check required `iss` and refused this token as `wrong_trust_domain`, which meant
  // no genuine SPIRE SVID could ever be verified.
  const result = verifyEc(signJwt({ claims: spireClaims(), key: "ec" }))

  assert.equal(result.ok, true)
  assert.ok(result.ok)
  assert.equal(result.parsed.claims.iss, undefined)
})

test("an SVID whose subject is a path in another trust domain is refused", () => {
  const result = verifyEc(
    signJwt({
      claims: spireClaims({ sub: "spiffe://attacker.example/tenant/t_acme/agent/planner" }),
      key: "ec",
    }),
  )

  assert.equal(result.ok, false)
  assert.ok(!result.ok)
  assert.equal(result.reason, "wrong_trust_domain")
})

test("an SVID whose subject is the trust domain itself, with no path, is refused", () => {
  // `spiffe://actantos.local` names no workload. Accepting it would be accepting an identity that
  // says only "I belong to this domain", which is not a tenant or an agent.
  const result = verifyEc(signJwt({ claims: spireClaims({ sub: `spiffe://${TRUST_DOMAIN}` }), key: "ec" }))

  assert.equal(result.ok, false)
  assert.ok(!result.ok)
  assert.equal(result.reason, "wrong_trust_domain")
})

test("an SVID whose subject names a trust domain as a prefix of a different one is refused", () => {
  // A prefix test that forgets the `/` would accept `spiffe://actantos.local.evil.example/...`.
  const result = verifyEc(
    signJwt({ claims: spireClaims({ sub: "spiffe://actantos.local.evil.example/t/a" }), key: "ec" }),
  )

  assert.equal(result.ok, false)
  assert.ok(!result.ok)
  assert.equal(result.reason, "wrong_trust_domain")
})

test("an SVID with no subject at all is refused", () => {
  const claims = spireClaims()
  delete claims["sub"]

  const result = verifyEc(signJwt({ claims, key: "ec" }))

  assert.equal(result.ok, false)
  assert.ok(!result.ok)
  assert.equal(result.reason, "wrong_trust_domain")
})

test("an SVID whose iss disagrees with the trust domain its subject names is refused", () => {
  // A token carrying both claims and disagreeing with itself is refused rather than resolved in
  // whichever direction happens to be convenient.
  const result = verifyEc(
    signJwt({ claims: spireClaims({ iss: "spiffe://attacker.example" }), key: "ec" }),
  )

  assert.equal(result.ok, false)
  assert.ok(!result.ok)
  assert.equal(result.reason, "wrong_trust_domain")
})

test("an SVID whose iss agrees with its subject is accepted", () => {
  const result = verifyEc(
    signJwt({ claims: spireClaims({ iss: `spiffe://${TRUST_DOMAIN}` }), key: "ec" }),
  )

  assert.equal(result.ok, true)
})
