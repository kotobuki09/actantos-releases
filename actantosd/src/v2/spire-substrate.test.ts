import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { createPublicKey, verify } from "node:crypto"
import net from "node:net"
import test from "node:test"

import { fetchJwtSvid } from "./spiffe-workload-api.ts"
import { buildSpiffeId } from "./workload-identity.ts"
import {
  createSpireIdentityProvider,
  fetchJwks,
  parseJwt,
  rawEcdsaToDer,
  requestSvid,
  verifyJwtSvid,
} from "./workload-identity-provider.ts"

/**
 * The real-substrate half of phase H (invariant S4).
 *
 * ## Why this file exists separately
 *
 * `workload-identity-provider.test.ts` and `spire-identity-runtime.test.ts` prove that the code can
 * parse a JWT-SVID, verify it against published keys, and have a real sidecar enforce it. What they
 * cannot prove is that SPIRE issues SVIDs the way this code expects, and — the part S4 actually
 * turns on — that node attestation prevents one workload from obtaining another's identity.
 *
 * A local stub standing in for the Workload API attests nothing. It will happily hand over any SVID
 * it is told to. So every property that depends on the *authority* rather than on the *client* has
 * to be run against spire-server itself, and skipped loudly when it is absent.
 *
 * ## What running it against a real SPIRE changed
 *
 * The first version of this file asserted that a real SPIRE SVID was *refused*, and recorded four
 * measured defects. All four are now fixed, and the tests below assert the opposite: that the
 * client's own gRPC client obtains an SVID from a live agent and `verifyJwtSvid` accepts it. Every
 * constant the fix rests on was measured on this host, not read from documentation:
 *
 * 1. The Workload API is gRPC over a Unix socket at `/SpiffeWorkloadAPI/FetchJWTSVID`. It does not
 *    answer HTTP/1.1, and the dotted service name `SpiffeWorkloadAPI.FetchJWTSVID` is refused as a
 *    malformed method.
 * 2. Every call must carry `workload.spiffe.io: true` — literally the string `true`, and SPIRE
 *    1.15.3 has no configuration key for the value.
 * 3. `JWTSVIDRequest` numbers `audience` as 1 and `spiffe_id` as 2. Swapped, the agent answers
 *    `invalid requested SPIFFE ID` rather than a parse error.
 * 4. SPIRE signs ES256, emits no `iss` claim at all, and signs in the raw R‖S that JWS specifies.
 *
 * The DER check below is kept deliberately. It is the reason ES256 alone was not enough, and if a
 * future change ever made the conversion a no-op it would fail rather than quietly pass.
 */

const SPIFFE_ID = process.env["ACTANTOS_SPIRE_SPIFFE_ID"]
const TRUST_DOMAIN = process.env["ACTANTOS_SPIRE_TRUST_DOMAIN"]
const JWKS_URI = process.env["ACTANTOS_SPIRE_JWKS_URI"]
const WORKLOAD_API = process.env["ACTANTOS_SPIRE_WORKLOAD_API"]
const WORKLOAD_SOCKET = process.env["ACTANTOS_SPIRE_WORKLOAD_SOCKET"]

/**
 * The agent's Workload API socket.
 *
 * Read from either the socket variable the daemon itself uses or a `unix://` Workload API URL, so
 * an operator who configured either name has a substrate run rather than a silent skip.
 */
const socketPath = (): string | undefined => {
  if (WORKLOAD_SOCKET !== undefined && WORKLOAD_SOCKET !== "") return WORKLOAD_SOCKET
  if (WORKLOAD_API === undefined) return undefined
  if (!WORKLOAD_API.startsWith("unix://")) return undefined

  return WORKLOAD_API.slice("unix://".length)
}

/**
 * The binaries, not just the configuration: a trust domain that is not running is not a substrate.
 *
 * Probed with `--version`, which is the flag spire-server actually accepts. The earlier `version`
 * probe exited 127 on a machine where SPIRE was installed and running, so this gate silently
 * skipped every test here and the group was reported as REAL_SUBSTRATE with nothing behind it.
 */
const spireInstalled = (): boolean => {
  for (const binary of ["spire-server", "spire-agent"]) {
    try {
      execFileSync(binary, ["--version"], { stdio: "ignore" })
    } catch {
      return false
    }
  }

  return true
}

const skip =
  SPIFFE_ID === undefined ||
  TRUST_DOMAIN === undefined ||
  JWKS_URI === undefined ||
  socketPath() === undefined ||
  !spireInstalled()

const todo = skip
  ? "SPIRE is not available — set ACTANTOS_SPIRE_SPIFFE_ID / _TRUST_DOMAIN / _JWKS_URI and ACTANTOS_SPIRE_WORKLOAD_SOCKET against a running trust domain. Node attestation cannot be demonstrated any other way."
  : undefined

const subject = buildSpiffeId("t_spire", "pi_demo")
const AUDIENCE = "actantos"

const requireSocket = (): string => {
  assert.notEqual(socketPath(), undefined, "no Workload API socket is configured for these tests")
  return socketPath() as string
}

/**
 * Write a literal HTTP/1.1 request down the Workload API socket and return whatever comes back.
 *
 * `fetch` cannot open a Unix socket, so the only way to ask whether SPIRE speaks HTTP at all is to
 * speak it directly. gRPC replies on HTTP/2, so an HTTP/1.1 request is answered with silence or
 * with bytes that are not an HTTP response — both of which are why this client uses HTTP/2.
 */
const rawHttpOverSocket = (socketPath: string, request: string): Promise<string> =>
  new Promise((resolve, reject) => {
    const chunks: Buffer[] = []
    const socket = net.createConnection(socketPath, () => socket.write(request))
    const finish = (): void => {
      clearTimeout(timer)
      socket.destroy()
      resolve(Buffer.concat(chunks).toString("utf8"))
    }
    const timer = setTimeout(finish, 3_000)

    socket.on("data", (chunk: Buffer) => chunks.push(chunk))
    // SPIRE resets the connection when it is sent HTTP/1.1. That reset *is* the finding, so it
    // resolves to whatever arrived rather than failing the test.
    socket.on("error", finish)
    socket.on("close", finish)
  })

/**
 * Ask the real Workload API for an SVID with this project's own client.
 *
 * Deliberately not `spire-agent api fetch jwt`. That command speaks the protocol correctly and
 * proves nothing about the code under test; this goes through the gRPC client in
 * `spiffe-workload-api.ts`, which is the thing that used to be unable to reach an agent at all.
 */
const fetchRealSvid = async (): Promise<string> => {
  const result = await fetchJwtSvid({
    socketPath: requireSocket(),
    spiffeId: subject,
    audience: [AUDIENCE],
    timeoutMs: 20_000,
  })

  assert.equal(
    result.ok,
    true,
    result.ok === false ? `the Workload API did not yield an SVID: ${result.failure}: ${result.detail}` : "",
  )

  return (result.ok ? (result.svids[0] as { jwt: string }).jwt : "")
}

/** Cross-check the client's SVID against one fetched by SPIRE's own CLI. */
const fetchSvidViaSpireCli = (): string => {
  const output = execFileSync(
    "spire-agent",
    [
      "api",
      "fetch",
      "jwt",
      "-socketPath",
      requireSocket(),
      "-spiffeID",
      subject,
      "-audience",
      AUDIENCE,
      "-output",
      "json",
    ],
    { encoding: "utf8", timeout: 30_000 },
  )
  const parsed = JSON.parse(output) as { svids?: { svid?: unknown }[] }[]
  const token = parsed[0]?.svids?.[0]?.svid

  assert.equal(typeof token, "string", "SPIRE's own client returned no JWT-SVID")

  return token as string
}

test(
  "S4: the live trust domain publishes a JWK Set this client can parse",
  { skip: skip === false ? undefined : todo },
  async () => {
    const jwks = await fetchJwks(JWKS_URI as string)

    assert.equal(jwks.ok, true, jwks.ok === false ? `${jwks.failure}: ${jwks.detail}` : "")
    assert.ok((jwks.ok ? jwks.keys : []).length > 0, "trust domain published no keys")

    // The trust domain's own JWT-SVID key is EC P-256, which is what the next tests are checked
    // against. Asserting it here means a JWKS that parses but carries nothing this client could
    // ever use fails with a clear message rather than three tests later.
    const ecKeys = (jwks.ok ? jwks.keys : []).filter((key) => key.kty === "EC" && key.crv === "P-256")

    assert.ok(ecKeys.length > 0, "trust domain published no EC P-256 signing key")
  },
)

test(
  "S4: this client's own gRPC client obtains an SVID from a live agent",
  { skip: skip === false ? undefined : todo },
  async () => {
    const token = await fetchRealSvid()

    // The transport used to be the whole blocker: a GET over HTTP/1.1 to the agent's socket is
    // reset, so there was no value of any configuration that reached an agent.
    assert.match(token, /^[\w-]+\.[\w-]+\.[\w-]+$/u, "the SVID is not JWS compact serialisation")

    const parsed = parseJwt(token)
    assert.notEqual(parsed, undefined, "the SVID the agent issued did not parse")

    // And it is the identity that was asked for, not something the client substituted.
    assert.equal(parsed?.claims.sub, subject)
    assert.deepEqual(parsed?.claims.aud, [AUDIENCE])
  },
)

test(
  "S4: a genuine SVID from a live agent is verified by this client",
  { skip: skip === false ? undefined : todo },
  async () => {
    const token = await fetchRealSvid()
    const jwks = await fetchJwks(JWKS_URI as string)

    assert.equal(jwks.ok, true, jwks.ok === false ? `${jwks.failure}: ${jwks.detail}` : "")

    // The whole point. A live SPIRE 1.15.3 SVID is refused as `unsupported_algorithm` before this
    // change and as `wrong_trust_domain` after only the algorithm is fixed; this is the assertion
    // that both are closed, and that the trust domain's signature checks out against the key it
    // published rather than against anything the client carries.
    const verified = verifyJwtSvid(token, {
      jwks: jwks.ok ? jwks.keys : [],
      expectedTrustDomain: TRUST_DOMAIN as string,
      expectedAudience: AUDIENCE,
      now: new Date(),
    })

    assert.equal(
      verified.ok,
      true,
      verified.ok === false
        ? `a genuine SPIRE SVID was refused: ${verified.reason}: ${verified.detail}`
        : "",
    )
  },
)

test(
  "S4: the trust domain signs ES256 with no iss claim, and this client reads both",
  { skip: skip === false ? undefined : todo },
  async () => {
    const token = await fetchRealSvid()
    const parsed = parseJwt(token)

    assert.notEqual(parsed, undefined)
    // If a future SPIRE changes either of these, this test says so rather than the suite quietly
    // covering for it. The client's behaviour is keyed to both facts.
    assert.equal(parsed?.header.alg, "ES256", "SPIRE is no longer signing with ES256")
    assert.equal(parsed?.claims.iss, undefined, "SPIRE now emits an iss claim; re-check the trust-domain check")
  },
)

test(
  "S4: the raw JWS signature needs the DER conversion, and the product performs exactly that one",
  { skip: skip === false ? undefined : todo },
  async () => {
    const token = await fetchRealSvid()
    const jwks = await fetchJwks(JWKS_URI as string)

    assert.equal(jwks.ok, true, jwks.ok === false ? `${jwks.failure}: ${jwks.detail}` : "")

    const parsed = parseJwt(token)
    const kid = parsed?.header.kid
    assert.equal(typeof kid, "string", "SVID header has no kid")
    const jwk = (jwks.ok ? jwks.keys : []).find((key) => key.kid === kid)
    assert.notEqual(jwk, undefined, `trust domain published no key for kid ${String(kid)}`)

    const publicKey = createPublicKey({ key: jwk as never, format: "jwk" })
    const signingInput = parsed?.signingInput as Buffer
    const signature = parsed?.signature as Buffer

    assert.equal(signature.length, 64, "the JWS signature is not the 64 bytes ES256 produces")

    // Handing these bytes to node:crypto unchanged does not verify. This is why ES256 alone was
    // not a sufficient fix, and it is asserted so that conversion can never quietly become a
    // pass-through: if it did, this would flip to true.
    assert.equal(
      verify("sha256", signingInput, publicKey, signature),
      false,
      "node:crypto accepted the raw JWS signature, so the DER conversion is no longer doing anything",
    )

    // The product's own conversion, not a copy in this file, produces something that verifies.
    const der = rawEcdsaToDer(signature)
    assert.notEqual(der, undefined, "the product refused to re-encode a genuine P-256 signature")
    assert.equal(
      verify("sha256", signingInput, publicKey, der as Buffer),
      true,
      "the trust domain's own signature did not verify after the product's conversion",
    )
  },
)

test(
  "S4: the provider issues a real identity from a live agent, over its own socket",
  { skip: skip === false ? undefined : todo },
  async () => {
    const provider = createSpireIdentityProvider({
      spiffeId: SPIFFE_ID as string,
      trustDomain: TRUST_DOMAIN as string,
      jwksUri: JWKS_URI as string,
      expectedAudience: AUDIENCE,
      workloadSocket: requireSocket(),
    })

    const issued = await provider.issue("t_spire", "pi_demo")

    assert.equal(issued.identity.spiffe_id, subject)
    assert.equal(issued.identity.trust_domain, TRUST_DOMAIN)
    assert.equal(issued.identity.tenant_id, "t_spire")
    assert.equal(issued.identity.agent_id, "pi_demo")

    // The token really is the agent's, not one this process minted: it is a JWS the trust domain
    // signed, and it is what crossed the wire.
    const parsed = parseJwt(issued.token as string)
    assert.equal(parsed?.header.alg, "ES256")
    assert.equal(parsed?.claims.sub, subject)
  },
)

test(
  "S4: an SVID for a workload this client was not attested as is refused",
  { skip: skip === false ? undefined : todo },
  async () => {
    const provider = createSpireIdentityProvider({
      spiffeId: SPIFFE_ID as string,
      trustDomain: TRUST_DOMAIN as string,
      jwksUri: JWKS_URI as string,
      expectedAudience: AUDIENCE,
      workloadSocket: requireSocket(),
    })

    // The claim node attestation exists to support. Against a local stub this is trivially true
    // because the stub is told what to return; against SPIRE it is the trust domain refusing.
    await assert.rejects(
      () => provider.issue("t_spire", "some-other-agent"),
      /cannot issue an identity/,
    )
  },
)

test(
  "S4: an agent asked for an identity this workload is not entitled to yields nothing",
  { skip: skip === false ? undefined : todo },
  async () => {
    // The client asking for someone else's SPIFFE ID, rather than the client refusing to issue it.
    // The client-side refusal above would hold even against a permissive agent; this one is the
    // trust domain saying no, which is the half that only a real substrate can demonstrate.
    const result = await fetchJwtSvid({
      socketPath: requireSocket(),
      spiffeId: buildSpiffeId("t_spire", "someone-else-entirely"),
      audience: [AUDIENCE],
      timeoutMs: 20_000,
    })

    assert.equal(result.ok, false, "the agent issued an SVID for a workload with no entry for it")
    assert.ok(!result.ok)
    assert.equal(result.failure, "no_svid_offered")
  },
)

test(
  "S4: the SVID this client obtains is the same identity SPIRE's own client would get",
  { skip: skip === false ? undefined : todo },
  async () => {
    // A guard against the gRPC client decoding the response into something plausible but wrong:
    // both clients ask for the same subject and audience, so the subjects must agree even though
    // the tokens themselves differ (SPIRE re-signs, and `iat` moves).
    const ours = parseJwt(await fetchRealSvid())
    const theirs = parseJwt(fetchSvidViaSpireCli())

    assert.notEqual(ours, undefined)
    assert.notEqual(theirs, undefined)
    assert.equal(ours?.claims.sub, theirs?.claims.sub)
    assert.deepEqual(ours?.claims.aud, theirs?.claims.aud)
  },
)

test(
  "S4: the real Workload API still does not serve HTTP, which is why the client speaks gRPC",
  { skip: skip === false ? undefined : todo },
  async () => {
    const response = await rawHttpOverSocket(
      requireSocket(),
      `GET /workload-api/jwt-svid?spiffe_id=${encodeURIComponent(subject)} HTTP/1.1\r\n` +
        "Host: localhost\r\nAccept: application/jwt\r\n\r\n",
    )

    assert.doesNotMatch(
      response,
      /^HTTP\/1\.[01] 200/,
      "the Workload API answered HTTP/1.1, so the gRPC client is no longer necessary",
    )

    // The consequence for the HTTP fallback, asserted rather than described: pointed at a socket
    // through `workloadApi`, the client still cannot obtain an identity, so `identity_source =
    // "spire"` genuinely needs the socket configured.
    const requested = await requestSvid({
      spiffeId: SPIFFE_ID as string,
      trustDomain: TRUST_DOMAIN as string,
      jwksUri: JWKS_URI as string,
      workloadApi: `unix://${requireSocket()}`,
    })

    assert.equal("failure" in requested, true, "requestSvid obtained an SVID over plain HTTP")
  },
)

test(
  "S12: an unreachable real Workload API is refused, not treated as an absent identity",
  { skip: skip === false ? undefined : todo },
  async () => {
    const provider = createSpireIdentityProvider({
      spiffeId: SPIFFE_ID as string,
      trustDomain: TRUST_DOMAIN as string,
      jwksUri: JWKS_URI as string,
      expectedAudience: AUDIENCE,
      // A path on the same host that nothing is listening on. Refusing this is S12 doing its job:
      // an agent that is not there must not read as an absent identity.
      workloadSocket: `${requireSocket()}.actantos-absent`,
    })

    await assert.rejects(
      () => provider.issue("t_spire", "pi_demo"),
      /workload_api_unreachable|workload_api_error/,
    )
  },
)