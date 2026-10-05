import { createPublicKey, verify, type KeyObject } from "node:crypto"

import { DEFAULT_WORKLOAD_SOCKET, fetchJwtSvid } from "./spiffe-workload-api.ts"

import {
  buildSpiffeId,
  parseSpiffeId,
  verifyWorkloadIdentity,
  type IdentityRejectionReason,
  type IdentityVerification,
  type VerifyWorkloadIdentityOptions,
  type WorkloadIdentity,
} from "./workload-identity.ts"

/**
 * SPIFFE Workload API client and workload identity authorities (invariant S4, phase H).
 *
 * ## Why the control plane signing its own identity was not enough
 *
 * Until now the daemon configured an Ed25519 key and signed a workload identity for itself. That
 * satisfies "the identity is signed" and nothing else. The process that asserts an identity is the
 * same process that holds the key that asserts it, so the signature proves the request came from
 * *somebody with this key* — which is exactly what an attacker who has read the environment
 * variable also satisfies. It cannot distinguish one agent from another, and it cannot distinguish
 * the agent from the control plane.
 *
 * S4 says each agent execution holds a *distinct, short-lived* identity. Distinctness has to come
 * from somewhere the agent does not control, or it is a claim rather than a property.
 *
 * ## What SPIRE changes
 *
 * A SPIRE agent attests the calling workload's identity to the SPIRE server using node
 * attestation, and the server issues an SVID signed by the trust domain. The workload never holds
 * the signing key and cannot mint an identity for another workload. That is the property the local
 * key never had.
 *
 * ## JWT-SVID, not X.509-SVID
 *
 * Both forms are specified. The JWT form is used here because it is a standard JWS and Node can
 * verify one with `crypto.createVerify` against a key fetched from the trust domain's published
 * JWKS. There is no X.509 chain-building API in Node either, so choosing the certificate form would
 * mean hand-rolling chain validation — which is the one thing this codebase must never do. Nothing
 * is invented here: JWS verification and Ed25519 are Node's, and the envelope format is SPIFFE's.
 *
 * ## What is and is not verified
 *
 * Verified: the JWS signature against a key from the trust domain's JWKS, the `exp`, that the
 * subject names a workload path inside the expected trust domain, the audience, and that the SPIFFE
 * ID in the subject parses to the tenant and agent the caller asked for.
 *
 * Not verified here: that the trust domain's JWKS is authentic. That is the bootstrap problem — who
 * vouches for the vouches — and it is solved by pinning the JWKS URI or the bundle out of band,
 * which is an operator deployment decision recorded in `docs/ARCHITECTURE_V2.md`. Without pinning,
 * this client trusts whatever the configured URL serves.
 */

/**
 * An HTTP base URL for the Workload API, used only when no socket path is configured.
 *
 * No SPIRE version serves the Workload API over HTTP — it is gRPC over a Unix socket, and an
 * HTTP/1.1 request to the agent's socket is met with a connection reset. This default exists for
 * the stub the tests stand up; the real default transport is `DEFAULT_WORKLOAD_SOCKET`.
 */
export const DEFAULT_WORKLOAD_API = "http://localhost:8080"

/**
 * Where the control plane's own workload identity comes from.
 *
 * `local_key` is the phase-F behaviour: the daemon signs the identity itself with a configured
 * Ed25519 key. It is the default because it is the only mode that works without SPIRE deployed,
 * and it is documented as weaker, not presented as equivalent — the process that asserts an
 * identity is the process that holds the key that asserts it.
 *
 * `spire` asks the SPIFFE Workload API for a JWT-SVID and verifies it against the trust domain's
 * published keys. The workload never holds a signing key.
 */
export const IDENTITY_SOURCES = ["local_key", "spire"] as const

export type IdentitySource = (typeof IDENTITY_SOURCES)[number]

export const DEFAULT_IDENTITY_SOURCE: IdentitySource = "local_key"

export const isIdentitySource = (value: string): value is IdentitySource =>
  (IDENTITY_SOURCES as readonly string[]).includes(value)

/**
 * Read the identity source from configuration.
 *
 * Unrecognised throws, for the same reason `resolveFabricMode` throws. The default is
 * `local_key`, which is the weaker of the two; a typo that fell back to it would run without
 * SPIRE while an operator believed node attestation was in force.
 */
export const resolveIdentitySource = (raw: string | undefined): IdentitySource => {
  if (raw === undefined || raw.trim() === "") {
    return DEFAULT_IDENTITY_SOURCE
  }

  const normalised = raw.trim().toLowerCase()

  if (isIdentitySource(normalised)) {
    return normalised
  }

  throw new Error(
    `ACTANTOS_FABRIC_IDENTITY_SOURCE is "${raw}", which is not one of ` +
      `${IDENTITY_SOURCES.join(", ")}. Refusing to start: falling back to a default here would ` +
      "silently decide whether this deployment is attested by SPIRE.",
  )
}

export type WorkloadIdentityProvider = {
  /** Human-readable name of the authority, recorded in evidence. */
  readonly kind: string
  issue(tenantId: string, agentId: string): Promise<IssuedIdentity>
}

/**
 * What an authority issued: the token to present, and what that token attests.
 *
 * They are kept separate because the enforcement point must derive the identity from the token
 * itself rather than from a copy the caller already parsed out of it. Presenting a
 * ready-made identity object would let whoever assembles the request assert an identity the
 * signature does not cover — the signature would then be verifying nothing at all.
 *
 * `token` is what crosses the wire. `identity` is for logs, evidence, and assertions.
 */
export type IssuedIdentity = {
  readonly token: unknown
  readonly identity: WorkloadIdentity
}

export type SvidFailure =
  | "workload_api_unreachable"
  | "workload_api_error"
  | "no_svid_offered"
  | "malformed_jwt"
  | "unsupported_algorithm"
  | "jwks_unavailable"
  | "unknown_signing_key"
  | "signature_invalid"
  | "expired"
  | "not_yet_valid"
  | "wrong_trust_domain"
  | "wrong_audience"
  | "spiffe_id_mismatch"
  | "not_a_workload_identity"

export type SvidResult =
  | { readonly ok: true; readonly identity: WorkloadIdentity }
  | { readonly ok: false; readonly reason: SvidFailure; readonly detail: string }

type JwtHeader = { alg?: unknown; kid?: unknown; typ?: unknown }
type JwtClaims = {
  sub?: unknown
  iss?: unknown
  aud?: unknown
  exp?: unknown
  nbf?: unknown
  iat?: unknown
  /** JWT ID. Used as the identity nonce when the trust domain sets one. */
  jti?: unknown
}

const base64UrlDecode = (segment: string): Buffer =>
  Buffer.from(segment.replace(/-/gu, "+").replace(/_/gu, "/"), "base64")

export type ParsedJwt = {
  readonly header: JwtHeader
  readonly claims: JwtClaims
  readonly signingInput: Buffer
  readonly signature: Buffer
}

/**
 * Split a JWS compact serialisation.
 *
 * Three segments, nothing accepted beyond that. `alg: none` and an empty signature are rejected in
 * `verifyJwtSignature` rather than here, because that is the check that matters and it is easier to
 * read next to the signature verification it would otherwise bypass.
 */
export const parseJwt = (token: string): ParsedJwt | undefined => {
  const parts = token.split(".")

  if (parts.length !== 3) return undefined

  const [header, payload, signature] = parts as [string, string, string]

  let headerJson: unknown
  let claimsJson: unknown

  try {
    headerJson = JSON.parse(base64UrlDecode(header).toString("utf8"))
    claimsJson = JSON.parse(base64UrlDecode(payload).toString("utf8"))
  } catch {
    return undefined
  }

  if (headerJson === null || typeof headerJson !== "object" || Array.isArray(headerJson)) return undefined
  if (claimsJson === null || typeof claimsJson !== "object" || Array.isArray(claimsJson)) return undefined

  return {
    header: headerJson as JwtHeader,
    claims: claimsJson as JwtClaims,
    signingInput: Buffer.from(`${header}.${payload}`, "ascii"),
    signature: base64UrlDecode(signature),
  }
}

export type Jwk = {
  kty?: unknown
  crv?: unknown
  kid?: unknown
  n?: unknown
  e?: unknown
  x?: unknown
  y?: unknown
}

/**
 * Re-encode a JWS ECDSA signature as DER.
 *
 * JWS carries ECDSA signatures as the raw fixed-width pair R‖S. `node:crypto`'s `verify` only
 * accepts the ASN.1 DER form. This is a re-encoding of the same two integers, not a new
 * signature scheme: the signature is still checked by the crypto layer against the trust domain's
 * published key, and nothing here can make a bad signature verify.
 *
 * Measured against a live SPIRE 1.15.3 agent: a genuine SVID's raw 64-byte signature fails
 * `verify` outright, and verifies once converted to the 72 bytes below.
 *
 * Exported so the padding rules can be tested against every shape rather than by waiting for a
 * signature to come out the right way: a leading `0x00` in R or S occurs in roughly 1 of 256
 * signatures, so a test that waits for one fails intermittently and hides the fact that the
 * other branch was never exercised at all.
 */
export const rawEcdsaToDer = (raw: Buffer): Buffer | undefined => {
  // P-256 is the only curve ES256 names, so R and S are each exactly 32 bytes.
  if (raw.length !== 64) return undefined

  const encodeInteger = (value: Buffer): Buffer => {
    let start = 0

    // DER integers are signed, so a leading byte of 0x00-0x7f is the sign bit and must go.
    while (start < value.length - 1 && value[start] === 0) start += 1

    const trimmed = value.subarray(start)
    // A trimmed value whose top bit is set would read as negative, so it is re-padded.
    const padded =
      (trimmed[0] as number) >= 0x80 ? Buffer.concat([Buffer.from([0x00]), trimmed]) : trimmed

    return Buffer.concat([Buffer.from([0x02, padded.length]), padded])
  }

  const body = Buffer.concat([encodeInteger(raw.subarray(0, 32)), encodeInteger(raw.subarray(32, 64))])

  // The SEQUENCE length is short enough that the short form is always correct here: two 32-byte
  // integers cannot exceed 70 bytes even when both are padded.
  if (body.length > 0x7f) return undefined

  return Buffer.concat([Buffer.from([0x30, body.length]), body])
}

/**
 * The JWS algorithms this client verifies, mapped to the algorithm argument `crypto.verify` takes.
 *
 * `Ed25519` is EdDSA. EdDSA signs the message itself and has no separate digest step, so Node's
 * `verify` is given `null` rather than a hash name — `crypto.createVerify("Ed25519")` throws
 * `Invalid digest`, because Ed25519 is not a digest. `RS256` is RSA with SHA-256, and `ES256` is
 * ECDSA on P-256 with SHA-256.
 *
 * `ES256` is not an extra algorithm this client chose to tolerate. The SPIFFE JWT-SVID
 * specification defines it as the only algorithm a conforming trust domain may issue, and a live
 * SPIRE 1.15.3 signs with it and nothing else — before this entry existed, a genuine SVID was
 * refused as `unsupported_algorithm`. Accepting it does not widen what verifies: an ES256 token is
 * still signature-checked against a key the trust domain published, and a token signed by anything
 * else still fails.
 *
 * `alg: none` and everything else is absent from this table on purpose, which is what makes an
 * unknown algorithm a refusal rather than something handed to the crypto layer to interpret.
 */
const VERIFY_ALGORITHMS: Readonly<Record<string, string | null>> = {
  Ed25519: null,
  ES256: "sha256",
  RS256: "sha256",
}

/** Build a verifier for a JWS signed by `alg`, or undefined if this JWK cannot be used for it. */
const jwkToVerifier = (
  jwk: Jwk,
  alg: string,
): ((signingInput: Buffer, signature: Buffer) => boolean) | undefined => {
  const expected = VERIFY_ALGORITHMS[alg]

  if (expected === undefined) return undefined

  if (alg === "Ed25519") {
    if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") return undefined
    const key = createPublicKey({ key: { ...jwk, key_ops: ["verify"] } as never, format: "jwk" })

    return (signingInput, signature) => verify(null, signingInput, key, signature)
  }

  if (alg === "ES256") {
    // The curve is pinned rather than read from the JWK: ES256 is defined as P-256, so a key
    // published for a different curve is not a key this algorithm can have been signed with.
    if (jwk.kty !== "EC" || jwk.crv !== "P-256" || typeof jwk.x !== "string" || typeof jwk.y !== "string") {
      return undefined
    }

    const key = createPublicKey({ key: { ...jwk, key_ops: ["verify"] } as never, format: "jwk" })

    return (signingInput, signature) => {
      const der = rawEcdsaToDer(signature)

      // A signature that is not 64 bytes cannot be a P-256 JWS signature, so it is refused rather
      // than passed on in a shape the crypto layer would have to interpret.
      if (der === undefined) return false

      return verify("sha256", signingInput, key, der)
    }
  }

  if (jwk.kty !== "RSA" || typeof jwk.n !== "string" || typeof jwk.e !== "string") return undefined
  const key = createPublicKey({ key: { ...jwk, key_ops: ["verify"] } as never, format: "jwk" })

  return (signingInput, signature) => verify("sha256", signingInput, key, signature)
}

/** The SPIFFE ID an SVD's subject names, or undefined if the subject is not a workload path. */
export const spiffeIdFromClaims = (claims: JwtClaims): string | undefined =>
  typeof claims.sub === "string" ? claims.sub : undefined

export type VerifyJwtOptions = {
  /** Keys published by the trust domain. An empty set means nothing can be verified. */
  readonly jwks: readonly Jwk[]
  readonly expectedTrustDomain: string
  readonly expectedAudience?: string | undefined
  readonly now: Date
}

export type VerifyJwtResult =
  | { readonly ok: true; readonly parsed: ParsedJwt }
  | { readonly ok: false; readonly reason: SvidFailure; readonly detail: string }

/**
 * Verify a JWT-SVID: signature, validity window, trust domain, audience.
 *
 * Every rejection has its own code. "The signature was forged" and "the SVID expired" are different
 * incidents, and an operator looking at a spike of one of them needs to know which.
 */
export const verifyJwtSvid = (token: string, options: VerifyJwtOptions): VerifyJwtResult => {
  const parsed = parseJwt(token)

  if (parsed === undefined) {
    return { ok: false, reason: "malformed_jwt", detail: "not three base64url JSON segments" }
  }

  const alg = parsed.header.alg

  // `none` is checked explicitly rather than being caught by the algorithm whitelist below,
  // because it is the one value that would otherwise mean "no signature at all".
  if (alg === "none" || typeof alg !== "string") {
    return { ok: false, reason: "unsupported_algorithm", detail: `alg is ${String(alg)}` }
  }

  // The whitelist is checked before the key is even looked up. An algorithm this client cannot
  // verify is refused as such rather than falling through to a signature failure, which would tell
  // an operator their trust domain published a bad key when the real answer is that the caller
  // asked for an algorithm SPIFFE does not issue.
  if (!(alg in VERIFY_ALGORITHMS)) {
    return { ok: false, reason: "unsupported_algorithm", detail: `alg ${alg} is not supported` }
  }

  const kid = parsed.header.kid

  if (typeof kid !== "string") {
    return { ok: false, reason: "malformed_jwt", detail: "header has no kid" }
  }

  const candidates = options.jwks.filter((jwk) => jwk.kid === kid)

  if (candidates.length === 0) {
    return { ok: false, reason: "unknown_signing_key", detail: `no published key for kid ${kid}` }
  }

  let verified = false

  for (const jwk of candidates) {
    const verifier = jwkToVerifier(jwk, alg)

    if (verifier === undefined) continue

    try {
      if (verifier(parsed.signingInput, parsed.signature)) {
        verified = true
        break
      }
    } catch {
      // A key that cannot verify this token simply is not the right key for it. Another candidate
      // may be, and if none verifies the result below is a signature failure.
    }
  }

  if (!verified) {
    return { ok: false, reason: "signature_invalid", detail: `no published key verified kid ${kid}` }
  }

  const nowSeconds = options.now.getTime() / 1000

  if (typeof parsed.claims.exp !== "number") {
    return { ok: false, reason: "malformed_jwt", detail: "claims have no numeric exp" }
  }

  if (parsed.claims.exp <= nowSeconds) {
    return { ok: false, reason: "expired", detail: `exp ${parsed.claims.exp} <= now ${nowSeconds}` }
  }

  if (typeof parsed.claims.nbf === "number" && parsed.claims.nbf > nowSeconds) {
    return { ok: false, reason: "not_yet_valid", detail: `nbf ${parsed.claims.nbf} > now ${nowSeconds}` }
  }

  // The trust domain is established from the subject, because that is where SPIRE puts it.
  //
  // A live SPIRE 1.15.3 emits `sub`, `aud`, `iat` and `exp` and no `iss` at all — measured, not
  // inferred — so a check that requires `iss` refuses every genuine SVID. The SPIFFE JWT-SVID
  // profile does not define an `iss` claim for this reason: the trust domain is carried by the
  // `sub` SPIFFE ID and by the fact that the signing key came out of that trust domain's bundle.
  //
  // Requiring the subject to be a workload path inside the expected trust domain enforces the same
  // property the `iss` check did — a token from another trust domain is refused — using the claim
  // the token actually has. An `iss` that *is* present must still agree, so a token carrying both
  // and disagreeing with itself is refused rather than resolved in either direction.
  const spiffeId = spiffeIdFromClaims(parsed.claims)
  const expectedPrefix = `spiffe://${options.expectedTrustDomain}/`

  if (spiffeId === undefined || !spiffeId.startsWith(expectedPrefix)) {
    return {
      ok: false,
      reason: "wrong_trust_domain",
      detail: `sub is ${String(spiffeId)}, which is not a path in ${expectedPrefix}`,
    }
  }

  if (parsed.claims.iss !== undefined && parsed.claims.iss !== `spiffe://${options.expectedTrustDomain}`) {
    return {
      ok: false,
      reason: "wrong_trust_domain",
      detail: `iss is ${String(parsed.claims.iss)}, which does not name the trust domain that sub does`,
    }
  }

  if (options.expectedAudience !== undefined) {
    const audiences = Array.isArray(parsed.claims.aud)
      ? parsed.claims.aud
      : typeof parsed.claims.aud === "string"
        ? [parsed.claims.aud]
        : []

    if (!audiences.includes(options.expectedAudience)) {
      return {
        ok: false,
        reason: "wrong_audience",
        detail: `aud ${JSON.stringify(parsed.claims.aud)} does not include ${options.expectedAudience}`,
      }
    }
  }

  return { ok: true, parsed }
}

export type VerifyIdentityTokenOptions = VerifyWorkloadIdentityOptions & {
  /**
   * When set, a JWT-SVID is also an acceptable token, verified against this trust domain's keys.
   *
   * Absent means only the locally-signed envelope is accepted. That is the correct default for a
   * deployment with no SPIRE, and it is not a silent fallback: a JWT-SVID sent to a sidecar with no
   * keys configured is refused, not quietly reinterpreted.
   */
  readonly spire?: {
    readonly keys: readonly Jwk[]
    readonly trustDomain: string
    readonly audience?: string | undefined
  } | undefined
}

/**
 * Verify a workload identity token of either supported form.
 *
 * The sidecar calls this rather than `verifyWorkloadIdentity` directly, so that a deployment can
 * move from a locally-signed envelope to a SPIFFE-issued SVID without the enforcement point
 * changing shape.
 *
 * The form is decided by the token itself, which is safe: both forms are verified to the same
 * standard before any claim is used, so a token cannot gain authority by being shaped differently.
 * A JWT-SVID reaching a sidecar with no SPIRE keys configured is refused as `malformed_identity`.
 */
export const verifyIdentityToken = (
  candidate: unknown,
  options: VerifyIdentityTokenOptions,
): IdentityVerification => {
  const isJwt = typeof candidate === "string" && candidate.split(".").length === 3

  if (!isJwt) {
    return verifyWorkloadIdentity(candidate, options)
  }

  const spire = options.spire

  if (spire === undefined) {
    return { accepted: false, reason: "malformed_identity" }
  }

  const result = verifyJwtSvid(candidate as string, {
    jwks: spire.keys,
    expectedTrustDomain: spire.trustDomain,
    ...(spire.audience === undefined ? {} : { expectedAudience: spire.audience }),
    now: options.now ?? new Date(),
  })

  if (!result.ok) {
    // The SVID reasons are a finer vocabulary than the envelope's. They are mapped rather than
    // passed through so a caller's switch over `IdentityRejectionReason` stays exhaustive — a new
    // rejection appearing at runtime would otherwise be invisible.
    const mapped: Record<SvidFailure, IdentityRejectionReason> = {
      workload_api_unreachable: "malformed_identity",
      workload_api_error: "malformed_identity",
      no_svid_offered: "malformed_identity",
      malformed_jwt: "malformed_identity",
      unsupported_algorithm: "unsupported_algorithm",
      jwks_unavailable: "malformed_identity",
      unknown_signing_key: "untrusted_issuer",
      signature_invalid: "invalid_signature",
      expired: "expired",
      not_yet_valid: "not_yet_valid",
      wrong_trust_domain: "untrusted_issuer",
      wrong_audience: "invalid_signature",
      spiffe_id_mismatch: "spiffe_mismatch",
      not_a_workload_identity: "malformed_identity",
    }

    return { accepted: false, reason: mapped[result.reason] }
  }

  const spiffeId = spiffeIdFromClaims(result.parsed.claims)
  const subject = spiffeId === undefined ? undefined : parseSpiffeId(spiffeId)
  const exp = result.parsed.claims.exp
  const iat = result.parsed.claims.iat

  if (
    subject === undefined ||
    subject.tenantId !== options.expectedTenantId ||
    typeof exp !== "number"
  ) {
    return { accepted: false, reason: "spiffe_mismatch" }
  }

  if (options.revokedAgentIds?.has(subject.agentId) === true) {
    return { accepted: false, reason: "revoked" }
  }

  // The SVID's `sub` is the identity, and `jti` is its per-issuance nonce when the trust domain
  // sets one. Where there is no `jti`, the pair of subject and `iat` is used — both are inside
  // what the signature covers, so neither can be changed without invalidating the token.
  const nonce =
    typeof result.parsed.claims.jti === "string"
      ? result.parsed.claims.jti
      : `${String(iat ?? "0")}.${spiffeId ?? ""}`

  if (options.revokedNonces?.has(nonce) === true) {
    return { accepted: false, reason: "revoked" }
  }

  return {
    accepted: true,
    identity: {
      spiffe_id: spiffeId as string,
      trust_domain: spire.trustDomain,
      tenant_id: subject.tenantId,
      agent_id: subject.agentId,
      nonce,
      issued_at: new Date((typeof iat === "number" ? iat : 0) * 1000).toISOString(),
      expires_at: new Date(exp * 1000).toISOString(),
    },
  }
}

export type SpireOptions = {
  /**
   * Path to the SPIRE agent's Workload API Unix socket.
   *
   * This is the real transport. It is preferred over `workloadApi` whenever it is set, and it
   * defaults to SPIRE's own default path.
   */
  readonly workloadSocket?: string
  /**
   * An HTTP base URL for the Workload API, used only when `workloadSocket` is unset.
   *
   * No SPIRE version serves the Workload API over HTTP; it is gRPC over a Unix socket. This
   * exists for tests that stand up a stub and for deployments fronting the agent, and it is not
   * a fallback SPIRE offers. Prefer `workloadSocket`.
   */
  readonly workloadApi?: string
  /** The SPIFFE ID to request. */
  readonly spiffeId: string
  /** Trust domain whose JWKS signs the SVID. */
  readonly trustDomain: string
  /**
   * Where the trust domain publishes its signing keys.
   *
   * This is a trust anchor. See the module comment: nothing here establishes that the JWKS is
   * authentic, so in a deployment this should be pinned out of band rather than discovered.
   */
  readonly jwksUri: string
  readonly expectedAudience?: string | undefined
  readonly now?: () => Date
  readonly fetchImpl?: typeof fetch
  /**
   * Node attestation hints SPIRE matches on. Sent as query parameters so an operator can select an
   * entry without the client embedding a workload-name format it would have to keep in step with
   * SPIRE's.
   */
  readonly selector?: Readonly<Record<string, string>>
}

type WorkloadApiResponse = Record<string, { svid?: { jwt?: unknown } }>

/**
 * Request a JWT-SVID from the SPIFFE Workload API.
 *
 * ## The transport
 *
 * With a socket path — the default — this speaks gRPC over the agent's Unix socket, which is what
 * a SPIRE agent actually serves. Verified against a live SPIRE 1.15.3 trust domain: the call
 * returns `grpc-status 0` and a JWT-SVID that `verifyJwtSvid` then accepts.
 *
 * With `workloadApi` set instead, it falls back to an HTTP GET against a stub. No SPIRE version
 * answers that — the agent resets an HTTP/1.1 request on its socket — so the fallback is for tests
 * and for deployments that put something in front of the agent, not for SPIRE itself.
 */
export const requestSvid = async (
  options: SpireOptions,
): Promise<{ readonly token: string } | { readonly failure: SvidFailure; readonly detail: string }> => {
  // An explicit `workloadApi` means an operator chose the HTTP path; otherwise the socket is used.
  const socketPath =
    options.workloadSocket ?? (options.workloadApi === undefined ? DEFAULT_WORKLOAD_SOCKET : undefined)

  if (socketPath !== undefined) {
    const result = await fetchJwtSvid({
      socketPath,
      spiffeId: options.spiffeId,
      audience: options.expectedAudience === undefined ? [] : [options.expectedAudience],
    })

    if (!result.ok) {
      return { failure: result.failure, detail: result.detail }
    }

    return { token: (result.svids[0] as { jwt: string }).jwt }
  }

  const base = options.workloadApi ?? DEFAULT_WORKLOAD_API
  const doFetch = options.fetchImpl ?? fetch
  const selector = new URLSearchParams({
    "spiffe_id": options.spiffeId,
    ...(options.selector ?? {}),
  })

  const url = new URL(`/workload-api/jwt-svid?${selector.toString()}`, base)

  let response: Response

  try {
    response = await doFetch(url, { headers: { accept: "application/jwt" } })
  } catch (error) {
    return {
      failure: "workload_api_unreachable",
      detail: error instanceof Error ? error.message : "request failed",
    }
  }

  if (!response.ok) {
    return {
      failure: response.status === 404 ? "no_svid_offered" : "workload_api_unreachable",
      detail: `workload API returned ${response.status}`,
    }
  }

  const body = (await response.json()) as WorkloadApiResponse
  const first = Object.values(body)[0]
  const token = first?.svid?.jwt

  if (typeof token !== "string") {
    return { failure: "no_svid_offered", detail: "response carried no svid.jwt" }
  }

  return { token }
}

export type JwksResult =
  | { readonly ok: true; readonly keys: readonly Jwk[] }
  | { readonly ok: false; readonly failure: SvidFailure; readonly detail: string }

export const fetchJwks = async (
  uri: string,
  fetchImpl: typeof fetch = fetch,
): Promise<JwksResult> => {
  let response: Response

  try {
    response = await fetchImpl(uri)
  } catch (error) {
    return {
      ok: false,
      failure: "jwks_unavailable",
      detail: error instanceof Error ? error.message : "request failed",
    }
  }

  if (!response.ok) {
    return { ok: false, failure: "jwks_unavailable", detail: `JWKS endpoint returned ${response.status}` }
  }

  const body = (await response.json()) as { keys?: unknown }

  if (!Array.isArray(body.keys)) {
    return { ok: false, failure: "jwks_unavailable", detail: "JWKS body has no keys array" }
  }

  return { ok: true, keys: body.keys as Jwk[] }
}

/**
 * Build a `WorkloadIdentityProvider` backed by SPIRE.
 *
 * The returned identity keeps the `nonce` from the SVD subject path rather than generating one.
 * It has to: the SVD is what the sidecar will be shown, and an identity whose nonce is not part of
 * what was attested is an identity the attestation does not actually cover.
 */
export const createSpireIdentityProvider = (options: SpireOptions): WorkloadIdentityProvider => ({
  kind: "spire",
  issue: async (tenantId, agentId): Promise<IssuedIdentity> => {
    const parsed = parseSpiffeId(options.spiffeId)

    if (parsed === undefined || parsed.tenantId !== tenantId || parsed.agentId !== agentId) {
      // Refusing to mint an identity for a workload this client was not attested as is the entire
      // point of node attestation. If this were allowed, one attested workload could ask for
      // another's identity and the fabric would have no way to tell.
      throw new Error(
        `SPIRE client is attested as ${options.spiffeId} and cannot issue an identity for ` +
          `${buildSpiffeId(tenantId, agentId)}`,
      )
    }

    const requested = await requestSvid(options)

    if ("failure" in requested) throw new Error(`${requested.failure}: ${requested.detail}`)

    const jwks = await fetchJwks(options.jwksUri, options.fetchImpl)

    if (!jwks.ok) throw new Error(`${jwks.failure}: ${jwks.detail}`)

    const verified = verifyJwtSvid(requested.token, {
      jwks: jwks.keys,
      expectedTrustDomain: options.trustDomain,
      expectedAudience: options.expectedAudience,
      now: (options.now ?? ((): Date => new Date()))(),
    })

    if (!verified.ok) throw new Error(`${verified.reason}: ${verified.detail}`)

    const spiffeId = spiffeIdFromClaims(verified.parsed.claims)

    if (spiffeId === undefined) {
      throw new Error("not_a_workload_identity: the SVD has no sub claim")
    }

    const subject = parseSpiffeId(spiffeId)

    if (subject === undefined || subject.tenantId !== tenantId || subject.agentId !== agentId) {
      throw new Error(
        `spiffe_id_mismatch: SVD subject ${spiffeId} does not name ${tenantId}/${agentId}`,
      )
    }

    const claims = verified.parsed.claims

    return {
      // The verified JWT itself, not the identity parsed from it. The sidecar re-derives the
      // identity from these exact bytes and re-checks the signature against its own copy of the
      // trust domain's keys. Sending the parsed object instead would mean the thing that was
      // verified here is not the thing that is enforced there.
      token: requested.token,
      identity: {
        spiffe_id: spiffeId,
        trust_domain: options.trustDomain,
        tenant_id: subject.tenantId,
        agent_id: subject.agentId,
        // Derived from claims inside the signature, never generated here. An identity whose nonce
        // is not part of what was attested is an identity the attestation does not cover.
        nonce:
          typeof claims.jti === "string"
            ? claims.jti
            : `${String(claims.iat ?? "0")}.${spiffeId}`,
        issued_at: new Date((typeof claims.iat === "number" ? claims.iat : 0) * 1000).toISOString(),
        expires_at: new Date((claims.exp as number) * 1000).toISOString(),
      },
    }
  },
})