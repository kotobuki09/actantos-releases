import { createHash, createHmac, createPrivateKey, sign as nodeSign } from "node:crypto"

/**
 * Request signing for the production credential providers.
 *
 * This module invents no cryptographic primitive. Every signature here is produced by
 * `node:crypto` from a published, independently implemented specification:
 *
 *   - RS256 is RFC 7518 §3.3, the JWS algorithm GitHub App authentication requires.
 *   - Signature Version 4 is AWS's documented scheme, and it is built from HMAC-SHA256
 *     and SHA-256. The derivation is implemented because no library is vendored here;
 *     it is a protocol implementation, not a new algorithm. `sts-sigv4.test.ts` verifies
 *     each step against an independently written recomputation, and
 *     `aws-sigv4-server.test.ts` verifies it against a server that rebuilds the signature
 *     from the raw request it actually received.
 *
 * The private keys used with these functions are long-lived, deployment-scoped secrets
 * (a GitHub App key, an AWS access key, a Vault AppRole secret id). None of them is ever
 * passed to a model, and nothing in this module returns key material.
 */

export const base64url = (input: Buffer | string): string =>
  (typeof input === "string" ? Buffer.from(input, "utf8") : input)
    .toString("base64")
    .replace(/\+/gu, "-")
    .replace(/\//gu, "_")
    .replace(/=+$/u, "")

export const sha256Hex = (input: Buffer | string): string =>
  createHash("sha256")
    .update(typeof input === "string" ? Buffer.from(input, "utf8") : input)
    .digest("hex")

const hmac = (key: Buffer | string, data: string): Buffer =>
  createHmac("sha256", key).update(data, "utf8").digest()

/** RFC 7519. Signature is RS256 over `base64url(header).base64url(payload)`. */
export const signRs256Jwt = (
  claims: Readonly<Record<string, unknown>>,
  privateKeyPem: string,
  header: Readonly<Record<string, unknown>> = { alg: "RS256", typ: "JWT" },
): string => {
  const signingInput = `${base64url(JSON.stringify(header))}.${base64url(JSON.stringify(claims))}`
  const signature = nodeSign(
    "sha256",
    Buffer.from(signingInput, "utf8"),
    createPrivateKey(privateKeyPem),
  )
  return `${signingInput}.${base64url(signature)}`
}

// --- AWS Signature Version 4 -------------------------------------------------------------

export const SIGV4_ALGORITHM = "AWS4-HMAC-SHA256"
export const SIGV4_SERVICE = "sts"

/**
 * RFC 3986 percent-encoding as SigV4 specifies it: only unreserved characters stay
 * literal, and a space becomes `%20` rather than `+`. `encodeURIComponent` encodes the
 * unreserved set `!'()*` that SigV4 requires be left alone, so this cannot be used here.
 */
export const sigv4Encode = (value: string): string =>
  Array.from(Buffer.from(value, "utf8"))
    .map((byte) => {
      const character = String.fromCharCode(byte)
      if (/^[A-Za-z0-9\-._~]$/u.test(character)) return character
      return `%${byte.toString(16).toUpperCase().padStart(2, "0")}`
    })
    .join("")

/**
 * The `YYYYMMDD'T'HHMMSS'Z'` stamp SigV4 signs with, plus its date part.
 *
 * `toISOString()` already ends in `Z`, so the result is used as-is. Appending a second `Z`
 * is a mistake this function exists to prevent: it produced a well-formed-looking timestamp
 * that no server accepts, and the failure surfaced only as an opaque 403 from AWS.
 */
export const amzDate = (at: Date): { readonly full: string; readonly short: string } => {
  const stamp = at.toISOString().replace(/[:-]|\.\d{3}/gu, "")

  if (!/^\d{8}T\d{6}Z$/u.test(stamp)) {
    throw new Error(`could not derive an AWS timestamp from ${at.toISOString()}`)
  }

  return { full: stamp, short: stamp.slice(0, 8) }
}

const canonicalHeaders = (headers: ReadonlyMap<string, string>): {
  readonly canonical: string
  readonly signed: string
} => {
  const entries = [...headers.entries()]
    .map(([name, value]) => [name.toLowerCase(), value.trim().replace(/\s+/gu, " ")] as const)
    .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0))

  return {
    canonical: entries.map(([name, value]) => `${name}:${value}\n`).join(""),
    signed: entries.map(([name]) => name).join(";"),
  }
}

/** The SigV4 signing-key derivation. Exposed so a test can recompute it independently. */
export const sigv4SigningKey = (args: {
  readonly secretAccessKey: string
  readonly dateStamp: string
  readonly region: string
  readonly service: string
}): Buffer =>
  hmac(
    hmac(hmac(hmac(`AWS4${args.secretAccessKey}`, args.dateStamp), args.region), args.service),
    "aws4_request",
  )

export type Sigv4Request = {
  readonly method: string
  readonly canonicalUri: string
  readonly canonicalQuery: string
  readonly headers: ReadonlyMap<string, string>
  readonly payload: string
  readonly at: Date
}

export const buildCanonicalRequest = (request: Sigv4Request): string => {
  const { canonical, signed } = canonicalHeaders(request.headers)
  return [
    request.method.toUpperCase(),
    request.canonicalUri,
    request.canonicalQuery,
    canonical,
    signed,
    sha256Hex(request.payload),
  ].join("\n")
}

export const buildStringToSign = (args: {
  readonly canonicalRequest: string
  readonly at: Date
  readonly region: string
  readonly service: string
}): string => {
  const stamp = amzDate(args.at)
  return [
    SIGV4_ALGORITHM,
    stamp.full,
    `${stamp.short}/${args.region}/${args.service}/aws4_request`,
    sha256Hex(args.canonicalRequest),
  ].join("\n")
}

/**
 * Sign a request and return the headers to send, including `Authorization`.
 *
 * `headers` must already contain `host`, `x-amz-date` and any other signed header. The
 * returned map is a new map; the input is not mutated.
 */
export const signSigv4 = (args: {
  readonly request: Sigv4Request
  readonly accessKeyId: string
  readonly secretAccessKey: string
  readonly region: string
  readonly service: string
}): ReadonlyMap<string, string> => {
  const canonicalRequest = buildCanonicalRequest(args.request)
  const stringToSign = buildStringToSign({
    canonicalRequest,
    at: args.request.at,
    region: args.region,
    service: args.service,
  })
  const stamp = amzDate(args.request.at)
  const scope = `${stamp.short}/${args.region}/${args.service}/aws4_request`
  const signature = hmac(
    sigv4SigningKey({
      secretAccessKey: args.secretAccessKey,
      dateStamp: stamp.short,
      region: args.region,
      service: args.service,
    }),
    stringToSign,
  ).toString("hex")

  const { signed } = canonicalHeaders(args.request.headers)
  const headers = new Map(args.request.headers)
  headers.set(
    "authorization",
    `${SIGV4_ALGORITHM} Credential=${args.accessKeyId}/${scope}, SignedHeaders=${signed}, Signature=${signature}`,
  )
  return headers
}

/**
 * `application/x-www-form-urlencoded` body, with keys sorted.
 *
 * SigV4 signs the exact bytes sent, and SigV4's canonical form requires sorted parameters,
 * so building the body and the signature from one function removes the chance of the two
 * disagreeing — the classic source of an opaque "signature mismatch" from AWS.
 */
export const sigv4FormBody = (parameters: Readonly<Record<string, string>>): string =>
  Object.keys(parameters)
    .sort()
    .map((key) => `${sigv4Encode(key)}=${sigv4Encode(parameters[key] ?? "")}`)
    .join("&")