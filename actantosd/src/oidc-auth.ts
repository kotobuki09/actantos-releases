import { createHmac, timingSafeEqual } from "node:crypto"

export type OidcConfig = {
  readonly issuer: string
  readonly audience: string
  /** Dev/test HS256 secret (Stage 2). Production may swap for JWKS later. */
  readonly clientSecret: string
}

export type OidcPrincipal = {
  readonly sub: string
  readonly iss: string
  readonly aud: string
}

const b64urlJson = (value: unknown): string =>
  Buffer.from(JSON.stringify(value)).toString("base64url")

const parseB64urlJson = (segment: string): unknown => {
  const json = Buffer.from(segment, "base64url").toString("utf8")
  return JSON.parse(json) as unknown
}

/** Mint HS256 JWT for tests and local OIDC-style operator auth. */
export const mintOidcAccessToken = (
  config: OidcConfig,
  claims: { readonly sub: string; readonly expSecondsFromNow?: number },
): string => {
  const header = b64urlJson({ alg: "HS256", typ: "JWT" })
  const now = Math.floor(Date.now() / 1000)
  const payload = b64urlJson({
    sub: claims.sub,
    iss: config.issuer,
    aud: config.audience,
    iat: now,
    exp: now + (claims.expSecondsFromNow ?? 3600),
  })
  const data = `${header}.${payload}`
  const sig = createHmac("sha256", config.clientSecret).update(data).digest("base64url")
  return `${data}.${sig}`
}

export const verifyOidcBearerToken = (
  authorizationHeader: string | undefined,
  config: OidcConfig,
): OidcPrincipal | null => {
  if (authorizationHeader === undefined || !authorizationHeader.startsWith("Bearer ")) {
    return null
  }
  const token = authorizationHeader.slice("Bearer ".length).trim()
  const parts = token.split(".")
  if (parts.length !== 3) {
    return null
  }
  const [headerB64, payloadB64, signatureB64] = parts
  if (headerB64 === undefined || payloadB64 === undefined || signatureB64 === undefined) {
    return null
  }

  const data = `${headerB64}.${payloadB64}`
  const expected = createHmac("sha256", config.clientSecret).update(data).digest("base64url")
  const expectedBuf = Buffer.from(expected)
  const providedBuf = Buffer.from(signatureB64)
  if (expectedBuf.length !== providedBuf.length || !timingSafeEqual(expectedBuf, providedBuf)) {
    return null
  }

  try {
    const header = parseB64urlJson(headerB64) as { alg?: string }
    if (header.alg !== "HS256") {
      return null
    }
    const payload = parseB64urlJson(payloadB64) as {
      sub?: string
      iss?: string
      aud?: string | string[]
      exp?: number
    }
    if (typeof payload.sub !== "string" || payload.sub.length === 0) {
      return null
    }
    if (payload.iss !== config.issuer) {
      return null
    }
    const audOk = Array.isArray(payload.aud)
      ? payload.aud.includes(config.audience)
      : payload.aud === config.audience
    if (!audOk) {
      return null
    }
    if (typeof payload.exp !== "number" || payload.exp < Math.floor(Date.now() / 1000)) {
      return null
    }
    return { sub: payload.sub, iss: config.issuer, aud: config.audience }
  } catch {
    return null
  }
}

export const loadOidcConfigFromEnv = (
  env: NodeJS.ProcessEnv = process.env,
): OidcConfig | undefined => {
  const issuer = env["ACTANTOS_OIDC_ISSUER"]?.trim()
  const audience = env["ACTANTOS_OIDC_AUDIENCE"]?.trim()
  const clientSecret = env["ACTANTOS_OIDC_CLIENT_SECRET"]?.trim()
  if (
    issuer === undefined ||
    issuer.length === 0 ||
    audience === undefined ||
    audience.length === 0 ||
    clientSecret === undefined ||
    clientSecret.length === 0
  ) {
    return undefined
  }
  return { issuer, audience, clientSecret }
}
