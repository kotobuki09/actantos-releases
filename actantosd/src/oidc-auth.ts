import { createHmac, createPublicKey, timingSafeEqual, verify } from "node:crypto"
import { request as httpRequest } from "node:http"
import { request as httpsRequest } from "node:https"
import { z } from "zod"

export const tenantRoles = ["viewer", "operator", "admin"] as const
export type TenantRole = (typeof tenantRoles)[number]

export type TenantMembership = {
  readonly tenantId: string
  readonly role: TenantRole
  readonly scopes: readonly string[]
}

export type AuthenticatedPrincipal = {
  readonly kind: "oidc" | "service"
  readonly subject: string
  readonly issuer: string
  readonly audience: string
  readonly tenantId: string
  readonly memberships: readonly TenantMembership[]
  readonly role: TenantRole
  readonly scopes: readonly string[]
}

export interface MembershipResolver {
  resolve(subject: string): Promise<readonly TenantMembership[]>
}

export type JsonWebKey = Readonly<Record<string, unknown>>
export interface JwksResolver {
  resolve(issuer: string, kid: string): Promise<JsonWebKey | undefined>
}

export type OidcConfig = {
  readonly issuer: string
  readonly audience: string
  readonly allowedAlgorithms: readonly ("RS256" | "HS256")[]
  readonly membershipResolver: MembershipResolver
  readonly jwksResolver?: JwksResolver
  readonly clientSecret?: string
  readonly allowDevelopmentHs256?: boolean
  readonly clock?: () => number
}

const jwtHeaderSchema = z.object({ alg: z.enum(["RS256", "HS256"]), kid: z.string().min(1).optional() })
const jwtPayloadSchema = z.object({
  sub: z.string().min(1), iss: z.string().url(), aud: z.union([z.string(), z.array(z.string())]),
  exp: z.number().int(), nbf: z.number().int().optional(),
})

const parseSegment = (segment: string): unknown =>
  JSON.parse(Buffer.from(segment, "base64url").toString("utf8")) as unknown

const selectMembership = (
  memberships: readonly TenantMembership[], requestedTenant: string | undefined,
): TenantMembership | undefined => {
  if (requestedTenant !== undefined) return memberships.find(({ tenantId }) => tenantId === requestedTenant)
  return memberships.length === 1 ? memberships[0] : undefined
}

export const verifyOidcBearerToken = async (
  authorizationHeader: string | undefined,
  requestedTenant: string | undefined,
  config: OidcConfig,
): Promise<AuthenticatedPrincipal | null> => {
  if (authorizationHeader === undefined || !authorizationHeader.startsWith("Bearer ")) return null
  const parts = authorizationHeader.slice(7).trim().split(".")
  if (parts.length !== 3) return null
  const [headerPart, payloadPart, signaturePart] = parts
  if (headerPart === undefined || payloadPart === undefined || signaturePart === undefined) return null
  try {
    const header = jwtHeaderSchema.parse(parseSegment(headerPart))
    const payload = jwtPayloadSchema.parse(parseSegment(payloadPart))
    if (!config.allowedAlgorithms.includes(header.alg) || payload.iss !== config.issuer) return null
    if (!(Array.isArray(payload.aud) ? payload.aud.includes(config.audience) : payload.aud === config.audience)) return null
    const now = Math.floor((config.clock?.() ?? Date.now()) / 1000)
    if (payload.exp <= now || (payload.nbf !== undefined && payload.nbf > now)) return null
    const signed = Buffer.from(`${headerPart}.${payloadPart}`)
    const signature = Buffer.from(signaturePart, "base64url")
    if (header.alg === "HS256") {
      if (config.allowDevelopmentHs256 !== true || config.clientSecret === undefined) return null
      const expected = createHmac("sha256", config.clientSecret).update(signed).digest()
      if (expected.length !== signature.length || !timingSafeEqual(expected, signature)) return null
    } else {
      if (header.kid === undefined || config.jwksResolver === undefined) return null
      const key = await config.jwksResolver.resolve(config.issuer, header.kid)
      if (key === undefined || !verify("RSA-SHA256", signed, createPublicKey({ key, format: "jwk" }), signature)) return null
    }
    const memberships = await config.membershipResolver.resolve(payload.sub)
    const membership = selectMembership(memberships, requestedTenant)
    if (membership === undefined) return null
    return { kind: "oidc", subject: payload.sub, issuer: payload.iss, audience: config.audience,
      tenantId: membership.tenantId, memberships, role: membership.role, scopes: membership.scopes }
  } catch {
    return null
  }
}

const readJson = (url: URL): Promise<unknown> => new Promise((resolve, reject) => {
  const send = url.protocol === "https:" ? httpsRequest : httpRequest
  const request = send(url, { method: "GET", timeout: 5_000 }, (response) => {
    const chunks: Buffer[] = []
    response.on("data", (chunk: Buffer) => chunks.push(chunk))
    response.on("end", () => {
      if (response.statusCode !== 200) return reject(new Error(`OIDC endpoint returned ${response.statusCode}`))
      try { resolve(JSON.parse(Buffer.concat(chunks).toString("utf8")) as unknown) } catch (error) { reject(error) }
    })
  })
  request.on("timeout", () => request.destroy(new Error("OIDC endpoint timed out")))
  request.on("error", reject)
  request.end()
})

const discoverySchema = z.object({ jwks_uri: z.string().url() })
const jwksSchema = z.object({ keys: z.array(z.record(z.string(), z.unknown())) })

export const createRemoteJwksResolver = (): JwksResolver => ({
  async resolve(issuer, kid) {
    const discoveryUrl = new URL(".well-known/openid-configuration", `${issuer.replace(/\/$/, "")}/`)
    const discovery = discoverySchema.parse(await readJson(discoveryUrl))
    const jwks = jwksSchema.parse(await readJson(new URL(discovery.jwks_uri)))
    return jwks.keys.find((key) => key["kid"] === kid)
  },
})

export const mintOidcAccessToken = (
  config: Pick<OidcConfig, "issuer" | "audience"> & { readonly clientSecret: string },
  claims: { readonly sub: string; readonly expSecondsFromNow?: number },
): string => {
  const header = Buffer.from(JSON.stringify({ alg: "HS256", typ: "JWT" })).toString("base64url")
  const now = Math.floor(Date.now() / 1000)
  const payload = Buffer.from(JSON.stringify({ sub: claims.sub, iss: config.issuer, aud: config.audience,
    iat: now, exp: now + (claims.expSecondsFromNow ?? 3600) })).toString("base64url")
  const data = `${header}.${payload}`
  return `${data}.${createHmac("sha256", config.clientSecret).update(data).digest("base64url")}`
}

const parseStaticMemberships = (raw: string | undefined): readonly TenantMembership[] => {
  if (raw === undefined || raw.trim().length === 0) {
    return []
  }
  const parsed = JSON.parse(raw) as unknown
  if (!Array.isArray(parsed)) {
    throw new Error("ACTANTOS_OIDC_STATIC_MEMBERSHIPS must be a JSON array")
  }
  return parsed.map((entry) => {
    const row = entry as {
      readonly tenantId?: unknown
      readonly role?: unknown
      readonly scopes?: unknown
    }
    if (typeof row.tenantId !== "string" || row.tenantId.length === 0) {
      throw new Error("membership tenantId is required")
    }
    if (row.role !== "viewer" && row.role !== "operator" && row.role !== "admin") {
      throw new Error("membership role must be viewer|operator|admin")
    }
    const scopes = Array.isArray(row.scopes)
      ? row.scopes.filter((scope): scope is string => typeof scope === "string")
      : []
    return { tenantId: row.tenantId, role: row.role, scopes }
  })
}

/**
 * Stage 3 OIDC env loader.
 * HS256 remains available only when ACTANTOS_OIDC_ALLOW_HS256=true and a client secret is set.
 * Static memberships bridge until DB-backed membership resolvers land in T5.
 */
export const loadOidcConfigFromEnv = (
  env: NodeJS.ProcessEnv = process.env,
): OidcConfig | undefined => {
  const issuer = env["ACTANTOS_OIDC_ISSUER"]?.trim()
  const audience = env["ACTANTOS_OIDC_AUDIENCE"]?.trim()
  if (issuer === undefined || issuer.length === 0 || audience === undefined || audience.length === 0) {
    return undefined
  }

  const allowDevelopmentHs256 = env["ACTANTOS_OIDC_ALLOW_HS256"] === "true"
  const clientSecret = env["ACTANTOS_OIDC_CLIENT_SECRET"]?.trim()
  if (allowDevelopmentHs256 && (clientSecret === undefined || clientSecret.length === 0)) {
    return undefined
  }

  const staticMemberships = parseStaticMemberships(env["ACTANTOS_OIDC_STATIC_MEMBERSHIPS"])
  const defaultTenant = env["ACTANTOS_DEFAULT_TENANT"]?.trim()
  const memberships: readonly TenantMembership[] =
    staticMemberships.length > 0
      ? staticMemberships
      : defaultTenant !== undefined && defaultTenant.length > 0
        ? [{ tenantId: defaultTenant, role: "admin", scopes: ["*"] }]
        : [{ tenantId: "t_demo", role: "admin", scopes: ["*"] }]

  const allowedAlgorithms: readonly ("RS256" | "HS256")[] = allowDevelopmentHs256
    ? ["RS256", "HS256"]
    : ["RS256"]

  return {
    issuer,
    audience,
    allowedAlgorithms,
    allowDevelopmentHs256,
    ...(clientSecret === undefined || clientSecret.length === 0 ? {} : { clientSecret }),
    jwksResolver: createRemoteJwksResolver(),
    membershipResolver: {
      async resolve() {
        return memberships
      },
    },
  }
}
