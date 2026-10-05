import type { FastifyInstance } from "fastify"
import { randomBytes } from "node:crypto"
import { Issuer, generators, type Client } from "openid-client"
import "@fastify/session"

declare module "fastify" {
  interface Session {
    oidcState?: string
    oidcNonce?: string
    oidcCodeVerifier?: string
    user?: {
      id: string
      email?: string
      roles: string[]
    }
  }
}

export type OidcConfig = {
  readonly issuer: string
  readonly clientId: string
  readonly clientSecret: string
  readonly redirectUri: string
}

type RegisterOidcRoutesOptions = {
  readonly oidcConfig: OidcConfig
}

export const registerOidcRoutes = async (
  server: FastifyInstance,
  options: RegisterOidcRoutesOptions,
): Promise<void> => {
  let client: Client | undefined = undefined

  try {
    const issuer = await Issuer.discover(options.oidcConfig.issuer)
    client = new issuer.Client({
      client_id: options.oidcConfig.clientId,
      client_secret: options.oidcConfig.clientSecret,
      redirect_uris: [options.oidcConfig.redirectUri],
      response_types: ["code"],
    })
  } catch (error) {
    server.log.error(error, "Failed to discover OIDC issuer. OIDC login will be unavailable.")
  }

  server.get("/auth/login", async (request, reply) => {
    if (client === undefined) {
      return reply.code(500).send({ error: "oidc_not_configured", message: "OIDC client initialization failed" })
    }

    const nonce = generators.nonce()
    const state = generators.state()
    const code_verifier = generators.codeVerifier()
    const code_challenge = generators.codeChallenge(code_verifier)

    request.session.oidcState = state
    request.session.oidcNonce = nonce
    request.session.oidcCodeVerifier = code_verifier

    const url = client.authorizationUrl({
      scope: "openid email profile",
      state,
      nonce,
      code_challenge,
      code_challenge_method: "S256",
    })

    return reply.redirect(url)
  })

  server.get("/auth/callback", async (request, reply) => {
    if (client === undefined) {
      return reply.code(500).send({ error: "oidc_not_configured" })
    }

    const params = client.callbackParams(request.raw)
    const state = request.session.oidcState
    const nonce = request.session.oidcNonce
    const code_verifier = request.session.oidcCodeVerifier

    if (!state || !nonce || !code_verifier) {
      return reply.code(400).send({ error: "invalid_session", message: "Session state missing" })
    }

    try {
      const tokenSet = await client.callback(options.oidcConfig.redirectUri, params, { state, nonce, code_verifier })
      const claims = tokenSet.claims()
      
      request.session.user = {
        id: claims.sub,
        ...(claims.email ? { email: claims.email } : {}),
        roles: Array.isArray(claims["roles"]) ? claims["roles"] : [],
      }
      
      return reply.redirect("/dashboard")
    } catch (error) {
      server.log.error(error, "OIDC callback failed")
      return reply.code(401).send({ error: "oidc_callback_failed" })
    }
  })
}
