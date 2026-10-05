import test from "node:test"
import assert from "node:assert"
import { buildServer } from "./server.ts"
import { type OidcConfig } from "./oidc-routes.ts"

// Mock the openid-client Issuer discovery for testing
import { Issuer } from "openid-client"
Issuer.discover = async () => {
  return new Issuer({
    issuer: "https://example.com",
    authorization_endpoint: "https://example.com/auth",
    token_endpoint: "https://example.com/token",
  })
}

test("Unauthenticated requests to /dashboard without OIDC redirect to login", async () => {
  const server = buildServer()
  const response = await server.inject({
    method: "GET",
    url: "/dashboard"
  })
  // If no OIDC is configured, it should just serve the page.
  assert.strictEqual(response.statusCode, 200)
  assert.ok(response.payload.includes("ActantOS Dashboard"))
})

test("Unauthenticated requests to /dashboard WITH OIDC redirect to login", async () => {
  const oidcConfig: OidcConfig = {
    issuer: "https://example.com",
    clientId: "test-client",
    clientSecret: "test-secret",
    redirectUri: "http://localhost:3100/auth/callback"
  }
  const server = buildServer({ oidcConfig })
  
  const response = await server.inject({
    method: "GET",
    url: "/dashboard"
  })
  
  assert.strictEqual(response.statusCode, 302)
  assert.strictEqual(response.headers.location, "/auth/login")
})

test("/auth/login returns redirect to OIDC provider", async () => {
  const oidcConfig: OidcConfig = {
    issuer: "https://example.com",
    clientId: "test-client",
    clientSecret: "test-secret",
    redirectUri: "http://localhost:3100/auth/callback"
  }
  const server = buildServer({ oidcConfig })
  
  const response = await server.inject({
    method: "GET",
    url: "/auth/login"
  })
  
  assert.strictEqual(response.statusCode, 302)
  assert.ok(response.headers.location?.startsWith("https://example.com/auth"))
})
