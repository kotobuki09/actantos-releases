import assert from "node:assert/strict"
import test from "node:test"

import { mintOidcAccessToken, verifyOidcBearerToken } from "./oidc-auth.ts"
import { buildServer } from "./server.ts"
import { createTestDatabase } from "./test-database.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"

const oidc = {
  issuer: "https://issuer.actantos.test",
  audience: "actantos-ops",
  clientSecret: "stage2-oidc-secret",
  allowedAlgorithms: ["HS256"] as const,
  allowDevelopmentHs256: true,
  membershipResolver: {
    async resolve() { return [{ tenantId: "t_demo", role: "admin" as const, scopes: ["*"] }] },
  },
}

test("verifyOidcBearerToken accepts explicit development HS256 and rejects malformed tokens", async () => {
  const token = mintOidcAccessToken(oidc, { sub: "op_demo" })
  const principal = await verifyOidcBearerToken(`Bearer ${token}`, undefined, oidc)
  assert.deepEqual(principal, {
    kind: "oidc", subject: "op_demo", issuer: oidc.issuer, audience: oidc.audience,
    tenantId: "t_demo", memberships: [{ tenantId: "t_demo", role: "admin", scopes: ["*"] }],
    role: "admin", scopes: ["*"],
  })
  assert.equal(await verifyOidcBearerToken(undefined, undefined, oidc), null)
  assert.equal(await verifyOidcBearerToken("Bearer not-a-jwt", undefined, oidc), null)
  assert.equal(await verifyOidcBearerToken(`Bearer ${token}x`, undefined, oidc), null)
  assert.equal(await verifyOidcBearerToken(`Bearer ${token}`, undefined, { ...oidc, allowDevelopmentHs256: false }), null)
})

test("verifyOidcBearerToken rejects ambiguous and cross-tenant memberships", async () => {
  const token = mintOidcAccessToken(oidc, { sub: "op_demo" })
  const multi = { ...oidc, membershipResolver: { async resolve() { return [
    { tenantId: "t_one", role: "viewer" as const, scopes: [] },
    { tenantId: "t_two", role: "operator" as const, scopes: ["execute"] },
  ] } } }
  assert.equal(await verifyOidcBearerToken(`Bearer ${token}`, undefined, multi), null)
  assert.equal(await verifyOidcBearerToken(`Bearer ${token}`, "t_other", multi), null)
  assert.equal((await verifyOidcBearerToken(`Bearer ${token}`, "t_two", multi))?.tenantId, "t_two")
})

test("ops routes deny without OIDC bearer when oidc is configured", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
    oidc,
  })
  await server.ready()

  const denied = await server.inject({
    method: "GET",
    url: "/v1/sessions?tenant_id=t_demo",
  })
  assert.equal(denied.statusCode, 401)
  assert.equal(denied.json().error, "unauthorized")

  const token = mintOidcAccessToken(oidc, { sub: "op_demo" })
  const allowed = await server.inject({
    method: "GET",
    url: "/v1/sessions?tenant_id=t_demo",
    headers: { authorization: `Bearer ${token}` },
  })
  assert.equal(allowed.statusCode, 200)
  assert.equal(allowed.json().tenant_id, "t_demo")

  const health = await server.inject({ method: "GET", url: "/health/ready" })
  assert.equal(health.statusCode, 200)

  await server.close()
  await database.close()
})

test("hardened API key auth rejects query-string secrets", async () => {
  const server = buildServer({ apiKey: "secret", hardenedAuth: true })
  const denied = await server.inject({ method: "GET", url: "/v1/sessions?api_key=secret&tenant_id=t_demo" })
  assert.equal(denied.statusCode, 401)
  const allowed = await server.inject({
    method: "GET",
    url: "/v1/sessions?tenant_id=t_demo",
    headers: { "x-actantos-api-key": "secret" },
  })
  assert.equal(allowed.statusCode, 200)
  await server.close()
})
