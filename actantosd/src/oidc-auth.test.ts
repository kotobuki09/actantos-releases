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
}

test("verifyOidcBearerToken accepts minted tokens and rejects bad/missing ones", () => {
  const token = mintOidcAccessToken(oidc, { sub: "op_demo" })
  const principal = verifyOidcBearerToken(`Bearer ${token}`, oidc)
  assert.deepEqual(principal, {
    sub: "op_demo",
    iss: oidc.issuer,
    aud: oidc.audience,
  })
  assert.equal(verifyOidcBearerToken(undefined, oidc), null)
  assert.equal(verifyOidcBearerToken("Bearer not-a-jwt", oidc), null)
  assert.equal(verifyOidcBearerToken(`Bearer ${token}x`, oidc), null)
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
