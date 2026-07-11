import assert from "node:assert/strict"
import { createHash } from "node:crypto"
import test from "node:test"
import { buildServer } from "./server.ts"

test("service principal is tenant-bound and role-limited through live Fastify requests", async () => {
  const service = { id: "runner", secretHash: createHash("sha256").update("secret").digest("hex"),
    tenantId: "t_one", role: "viewer" as const, scopes: ["read"] }
  const server = buildServer({ servicePrincipals: { async resolve(id) { return id === service.id ? service : undefined } } })
  const allowed = await server.inject({ method: "GET", url: "/v1/sessions?tenant_id=t_one",
    headers: { authorization: "Service runner:secret" } })
  assert.equal(allowed.statusCode, 200)
  const crossTenant = await server.inject({ method: "GET", url: "/v1/sessions?tenant_id=t_two",
    headers: { authorization: "Service runner:secret" } })
  assert.equal(crossTenant.statusCode, 403)
  const mutation = await server.inject({ method: "POST", url: "/v1/webhooks/events",
    headers: { authorization: "Service runner:secret" }, payload: {} })
  assert.equal(mutation.statusCode, 403)
  await server.close()
})
