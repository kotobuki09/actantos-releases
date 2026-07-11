import assert from "node:assert/strict"
import test from "node:test"

import { buildServer } from "./server.ts"

const runtimeAndInMemoryRoutes = [
  { method: "POST", url: "/v1/intercept/tool-call" },
  { method: "POST", url: "/v1/tool-result" },
  { method: "GET", url: "/v1/mcp/sse" },
  { method: "POST", url: "/v1/mcp/message" },
  { method: "GET", url: "/v1/agents" },
  { method: "GET", url: "/v1/approvals/pending" },
  { method: "POST", url: "/v1/approvals/:approval_id/decide" },
  { method: "GET", url: "/v1/decisions" },
  { method: "GET", url: "/v1/evidence/export" },
  { method: "GET", url: "/v1/kill-switches" },
  { method: "POST", url: "/v1/kill-switches" },
  { method: "DELETE", url: "/v1/kill-switches/:id" },
  { method: "GET", url: "/v1/sessions" },
  { method: "GET", url: "/v1/sessions/:session_id/events" },
  { method: "POST", url: "/v1/webhooks/evidence" },
] as const

const postgresOnlyRoutes = [
  { method: "GET", url: "/v1/budgets" },
  { method: "POST", url: "/v1/budgets" },
  { method: "GET", url: "/v1/metrics/usage" },
  { method: "GET", url: "/v1/mcp/tool-versions/pending" },
  { method: "POST", url: "/v1/mcp/tool-versions/:id/approve" },
  { method: "GET", url: "/v1/policy-bundles" },
  { method: "GET", url: "/v1/policy-bundles/:id" },
  { method: "POST", url: "/v1/policy-bundles" },
  { method: "POST", url: "/v1/policy-bundles/:id/activate" },
  { method: "POST", url: "/v1/policy-bundles/:id/test" },
  { method: "GET", url: "/v1/rate-limits" },
  { method: "PUT", url: "/v1/rate-limits" },
  { method: "GET", url: "/v1/risk-rules" },
  { method: "PUT", url: "/v1/risk-rules" },
] as const

const hasRoute = (
  server: ReturnType<typeof buildServer>,
  route: { readonly method: string; readonly url: string },
) => server.hasRoute(route)

test("the frozen /v1 surface remains available in in-memory mode", async () => {
  const server = buildServer()
  await server.ready()

  for (const route of runtimeAndInMemoryRoutes) {
    assert.equal(hasRoute(server, route), true, `${route.method} ${route.url} should be registered`)
  }

  for (const route of postgresOnlyRoutes) {
    assert.equal(hasRoute(server, route), false, `${route.method} ${route.url} should require Postgres`)
  }

  await server.close()
})

test("the frozen Postgres-backed /v1 surface registers when a database is configured", async () => {
  const server = buildServer({
    database: {
      async query() {
        return []
      },
      async close() {
        return undefined
      },
      async transaction(callback) {
        return callback(this)
      },
    },
  })
  await server.ready()

  for (const route of runtimeAndInMemoryRoutes) {
    assert.equal(hasRoute(server, route), true, `${route.method} ${route.url} should stay registered`)
  }

  for (const route of postgresOnlyRoutes) {
    assert.equal(hasRoute(server, route), true, `${route.method} ${route.url} should be registered`)
  }

  await server.close()
})
