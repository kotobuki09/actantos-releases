import test from "node:test"
import assert from "node:assert"
import { buildServer } from "./server.ts"

test("standalone role (default) exposes both data and control planes", async () => {
  const server = buildServer()
  
  // Data plane route
  const interceptRes = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: {
      decision_id: "00000000-0000-0000-0000-000000000000",
      tool_name: "test",
      tool_arguments: "{}",
    }
  })
  // 400 Bad Request means it hit the route and zod validation ran
  assert.strictEqual(interceptRes.statusCode, 400)

  // Control plane route
  const dashboardRes = await server.inject({
    method: "GET",
    url: "/dashboard"
  })
  assert.strictEqual(dashboardRes.statusCode, 200)
})

test("data_plane role disables control plane routes", async () => {
  const server = buildServer({ serviceRole: "data_plane" })
  
  // Data plane route still active
  const interceptRes = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: {
      decision_id: "00000000-0000-0000-0000-000000000000",
      tool_name: "test",
      tool_arguments: "{}",
    }
  })
  assert.strictEqual(interceptRes.statusCode, 400)

  // Control plane route is 404
  const dashboardRes = await server.inject({
    method: "GET",
    url: "/dashboard"
  })
  assert.strictEqual(dashboardRes.statusCode, 404)
})

test("control_plane role disables data plane routes", async () => {
  const server = buildServer({ serviceRole: "control_plane" })
  
  // Data plane route is 404
  const interceptRes = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: {
      decision_id: "00000000-0000-0000-0000-000000000000",
      tool_name: "test",
      tool_arguments: "{}",
    }
  })
  assert.strictEqual(interceptRes.statusCode, 404)

  // Control plane route still active
  const dashboardRes = await server.inject({
    method: "GET",
    url: "/dashboard"
  })
  assert.strictEqual(dashboardRes.statusCode, 200)
})
