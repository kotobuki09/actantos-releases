import { test } from "node:test"
import assert from "node:assert/strict"
import { publishSseEvent, registerSseRoutes } from "./sse-routes.ts"
import Fastify from "fastify"

// Integration test – verifies the endpoint exists, returns the SSE headers, and
// that the pub/sub helper is callable without throwing.
//
// This must use a real listening socket rather than server.inject(): the route
// handler awaits a promise that only settles on socket close and holds a 30s
// heartbeat interval. Under inject() neither ever fires, so the timer keeps the
// event loop alive forever and the test file can never exit.

test("SSE routes: GET /v1/events/stream returns 200 with correct headers", async () => {
  const server = Fastify({ logger: false })
  registerSseRoutes(server)
  await server.listen({ port: 0, host: "127.0.0.1" })

  const { port } = server.server.address() as { port: number }
  const controller = new AbortController()

  try {
    const response = await fetch(`http://127.0.0.1:${port}/v1/events/stream`, {
      signal: controller.signal,
    })

    assert.equal(response.status, 200)
    assert.equal(response.headers.get("content-type"), "text/event-stream")

    // The route must emit an initial heartbeat before any published event.
    const reader = response.body?.getReader()
    assert.ok(reader, "SSE response must expose a readable body")

    const first = await reader.read()
    assert.match(new TextDecoder().decode(first.value ?? new Uint8Array()), /heartbeat/)

    // Aborting closes the socket, which is what clears the handler's timer.
    controller.abort()
  } finally {
    server.server.closeAllConnections()
    await server.close()
  }
})

test("publishSseEvent: does not throw when there are no subscribers", () => {
  assert.doesNotThrow(() => {
    publishSseEvent({
      type: "tool_call_intercepted",
      data: { tool_name: "bash", verdict: "allow" },
    })
  })
})