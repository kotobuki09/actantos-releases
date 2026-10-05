import type { FastifyInstance, FastifyReply } from "fastify"

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export type SseEventType =
  | "tool_call_intercepted"
  | "approval_created"
  | "approval_decided"
  | "kill_switch_toggled"
  | "heartbeat"

export type SseEvent = {
  readonly type: SseEventType
  readonly data: Record<string, unknown>
}

// ---------------------------------------------------------------------------
// In-memory pub/sub
// ---------------------------------------------------------------------------

type Subscriber = (event: SseEvent) => void

const subscribers = new Set<Subscriber>()

/**
 * Push an SSE event to all connected dashboard clients.
 * Call this from any route handler that wants to broadcast real-time updates.
 */
export const publishSseEvent = (event: SseEvent): void => {
  for (const sub of subscribers) {
    try {
      sub(event)
    } catch {
      // subscriber may have already disconnected; ignore
    }
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const formatSseMessage = (event: SseEvent): string => {
  const payload = JSON.stringify(event.data)
  return `event: ${event.type}\ndata: ${payload}\n\n`
}

const writeEvent = (reply: FastifyReply, event: SseEvent): boolean => {
  try {
    reply.raw.write(formatSseMessage(event))
    return true
  } catch {
    return false
  }
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

export const registerSseRoutes = (server: FastifyInstance): void => {
  server.get("/v1/events/stream", async (request, reply) => {
    // Disable Fastify's buffered response; we take control of the raw socket.
    reply.raw.writeHead(200, {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache",
      Connection: "keep-alive",
      "X-Accel-Buffering": "no",
    })

    // Send an initial connection event so the client knows the stream is live.
    reply.raw.write(
      formatSseMessage({ type: "heartbeat", data: { ts: new Date().toISOString() } }),
    )

    // Subscribe to future events.
    const subscriber: Subscriber = (event) => {
      writeEvent(reply, event)
    }
    subscribers.add(subscriber)

    // Heartbeat every 30 s to keep the connection alive through proxies.
    const heartbeatTimer = setInterval(() => {
      const ok = writeEvent(reply, {
        type: "heartbeat",
        data: { ts: new Date().toISOString() },
      })
      if (!ok) {
        // Socket is gone – clean up.
        clearInterval(heartbeatTimer)
        subscribers.delete(subscriber)
      }
    }, 30_000)

    // Clean up when the client disconnects.
    request.raw.on("close", () => {
      clearInterval(heartbeatTimer)
      subscribers.delete(subscriber)
    })

    // Return a never-resolving promise so Fastify does not close the socket.
    await new Promise<void>((resolve) => {
      request.raw.on("close", resolve)
    })
  })
}
