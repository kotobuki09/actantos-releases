import { useEffect } from "react"
import { type SseEvent, useEventsStore } from "./store"

/**
 * Opens an EventSource to /v1/events/stream and feeds events into the
 * Zustand store.  Reconnects automatically on error.
 */
export const useSse = () => {
  const setConnected = useEventsStore((s) => s.setConnected)
  const pushEvent = useEventsStore((s) => s.pushEvent)

  useEffect(() => {
    let es: EventSource | null = null
    let retryTimeout: ReturnType<typeof setTimeout> | null = null
    let alive = true

    const connect = () => {
      if (!alive) return
      es = new EventSource("/v1/events/stream")

      es.onopen = () => setConnected(true)

      es.onerror = () => {
        setConnected(false)
        es?.close()
        if (alive) {
          retryTimeout = setTimeout(connect, 4000)
        }
      }

      const eventTypes: SseEvent["type"][] = [
        "tool_call_intercepted",
        "approval_created",
        "approval_decided",
        "kill_switch_toggled",
        "heartbeat",
      ]

      for (const type of eventTypes) {
        es.addEventListener(type, (e: MessageEvent) => {
          try {
            const data = JSON.parse(e.data)
            pushEvent({ type, data } as SseEvent)
          } catch {
            // ignore malformed events
          }
        })
      }
    }

    connect()

    return () => {
      alive = false
      if (retryTimeout !== null) clearTimeout(retryTimeout)
      es?.close()
      setConnected(false)
    }
  }, [setConnected, pushEvent])
}
