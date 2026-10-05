import { create } from "zustand"

// ─── SSE event types ───────────────────────────────────────────────────────

export type SseEvent =
  | { type: "tool_call_intercepted"; data: Record<string, unknown> }
  | { type: "approval_created"; data: Record<string, unknown> }
  | { type: "approval_decided"; data: Record<string, unknown> }
  | { type: "kill_switch_toggled"; data: Record<string, unknown> }
  | { type: "heartbeat"; data: { ts: string } }

// ─── Store ─────────────────────────────────────────────────────────────────

type EventsStore = {
  connected: boolean
  lastHeartbeat: string | null
  recentEvents: SseEvent[]
  pendingApprovalCount: number
  setConnected: (v: boolean) => void
  pushEvent: (e: SseEvent) => void
  setPendingApprovalCount: (n: number) => void
}

export const useEventsStore = create<EventsStore>((set) => ({
  connected: false,
  lastHeartbeat: null,
  recentEvents: [],
  pendingApprovalCount: 0,
  setConnected: (connected) => set({ connected }),
  pushEvent: (event) =>
    set((s) => {
      const recentEvents = [event, ...s.recentEvents].slice(0, 200)
      const pendingApprovalCount =
        event.type === "approval_created"
          ? s.pendingApprovalCount + 1
          : event.type === "approval_decided"
          ? Math.max(0, s.pendingApprovalCount - 1)
          : s.pendingApprovalCount
      const lastHeartbeat =
        event.type === "heartbeat"
          ? (event.data as { ts: string }).ts
          : s.lastHeartbeat
      return { recentEvents, pendingApprovalCount, lastHeartbeat }
    }),
  setPendingApprovalCount: (pendingApprovalCount) =>
    set({ pendingApprovalCount }),
}))
