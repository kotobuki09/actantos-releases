import { useEffect, useRef, useState } from "react"
import { useEventsStore } from "../store"

type Decision = {
  decision_id: string
  request_id: string
  final_decision: "allow" | "deny" | "approval_required"
  reason_code: string
  tool: { kind: string; name: string; operation: string }
  agent_id: string
  session_id: string
  created_at: string
}

const VerdictBadge = ({ v }: { v: string }) => {
  if (v === "allow") return <span className="badge allow">ALLOW</span>
  if (v === "deny") return <span className="badge deny">DENY</span>
  return <span className="badge pending">PENDING</span>
}

const SkeletonRow = () => (
  <tr>
    {Array.from({ length: 6 }).map((_, i) => (
      <td key={i}><div className="skeleton" style={{ height: 14, width: "80%" }} /></td>
    ))}
  </tr>
)

export const ToolCallsPage = () => {
  const [decisions, setDecisions] = useState<Decision[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const recentEvents = useEventsStore((s) => s.recentEvents)

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    fetch("/v1/decisions?tenant_id=t_demo", { signal: controller.signal })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json() as Promise<{ decisions: Decision[] }>
      })
      .then((d) => setDecisions(d.decisions))
      .catch((e: Error) => {
        if (e.name !== "AbortError") setError(e.message)
      })
      .finally(() => setLoading(false))
    return () => controller.abort()
  }, [])

  // Prepend live SSE events
  const liveCount = recentEvents.filter(
    (e) => e.type === "tool_call_intercepted",
  ).length

  return (
    <>
      <div className="page-header">
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <h1 className="page-title">Tool Calls</h1>
          <div style={{ display: "flex", alignItems: "center", gap: "6px" }}>
            <div className="live-dot" />
            <span style={{ fontSize: "12px", color: "var(--accent-green)", fontWeight: 600 }}>
              LIVE
            </span>
          </div>
        </div>
        <p className="page-subtitle">
          Real-time policy decision log
          {liveCount > 0 && (
            <span
              style={{
                marginLeft: 10,
                background: "var(--accent-dim)",
                color: "var(--accent)",
                padding: "2px 8px",
                borderRadius: 99,
                fontSize: 11,
                fontWeight: 700,
              }}
            >
              +{liveCount} live
            </span>
          )}
        </p>
      </div>

      <div className="page-body">
        {error && <div className="error-banner">⚠ {error}</div>}

        <div className="card" style={{ overflow: "hidden" }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Verdict</th>
                <th>Tool</th>
                <th>Operation</th>
                <th>Agent</th>
                <th>Reason</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {loading
                ? Array.from({ length: 8 }).map((_, i) => <SkeletonRow key={i} />)
                : decisions.map((d) => (
                    <tr key={d.decision_id}>
                      <td><VerdictBadge v={d.final_decision} /></td>
                      <td>
                        <span style={{ fontWeight: 600 }}>{d.tool.name}</span>
                        <span className="badge info" style={{ marginLeft: 6 }}>
                          {d.tool.kind}
                        </span>
                      </td>
                      <td>
                        <span className="mono" style={{ color: "var(--text-secondary)" }}>
                          {d.tool.operation}
                        </span>
                      </td>
                      <td style={{ color: "var(--text-secondary)" }}>{d.agent_id}</td>
                      <td>
                        <span className="badge accent">{d.reason_code}</span>
                      </td>
                      <td style={{ color: "var(--text-muted)", fontSize: "11px" }}>
                        {new Date(d.created_at).toLocaleTimeString()}
                      </td>
                    </tr>
                  ))}
            </tbody>
          </table>

          {!loading && decisions.length === 0 && !error && (
            <div className="empty-state">
              <div className="empty-icon">🔍</div>
              <div className="empty-title">No decisions yet</div>
              <div className="empty-desc">
                Tool call decisions will appear here as agents run through the
                ActantOS intercept layer.
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  )
}
