import { useEffect, useState } from "react"

type Session = {
  id: string
  external_id: string
  status: string
  purpose: string | null
  started_at: string
  ended_at: string | null
  agent: { name: string; external_id: string }
}

const statusColor = (s: string) => {
  if (s === "active") return "var(--accent-green)"
  if (s === "ended") return "var(--text-muted)"
  return "var(--accent-amber)"
}

const SkeletonRow = () => (
  <tr>
    {Array.from({ length: 5 }).map((_, i) => (
      <td key={i}>
        <div className="skeleton" style={{ height: 14, width: "80%" }} />
      </td>
    ))}
  </tr>
)

export const SessionsPage = () => {
  const [sessions, setSessions] = useState<Session[]>([])
  const [filter, setFilter] = useState("t_demo")
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)

  const load = () => {
    const controller = new AbortController()
    setLoading(true)
    setError(null)
    fetch(`/v1/sessions?tenant_id=${encodeURIComponent(filter)}`, {
      signal: controller.signal,
    })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json() as Promise<{ sessions: Session[] }>
      })
      .then((d) => setSessions(d.sessions))
      .catch((e: Error) => {
        if (e.name !== "AbortError") setError(e.message)
      })
      .finally(() => setLoading(false))
    return controller
  }

  useEffect(() => {
    const ctrl = load()
    return () => ctrl.abort()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter])

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Sessions</h1>
        <p className="page-subtitle">Active and historical agent sessions</p>
      </div>

      <div className="page-body">
        {/* Filter row */}
        <div style={{ display: "flex", gap: "10px", marginBottom: "20px" }}>
          <input
            style={{ maxWidth: 240 }}
            placeholder="Tenant ID…"
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
          />
        </div>

        {error && <div className="error-banner">⚠ {error}</div>}

        <div className="card" style={{ overflow: "hidden" }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Session ID</th>
                <th>Agent</th>
                <th>Status</th>
                <th>Purpose</th>
                <th>Started</th>
              </tr>
            </thead>
            <tbody>
              {loading
                ? Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} />)
                : sessions.map((s) => (
                    <tr
                      key={s.id}
                      style={{ cursor: "pointer" }}
                      onClick={() =>
                        setExpanded(expanded === s.external_id ? null : s.external_id)
                      }
                    >
                      <td>
                        <span className="mono" style={{ color: "var(--accent)" }}>
                          {s.external_id}
                        </span>
                      </td>
                      <td>{s.agent.name}</td>
                      <td>
                        <span
                          className="badge"
                          style={{
                            background: `color-mix(in srgb, ${statusColor(s.status)} 15%, transparent)`,
                            color: statusColor(s.status),
                          }}
                        >
                          {s.status}
                        </span>
                      </td>
                      <td style={{ color: "var(--text-secondary)" }}>
                        {s.purpose ?? "—"}
                      </td>
                      <td style={{ color: "var(--text-muted)", fontSize: "12px" }}>
                        {new Date(s.started_at).toLocaleString()}
                      </td>
                    </tr>
                  ))}
            </tbody>
          </table>

          {!loading && sessions.length === 0 && !error && (
            <div className="empty-state">
              <div className="empty-icon">📭</div>
              <div className="empty-title">No sessions found</div>
              <div className="empty-desc">
                Sessions appear here once agents start running through ActantOS.
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  )
}
