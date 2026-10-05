import { useEffect, useState } from "react"

type Budget = {
  id: string
  scope_type: string
  scope_id: string
  metric: string
  limit_value: number
  window_seconds: number
  current_value: number
  window_start: string
}

const UsageBar = ({ current, limit }: { current: number; limit: number }) => {
  const pct = limit > 0 ? Math.min(100, (current / limit) * 100) : 0
  const color =
    pct > 85 ? "var(--accent-red)" : pct > 60 ? "var(--accent-amber)" : "var(--accent-green)"
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
      <div
        style={{
          flex: 1,
          height: 6,
          background: "var(--bg-card)",
          borderRadius: 99,
          overflow: "hidden",
          border: "1px solid var(--border)",
        }}
      >
        <div
          style={{
            height: "100%",
            width: `${pct}%`,
            background: color,
            borderRadius: 99,
            transition: "width 0.4s ease",
          }}
        />
      </div>
      <span style={{ fontSize: 11, color, fontWeight: 600, minWidth: 40, textAlign: "right" }}>
        {current}/{limit}
      </span>
    </div>
  )
}

const SkeletonRow = () => (
  <tr>
    {Array.from({ length: 5 }).map((_, i) => (
      <td key={i}><div className="skeleton" style={{ height: 14, width: "80%" }} /></td>
    ))}
  </tr>
)

export const BudgetsPage = () => {
  const [budgets, setBudgets] = useState<Budget[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  const load = () => {
    const controller = new AbortController()
    setLoading(true)
    setError(null)
    fetch("/v1/budgets?tenant_id=t_demo", { signal: controller.signal })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json() as Promise<{ budgets: Budget[] }>
      })
      .then((d) => setBudgets(d.budgets))
      .catch((e: Error) => {
        if (e.name !== "AbortError") setError(e.message)
      })
      .finally(() => setLoading(false))
    return controller
  }

  useEffect(() => {
    const ctrl = load()
    return () => ctrl.abort()
  }, [])

  const fmtWindow = (secs: number) => {
    if (secs < 60) return `${secs}s`
    if (secs < 3600) return `${Math.round(secs / 60)}m`
    return `${Math.round(secs / 3600)}h`
  }

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Budgets</h1>
        <p className="page-subtitle">Per-scope tool call budgets and current utilization</p>
      </div>

      <div className="page-body">
        {error && <div className="error-banner">⚠ {error}</div>}

        <div className="card" style={{ overflow: "hidden" }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Scope</th>
                <th>Scope ID</th>
                <th>Metric</th>
                <th>Window</th>
                <th>Usage</th>
              </tr>
            </thead>
            <tbody>
              {loading
                ? Array.from({ length: 4 }).map((_, i) => <SkeletonRow key={i} />)
                : budgets.map((b) => (
                    <tr key={b.id}>
                      <td>
                        <span className="badge info">{b.scope_type}</span>
                      </td>
                      <td>
                        <span className="mono" style={{ color: "var(--text-secondary)" }}>
                          {b.scope_id}
                        </span>
                      </td>
                      <td style={{ color: "var(--text-secondary)" }}>{b.metric}</td>
                      <td style={{ color: "var(--text-muted)", fontSize: 12 }}>
                        {fmtWindow(b.window_seconds)}
                      </td>
                      <td style={{ minWidth: 180 }}>
                        <UsageBar current={b.current_value} limit={b.limit_value} />
                      </td>
                    </tr>
                  ))}
            </tbody>
          </table>

          {!loading && budgets.length === 0 && !error && (
            <div className="empty-state">
              <div className="empty-icon">💰</div>
              <div className="empty-title">No budgets configured</div>
              <div className="empty-desc">
                Create budgets via the API to set per-agent or per-session tool call limits.
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  )
}
