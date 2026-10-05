import { useEffect, useState } from "react"

type Agent = {
  id: string
  external_id: string
  name: string
  runtime_type: string
  risk_tier: string
  status: string
  environment: string
  created_at: string
}

const riskColor = (tier: string) => {
  if (tier === "low") return "var(--accent-green)"
  if (tier === "high") return "var(--accent-red)"
  return "var(--accent-amber)"
}

const SkeletonRow = () => (
  <tr>
    {Array.from({ length: 5 }).map((_, i) => (
      <td key={i}><div className="skeleton" style={{ height: 14, width: "80%" }} /></td>
    ))}
  </tr>
)

export const AgentsPage = () => {
  const [agents, setAgents] = useState<Agent[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    fetch("/v1/agents?tenant_id=t_demo", { signal: controller.signal })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json() as Promise<{ agents: Agent[] }>
      })
      .then((d) => setAgents(d.agents))
      .catch((e: Error) => {
        if (e.name !== "AbortError") setError(e.message)
      })
      .finally(() => setLoading(false))
    return () => controller.abort()
  }, [])

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Agents</h1>
        <p className="page-subtitle">Registered agent runtimes and their risk classification</p>
      </div>

      <div className="page-body">
        {error && <div className="error-banner">⚠ {error}</div>}

        <div className="card" style={{ overflow: "hidden" }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Runtime</th>
                <th>Risk Tier</th>
                <th>Environment</th>
                <th>Status</th>
              </tr>
            </thead>
            <tbody>
              {loading
                ? Array.from({ length: 5 }).map((_, i) => <SkeletonRow key={i} />)
                : agents.map((a) => (
                    <tr key={a.id}>
                      <td>
                        <div style={{ fontWeight: 600 }}>{a.name}</div>
                        <div className="mono" style={{ color: "var(--text-muted)", fontSize: 11, marginTop: 2 }}>
                          {a.external_id}
                        </div>
                      </td>
                      <td>
                        <span className="badge info">{a.runtime_type}</span>
                      </td>
                      <td>
                        <span
                          className="badge"
                          style={{
                            background: `color-mix(in srgb, ${riskColor(a.risk_tier)} 15%, transparent)`,
                            color: riskColor(a.risk_tier),
                          }}
                        >
                          {a.risk_tier}
                        </span>
                      </td>
                      <td style={{ color: "var(--text-secondary)" }}>{a.environment}</td>
                      <td>
                        <span
                          className="badge"
                          style={{
                            background:
                              a.status === "active"
                                ? "var(--accent-green-dim)"
                                : "var(--bg-card)",
                            color:
                              a.status === "active"
                                ? "var(--accent-green)"
                                : "var(--text-muted)",
                          }}
                        >
                          {a.status}
                        </span>
                      </td>
                    </tr>
                  ))}
            </tbody>
          </table>

          {!loading && agents.length === 0 && !error && (
            <div className="empty-state">
              <div className="empty-icon">🤖</div>
              <div className="empty-title">No agents registered</div>
              <div className="empty-desc">
                Register agents via the ActantOS SDK to see them here.
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  )
}
