import { useEffect, useState } from "react"

type Metrics = {
  summary: {
    session_count: number
    decision_count: number
    allow_count: number
    deny_count: number
    approval_required_count: number
    approval_count: number
    active_kill_switch_count: number
  }
}

const StatCard = ({
  label,
  value,
  sub,
  accent,
}: {
  label: string
  value: string | number
  sub?: string
  accent?: string
}) => (
  <div className="card stat-card">
    <div className="stat-card-label">{label}</div>
    <div className="stat-card-value" style={accent ? { color: accent } : {}}>
      {value}
    </div>
    {sub && <div className="stat-card-sub">{sub}</div>}
  </div>
)

const SkeletonCard = () => (
  <div className="card stat-card">
    <div className="skeleton" style={{ height: 12, width: "60%", marginBottom: 12 }} />
    <div className="skeleton" style={{ height: 36, width: "40%" }} />
  </div>
)

export const OverviewPage = () => {
  const [metrics, setMetrics] = useState<Metrics | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)
    fetch("/v1/metrics/usage?tenant_id=t_demo", { signal: controller.signal })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json() as Promise<Metrics>
      })
      .then(setMetrics)
      .catch((e: Error) => {
        if (e.name !== "AbortError") setError(e.message)
      })
      .finally(() => setLoading(false))
    return () => controller.abort()
  }, [])

  const s = metrics?.summary

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Overview</h1>
        <p className="page-subtitle">System-wide activity at a glance</p>
      </div>

      <div className="page-body">
        {error && (
          <div className="error-banner">
            ⚠ Could not load metrics — {error}. The API may be unavailable.
          </div>
        )}

        <div className="stats-grid">
          {loading ? (
            Array.from({ length: 7 }).map((_, i) => <SkeletonCard key={i} />)
          ) : (
            <>
              <StatCard label="Sessions" value={s?.session_count ?? 0} sub="All time" />
              <StatCard
                label="Tool Calls Today"
                value={s?.decision_count ?? 0}
                sub="Policy decisions"
              />
              <StatCard
                label="Allowed"
                value={s?.allow_count ?? 0}
                accent="var(--accent-green)"
                sub="Decisions"
              />
              <StatCard
                label="Denied"
                value={s?.deny_count ?? 0}
                accent="var(--accent-red)"
                sub="Decisions"
              />
              <StatCard
                label="Pending Approval"
                value={s?.approval_count ?? 0}
                accent="var(--accent-amber)"
                sub="Approval queue"
              />
              <StatCard
                label="Approval Required"
                value={s?.approval_required_count ?? 0}
                sub="Escalated calls"
              />
              <StatCard
                label="Active Kill Switches"
                value={s?.active_kill_switch_count ?? 0}
                accent={
                  (s?.active_kill_switch_count ?? 0) > 0
                    ? "var(--accent-red)"
                    : undefined
                }
                sub="Global pauses"
              />
            </>
          )}
        </div>

        {/* Allow/deny ratio bar */}
        {metrics && (() => {
          const allow = s?.allow_count ?? 0
          const deny = s?.deny_count ?? 0
          const total = allow + deny
          const pct = total > 0 ? (allow / total) * 100 : 0
          return (
            <div className="card" style={{ padding: "20px" }}>
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  marginBottom: "10px",
                  fontSize: "13px",
                  fontWeight: 600,
                }}
              >
                <span style={{ color: "var(--accent-green)" }}>
                  Allow {Math.round(pct)}%
                </span>
                <span style={{ color: "var(--text-secondary)" }}>
                  Allow / Deny ratio — {total} total decisions
                </span>
                <span style={{ color: "var(--accent-red)" }}>
                  Deny {Math.round(100 - pct)}%
                </span>
              </div>
              <div
                style={{
                  height: 8,
                  borderRadius: 99,
                  background: "var(--accent-red-dim)",
                  overflow: "hidden",
                }}
              >
                <div
                  style={{
                    height: "100%",
                    width: `${pct}%`,
                    background:
                      "linear-gradient(90deg, var(--accent-green) 0%, #16a34a 100%)",
                    borderRadius: 99,
                    transition: "width 0.6s ease",
                  }}
                />
              </div>
            </div>
          )
        })()}
      </div>
    </>
  )
}
