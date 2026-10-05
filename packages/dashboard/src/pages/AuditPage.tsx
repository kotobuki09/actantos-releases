import { useEffect, useState } from "react"

type AuditEvent = {
  id: string
  event_type: string
  entity_type: string
  entity_id: string
  payload: Record<string, unknown>
  hash: string
  previous_hash: string | null
  hash_valid?: boolean
  created_at: string
}

const SkeletonRow = () => (
  <tr>
    {Array.from({ length: 6 }).map((_, i) => (
      <td key={i}><div className="skeleton" style={{ height: 14, width: "80%" }} /></td>
    ))}
  </tr>
)

export const AuditPage = () => {
  const [events, setEvents] = useState<AuditEvent[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    setLoading(true)

    // Try to get audit events — fall back gracefully if endpoint differs
    fetch("/v1/audit-events?tenant_id=t_demo", { signal: controller.signal })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json() as Promise<{ events?: AuditEvent[]; audit_events?: AuditEvent[] }>
      })
      .then((d) => {
        const list = d.events ?? d.audit_events ?? []
        setEvents(list)
      })
      .catch((e: Error) => {
        if (e.name !== "AbortError") setError(e.message)
      })
      .finally(() => setLoading(false))

    return () => controller.abort()
  }, [])

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Audit Log</h1>
        <p className="page-subtitle">Tamper-evident chain of custody for all policy decisions</p>
      </div>

      <div className="page-body">
        {error && (
          <div className="error-banner" style={{ marginBottom: 16 }}>
            ⚠ {error} — audit endpoint may not be available in this deployment.
          </div>
        )}

        <div className="card" style={{ overflow: "hidden" }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Chain</th>
                <th>Event Type</th>
                <th>Entity</th>
                <th>Entity ID</th>
                <th>Hash (short)</th>
                <th>Time</th>
              </tr>
            </thead>
            <tbody>
              {loading
                ? Array.from({ length: 8 }).map((_, i) => <SkeletonRow key={i} />)
                : events.map((ev) => (
                    <>
                      <tr
                        key={ev.id}
                        style={{ cursor: "pointer" }}
                        onClick={() =>
                          setExpanded(expanded === ev.id ? null : ev.id)
                        }
                      >
                        <td>
                          {ev.hash_valid === false ? (
                            <span className="hash-bad" title="Chain integrity failure">✗</span>
                          ) : ev.hash_valid === true ? (
                            <span className="hash-ok" title="Chain intact">✓</span>
                          ) : (
                            <span title="Not verified" style={{ color: "var(--text-muted)", fontSize: 14 }}>—</span>
                          )}
                        </td>
                        <td>
                          <span className="badge accent">{ev.event_type}</span>
                        </td>
                        <td style={{ color: "var(--text-secondary)" }}>{ev.entity_type}</td>
                        <td>
                          <span className="mono" style={{ color: "var(--text-muted)", fontSize: 11 }}>
                            {ev.entity_id.slice(0, 16)}…
                          </span>
                        </td>
                        <td>
                          <span className="mono" style={{ color: "var(--text-muted)", fontSize: 11 }}>
                            {ev.hash?.slice(0, 12) ?? "—"}…
                          </span>
                        </td>
                        <td style={{ color: "var(--text-muted)", fontSize: 11 }}>
                          {new Date(ev.created_at).toLocaleString()}
                        </td>
                      </tr>
                      {expanded === ev.id && (
                        <tr key={`${ev.id}-exp`}>
                          <td colSpan={6} style={{ background: "var(--bg-base)", padding: "12px 16px" }}>
                            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 12 }}>
                              <div>
                                <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>
                                  CURRENT HASH
                                </div>
                                <span className="mono" style={{ fontSize: 11, color: "var(--text-secondary)", wordBreak: "break-all" }}>
                                  {ev.hash ?? "—"}
                                </span>
                              </div>
                              <div>
                                <div style={{ fontSize: 11, color: "var(--text-muted)", marginBottom: 4 }}>
                                  PREVIOUS HASH
                                </div>
                                <span className="mono" style={{ fontSize: 11, color: "var(--text-secondary)", wordBreak: "break-all" }}>
                                  {ev.previous_hash ?? "genesis"}
                                </span>
                              </div>
                            </div>
                            <details style={{ marginTop: 12 }}>
                              <summary style={{ cursor: "pointer", fontSize: 12, color: "var(--text-muted)" }}>
                                Payload
                              </summary>
                              <pre
                                style={{
                                  marginTop: 8,
                                  background: "var(--bg-surface)",
                                  border: "1px solid var(--border)",
                                  borderRadius: 6,
                                  padding: 10,
                                  fontSize: 11,
                                  color: "var(--text-secondary)",
                                  overflowX: "auto",
                                }}
                              >
                                {JSON.stringify(ev.payload, null, 2)}
                              </pre>
                            </details>
                          </td>
                        </tr>
                      )}
                    </>
                  ))}
            </tbody>
          </table>

          {!loading && events.length === 0 && !error && (
            <div className="empty-state">
              <div className="empty-icon">📜</div>
              <div className="empty-title">No audit events</div>
              <div className="empty-desc">
                Audit events are recorded for every significant action across the system.
              </div>
            </div>
          )}
        </div>
      </div>
    </>
  )
}
