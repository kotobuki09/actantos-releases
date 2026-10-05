import { useCallback, useEffect, useState } from "react"
import { useEventsStore } from "../store"

type Approval = {
  approval_id: string
  status: string
  reason: string
  reason_code: string
  tool: { kind: string; name: string }
  agent_id: string
  session_id: string
  expires_at: string
  created_at: string
}

const SkeletonCard = () => (
  <div className="card approval-card" style={{ marginBottom: 12 }}>
    <div style={{ flex: 1 }}>
      <div className="skeleton" style={{ height: 18, width: "40%", marginBottom: 10 }} />
      <div className="skeleton" style={{ height: 12, width: "70%", marginBottom: 6 }} />
      <div className="skeleton" style={{ height: 12, width: "50%" }} />
    </div>
    <div style={{ display: "flex", gap: 8 }}>
      <div className="skeleton" style={{ height: 34, width: 80, borderRadius: 8 }} />
      <div className="skeleton" style={{ height: 34, width: 80, borderRadius: 8 }} />
    </div>
  </div>
)

export const ApprovalsPage = () => {
  const [approvals, setApprovals] = useState<Approval[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [deciding, setDeciding] = useState<Record<string, boolean>>({})
  const recentEvents = useEventsStore((s) => s.recentEvents)
  const setPendingApprovalCount = useEventsStore((s) => s.setPendingApprovalCount)

  const load = useCallback(() => {
    const controller = new AbortController()
    setLoading(true)
    setError(null)
    fetch("/v1/approvals/pending?tenant_id=t_demo", { signal: controller.signal })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json() as Promise<{ approvals: Approval[] }>
      })
      .then((d) => {
        setApprovals(d.approvals)
        setPendingApprovalCount(d.approvals.length)
      })
      .catch((e: Error) => {
        if (e.name !== "AbortError") setError(e.message)
      })
      .finally(() => setLoading(false))
    return controller
  }, [setPendingApprovalCount])

  // Reload whenever an approval event fires over SSE
  const lastApprovalEvent = recentEvents.find(
    (e) => e.type === "approval_created" || e.type === "approval_decided",
  )
  useEffect(() => {
    const ctrl = load()
    return () => ctrl.abort()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [lastApprovalEvent])

  const decide = async (id: string, decision: "approved" | "denied") => {
    setDeciding((d) => ({ ...d, [id]: true }))
    try {
      const r = await fetch(`/v1/approvals/${id}/decide`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ decision, approver_user_id: "operator" }),
      })
      if (!r.ok) {
        const body = (await r.json()) as { message?: string }
        throw new Error(body.message ?? `HTTP ${r.status}`)
      }
      setApprovals((prev) => prev.filter((a) => a.approval_id !== id))
      setPendingApprovalCount(approvals.length - 1)
    } catch (e) {
      alert(`Decision failed: ${(e as Error).message}`)
    } finally {
      setDeciding((d) => ({ ...d, [id]: false }))
    }
  }

  return (
    <>
      <div className="page-header">
        <div style={{ display: "flex", alignItems: "center", gap: "10px" }}>
          <h1 className="page-title">Approvals</h1>
          {approvals.length > 0 && (
            <span
              style={{
                background: "var(--accent-amber-dim)",
                color: "var(--accent-amber)",
                fontSize: 12,
                fontWeight: 700,
                padding: "4px 10px",
                borderRadius: 99,
              }}
            >
              {approvals.length} pending
            </span>
          )}
        </div>
        <p className="page-subtitle">Review and decide on pending tool-call approvals</p>
      </div>

      <div className="page-body">
        {error && <div className="error-banner">⚠ {error}</div>}

        {loading && Array.from({ length: 3 }).map((_, i) => <SkeletonCard key={i} />)}

        {!loading && approvals.length === 0 && !error && (
          <div className="card">
            <div className="empty-state">
              <div className="empty-icon">✅</div>
              <div className="empty-title">All clear</div>
              <div className="empty-desc">
                No pending approvals. Approvals appear when a policy requires
                human sign-off before a tool call can proceed.
              </div>
            </div>
          </div>
        )}

        {!loading &&
          approvals.map((a) => (
            <div key={a.approval_id} className="card approval-card" style={{ marginBottom: 12 }}>
              <div className="approval-meta">
                <div className="approval-tool">
                  {a.tool.name}
                  <span className="badge info" style={{ marginLeft: 8, fontSize: 10 }}>
                    {a.tool.kind}
                  </span>
                </div>
                <div className="approval-details">
                  <span>
                    <span style={{ color: "var(--text-muted)" }}>Agent </span>
                    {a.agent_id}
                  </span>
                  <span>
                    <span style={{ color: "var(--text-muted)" }}>Session </span>
                    {a.session_id}
                  </span>
                  <span>
                    <span style={{ color: "var(--text-muted)" }}>Expires </span>
                    {new Date(a.expires_at).toLocaleTimeString()}
                  </span>
                </div>
                <div className="approval-reason">
                  <span className="badge accent" style={{ marginRight: 6 }}>
                    {a.reason_code}
                  </span>
                  {a.reason}
                </div>
              </div>

              <div className="approval-actions">
                <button
                  className="btn btn-success"
                  disabled={deciding[a.approval_id]}
                  onClick={() => decide(a.approval_id, "approved")}
                >
                  {deciding[a.approval_id] ? "…" : "✓ Approve"}
                </button>
                <button
                  className="btn btn-danger"
                  disabled={deciding[a.approval_id]}
                  onClick={() => decide(a.approval_id, "denied")}
                >
                  {deciding[a.approval_id] ? "…" : "✕ Deny"}
                </button>
              </div>
            </div>
          ))}
      </div>
    </>
  )
}
