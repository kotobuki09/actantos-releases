import { useEffect, useState } from "react"
import { useEventsStore } from "../store"

type KillSwitch = {
  id: string
  scope_type: string
  scope_id: string
  reason: string
  enabled: boolean
  created_at: string
}

type ConfirmModal = {
  action: "enable" | "disable"
  id?: string
}

export const KillSwitchPage = () => {
  const [switches, setSwitches] = useState<KillSwitch[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [modal, setModal] = useState<ConfirmModal | null>(null)
  const [acting, setActing] = useState(false)
  const [reason, setReason] = useState("")
  const recentEvents = useEventsStore((s) => s.recentEvents)

  const hasActive = switches.some((s) => s.enabled)

  const load = () => {
    const ctrl = new AbortController()
    setLoading(true)
    fetch("/v1/kill-switches?tenant_id=t_demo", { signal: ctrl.signal })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json() as Promise<{ kill_switches: KillSwitch[] }>
      })
      .then((d) => setSwitches(d.kill_switches))
      .catch((e: Error) => { if (e.name !== "AbortError") setError(e.message) })
      .finally(() => setLoading(false))
    return ctrl
  }

  useEffect(() => {
    const ctrl = load()
    return () => ctrl.abort()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [recentEvents.find((e) => e.type === "kill_switch_toggled")])

  const enableKillSwitch = async () => {
    if (!reason.trim()) return alert("Please provide a reason.")
    setActing(true)
    try {
      const r = await fetch("/v1/kill-switches", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          scope_type: "tenant",
          scope_id: "t_demo",
          reason: reason.trim(),
          tenant_id: "t_demo",
        }),
      })
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      setReason("")
      setModal(null)
      load()
    } catch (e) {
      alert(`Failed: ${(e as Error).message}`)
    } finally {
      setActing(false)
    }
  }

  const disableKillSwitch = async (id: string) => {
    setActing(true)
    try {
      const r = await fetch(`/v1/kill-switches/${id}`, { method: "DELETE" })
      if (!r.ok) throw new Error(`HTTP ${r.status}`)
      setModal(null)
      load()
    } catch (e) {
      alert(`Failed: ${(e as Error).message}`)
    } finally {
      setActing(false)
    }
  }

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Kill Switch</h1>
        <p className="page-subtitle">Globally pause all tool call execution for this tenant</p>
      </div>

      <div className="page-body">
        {error && <div className="error-banner">⚠ {error}</div>}

        <div className="kill-switch-center">
          {/* Big toggle area */}
          <div style={{ position: "relative", width: 220, height: 220, display: "flex", alignItems: "center", justifyContent: "center" }}>
            {hasActive && (
              <>
                <div className="kill-ring" />
                <div className="kill-ring" />
                <div className="kill-ring" />
              </>
            )}

            <div
              onClick={() => {
                if (hasActive) {
                  setModal({ action: "disable", id: switches.find((s) => s.enabled)?.id })
                } else {
                  setModal({ action: "enable" })
                }
              }}
              style={{
                width: 160,
                height: 160,
                borderRadius: "50%",
                display: "flex",
                flexDirection: "column",
                alignItems: "center",
                justifyContent: "center",
                cursor: "pointer",
                gap: 8,
                border: `3px solid ${hasActive ? "var(--accent-red)" : "var(--border)"}`,
                background: hasActive
                  ? "var(--accent-red-dim)"
                  : "var(--bg-card)",
                boxShadow: hasActive
                  ? "0 0 48px rgba(239,68,68,0.3)"
                  : "none",
                transition: "all 0.4s ease",
                position: "relative",
                zIndex: 1,
              }}
            >
              <span style={{ fontSize: 36 }}>{hasActive ? "🔴" : "⭕"}</span>
              <span
                style={{
                  fontSize: 13,
                  fontWeight: 700,
                  color: hasActive ? "var(--accent-red)" : "var(--text-secondary)",
                  textTransform: "uppercase",
                  letterSpacing: 1,
                }}
              >
                {loading ? "Loading…" : hasActive ? "ACTIVE" : "INACTIVE"}
              </span>
            </div>
          </div>

          <div style={{ textAlign: "center" }}>
            <div
              style={{
                fontSize: 20,
                fontWeight: 700,
                color: hasActive ? "var(--accent-red)" : "var(--text-secondary)",
                marginBottom: 8,
              }}
            >
              {hasActive ? "Kill switch is ACTIVE" : "Kill switch is inactive"}
            </div>
            <div style={{ fontSize: 13, color: "var(--text-muted)", maxWidth: 360 }}>
              {hasActive
                ? "All tool calls for this tenant are being blocked. Click the button above to deactivate."
                : "Click the button above to activate the global kill switch and block all tool calls."}
            </div>
          </div>

          {/* Active switches list */}
          {switches.length > 0 && (
            <div className="card" style={{ width: "100%", maxWidth: 560, overflow: "hidden" }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>Scope</th>
                    <th>Reason</th>
                    <th>Created</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {switches.map((ks) => (
                    <tr key={ks.id}>
                      <td>
                        <span className="badge deny">{ks.scope_type}: {ks.scope_id}</span>
                      </td>
                      <td style={{ color: "var(--text-secondary)" }}>{ks.reason}</td>
                      <td style={{ color: "var(--text-muted)", fontSize: 11 }}>
                        {new Date(ks.created_at).toLocaleString()}
                      </td>
                      <td>
                        <button
                          className="btn btn-ghost"
                          style={{ fontSize: 11, padding: "4px 10px" }}
                          onClick={() => setModal({ action: "disable", id: ks.id })}
                        >
                          Deactivate
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {/* Confirmation modal */}
        {modal && (
          <div className="modal-overlay" onClick={() => setModal(null)}>
            <div className="modal" onClick={(e) => e.stopPropagation()}>
              <div className="modal-title" style={{ color: modal.action === "enable" ? "var(--accent-red)" : "var(--text-primary)" }}>
                {modal.action === "enable" ? "🔴 Activate Kill Switch?" : "✅ Deactivate Kill Switch?"}
              </div>
              <p className="modal-desc">
                {modal.action === "enable"
                  ? "This will immediately block ALL tool calls for this tenant. Agents will receive a deny decision until the switch is deactivated."
                  : "This will re-enable tool calls for this tenant. Confirm you want to proceed."}
              </p>

              {modal.action === "enable" && (
                <input
                  placeholder="Reason for activation…"
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  style={{ marginBottom: 16 }}
                />
              )}

              <div className="modal-actions">
                <button className="btn btn-ghost" onClick={() => setModal(null)}>
                  Cancel
                </button>
                <button
                  className={`btn ${modal.action === "enable" ? "btn-danger" : "btn-success"}`}
                  disabled={acting}
                  onClick={() => {
                    if (modal.action === "enable") enableKillSwitch()
                    else if (modal.id) disableKillSwitch(modal.id)
                  }}
                >
                  {acting ? "…" : modal.action === "enable" ? "Confirm Activate" : "Confirm Deactivate"}
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    </>
  )
}
