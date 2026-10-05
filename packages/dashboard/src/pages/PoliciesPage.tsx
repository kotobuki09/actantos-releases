import { useEffect, useState } from "react"

type PolicyBundle = {
  id: string
  name: string
  version: string
  active: boolean
  created_at: string
  source_text?: string
}

const SkeletonRow = () => (
  <tr>
    {Array.from({ length: 5 }).map((_, i) => (
      <td key={i}><div className="skeleton" style={{ height: 14, width: "80%" }} /></td>
    ))}
  </tr>
)

export const PoliciesPage = () => {
  const [bundles, setBundles] = useState<PolicyBundle[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)
  const [uploading, setUploading] = useState(false)
  const [activating, setActivating] = useState<string | null>(null)
  const [policyText, setPolicyText] = useState("")
  const [version, setVersion] = useState("")
  const [selected, setSelected] = useState<PolicyBundle | null>(null)

  const load = () => {
    const controller = new AbortController()
    setLoading(true)
    fetch("/v1/policy-bundles?tenant_id=t_demo", { signal: controller.signal })
      .then((r) => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json() as Promise<{ bundles: PolicyBundle[] }>
      })
      .then((d) => setBundles(d.bundles))
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

  const upload = async () => {
    if (!policyText.trim()) return alert("Policy text is empty")
    setUploading(true)
    try {
      const r = await fetch("/v1/policy-bundles", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name: `policy-${Date.now()}`,
          version: version || "1.0.0",
          source_text: policyText,
          tenant_id: "t_demo",
        }),
      })
      if (!r.ok) {
        const b = (await r.json()) as { message?: string }
        throw new Error(b.message ?? `HTTP ${r.status}`)
      }
      setPolicyText("")
      setVersion("")
      load()
    } catch (e) {
      alert(`Upload failed: ${(e as Error).message}`)
    } finally {
      setUploading(false)
    }
  }

  const activate = async (id: string) => {
    setActivating(id)
    try {
      const r = await fetch(`/v1/policy-bundles/${id}/activate`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tenant_id: "t_demo" }),
      })
      if (!r.ok) {
        const b = (await r.json()) as { message?: string }
        throw new Error(b.message ?? `HTTP ${r.status}`)
      }
      load()
    } catch (e) {
      alert(`Activation failed: ${(e as Error).message}`)
    } finally {
      setActivating(null)
    }
  }

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Policies</h1>
        <p className="page-subtitle">Cedar policy bundles — upload, review, and activate</p>
      </div>

      <div className="page-body">
        {error && <div className="error-banner">⚠ {error}</div>}

        {/* Upload form */}
        <div className="card" style={{ padding: 20, marginBottom: 20 }}>
          <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 14 }}>
            Upload new policy bundle
          </div>
          <div style={{ display: "flex", gap: 10, marginBottom: 10 }}>
            <input
              placeholder="Version (e.g. 1.0.0)"
              value={version}
              onChange={(e) => setVersion(e.target.value)}
              style={{ maxWidth: 160 }}
            />
          </div>
          <textarea
            rows={8}
            placeholder="Paste Cedar policy here…"
            value={policyText}
            onChange={(e) => setPolicyText(e.target.value)}
            style={{ fontFamily: "monospace", fontSize: 12, marginBottom: 12 }}
          />
          <button className="btn btn-primary" onClick={upload} disabled={uploading}>
            {uploading ? "Uploading…" : "⬆ Upload Bundle"}
          </button>
        </div>

        {/* Bundle list */}
        <div className="card" style={{ overflow: "hidden" }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Version</th>
                <th>Status</th>
                <th>Created</th>
                <th>Action</th>
              </tr>
            </thead>
            <tbody>
              {loading
                ? Array.from({ length: 3 }).map((_, i) => <SkeletonRow key={i} />)
                : bundles.map((b) => (
                    <tr
                      key={b.id}
                      style={{ cursor: "pointer" }}
                      onClick={() => setSelected(selected?.id === b.id ? null : b)}
                    >
                      <td style={{ fontWeight: 600 }}>{b.name}</td>
                      <td>
                        <span className="mono" style={{ color: "var(--text-secondary)" }}>
                          {b.version}
                        </span>
                      </td>
                      <td>
                        {b.active ? (
                          <span className="badge allow">Active</span>
                        ) : (
                          <span className="badge" style={{ background: "var(--bg-card)", color: "var(--text-secondary)" }}>
                            Inactive
                          </span>
                        )}
                      </td>
                      <td style={{ color: "var(--text-muted)", fontSize: "12px" }}>
                        {new Date(b.created_at).toLocaleDateString()}
                      </td>
                      <td>
                        {!b.active && (
                          <button
                            className="btn btn-ghost"
                            style={{ fontSize: 11, padding: "5px 10px" }}
                            disabled={activating === b.id}
                            onClick={(e) => {
                              e.stopPropagation()
                              activate(b.id)
                            }}
                          >
                            {activating === b.id ? "…" : "Activate"}
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
            </tbody>
          </table>

          {!loading && bundles.length === 0 && !error && (
            <div className="empty-state">
              <div className="empty-icon">📋</div>
              <div className="empty-title">No policy bundles</div>
              <div className="empty-desc">
                Upload your first Cedar policy bundle to start enforcing access controls.
              </div>
            </div>
          )}
        </div>

        {/* Diff viewer */}
        {selected && (
          <div className="card" style={{ padding: 20, marginTop: 16 }}>
            <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 12 }}>
              {selected.name} — source
            </div>
            <pre
              style={{
                background: "var(--bg-base)",
                border: "1px solid var(--border)",
                borderRadius: 8,
                padding: 16,
                fontSize: 12,
                lineHeight: 1.6,
                overflowX: "auto",
                color: "var(--text-secondary)",
                maxHeight: 320,
                overflowY: "auto",
              }}
            >
              {selected.source_text ?? "(source not available)"}
            </pre>
          </div>
        )}
      </div>
    </>
  )
}
