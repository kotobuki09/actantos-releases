import { useState } from "react"

type SimResult = {
  decision?: string
  verdict?: string
  reason?: string
  reason_code?: string
}

export const PolicySimPage = () => {
  const [toolCallJson, setToolCallJson] = useState(
    JSON.stringify(
      {
        tool_kind: "file",
        tool_name: "read_file",
        operation: "read",
        parameters: { path: "/etc/passwd" },
      },
      null,
      2,
    ),
  )
  const [result, setResult] = useState<SimResult | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const simulate = async () => {
    let parsed: unknown
    try {
      parsed = JSON.parse(toolCallJson)
    } catch {
      setError("Invalid JSON")
      return
    }
    setLoading(true)
    setError(null)
    setResult(null)
    try {
      const r = await fetch("/v1/policy-simulate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ tool_call: parsed, tenant_id: "t_demo" }),
      })
      const body = (await r.json()) as SimResult
      if (!r.ok) throw new Error(String((body as { message?: string }).message ?? `HTTP ${r.status}`))
      setResult(body)
    } catch (e) {
      setError((e as Error).message)
    } finally {
      setLoading(false)
    }
  }

  const verdict = result?.decision ?? result?.verdict
  const verdictColor =
    verdict === "allow"
      ? "var(--accent-green)"
      : verdict === "deny"
      ? "var(--accent-red)"
      : "var(--accent-amber)"

  return (
    <>
      <div className="page-header">
        <h1 className="page-title">Policy Simulator</h1>
        <p className="page-subtitle">Dry-run a tool call against the active policy to preview the verdict</p>
      </div>

      <div className="page-body">
        <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
          <div className="card" style={{ padding: 20 }}>
            <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 14 }}>
              Tool call JSON
            </div>
            <textarea
              rows={14}
              style={{ fontFamily: "monospace", fontSize: 12, marginBottom: 14 }}
              value={toolCallJson}
              onChange={(e) => setToolCallJson(e.target.value)}
            />
            <button className="btn btn-primary" onClick={simulate} disabled={loading}>
              {loading ? "Simulating…" : "▶ Run Simulation"}
            </button>
          </div>

          <div className="card" style={{ padding: 20 }}>
            <div style={{ fontWeight: 700, fontSize: 14, marginBottom: 14 }}>
              Simulated verdict
            </div>

            {!result && !error && !loading && (
              <div className="empty-state" style={{ padding: "40px 0" }}>
                <div className="empty-icon">🧪</div>
                <div className="empty-desc">
                  Enter a tool call JSON and click Run Simulation.
                </div>
              </div>
            )}

            {error && (
              <div className="error-banner">⚠ {error}</div>
            )}

            {loading && (
              <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
                {Array.from({ length: 4 }).map((_, i) => (
                  <div key={i} className="skeleton" style={{ height: 16, width: `${60 + i * 10}%` }} />
                ))}
              </div>
            )}

            {result && (
              <div style={{ display: "flex", flexDirection: "column", gap: 16 }}>
                <div
                  style={{
                    display: "flex",
                    alignItems: "center",
                    gap: 12,
                    background: `color-mix(in srgb, ${verdictColor} 12%, transparent)`,
                    border: `1px solid ${verdictColor}`,
                    borderRadius: 12,
                    padding: "16px 20px",
                  }}
                >
                  <span style={{ fontSize: 32 }}>
                    {verdict === "allow" ? "✅" : verdict === "deny" ? "🚫" : "⏳"}
                  </span>
                  <div>
                    <div
                      style={{
                        fontSize: 22,
                        fontWeight: 800,
                        color: verdictColor,
                        textTransform: "uppercase",
                        letterSpacing: 1,
                      }}
                    >
                      {verdict ?? "unknown"}
                    </div>
                    {result.reason_code && (
                      <div style={{ fontSize: 12, color: "var(--text-secondary)" }}>
                        {result.reason_code}
                      </div>
                    )}
                  </div>
                </div>

                {result.reason && (
                  <div
                    style={{
                      background: "var(--bg-card)",
                      border: "1px solid var(--border)",
                      borderRadius: 8,
                      padding: "12px 16px",
                      fontSize: 13,
                      color: "var(--text-secondary)",
                      lineHeight: 1.6,
                    }}
                  >
                    {result.reason}
                  </div>
                )}

                <details>
                  <summary
                    style={{
                      cursor: "pointer",
                      fontSize: 12,
                      color: "var(--text-muted)",
                      userSelect: "none",
                    }}
                  >
                    Full response JSON
                  </summary>
                  <pre
                    style={{
                      marginTop: 8,
                      background: "var(--bg-base)",
                      border: "1px solid var(--border)",
                      borderRadius: 8,
                      padding: 12,
                      fontSize: 11,
                      color: "var(--text-secondary)",
                      overflowX: "auto",
                    }}
                  >
                    {JSON.stringify(result, null, 2)}
                  </pre>
                </details>
              </div>
            )}
          </div>
        </div>
      </div>
    </>
  )
}
