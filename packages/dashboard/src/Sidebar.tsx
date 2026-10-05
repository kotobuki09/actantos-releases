import { NavLink } from "react-router-dom"
import { useEventsStore } from "./store"

const navSections = [
  {
    label: "Overview",
    items: [
      { icon: "⬡", label: "Overview", to: "/dashboard" },
      { icon: "📊", label: "Sessions", to: "/dashboard/sessions" },
    ],
  },
  {
    label: "Policy",
    items: [
      { icon: "🔀", label: "Tool Calls", to: "/dashboard/tool-calls" },
      { icon: "✅", label: "Approvals", to: "/dashboard/approvals", badge: true },
      { icon: "📋", label: "Policies", to: "/dashboard/policies" },
      { icon: "🧪", label: "Policy Sim", to: "/dashboard/policy-sim" },
    ],
  },
  {
    label: "Agents",
    items: [
      { icon: "🤖", label: "Agents", to: "/dashboard/agents" },
      { icon: "💰", label: "Budgets", to: "/dashboard/budgets" },
    ],
  },
  {
    label: "Control",
    items: [
      { icon: "🔴", label: "Kill Switch", to: "/dashboard/kill-switch" },
      { icon: "📜", label: "Audit Log", to: "/dashboard/audit" },
    ],
  },
]

export const Sidebar = () => {
  const connected = useEventsStore((s) => s.connected)
  const pendingApprovalCount = useEventsStore((s) => s.pendingApprovalCount)

  return (
    <aside className="sidebar">
      <div className="sidebar-logo">
        <div className="sidebar-logo-mark">Ac</div>
        <div>
          <div className="sidebar-title">ActantOS</div>
          <div className="sidebar-subtitle">Operator Console</div>
        </div>
      </div>

      <nav className="sidebar-nav">
        {navSections.map((section) => (
          <div key={section.label}>
            <div className="nav-section-label">{section.label}</div>
            {section.items.map((item) => (
              <NavLink
                key={item.to}
                to={item.to}
                end={item.to === "/dashboard"}
                className={({ isActive }) =>
                  `nav-item${isActive ? " active" : ""}`
                }
              >
                <span className="nav-icon">{item.icon}</span>
                <span style={{ flex: 1 }}>{item.label}</span>
                {item.badge && pendingApprovalCount > 0 && (
                  <span
                    style={{
                      background: "var(--accent-amber)",
                      color: "#000",
                      fontSize: "10px",
                      fontWeight: 700,
                      padding: "2px 6px",
                      borderRadius: "99px",
                    }}
                  >
                    {pendingApprovalCount}
                  </span>
                )}
              </NavLink>
            ))}
          </div>
        ))}
      </nav>

      {/* Connection status */}
      <div
        style={{
          padding: "12px 20px",
          borderTop: "1px solid var(--border)",
          display: "flex",
          alignItems: "center",
          gap: "8px",
          fontSize: "11px",
          color: "var(--text-muted)",
        }}
      >
        <div
          style={{
            width: 7,
            height: 7,
            borderRadius: "50%",
            background: connected ? "var(--accent-green)" : "var(--text-muted)",
            flexShrink: 0,
            ...(connected
              ? { animation: "pulse 1.6s ease infinite", boxShadow: "0 0 6px var(--accent-green)" }
              : {}),
          }}
        />
        {connected ? "Live feed connected" : "Connecting…"}
      </div>
    </aside>
  )
}
