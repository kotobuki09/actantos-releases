import { StrictMode } from "react"
import { createRoot } from "react-dom/client"
import { BrowserRouter, Routes, Route, Navigate } from "react-router-dom"
import { Sidebar } from "./Sidebar"
import { useSse } from "./useSse"
import { OverviewPage } from "./pages/OverviewPage"
import { SessionsPage } from "./pages/SessionsPage"
import { ToolCallsPage } from "./pages/ToolCallsPage"
import { ApprovalsPage } from "./pages/ApprovalsPage"
import { PoliciesPage } from "./pages/PoliciesPage"
import { PolicySimPage } from "./pages/PolicySimPage"
import { AgentsPage } from "./pages/AgentsPage"
import { BudgetsPage } from "./pages/BudgetsPage"
import { KillSwitchPage } from "./pages/KillSwitchPage"
import { AuditPage } from "./pages/AuditPage"
import "./index.css"

function App() {
  useSse()
  return (
    <BrowserRouter basename="/dashboard">
      <div className="app-shell">
        <Sidebar />
        <main className="main-content">
          <Routes>
            <Route path="/" element={<OverviewPage />} />
            <Route path="/sessions" element={<SessionsPage />} />
            <Route path="/tool-calls" element={<ToolCallsPage />} />
            <Route path="/approvals" element={<ApprovalsPage />} />
            <Route path="/policies" element={<PoliciesPage />} />
            <Route path="/policy-sim" element={<PolicySimPage />} />
            <Route path="/agents" element={<AgentsPage />} />
            <Route path="/budgets" element={<BudgetsPage />} />
            <Route path="/kill-switch" element={<KillSwitchPage />} />
            <Route path="/audit" element={<AuditPage />} />
            <Route path="*" element={<Navigate to="/" replace />} />
          </Routes>
        </main>
      </div>
    </BrowserRouter>
  )
}

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <App />
  </StrictMode>,
)
