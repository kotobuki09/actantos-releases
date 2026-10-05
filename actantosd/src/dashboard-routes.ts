import type { FastifyInstance } from "fastify"
import { z } from "zod"

import type { Database } from "./database.ts"
import { listPendingApprovals } from "./approval-routes.ts"
import { listAgents } from "./agents-routes.ts"
import { listDecisions } from "./decisions-routes.ts"
import { listActiveKillSwitches } from "./kill-switch-routes.ts"
import { listSessionEvents } from "./session-events.ts"
import { listSessions } from "./sessions-routes.ts"

type RegisterDashboardRoutesOptions = {
  readonly database?: Database
}

const dashboardQuerySchema = z.object({
  tenant_id: z.string().min(1).optional().default("t_demo"),
  api_key: z.string().min(1).optional(),
  section: z.enum(["agents", "sessions", "decisions", "approvals", "audit"]).optional().default("agents"),
  session_id: z.string().min(1).optional(),
})

const escapeHtml = (value: string | number | boolean | null | undefined): string =>
  String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")

const buildDashboardHref = (
  tenantId: string,
  section: "agents" | "sessions" | "decisions" | "approvals" | "audit",
  apiKey?: string,
): string =>
  escapeHtml(
    `/dashboard?tenant_id=${encodeURIComponent(tenantId)}&section=${section}${apiKey === undefined ? "" : `&api_key=${encodeURIComponent(apiKey)}`}`,
  )

const buildAuditHref = (
  tenantId: string,
  sessionId: string | undefined,
  apiKey?: string,
): string =>
  escapeHtml(
    sessionId === undefined
      ? `/dashboard?tenant_id=${encodeURIComponent(tenantId)}&section=audit${apiKey === undefined ? "" : `&api_key=${encodeURIComponent(apiKey)}`}`
      : `/dashboard?tenant_id=${encodeURIComponent(tenantId)}&section=audit&session_id=${encodeURIComponent(sessionId)}${apiKey === undefined ? "" : `&api_key=${encodeURIComponent(apiKey)}`}`,
  )

const renderAgentsRows = (
  agents: readonly Awaited<ReturnType<typeof listAgents>>[number][],
): string => {
  if (agents.length === 0) {
    return `
      <div class="empty-state" data-empty-state="true">
        <h2>No agents registered</h2>
        <p>Add or seed an agent to see runtime identity, environment, and risk posture here.</p>
      </div>
    `
  }

  return `
    <table aria-label="Agents">
      <thead>
        <tr>
          <th>Name</th>
          <th>External ID</th>
          <th>Runtime</th>
          <th>Environment</th>
          <th>Risk Tier</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        ${agents.map((agent) => `
          <tr data-agent-id="${escapeHtml(agent.external_id)}">
            <td>
              <div class="primary">${escapeHtml(agent.name)}</div>
              <div class="secondary">${escapeHtml(agent.owner_user_id)}</div>
            </td>
            <td><code>${escapeHtml(agent.external_id)}</code></td>
            <td>${escapeHtml(agent.runtime_type)}</td>
            <td>${escapeHtml(agent.environment)}</td>
            <td><span class="risk risk-${escapeHtml(agent.risk_tier)}">${escapeHtml(agent.risk_tier)}</span></td>
            <td>${escapeHtml(agent.status)}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `
}

const renderSessionsRows = (
  sessions: readonly Awaited<ReturnType<typeof listSessions>>[number][],
): string => {
  if (sessions.length === 0) {
    return `
      <div class="empty-state" data-empty-state="true">
        <h2>No sessions recorded</h2>
        <p>Start or seed a session to review operator purpose, cwd, and agent association here.</p>
      </div>
    `
  }

  return `
    <table aria-label="Sessions">
      <thead>
        <tr>
          <th>Session</th>
          <th>Agent</th>
          <th>Purpose</th>
          <th>Working Directory</th>
          <th>Status</th>
        </tr>
      </thead>
      <tbody>
        ${sessions.map((session) => `
          <tr data-session-id="${escapeHtml(session.external_id)}">
            <td>
              <div class="primary">${escapeHtml(session.external_id)}</div>
              <div class="secondary">${escapeHtml(session.user_id)}</div>
            </td>
            <td>
              <div class="primary">${escapeHtml(session.agent.name)}</div>
              <div class="secondary">${escapeHtml(session.agent.external_id)}</div>
            </td>
            <td>${escapeHtml(session.purpose ?? "No purpose recorded")}</td>
            <td><code>${escapeHtml(session.cwd ?? "No cwd recorded")}</code></td>
            <td>${escapeHtml(session.status)}</td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `
}

const renderDecisionsRows = (
  decisions: readonly Awaited<ReturnType<typeof listDecisions>>[number][],
): string => {
  if (decisions.length === 0) {
    return `
      <div class="empty-state" data-empty-state="true">
        <h2>No decisions recorded</h2>
        <p>Run or seed an agent action to review allow, deny, and approval decisions here.</p>
      </div>
    `
  }

  return `
    <table aria-label="Decisions">
      <thead>
        <tr>
          <th>Request</th>
          <th>Tool</th>
          <th>Reason Code</th>
          <th>Decision</th>
        </tr>
      </thead>
      <tbody>
        ${decisions.map((decision) => `
          <tr data-decision-id="${escapeHtml(decision.decision_id)}">
            <td>
              <div class="primary">${escapeHtml(decision.request_id)}</div>
              <div class="secondary">${escapeHtml(decision.agent_id)} / ${escapeHtml(decision.session_id)}</div>
            </td>
            <td>
              <div class="primary">${escapeHtml(decision.tool.name)}</div>
              <div class="secondary">${escapeHtml(decision.tool.kind)} · ${escapeHtml(decision.tool.operation)}</div>
            </td>
            <td>
              <div class="primary">${escapeHtml(decision.reason_code)}</div>
              <div class="secondary">${escapeHtml(decision.reason)}</div>
            </td>
            <td>
              <span class="decision decision-${escapeHtml(decision.final_decision)}">${escapeHtml(decision.final_decision.replaceAll("_", " "))}</span>
            </td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `
}

const renderApprovalsRows = (
  approvals: readonly Awaited<ReturnType<typeof listPendingApprovals>>[number][],
): string => {
  if (approvals.length === 0) {
    return `
      <div class="empty-state" data-empty-state="true">
        <h2>No approvals pending</h2>
        <p>Approval-required actions will queue here with their request context and expiry.</p>
      </div>
    `
  }

  return `
    <table aria-label="Pending approvals">
      <thead>
        <tr>
          <th>Approval</th>
          <th>Request</th>
          <th>Reason</th>
          <th>Expiry</th>
          <th>Actions</th>
        </tr>
      </thead>
      <tbody>
        ${approvals.map((approval) => `
          <tr data-approval-id="${escapeHtml(approval.approval_id)}">
            <td>
              <div class="primary">${escapeHtml(approval.approval_id)}</div>
              <div class="secondary">${escapeHtml(approval.status)}</div>
            </td>
            <td>
              <div class="primary">${escapeHtml(approval.request_id)}</div>
              <div class="secondary">${escapeHtml(approval.tool.name)} · ${escapeHtml(approval.agent_id)} / ${escapeHtml(approval.session_id)}</div>
            </td>
            <td>
              <div class="primary">${escapeHtml(approval.reason_code)}</div>
              <div class="secondary">${escapeHtml(approval.reason)}</div>
            </td>
            <td><code>${escapeHtml(approval.expires_at)}</code></td>
            <td>
              <div class="actions" data-approval-actions="true">
                <button class="action-button action-approve" type="button" data-approval-action="approved" data-approval-id="${escapeHtml(approval.approval_id)}">Approve</button>
                <button class="action-button action-deny" type="button" data-approval-action="denied" data-approval-id="${escapeHtml(approval.approval_id)}">Deny</button>
              </div>
            </td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `
}

const renderAuditTimeline = (
  tenantId: string,
  sessions: readonly Awaited<ReturnType<typeof listSessions>>[number][],
  selectedSessionId: string | undefined,
  events: Awaited<ReturnType<typeof listSessionEvents>>,
  apiKey?: string,
): string => {
  if (sessions.length === 0) {
    return `
      <div class="empty-state" data-empty-state="true">
        <h2>No sessions available</h2>
        <p>Create or seed a session before reviewing the audit timeline.</p>
      </div>
    `
  }

  const sessionLinks = `
    <div class="session-links" data-audit-session-links="true">
      ${sessions.map((session) => `
        <a class="session-link${selectedSessionId === session.external_id ? " active" : ""}" href="${buildAuditHref(tenantId, session.external_id, apiKey)}" data-audit-session="${escapeHtml(session.external_id)}">${escapeHtml(session.external_id)}</a>
      `).join("")}
    </div>
  `

  if (events.length === 0) {
    return `
      ${sessionLinks}
      <div class="empty-state" data-empty-state="true">
        <h2>No audit events recorded</h2>
        <p>Run an action in this session to populate ordered policy and execution evidence.</p>
      </div>
    `
  }

  return `
    ${sessionLinks}
    <table aria-label="Audit timeline">
      <thead>
        <tr>
          <th>Timestamp</th>
          <th>Actor</th>
          <th>Event</th>
          <th>Context</th>
        </tr>
      </thead>
      <tbody>
        ${events.map((event) => `
          <tr data-audit-event="${escapeHtml(event.event_hash)}">
            <td><code>${escapeHtml(event.created_at)}</code></td>
            <td>
              <div class="primary">${escapeHtml(event.actor.id)}</div>
              <div class="secondary">${escapeHtml(event.actor.type)}</div>
            </td>
            <td>
              <div class="primary">${escapeHtml(event.event_type)}</div>
              <div class="secondary">${escapeHtml(event.final_decision ?? "no decision")}</div>
            </td>
            <td>
              <div class="primary">${escapeHtml(event.request_id ?? "no request id")}</div>
              <div class="secondary">${escapeHtml(event.tool === null ? "no tool context" : `${event.tool.name} · ${event.tool.kind}`)}</div>
              <div class="secondary">${escapeHtml(event.reason_code ?? "no reason code")}</div>
            </td>
          </tr>
        `).join("")}
      </tbody>
    </table>
  `
}

const renderOperatorShell = (
  tenantId: string,
  killSwitches: readonly Awaited<ReturnType<typeof listActiveKillSwitches>>[number][],
  selectedSessionId: string | undefined,
): string => {
  const hasTenantKillSwitch = killSwitches.some((killSwitch) =>
    killSwitch.scope_type === "tenant" && killSwitch.scope_id === tenantId
  )
  const killSwitchState = killSwitches.length === 0 ? "empty" : "active"
  const feedback = hasTenantKillSwitch
    ? "Tenant kill switch is active. New actions for this tenant should stop immediately."
    : killSwitches.length === 0
      ? "No active kill switches. Tenant actions are currently eligible to run."
      : "Scoped kill switches are active for this tenant."

  return `
    <section class="panel operator-shell-panel" data-operator-shell="true">
      <div class="panel-header">
        <div>
          <h2>Operator shell</h2>
          <p>Immediate operator controls for tenant-wide containment and live status review.</p>
        </div>
        <div class="statusline">Backed by <code>/v1/kill-switches</code></div>
      </div>
      <div class="operator-shell-layout">
        <div class="operator-actions">
          <div class="operator-card">
            <div class="operator-card-header">
              <div>
                <div class="primary">Tenant kill switch</div>
                <div class="secondary">Stop future actions for <code>${escapeHtml(tenantId)}</code>.</div>
              </div>
              <button
                class="action-button action-danger"
                type="button"
                data-kill-switch-button="tenant"
                data-kill-switch-tenant="${escapeHtml(tenantId)}"
              >
                Activate
              </button>
            </div>
            <p class="operator-feedback" data-kill-switch-feedback="true" data-kill-switch-state="${killSwitchState}">${feedback}</p>
          </div>
          <div class="operator-card">
            <div class="operator-card-header">
              <div>
                <div class="primary">Evidence export</div>
                <div class="secondary">${selectedSessionId === undefined ? "Export the tenant evidence package." : `Export the current session evidence package for ${escapeHtml(selectedSessionId)}.`}</div>
              </div>
              <button
                class="action-button"
                type="button"
                data-evidence-export-button="${selectedSessionId === undefined ? "tenant" : "session"}"
                data-evidence-export-tenant="${escapeHtml(tenantId)}"
                ${selectedSessionId === undefined ? "" : `data-evidence-export-session="${escapeHtml(selectedSessionId)}"`}
              >
                Download JSON
              </button>
            </div>
            <p class="operator-feedback" data-evidence-export-feedback="true" data-evidence-export-state="idle">${selectedSessionId === undefined ? "Download a tenant-wide evidence package with sessions, decisions, approvals, kill switches, and audit timelines." : "Download the currently selected session evidence package with decision and audit proof."}</p>
          </div>
        </div>
        <div class="operator-card">
          <div class="operator-card-header">
            <div class="primary">Active kill switches</div>
            <div class="secondary">${String(killSwitches.length)} active</div>
          </div>
          ${killSwitches.length === 0
            ? `
              <div class="empty-state compact-empty-state" data-kill-switch-state="empty">
                <h2>No active kill switches</h2>
                <p>Activate the tenant control above when you need an immediate stop.</p>
              </div>
            `
            : `
              <ul class="kill-switch-list" data-kill-switch-state="active">
                ${killSwitches.map((killSwitch) => `
                  <li class="kill-switch-item" data-kill-switch-id="${escapeHtml(killSwitch.id)}">
                    <div class="primary">${escapeHtml(killSwitch.scope_type)} scope</div>
                    <div class="secondary"><code>${escapeHtml(killSwitch.scope_id)}</code> · ${escapeHtml(killSwitch.created_at)}</div>
                    <div class="secondary">${escapeHtml(killSwitch.reason)}</div>
                  </li>
                `).join("")}
              </ul>
            `}
        </div>
      </div>
    </section>
  `
}

const renderDashboardPage = (
  tenantId: string,
  apiKey: string | undefined,
  section: "agents" | "sessions" | "decisions" | "approvals" | "audit",
  agents: readonly Awaited<ReturnType<typeof listAgents>>[number][],
  sessions: readonly Awaited<ReturnType<typeof listSessions>>[number][],
  decisions: readonly Awaited<ReturnType<typeof listDecisions>>[number][],
  approvals: readonly Awaited<ReturnType<typeof listPendingApprovals>>[number][],
  killSwitches: readonly Awaited<ReturnType<typeof listActiveKillSwitches>>[number][],
  selectedSessionId: string | undefined,
  auditEvents: Awaited<ReturnType<typeof listSessionEvents>>,
): string => `
<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>ActantOS Dashboard</title>
  <style>
    :root {
      color-scheme: dark;
      --bg: #0b1017;
      --panel: #131b27;
      --panel-alt: #0f1520;
      --border: #243244;
      --text: #ebf1fa;
      --muted: #9eacc0;
      --accent: #7fb3ff;
      --good: #3ddc97;
      --warn: #ffd166;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      font-family: Inter, "Segoe UI", system-ui, sans-serif;
      background: linear-gradient(180deg, #0e1520 0%, var(--bg) 220px);
      color: var(--text);
    }
    header {
      border-bottom: 1px solid var(--border);
      background: rgba(11, 16, 23, 0.92);
      backdrop-filter: blur(12px);
      position: sticky;
      top: 0;
    }
    .header-inner, main {
      max-width: 1200px;
      margin: 0 auto;
      padding: 20px 24px;
    }
    .eyebrow {
      color: var(--accent);
      font-size: 12px;
      text-transform: uppercase;
      font-weight: 700;
    }
    h1 {
      margin: 6px 0 6px;
      font-size: 30px;
    }
    p {
      margin: 0;
      color: var(--muted);
      line-height: 1.5;
    }
    nav {
      display: flex;
      gap: 8px;
      margin-top: 18px;
      flex-wrap: wrap;
    }
    .tab {
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 9px 12px;
      color: var(--muted);
      background: var(--panel-alt);
      text-decoration: none;
      font-weight: 600;
    }
    .tab.active {
      color: var(--text);
      border-color: rgba(127, 179, 255, 0.45);
      background: rgba(127, 179, 255, 0.12);
    }
    .hero {
      display: flex;
      justify-content: space-between;
      gap: 16px;
      align-items: end;
      margin-bottom: 18px;
    }
    .tenant {
      font-size: 12px;
      color: var(--muted);
    }
    .panel {
      background: linear-gradient(180deg, var(--panel), var(--panel-alt));
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 18px;
      box-shadow: 0 12px 40px rgba(0, 0, 0, 0.2);
    }
    .panel-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      gap: 12px;
      margin-bottom: 14px;
    }
    .panel-header h2 {
      margin: 0;
      font-size: 18px;
    }
    .statusline {
      display: flex;
      align-items: center;
      gap: 12px;
      color: var(--muted);
      font-size: 13px;
    }
    .loading {
      display: inline-flex;
      align-items: center;
      gap: 8px;
      color: var(--muted);
    }
    .dot {
      width: 8px;
      height: 8px;
      border-radius: 999px;
      background: var(--accent);
    }
    table {
      width: 100%;
      border-collapse: collapse;
    }
    th, td {
      text-align: left;
      padding: 12px 10px;
      border-top: 1px solid var(--border);
      vertical-align: top;
    }
    th {
      color: var(--muted);
      font-size: 12px;
      text-transform: uppercase;
      letter-spacing: 0.03em;
      font-weight: 700;
    }
    .primary {
      font-weight: 650;
    }
    .secondary, code {
      color: var(--muted);
      font-size: 13px;
    }
    code {
      font-family: ui-monospace, SFMono-Regular, Consolas, monospace;
    }
    .risk {
      display: inline-flex;
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 3px 8px;
      font-size: 12px;
      text-transform: capitalize;
    }
    .risk-low { color: var(--good); }
    .risk-medium { color: var(--warn); }
    .risk-high { color: #ff8b8b; }
    .decision {
      display: inline-flex;
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 3px 8px;
      font-size: 12px;
      text-transform: capitalize;
    }
    .decision-allow { color: var(--good); }
    .decision-deny { color: #ff8b8b; }
    .decision-approval_required { color: var(--warn); }
    .actions {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
    }
    .action-button {
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 8px 10px;
      color: var(--text);
      background: var(--panel-alt);
      cursor: pointer;
      font: inherit;
    }
    .action-approve {
      border-color: rgba(61, 220, 151, 0.35);
      color: var(--good);
    }
    .action-deny {
      border-color: rgba(255, 139, 139, 0.35);
      color: #ff8b8b;
    }
    .action-danger {
      border-color: rgba(255, 139, 139, 0.35);
      color: #ff8b8b;
      background: rgba(255, 139, 139, 0.08);
    }
    .session-links {
      display: flex;
      gap: 8px;
      flex-wrap: wrap;
      margin-bottom: 16px;
    }
    .session-link {
      border: 1px solid var(--border);
      border-radius: 999px;
      padding: 7px 10px;
      color: var(--muted);
      background: var(--panel-alt);
      text-decoration: none;
      font-size: 13px;
      font-weight: 600;
    }
    .session-link.active {
      color: var(--text);
      border-color: rgba(127, 179, 255, 0.45);
      background: rgba(127, 179, 255, 0.12);
    }
    .empty-state {
      padding: 26px 8px 8px;
    }
    .compact-empty-state {
      padding: 12px 0 0;
    }
    .empty-state h2 {
      margin: 0 0 8px;
      font-size: 18px;
    }
    .operator-shell-panel {
      margin-bottom: 18px;
    }
    .operator-shell-layout {
      display: grid;
      grid-template-columns: minmax(0, 1.1fr) minmax(0, 0.9fr);
      gap: 16px;
    }
    .operator-actions {
      display: flex;
      flex-direction: column;
      gap: 12px;
    }
    .operator-card {
      border: 1px solid var(--border);
      border-radius: 8px;
      background: rgba(11, 16, 23, 0.45);
      padding: 14px;
    }
    .operator-card-header {
      display: flex;
      justify-content: space-between;
      align-items: start;
      gap: 12px;
    }
    .operator-feedback {
      margin-top: 10px;
      font-size: 13px;
    }
    .operator-feedback[data-kill-switch-state="active"] {
      color: #ffb0b0;
    }
    .operator-feedback[data-kill-switch-state="success"] {
      color: #ffb0b0;
    }
    .operator-feedback[data-kill-switch-state="error"] {
      color: var(--warn);
    }
    .operator-feedback[data-kill-switch-state="pending"] {
      color: var(--accent);
    }
    .kill-switch-list {
      list-style: none;
      margin: 12px 0 0;
      padding: 0;
      display: flex;
      flex-direction: column;
      gap: 10px;
    }
    .kill-switch-item {
      border-top: 1px solid var(--border);
      padding-top: 10px;
    }
    .kill-switch-item:first-child {
      border-top: 0;
      padding-top: 0;
    }
    @media (max-width: 800px) {
      .hero, .panel-header, .operator-card-header {
        flex-direction: column;
        align-items: start;
      }
      .operator-shell-layout {
        grid-template-columns: 1fr;
      }
      table, thead, tbody, th, td, tr {
        display: block;
      }
      thead {
        display: none;
      }
      td {
        padding: 8px 0;
      }
      tr {
        border-top: 1px solid var(--border);
        padding: 12px 0;
      }
    }
  </style>
</head>
<body>
  <header>
    <div class="header-inner">
      <div class="eyebrow">ActantOS Dashboard</div>
      <h1>Operators</h1>
      <p>Monitor registered agents, session flow, decisions, approvals, and audit evidence.</p>
      <nav aria-label="Dashboard sections">
        <a class="tab${section === "agents" ? " active" : ""}" href="${buildDashboardHref(tenantId, "agents", apiKey)}">Agents</a>
        <a class="tab${section === "sessions" ? " active" : ""}" href="${buildDashboardHref(tenantId, "sessions", apiKey)}">Sessions</a>
        <a class="tab${section === "decisions" ? " active" : ""}" href="${buildDashboardHref(tenantId, "decisions", apiKey)}">Decisions</a>
        <a class="tab${section === "approvals" ? " active" : ""}" href="${buildDashboardHref(tenantId, "approvals", apiKey)}">Pending Approvals</a>
        <a class="tab${section === "audit" ? " active" : ""}" href="${buildAuditHref(tenantId, selectedSessionId, apiKey)}">Audit Timeline</a>
      </nav>
    </div>
  </header>
  <main>
    <section class="hero">
      <div>
        <div class="tenant">Tenant: <code>${escapeHtml(tenantId)}</code></div>
        <h2>${section === "agents" ? "Agents" : section === "sessions" ? "Sessions" : section === "decisions" ? "Decisions" : section === "approvals" ? "Pending Approvals" : "Audit Timeline"}</h2>
        <p>${section === "agents"
          ? "Registered runtime identities with environment and risk posture."
          : section === "sessions"
            ? "Operator sessions with agent association, purpose, cwd, and live status."
            : section === "decisions"
              ? "Policy outcomes with request identity, tool summary, and reason codes."
              : section === "approvals"
                ? "Queued approval-required actions with request context and direct operator actions."
                : "Ordered audit evidence for one session at a time, with actor and decision context."}</p>
      </div>
      <div class="statusline">
        <span class="loading" data-loading-state="ready"><span class="dot"></span>Loaded</span>
        <span>${String(section === "agents" ? agents.length : section === "sessions" ? sessions.length : section === "decisions" ? decisions.length : section === "approvals" ? approvals.length : auditEvents.length)} total</span>
      </div>
    </section>
    ${renderOperatorShell(tenantId, killSwitches, selectedSessionId)}
    <section class="panel">
      <div class="panel-header">
        <h2>${section === "agents" ? "Agent inventory" : section === "sessions" ? "Session inventory" : section === "decisions" ? "Decision inventory" : section === "approvals" ? "Pending approvals" : "Audit timeline"}</h2>
        <div class="statusline">Backed by <code>${section === "agents" ? "/v1/agents" : section === "sessions" ? "/v1/sessions" : section === "decisions" ? "/v1/decisions" : section === "approvals" ? "/v1/approvals/pending" : "/v1/sessions/:session_id/events"}</code></div>
      </div>
      ${section === "agents"
        ? renderAgentsRows(agents)
        : section === "sessions"
          ? renderSessionsRows(sessions)
          : section === "decisions"
            ? renderDecisionsRows(decisions)
            : section === "approvals"
              ? renderApprovalsRows(approvals)
              : renderAuditTimeline(tenantId, sessions, selectedSessionId, auditEvents, apiKey)}
    </section>
    <script>
      const dashboardApiKey = ${JSON.stringify(apiKey ?? "")}
      const appendApiKey = (url) => {
        if (dashboardApiKey.length === 0) {
          return url
        }

        const targetUrl = new URL(url, window.location.origin)
        targetUrl.searchParams.set("api_key", dashboardApiKey)
        return targetUrl.toString()
      }

      document.addEventListener("click", async (event) => {
        const target = event.target
        if (!(target instanceof HTMLButtonElement)) {
          return
        }

        const approvalId = target.dataset.approvalId
        const decision = target.dataset.approvalAction
        if (approvalId === undefined || decision === undefined) {
          const exportScope = target.dataset.evidenceExportButton
          const exportTenant = target.dataset.evidenceExportTenant
          if (exportScope !== undefined && exportTenant !== undefined) {
            const feedback = document.querySelector("[data-evidence-export-feedback='true']")
            if (!(feedback instanceof HTMLElement)) {
              return
            }

            target.disabled = true
            feedback.dataset.evidenceExportState = "pending"
            feedback.textContent = "Preparing evidence export..."

            try {
              const exportSession = target.dataset.evidenceExportSession
              const exportUrl = new URL("/v1/evidence/export", window.location.origin)
              exportUrl.searchParams.set("tenant_id", exportTenant)
              if (exportScope === "session" && exportSession !== undefined) {
                exportUrl.searchParams.set("session_id", exportSession)
              }

              const response = await fetch(appendApiKey(exportUrl.toString()))
              if (!response.ok) {
                target.disabled = false
                feedback.dataset.evidenceExportState = "error"
                feedback.textContent = "Evidence export failed. Check the API response and retry."
                return
              }

              const blob = await response.blob()
              const downloadUrl = URL.createObjectURL(blob)
              const anchor = document.createElement("a")
              anchor.href = downloadUrl
              anchor.download = exportScope === "session" && exportSession !== undefined
                ? "actantos-evidence-" + exportTenant + "-" + exportSession + ".json"
                : "actantos-evidence-" + exportTenant + ".json"
              anchor.click()
              URL.revokeObjectURL(downloadUrl)

              feedback.dataset.evidenceExportState = "success"
              feedback.textContent = exportScope === "session" && exportSession !== undefined
                ? "Session evidence package downloaded."
                : "Tenant evidence package downloaded."
            } catch {
              target.disabled = false
              feedback.dataset.evidenceExportState = "error"
              feedback.textContent = "Evidence export failed. Retry when the dashboard can reach the API."
              return
            }

            target.disabled = false
            return
          }

          const killSwitchScope = target.dataset.killSwitchButton
          const killSwitchTenant = target.dataset.killSwitchTenant
          if (killSwitchScope === undefined || killSwitchTenant === undefined) {
            return
          }

          const feedback = document.querySelector("[data-kill-switch-feedback='true']")
          if (!(feedback instanceof HTMLElement)) {
            return
          }

          target.disabled = true
          feedback.dataset.killSwitchState = "pending"
          feedback.textContent = "Activating tenant kill switch..."

          try {
            const response = await fetch(appendApiKey("/v1/kill-switches"), {
              method: "POST",
              headers: { "content-type": "application/json" },
              body: JSON.stringify({
                tenant_id: killSwitchTenant,
                scope_type: killSwitchScope,
                scope_id: killSwitchTenant,
                reason: "dashboard emergency stop",
              }),
            })

            if (!response.ok) {
              target.disabled = false
              feedback.dataset.killSwitchState = "error"
              feedback.textContent = "Kill switch activation failed. Check the API response and retry."
              return
            }

            const payload = await response.json()
            feedback.dataset.killSwitchState = "success"
            feedback.textContent = "Tenant kill switch activated. Refresh to review the active switch inventory."

            const emptyState = document.querySelector("[data-kill-switch-state='empty']")
            if (emptyState instanceof HTMLElement) {
              emptyState.remove()
            }

            const listContainer = document.querySelector(".kill-switch-list")
            if (listContainer instanceof HTMLElement) {
              const item = document.createElement("li")
              item.className = "kill-switch-item"
              item.setAttribute("data-kill-switch-id", String(payload.id))
              item.innerHTML =
                "<div class='primary'>tenant scope</div>" +
                "<div class='secondary'><code>" + killSwitchTenant + "</code> · just now</div>" +
                "<div class='secondary'>dashboard emergency stop</div>"
              listContainer.prepend(item)
            }
            target.disabled = true
          } catch {
            target.disabled = false
            feedback.dataset.killSwitchState = "error"
            feedback.textContent = "Kill switch activation failed. Retry when the dashboard can reach the API."
          }
          return
        }

        target.disabled = true

        try {
          const response = await fetch(appendApiKey("/v1/approvals/" + encodeURIComponent(approvalId) + "/decide"), {
            method: "POST",
            headers: { "content-type": "application/json" },
            body: JSON.stringify({
              decision,
              approver_user_id: "u_dashboard",
            }),
          })

          if (!response.ok) {
            target.disabled = false
            return
          }

          const row = target.closest("tr")
          if (row !== null) {
            row.setAttribute("data-approval-status", decision)
          }
        } catch {
          target.disabled = false
        }
      })
    </script>
  </main>
</body>
</html>
`

export const registerDashboardRoutes = (
  server: FastifyInstance,
  options: RegisterDashboardRoutesOptions,
): void => {
  server.get("/dashboard", async (request, reply) => {
    const query = dashboardQuerySchema.parse(request.query)

    const agents = query.section === "agents"
      ? await listAgents(options.database, query.tenant_id)
      : []
    const sessions = query.section === "sessions" || query.section === "audit"
      ? await listSessions(options.database, query.tenant_id)
      : []
    const decisions = query.section === "decisions"
      ? await listDecisions(options.database, query.tenant_id)
      : []
    const approvals = query.section === "approvals"
      ? await listPendingApprovals(options.database, query.tenant_id)
      : []
    const killSwitches = await listActiveKillSwitches(options.database, query.tenant_id)
    const selectedSessionId = query.section === "audit"
      ? query.session_id ?? sessions[0]?.external_id
      : undefined
    const auditEvents = query.section === "audit" && options.database !== undefined && selectedSessionId !== undefined
      ? await listSessionEvents(options.database, query.tenant_id, selectedSessionId)
      : []

    return reply
      .code(200)
      .type("text/html; charset=utf-8")
      .send(renderDashboardPage(query.tenant_id, query.api_key, query.section, agents, sessions, decisions, approvals, killSwitches, selectedSessionId, auditEvents))
  })
}
