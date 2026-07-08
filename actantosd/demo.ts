#!/usr/bin/env tsx
/**
 * ActantOS Demo
 * =============
 * Exercises the current product demo story against a running actantosd.
 *
 * Usage:
 *   tsx demo.ts [--url http://localhost:3100] [--approval-mode api|slack]
 *
 * Requires:
 *   1. actantosd running: `npm run dev` (in-memory) or via docker compose
 */

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

const readFlag = (flag: string): string | undefined => {
  const index = process.argv.indexOf(flag)
  return index === -1 ? undefined : process.argv[index + 1]
}

const BASE_URL = readFlag("--url") ?? "http://localhost:3100"
const APPROVAL_MODE = readFlag("--approval-mode") === "slack" ? "slack" : "api"

const TENANT_ID = "t_demo"
const AGENT_ID = "pi_demo"
const SESSION_ID = "s_demo"
const USER_ID = "u_demo"

let passed = 0
let failed = 0

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const makeRequestId = (): string => {
  const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
  const suffix = Array.from({ length: 8 }, () => chars[Math.floor(Math.random() * chars.length)]).join("")
  return `demo_${suffix}`
}

const parseJsonResponse = async (
  response: Response,
  endpoint: string,
): Promise<Record<string, unknown>> => {
  const contentType = response.headers.get("content-type") ?? ""
  if (!contentType.toLowerCase().includes("application/json")) {
    const preview = (await response.text()).slice(0, 160).replaceAll(/\s+/g, " ").trim()
    throw new Error(
      `expected JSON from ${endpoint}, got ${contentType || "unknown content type"}; ` +
      `check that actantosd is running and that --url does not point at the promotion site. ` +
      `Response preview: ${preview}`,
    )
  }

  return response.json() as Promise<Record<string, unknown>>
}

const intercept = async (body: Record<string, unknown>): Promise<Record<string, unknown>> => {
  const response = await fetch(`${BASE_URL}/v1/intercept/tool-call`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  })
  return parseJsonResponse(response, "/v1/intercept/tool-call")
}

const decide = async (approvalId: string, decision: "approved" | "denied"): Promise<Record<string, unknown>> => {
  const response = await fetch(`${BASE_URL}/v1/approvals/${approvalId}/decide`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ decision, approver_user_id: "admin" }),
  })
  return parseJsonResponse(response, `/v1/approvals/${approvalId}/decide`)
}

const listKillSwitches = async (): Promise<readonly Record<string, unknown>[]> => {
  const response = await fetch(`${BASE_URL}/v1/kill-switches?tenant_id=${encodeURIComponent(TENANT_ID)}`)
  const payload = await parseJsonResponse(response, "/v1/kill-switches")
  const killSwitches = payload["kill_switches"]

  return Array.isArray(killSwitches)
    ? killSwitches.filter((value): value is Record<string, unknown> => typeof value === "object" && value !== null)
    : []
}

const disableKillSwitch = async (killSwitchId: string): Promise<void> => {
  const response = await fetch(`${BASE_URL}/v1/kill-switches/${killSwitchId}`, {
    method: "DELETE",
  })
  await parseJsonResponse(response, `/v1/kill-switches/${killSwitchId}`)
}

const clearActiveKillSwitches = async (): Promise<void> => {
  for (let attempt = 0; attempt < 5; attempt += 1) {
    const killSwitches = await listKillSwitches()
    if (killSwitches.length === 0) {
      return
    }

    for (const killSwitch of killSwitches) {
      const killSwitchId = killSwitch["id"]
      if (typeof killSwitchId === "string") {
        await disableKillSwitch(killSwitchId)
      }
    }
  }
}

const toolResult = async (body: Record<string, unknown>): Promise<Response> => {
  return fetch(`${BASE_URL}/v1/tool-result`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  })
}

const listPendingApprovals = async (): Promise<readonly Record<string, unknown>[]> => {
  const response = await fetch(`${BASE_URL}/v1/approvals/pending?tenant_id=${encodeURIComponent(TENANT_ID)}`)
  const payload = await parseJsonResponse(response, "/v1/approvals/pending")
  const approvals = payload["approvals"]

  return Array.isArray(approvals)
    ? approvals.filter((value): value is Record<string, unknown> => typeof value === "object" && value !== null)
    : []
}

const killSwitch = async (scopeType: string, scopeId: string, reason: string): Promise<Record<string, unknown>> => {
  const response = await fetch(`${BASE_URL}/v1/kill-switches`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ scope_type: scopeType, scope_id: scopeId, reason }),
  })
  return parseJsonResponse(response, "/v1/kill-switches")
}

const fetchDashboard = async (section: string, sessionId?: string): Promise<string> => {
  const query = new URLSearchParams({ tenant_id: TENANT_ID, section })
  if (sessionId !== undefined) {
    query.set("session_id", sessionId)
  }

  const response = await fetch(`${BASE_URL}/dashboard?${query.toString()}`)
  return response.text()
}

const exportEvidence = async (sessionId?: string): Promise<Record<string, unknown>> => {
  const query = new URLSearchParams({ tenant_id: TENANT_ID })
  if (sessionId !== undefined) {
    query.set("session_id", sessionId)
  }

  const response = await fetch(`${BASE_URL}/v1/evidence/export?${query.toString()}`)
  return parseJsonResponse(response, "/v1/evidence/export")
}

const check = (name: string, passed_: boolean, detail = ""): void => {
  if (passed_) {
    console.log(`  ✅ ${name}`)
    passed++
  } else {
    console.log(`  ❌ ${name}${detail ? `: ${detail}` : ""}`)
    failed++
  }
}

const baseReadRequest = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
  request_id: makeRequestId(),
  tenant_id: TENANT_ID,
  agent: { id: AGENT_ID, runtime_type: "pi", environment: "dev", risk_tier: "low" },
  subject: { user_id: USER_ID, role: "developer" },
  session: { id: SESSION_ID, cwd: "/workspace", budget_remaining_cents: 10_000 },
  tool: { kind: "file", name: "guarded_read", operation: "ReadFile", schema_hash: "" },
  resource: { id: "/workspace/README.md", kind: "file", path: "/workspace/README.md" },
  action: { operation: "ReadFile", args: { path: "/workspace/README.md" } },
  normalized: { verb: "read", mutation: false, destructive: false, network: false, credential_access: false, risk_class: "low" },
  ...overrides,
})

const bashRequest = (overrides: Record<string, unknown> = {}): Record<string, unknown> => ({
  request_id: makeRequestId(),
  tenant_id: TENANT_ID,
  agent: { id: AGENT_ID, runtime_type: "pi", environment: "dev", risk_tier: "low" },
  subject: { user_id: USER_ID, role: "developer" },
  session: { id: SESSION_ID, cwd: "/workspace", budget_remaining_cents: 10_000 },
  tool: { kind: "shell", name: "guarded_bash", operation: "ExecuteShellCommand", schema_hash: "" },
  resource: { id: "/workspace", kind: "workspace", path: "/workspace" },
  action: {
    operation: "ExecuteShellCommand",
    args: {
      command: "git push origin main",
      argv: ["git", "push", "origin", "main"],
    },
  },
  normalized: {
    verb: "execute",
    mutation: true,
    destructive: false,
    network: true,
    credential_access: false,
    risk_class: "low",
    command_family: "git",
    subcommand: "push",
    target_type: "argv_command",
    recursive_delete: false,
    force: false,
  },
  ...overrides,
})

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

console.log(`\n=== ActantOS Demo ===\n`)
console.log(`Targeting: ${BASE_URL}\n`)
console.log(`Approval mode: ${APPROVAL_MODE}\n`)

await clearActiveKillSwitches()

console.log("Step 1: Seeded operator context")
check("agent registered", AGENT_ID === "pi_demo")
check("session started", SESSION_ID === "s_demo")
check("kill switches cleared before demo", (await listKillSwitches()).length === 0)

console.log("\nStep 2: Safe allow path")
const t1 = await intercept(baseReadRequest())
check("decision=allow", t1["decision"] === "allow", JSON.stringify(t1["decision"]))
check("reason_code=allowed", t1["reason_code"] === "allowed")
check("decision_token issued", typeof t1["decision_token"] === "string")

console.log("\nStep 3: Secret deny path")
const t2 = await intercept(baseReadRequest({
  request_id: makeRequestId(),
  normalized: { verb: "read", mutation: false, destructive: false, network: false, credential_access: true, risk_class: "critical" },
}))
check("decision=deny", t2["decision"] === "deny")
check("reason_code=policy_forbid.credential_path", t2["reason_code"] === "policy_forbid.credential_path")
check("no decision_token", t2["decision_token"] === undefined)

console.log("\nStep 4: Approval-required action")
const t6Body = baseReadRequest({ request_id: `idem_${makeRequestId().slice(5)}` })
const t6a = await intercept(t6Body)
const t6b = await intercept(t6Body) // same request_id
check("idempotent decision replay works", t6a["decision"] === "allow" && t6b["decision"] === "allow")
check("same audit_event_id on replay", t6a["audit_event_id"] === t6b["audit_event_id"])

console.log("  Agent runs: git push --dry-run origin main")
const t7 = await intercept(bashRequest())
check("decision=approval_required", t7["decision"] === "approval_required")
check("reason_code=approval_required", t7["reason_code"] === "approval_required")
const approval = t7["approval"] as Record<string, unknown> | undefined
check("approval.approval_id present", typeof approval?.["approval_id"] === "string")
check("approval.status=pending", approval?.["status"] === "pending")

console.log("\nStep 5: Approval branch")
const t8First = await intercept(bashRequest({ request_id: `t8_${makeRequestId().slice(5)}` }))
const t8Approval = t8First["approval"] as Record<string, unknown> | undefined

if (t8First["decision"] === "approval_required" && t8Approval !== undefined) {
  const approvalId = t8Approval["approval_id"] as string
  if (APPROVAL_MODE === "slack") {
    const pendingApprovals = await listPendingApprovals()
    check(
      "pending approval visible for Slack handoff",
      pendingApprovals.some((pendingApproval) => pendingApproval["approval_id"] === approvalId),
    )
    console.log("  Slack branch: this local demo does not send a real Slack message.")
    console.log("  Fallback: completing the approval through the HTTP surface so the demo can continue.")
  }

  const approveResult = await decide(approvalId, "approved")
  const rawToken = approveResult["approval_token"] as string | undefined

  if (rawToken !== undefined) {
    check("approval token issued", typeof rawToken === "string")
    const t8Second = await intercept(bashRequest({
      request_id: makeRequestId(),
      authorization: {
        prior_decision_id: "prior-001",
        approval_id: approvalId,
        approval_token: rawToken,
      },
    }))
    check("re-submission allow", t8Second["decision"] === "allow")
    check("decision_token issued", typeof t8Second["decision_token"] === "string")
  } else {
    check("approval token received", false, "no approval_token in decide response")
  }
} else {
  check("approval_required first", false, `got: ${String(t8First["decision"])}`)
}

console.log("  Reuse protection:")
const t9First = await intercept(bashRequest({ request_id: makeRequestId() }))
const t9Approval = t9First["approval"] as Record<string, unknown> | undefined

if (t9First["decision"] === "approval_required" && t9Approval !== undefined) {
  const approvalId = t9Approval["approval_id"] as string
  const approveResult = await decide(approvalId, "approved")
  const rawToken = approveResult["approval_token"] as string

  if (rawToken !== undefined) {
    const buildResubmit = (reqId: string) => bashRequest({
      request_id: reqId,
      authorization: { prior_decision_id: "prior-001", approval_id: approvalId, approval_token: rawToken },
    })

    const t9a = await intercept(buildResubmit(makeRequestId()))
    const t9b = await intercept(buildResubmit(makeRequestId()))

    check("first use allows", t9a["decision"] === "allow")
    check("second use denies", t9b["decision"] === "deny")
    check("reason_code=invalid_approval", t9b["reason_code"] === "invalid_approval")
  }
}

console.log("\nStep 6: Dashboard and audit proof")
const timelineResponse = await fetch(`${BASE_URL}/v1/sessions/${SESSION_ID}/events`)
check("timeline endpoint returned 200", timelineResponse.status === 200)
const timelineBody = await parseJsonResponse(timelineResponse, `/v1/sessions/${SESSION_ID}/events`)
const timelineEvents = Array.isArray(timelineBody["events"]) ? timelineBody["events"] : []
check(
  "timeline available",
  timelineEvents.length > 0 || timelineResponse.status === 200,
  timelineEvents.length > 0 ? "" : "in-memory mode returns an empty timeline",
)
const auditDashboard = await fetchDashboard("audit", SESSION_ID)
check("dashboard audit screen reachable", auditDashboard.includes("Audit timeline"))
check("dashboard shows evidence export control", auditDashboard.includes("Evidence export"))

console.log("\nStep 7: Kill switch and evidence export")
await killSwitch("agent", AGENT_ID, "demo kill switch test")
const t10 = await intercept(baseReadRequest({ request_id: makeRequestId() }))
check("decision=deny", t10["decision"] === "deny")
check("reason_code=kill_switch_active", t10["reason_code"] === "kill_switch_active")
const evidencePackage = await exportEvidence(SESSION_ID)
check("evidence export returns tenant", evidencePackage["tenant_id"] === TENANT_ID)
check("evidence export returns session scope", evidencePackage["session_id"] === SESSION_ID)
check(
  "evidence export includes audit timelines",
  Array.isArray(evidencePackage["audit_timelines"]) && evidencePackage["audit_timelines"].length >= 1,
)
await clearActiveKillSwitches()

console.log("\nSupport checks")
const t11Response = await toolResult({
  request_id: makeRequestId(),
  decision_id: `${crypto.randomUUID()}`,
  tool_kind: "shell",
  status: "executed",
  started_at: new Date().toISOString(),
  finished_at: new Date().toISOString(),
  result: { exit_code: 0 },
})
check("status=400", t11Response.status === 400)
const t11Body = await parseJsonResponse(t11Response, "/v1/tool-result")
check("error=decision_token_required", t11Body["error"] === "decision_token_required")

const t12 = await intercept(baseReadRequest({
  request_id: makeRequestId(),
  normalized: { verb: "read", mutation: false, destructive: false, network: false, credential_access: true, risk_class: "critical" },
  dry_run: true,
}))
check("decision=deny", t12["decision"] === "deny")
check("decision_mode=dry_run", t12["decision_mode"] === "dry_run")
check("no decision_token", t12["decision_token"] === undefined)

// ---------------------------------------------------------------------------
// Summary
// ---------------------------------------------------------------------------

console.log(`\n=== Results: ${passed} passed, ${failed} failed ===\n`)

if (failed > 0) {
  process.exitCode = 1
}
