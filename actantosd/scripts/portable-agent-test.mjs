import { randomUUID } from "node:crypto"
import process from "node:process"

const urlIndex = process.argv.indexOf("--url")
const baseUrl = urlIndex === -1 ? "http://127.0.0.1:4310" : process.argv[urlIndex + 1]
if (baseUrl === undefined) {
  throw new Error("--url requires a value")
}

const call = async (path, init) => {
  const response = await fetch(`${baseUrl}${path}`, init)
  if (!response.ok) {
    throw new Error(`${init?.method ?? "GET"} ${path} returned ${response.status}`)
  }
  return response.json()
}

const intercept = (request) => call("/v1/intercept/tool-call", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify(request),
})

const request = (overrides = {}) => ({
  request_id: `portable_${randomUUID()}`,
  tenant_id: "t_demo",
  agent: { id: "portable_agent", runtime_type: "custom", environment: "dev", risk_tier: "low" },
  subject: { user_id: "portable_user", role: "developer" },
  session: { id: "portable_session", cwd: "/workspace", budget_remaining_cents: 10_000 },
  tool: { kind: "file", name: "guarded_read", operation: "ReadFile", schema_hash: "" },
  resource: { id: "/workspace/README.md", kind: "file", path: "/workspace/README.md" },
  action: { operation: "ReadFile", args: { path: "/workspace/README.md" } },
  normalized: {
    verb: "read",
    mutation: false,
    destructive: false,
    network: false,
    credential_access: false,
    risk_class: "low",
  },
  ...overrides,
})

const expectDecision = (label, payload, expected) => {
  if (payload.decision !== expected) {
    throw new Error(`${label}: expected ${expected}, received ${String(payload.decision)}`)
  }
  console.log(`  PASS ${label}: ${expected}`)
}

console.log("Testing a portable agent through ActantOS")

const allowed = await intercept(request())
expectDecision("safe workspace read", allowed, "allow")

const denied = await intercept(request({
  resource: { id: "/workspace/.env", kind: "file", path: "/workspace/.env" },
  action: { operation: "ReadFile", args: { path: "/workspace/.env" } },
  normalized: {
    verb: "read",
    mutation: false,
    destructive: false,
    network: false,
    credential_access: true,
    risk_class: "critical",
  },
}))
expectDecision("credential read", denied, "deny")

const approval = await intercept(request({
  tool: { kind: "shell", name: "guarded_bash", operation: "ExecuteShellCommand", schema_hash: "" },
  resource: { id: "/workspace", kind: "workspace", path: "/workspace" },
  action: {
    operation: "ExecuteShellCommand",
    args: { command: "git push origin main", argv: ["git", "push", "origin", "main"] },
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
}))
expectDecision("remote agent action", approval, "approval_required")

const timeline = await call("/v1/sessions/portable_session/events")
if (!Array.isArray(timeline.events)) {
  throw new Error("agent audit timeline endpoint returned an invalid response")
}
if ([allowed, denied, approval].some((payload) => typeof payload.audit_event_id !== "string")) {
  throw new Error("agent decisions did not return audit event identifiers")
}
console.log("  PASS agent decisions returned audit evidence identifiers")
console.log("Portable agent test passed: 4 checks, 0 failed")
