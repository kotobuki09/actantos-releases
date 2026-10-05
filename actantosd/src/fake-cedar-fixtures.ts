import type { ToolCallContext } from "./contracts.ts"

/**
 * The authorization fixtures the FakeCedarProvider suites stand on.
 *
 * ## Why these are exported rather than written inline
 *
 * Each of these was originally a private `baseShellRequest` in its own test file, and each built
 * an "allow" as a precondition for asserting something unrelated — that the audit chain links,
 * that the tool result is recorded. That arrangement hid a real defect: `commandFromRequest`
 * derives the workspace as `dirname(resource.path)`, so `resource.path = "/workspace"` derives the
 * workspace `"/"`, and `policies/default.cedar` permits only `resource.path == "" ||
 * resource.workspace_path == "/workspace"`. The shipped policy denied those requests. They passed
 * because `FakeCedarProvider` is more permissive than production.
 *
 * Duplicated fixtures are what let that survive. A parity guard that re-declares the shape it
 * checks is checking its own copy: removing `host_workspace_path` from the real fixture left the
 * guard green. So the fixtures live here, once, and `cedar-fixture-parity.test.ts` evaluates these
 * exact objects against the real `cedar-policy-cli`.
 *
 * ## The `host_workspace_path` field is load-bearing
 *
 * It is not decoration. Delete it and the derived workspace becomes `"/"`, the shipped policy
 * denies, and the parity test fails by name.
 */

/** The default approved workspace. Matches `policies/default.cedar`. */
export const APPROVED_WORKSPACE = "/workspace"

/**
 * A shell request for a resource in the approved workspace, with the workspace declared.
 *
 * `requestId` varies because two suites assert on request identity; the authorization-relevant
 * fields are otherwise identical, which is the point of sharing one definition.
 */
export const approvedWorkspaceShellRequest = (
  requestId = "req_fixture_0001",
): ToolCallContext => ({
  request_id: requestId,
  tenant_id: "t_demo",
  agent: {
    id: "pi_demo",
    runtime_type: "pi",
    environment: "dev",
    risk_tier: "low",
  },
  subject: {
    user_id: "u_demo",
    role: "developer",
  },
  session: {
    id: "s_demo",
    cwd: APPROVED_WORKSPACE,
    budget_remaining_cents: 10_000,
  },
  // The PDP evaluates a ToolCallContext, which carries the scope hash a decision is bound to. It
  // plays no part in Cedar's evaluation, but omitting it would make these fixtures unusable with
  // the real provider — and a fixture the real authorizer cannot be handed is exactly what this
  // module exists to eliminate.
  scope_hash: "scope_fixture_0001",
  tool: {
    kind: "shell",
    name: "guarded_bash",
    operation: "ExecuteShellCommand",
    schema_hash: "",
  },
  resource: {
    id: APPROVED_WORKSPACE,
    kind: "workspace",
    path: APPROVED_WORKSPACE,
  },
  action: {
    operation: "ExecuteShellCommand",
    args: {
      command: "printf hello",
      argv: ["printf", "hello"],
      host_workspace_path: APPROVED_WORKSPACE,
    },
  },
  normalized: {
    verb: "execute",
    mutation: false,
    destructive: false,
    network: false,
    credential_access: false,
    risk_class: "low",
    command_family: "printf",
    subcommand: "hello",
  },
})

/**
 * The same request with credential access flagged.
 *
 * Used to check that the fake's one real rule — `credential_access` denies — still matches what
 * the shipped policy does, rather than assuming it does.
 */
export const credentialAccessShellRequest = (): ToolCallContext => {
  const request = approvedWorkspaceShellRequest("req_fixture_0002")
  return { ...request, normalized: { ...request.normalized, credential_access: true } }
}

/**
 * An MCP tool call shaped exactly as `src/mcp-gateway.ts` builds one.
 *
 * This is not a fixture defect. `mcp-gateway.ts` derives `resource.path` as
 * `/mcp/<server>/tools/<tool>` in production code and sets no `host_workspace_path`, so the
 * derived workspace is the `tools` directory and the shipped policy denies every MCP tool call.
 * The gateway tests hide that behind the fake.
 *
 * It lives here so `cedar-fixture-parity.test.ts` can assert the divergence against the shape
 * production actually produces, rather than against a shape someone hoped production produced.
 */
export const mcpToolCallRequest = (): ToolCallContext =>
  ({
    request_id: "req_fixture_0003",
    tenant_id: "t_demo",
    agent: {
      id: "pi_demo",
      runtime_type: "pi",
      environment: "dev",
      risk_tier: "low",
    },
    subject: {
      user_id: "u_demo",
      role: "developer",
    },
    session: {
      id: "s_demo",
      cwd: APPROVED_WORKSPACE,
      budget_remaining_cents: 10_000,
    },
    scope_hash: "scope_fixture_0003",
    tool: {
      kind: "mcp",
      name: "read_repo_file",
      operation: "tools/call",
      schema_hash: "abc",
    },
    resource: {
      id: "mcp://github/tools/read_repo_file",
      kind: "mcp_tool",
      path: "/mcp/github/tools/read_repo_file",
    },
    action: {
      operation: "tools/call",
      name: "read_repo_file",
      args: { path: "README.md" },
    },
    normalized: {
      verb: "execute",
      mutation: false,
      destructive: false,
      network: false,
      credential_access: false,
      risk_class: "low",
      command_family: "read",
      subcommand: "read",
    },
  })