import assert from "node:assert/strict"
import test from "node:test"

import { buildServer } from "../server.ts"
import type { ToolCallInterceptionRequest } from "../contracts.ts"
import { EGRESS_BROKER_REQUIRED, resolveEgressCellMode, type EgressCellMode } from "./egress-cell.ts"

/**
 * Phase G end to end: the egress cell, on a real server, changing a real decision.
 *
 * `egress-cell.test.ts` proves the mode semantics and `egress-proxy.test.ts` proves the proxy over
 * real sockets. Neither proves that `broker_only` is consulted on a live request — and a rule that
 * exists and is never read is not enforcement.
 *
 * The cell mode is process-scoped by design, so these tests inject it rather than setting an env
 * var. That is the one gap this file cannot close, and `resolveEgressCellMode` is tested directly
 * in `egress-cell.test.ts` instead.
 */

const TENANT = "t_cell"
const AGENT = "pi_demo"

const toolCall = (
  overrides: Partial<ToolCallInterceptionRequest> = {},
): ToolCallInterceptionRequest => ({
  request_id: `req_cell_${Math.random().toString(36).slice(2, 10)}`,
  tenant_id: TENANT,
  agent: { id: AGENT, runtime_type: "pi", environment: "dev", risk_tier: "low" },
  subject: { user_id: "u_demo", role: "developer" },
  session: { id: "s_demo", cwd: "/workspace", budget_remaining_cents: 10_000 },
  tool: { kind: "github", name: "github.issues.read", operation: "ReadIssues" },
  resource: { url: "https://api.github.com/repos/org/repo/issues" },
  action: { operation: "ReadIssues", args: {} },
  normalized: {
    verb: "read",
    mutation: false,
    destructive: false,
    network: true,
    credential_access: false,
    risk_class: "low",
  },
  ...overrides,
})

/** The same call, but one that needs no network at all. */
const offlineToolCall = (): ToolCallInterceptionRequest =>
  toolCall({
    tool: { kind: "file", name: "file.read", operation: "ReadFile" },
    resource: { url: "file:///workspace/README.md" },
    action: { operation: "ReadFile", args: {} },
    normalized: {
      verb: "read",
      mutation: false,
      destructive: false,
      network: false,
      credential_access: false,
      risk_class: "low",
    },
  })

const startServer = (egressCellMode?: EgressCellMode) =>
  buildServer({
    hmacSecret: "cell-test-secret",
    logger: false,
    ...(egressCellMode === undefined ? {} : { egressCellMode }),
  })

const intercept = async (
  server: ReturnType<typeof buildServer>,
  body: ToolCallInterceptionRequest,
): Promise<{ readonly decision: string; readonly reason_code: string }> => {
  const response = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: body,
  })

  const parsed = response.json() as { decision: string; reason_code: string }
  return { decision: parsed.decision, reason_code: parsed.reason_code }
}

test("S2: with no cell mode configured, a network call behaves exactly as v1 did", async () => {
  const server = startServer()
  await server.ready()

  try {
    const result = await intercept(server, toolCall())

    // The default is `none`, and under `none` v1 already produced this allow with a network
    // constraint. If this ever starts denying, the default has silently become a policy change.
    assert.equal(result.decision, "allow")
    assert.notEqual(result.reason_code, EGRESS_BROKER_REQUIRED)
  } finally {
    await server.close()
  }
})

test("S2: broker_only denies a call that needs a network, with its own reason code", async () => {
  const server = startServer("broker_only")
  await server.ready()

  try {
    const result = await intercept(server, toolCall())

    assert.equal(result.decision, "deny")
    assert.equal(result.reason_code, EGRESS_BROKER_REQUIRED)
  } finally {
    await server.close()
  }
})

test("S2: broker_only leaves a call that needs no network alone", async () => {
  const server = startServer("broker_only")
  await server.ready()

  try {
    const result = await intercept(server, offlineToolCall())

    // The mode is about networks, not about denying everything. A cell that broke working calls
    // would be turned off, and then it would not be a cell.
    assert.equal(result.decision, "allow")
    assert.notEqual(result.reason_code, EGRESS_BROKER_REQUIRED)
  } finally {
    await server.close()
  }
})

test("S2: none denies nothing on its own, and egress_proxy does not deny at decision time", async () => {
  const none = startServer("none")
  const proxy = startServer("egress_proxy")

  await none.ready()
  await proxy.ready()

  try {
    // `egress_proxy` constrains where a connection may be *opened*, which is the proxy's job at
    // connect time. Denying here would be the decision layer second-guessing a check it cannot
    // make, and would make the proxy unreachable for the requests it exists to authorise.
    assert.equal((await intercept(none, toolCall())).decision, "allow")
    assert.equal((await intercept(proxy, toolCall())).decision, "allow")
  } finally {
    await none.close()
    await proxy.close()
  }
})

test("S2: the operator's mode string reaches the service through the same strict parse", async () => {
  // The wiring above takes an already-parsed mode, so this pins the two halves together: a bad
  // ACTANTOS_EGRESS_CELL never becomes a value the service could be built with.
  assert.equal(resolveEgressCellMode("broker_only"), "broker_only")
  assert.throws(() => resolveEgressCellMode("broker only"), /ACTANTOS_EGRESS_CELL/u)
  assert.throws(() => resolveEgressCellMode("brokeronly"), /ACTANTOS_EGRESS_CELL/u)
})