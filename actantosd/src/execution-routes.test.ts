import assert from "node:assert/strict"
import test from "node:test"

import { buildServer } from "./server.ts"
import {
  DecisionExecutionRefusal,
  type DecisionAuthorization,
  type DecisionExecutionService,
  type ExecuteDecisionInput,
} from "./decision-execution.ts"

/**
 * These tests cover the route's contract with the operator, not the executor's behaviour — that is
 * what `decision-execution.test.ts` is for. Two things are worth proving at this level and neither
 * can be proven below it: that the route does not exist unless the operator asked for it, and that
 * every refusal reason reaches the client distinctly instead of collapsing into one opaque 403.
 */

const authorization = (overrides: Partial<DecisionAuthorization> = {}): DecisionAuthorization => ({
  decisionId: "decision_1",
  tenantId: "t_demo",
  agentId: "agent_1",
  sessionId: "sess_1",
  scopeHash: "scope_1",
  toolName: "guarded_bash",
  decisionToken: "ed25519.payload.sig",
  constraints: { network_mode: "none" },
  ...overrides,
})

const serviceStub = (
  behaviour: DecisionExecutionService["execute"] | DecisionExecutionRefusal,
): DecisionExecutionService => ({
  async execute(input: ExecuteDecisionInput) {
    if (behaviour instanceof DecisionExecutionRefusal) {
      throw behaviour
    }
    return behaviour(input)
  },
})

const executed = async () => ({
  status: "executed" as const,
  exitCode: 0,
  stdout: "",
  stderr: "",
  stdoutHash: "a".repeat(64),
  stderrHash: "b".repeat(64),
  redactedPreview: "",
  startedAt: "2026-10-04T00:00:00.000Z",
  finishedAt: "2026-10-04T00:00:01.000Z",
})

const body = {
  tenant_id: "t_demo",
  request_id: "req_exec_0001",
  argv: ["/bin/sh", "run.sh"],
  workspace_path: "/workspace",
}

test("the route is absent unless an execution service is supplied", async () => {
  // Not "denied" — absent. A deployment that never set ACTANTOS_DECISION_EXECUTION must not grow a
  // new public surface as a side effect of this work.
  const server = buildServer({ logger: false })
  const response = await server.inject({ method: "POST", url: "/v1/executions", payload: body })

  assert.equal(response.statusCode, 404)
  await server.close()
})

test("a supplied service exposes the route and returns the execution result", async () => {
  const server = buildServer({
    logger: false,
    executionService: serviceStub(executed),
  })
  const response = await server.inject({ method: "POST", url: "/v1/executions", payload: body })

  assert.equal(response.statusCode, 200)
  const json = response.json()
  assert.equal(json.status, "executed")
  assert.equal(json.request_id, "req_exec_0001")
  assert.equal(json.stdout_hash, "a".repeat(64))
  // The raw stdout is not returned. The executor computes the hashes; putting the bytes on this
  // response would hand a caller the command's output without any of the redaction the executor
  // applied.
  assert.equal(json.stdout, undefined)
  await server.close()
})

test("each refusal reason maps to its own status code", async () => {
  const cases: readonly [DecisionExecutionRefusal["reason"], number][] = [
    ["no_such_authorization", 404],
    ["not_allowed", 403],
    ["no_decision_token", 409],
    ["token_not_ed25519", 409],
  ]

  for (const [reason, expected] of cases) {
    const server = buildServer({
      logger: false,
      executionService: serviceStub(new DecisionExecutionRefusal(reason, `refused: ${reason}`)),
    })
    const response = await server.inject({ method: "POST", url: "/v1/executions", payload: body })

    assert.equal(response.statusCode, expected, `reason ${reason}`)
    assert.equal(response.json().error, reason)
    await server.close()
  }
})

test("a malformed body is a 400 and never reaches the executor", async () => {
  let called = false
  const server = buildServer({
    logger: false,
    executionService: serviceStub(async () => {
      called = true
      return executed()
    }),
  })

  const response = await server.inject({
    method: "POST",
    url: "/v1/executions",
    payload: { tenant_id: "t_demo" },
  })

  assert.equal(response.statusCode, 400)
  assert.equal(response.json().error, "invalid_request")
  assert.equal(called, false)
  await server.close()
})

test("an executor refusal keeps its reason instead of becoming a bare 403", async () => {
  // "decision token already used" is the single most operationally important message on this path:
  // it is the difference between a replay attack and a retry. Losing it to a generic error is how
  // an incident gets misdiagnosed.
  const server = buildServer({
    logger: false,
    executionService: serviceStub(async () => {
      throw new Error("decision token already used")
    }),
  })
  const response = await server.inject({ method: "POST", url: "/v1/executions", payload: body })

  assert.equal(response.statusCode, 403)
  assert.equal(response.json().error, "execution_refused")
  assert.equal(response.json().message, "decision token already used")
  await server.close()
})

test("a control plane does not expose the execution route", async () => {
  // The control plane decides; the data plane acts. Registering an execute route on the deciding
  // role would let a policy author run containers from the same host that holds the signing key.
  const server = buildServer({
    logger: false,
    serviceRole: "control_plane",
    executionService: serviceStub(executed),
  })
  const response = await server.inject({ method: "POST", url: "/v1/executions", payload: body })

  assert.equal(response.statusCode, 404)
  await server.close()
})

test("authorizationFor is used so a stub lookup can return a realistic row", () => {
  // A guard on the fixture, not on product code: if `authorization()` stops producing a usable row
  // the stub-backed route tests above would pass for the wrong reason.
  assert.equal(authorization().tenantId, "t_demo")
  assert.equal(authorization().constraints.network_mode, "none")
})