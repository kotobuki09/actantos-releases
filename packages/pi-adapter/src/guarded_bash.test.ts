import assert from "node:assert/strict"
import { createHmac } from "node:crypto"
import http from "node:http"
import test from "node:test"
import type { AddressInfo } from "node:net"
import { EventEmitter } from "node:events"

import { ApprovalRequired } from "./errors.ts"
import {
  approveAndResumeGuardedBash,
  guardedBash,
  type GuardedBashDependencies,
  type GuardedBashPlan,
  runGuardedBash,
} from "./guarded_bash.ts"

type CapturedRequest = Record<string, unknown>

type StubServer = {
  readonly url: string
  readonly requests: CapturedRequest[]
  readonly close: () => Promise<void>
}

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null

const getAddressInfo = (value: string | AddressInfo | null): AddressInfo => {
  if (value === null || typeof value === "string") {
    throw new Error("server did not expose an AddressInfo result")
  }

  return value
}

const parseCapturedRequest = (value: unknown): CapturedRequest => {
  if (!isRecord(value)) {
    throw new Error("captured request payload was not an object")
  }

  return value
}

const getCapturedRequest = (requests: readonly CapturedRequest[]): CapturedRequest => {
  const request = requests[0]
  if (request === undefined) {
    throw new Error("expected a captured request")
  }

  return request
}

const getCapturedRequestAt = (
  requests: readonly CapturedRequest[],
  index: number,
): CapturedRequest => {
  const request = requests[index]
  if (request === undefined) {
    throw new Error(`expected a captured request at index ${String(index)}`)
  }

  return request
}

const getNestedRecord = (
  record: CapturedRequest,
  key: string,
): Record<string, unknown> => {
  const value = record[key]
  if (!isRecord(value)) {
    throw new Error(`expected ${key} to be an object`)
  }

  return value
}

const withStubServer = async (responseBody: object): Promise<StubServer> => {
  const requests: CapturedRequest[] = []
  const server = http.createServer((request, response) => {
    const chunks: Buffer[] = []
    request.on("data", (chunk: Buffer) => {
      chunks.push(chunk)
    })
    request.on("end", () => {
      requests.push(parseCapturedRequest(JSON.parse(Buffer.concat(chunks).toString("utf8"))))
      response.writeHead(200, { "content-type": "application/json" })
      response.end(JSON.stringify(responseBody))
    })
  })

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve())
  })

  const address = getAddressInfo(server.address())
  return {
    url: `http://127.0.0.1:${address.port}/v1/intercept/tool-call`,
    requests,
    close: async () => {
      await new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error !== undefined) {
            reject(error)
            return
          }
          resolve()
        })
      })
    },
  }
}

const createDependencies = (interceptUrl: string): GuardedBashDependencies => ({
  workspaceRoot: "/workspace",
  interceptUrl,
  tenantId: "t_demo",
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
    cwd: "/workspace",
    budget_remaining_cents: 10_000,
  },
  requestIdFactory: () => "req_70000001",
})

const assertAllowedPlan = (value: GuardedBashPlan): GuardedBashPlan => value

class FakeStream extends EventEmitter {}

class FakeChildProcess extends EventEmitter {
  readonly stdout = new FakeStream()
  readonly stderr = new FakeStream()
  #onKill?: () => void

  setOnKill(onKill: () => void): void {
    this.#onKill = onKill
  }

  kill(_signal?: NodeJS.Signals): boolean {
    this.#onKill?.()
    return true
  }
}

const signDecisionToken = (payload: string, secret: string): string =>
  `${Buffer.from(payload, "utf8").toString("base64url")}.${createHmac("sha256", secret).update(payload).digest("base64url")}`

const createDecisionToken = (
  overrides: Partial<{
    request_id: string
    tenant_id: string
    agent_id: string
    session_id: string
    tool_name: string
  }> = {},
  secret = "adapter-secret",
): string =>
  signDecisionToken(
    JSON.stringify({
      request_id: "req_70000001",
      tenant_id: "t_demo",
      agent_id: "pi_demo",
      session_id: "s_demo",
      tool_name: "guarded_bash",
      ...overrides,
    }),
    secret,
  )

const createFetchHarness = (options: {
  readonly interceptResponse: Record<string, unknown>
}) => {
  const toolResults: Record<string, unknown>[] = []

  const fetchImpl = async (input: string, init?: RequestInit): Promise<Response> => {
    const url = typeof input === "string" ? input : String(input)
    const body = init?.body === undefined
      ? undefined
      : JSON.parse(String(init.body)) as Record<string, unknown>

    if (url.endsWith("/v1/intercept/tool-call")) {
      return new Response(JSON.stringify(options.interceptResponse), {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    }

    if (url.endsWith("/v1/tool-result")) {
      if (body !== undefined) {
        toolResults.push(body)
      }
      return new Response(JSON.stringify({ recorded_at: "2026-07-06T00:00:00.000Z" }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    }

    throw new Error(`unexpected fetch url: ${url}`)
  }

  return { fetchImpl, toolResults }
}

test("Given a low-risk command when guardedBash runs Then it returns an argv execution plan", async () => {
  const server = await withStubServer({
    decision: "allow",
    decision_id: "5f2de0d5-c5a8-4348-b553-aef4fb9f7052",
    reason: "permitted by policy",
    reason_code: "allowed",
    decision_token: "decision-token-123",
    constraints: {
      network_mode: "none",
      timeout_ms: 30_000,
    },
  })

  try {
    const plan = assertAllowedPlan(
      await guardedBash(createDependencies(server.url), "printf hello"),
    )

    assert.deepEqual(plan.argv, ["printf", "hello"])
    assert.equal(plan.decisionId, "5f2de0d5-c5a8-4348-b553-aef4fb9f7052")
    assert.equal(plan.decisionToken, "decision-token-123")
    assert.equal(plan.constraints?.network_mode, "none")

    const request = getCapturedRequest(server.requests)
    assert.equal(getNestedRecord(request, "tool")["name"], "guarded_bash")
    assert.equal(getNestedRecord(request, "normalized")["command_family"], "printf")
    assert.equal(getNestedRecord(request, "normalized")["subcommand"], "hello")
  } finally {
    await server.close()
  }
})

test("Given git push when guardedBash runs Then it throws ApprovalRequired and sends shell risk metadata", async () => {
  const server = await withStubServer({
    decision: "approval_required",
    decision_id: "9bf74718-5539-4e2e-9f47-fd63ce0cb4f6",
    reason: "risk.shell.git_push - approval required",
    reason_code: "approval_required",
    approval: {
      approval_id: "4a26995d-551d-4671-8f38-e24f8cc48bc2",
    },
  })

  try {
    await assert.rejects(
      guardedBash(createDependencies(server.url), "git push --dry-run origin main"),
      (error: unknown) =>
        error instanceof ApprovalRequired &&
        error.approvalId === "4a26995d-551d-4671-8f38-e24f8cc48bc2",
    )

    const request = getCapturedRequest(server.requests)
    const normalized = getNestedRecord(request, "normalized")
    assert.equal(normalized["command_family"], "git")
    assert.equal(normalized["subcommand"], "push")
    assert.equal(normalized["network"], true)
    assert.equal(normalized["mutation"], true)
  } finally {
    await server.close()
  }
})

test("Given an ambiguous shell string when guardedBash runs Then it routes it as approval-required high risk", async () => {
  const server = await withStubServer({
    decision: "approval_required",
    decision_id: "8f2b2847-4b36-4108-a846-83df44f983d8",
    reason: "risk.shell.ambiguous - approval required",
    reason_code: "approval_required",
    approval: {
      approval_id: "12f9c1db-80cb-465b-b79f-42bcd9f754fd",
    },
  })

  try {
    await assert.rejects(
      guardedBash(createDependencies(server.url), "git push && echo shipped"),
      (error: unknown) =>
        error instanceof ApprovalRequired &&
        error.approvalId === "12f9c1db-80cb-465b-b79f-42bcd9f754fd",
    )

    const request = getCapturedRequest(server.requests)
    const normalized = getNestedRecord(request, "normalized")
    const action = getNestedRecord(request, "action")
    const args = getNestedRecord(action, "args")
    assert.equal(normalized["target_type"], "ambiguous_shell")
    assert.equal(normalized["command_family"], "__ambiguous__")
    assert.deepEqual(args["argv"], [])
  } finally {
    await server.close()
  }
})

test("Given an approval-required shell command when approval is granted Then approveAndResumeGuardedBash re-submits with a new request id and token", async () => {
  const requests: CapturedRequest[] = []
  let callCount = 0
  const server = http.createServer((request, response) => {
    const chunks: Buffer[] = []
    request.on("data", (chunk: Buffer) => {
      chunks.push(chunk)
    })
    request.on("end", () => {
      requests.push(parseCapturedRequest(JSON.parse(Buffer.concat(chunks).toString("utf8"))))

      if (request.url?.includes("/v1/approvals/")) {
        response.writeHead(200, { "content-type": "application/json" })
        response.end(
          JSON.stringify({
            approval_id: "6d0c8663-0204-4965-bc6c-2f1bfa7cf24f",
            decision: "approved",
            approval_token: "one-use-token",
            decided_at: "2026-07-06T00:00:00.000Z",
            expires_at: "2026-07-06T00:10:00.000Z",
          }),
        )
        return
      }

      callCount += 1
      response.writeHead(200, { "content-type": "application/json" })
      if (callCount === 1) {
        response.end(
          JSON.stringify({
            decision: "approval_required",
            decision_id: "745e9467-cf6f-442a-998b-0b0fe4efd52f",
            reason: "risk.shell.git_push - approval required",
            reason_code: "approval_required",
            approval: {
              approval_id: "6d0c8663-0204-4965-bc6c-2f1bfa7cf24f",
            },
          }),
        )
        return
      }

      response.end(
          JSON.stringify({
            decision: "allow",
            decision_id: "a9908a15-feb4-4057-bfc4-1ab0ec4366ff",
            reason: "approval verified - action permitted",
            reason_code: "allowed",
          decision_token: "decision-token-456",
          constraints: {
            network_mode: "egress_proxy",
          },
        }),
      )
    })
  })

  await new Promise<void>((resolve) => {
    server.listen(0, "127.0.0.1", () => resolve())
  })

  const address = getAddressInfo(server.address())
  const dependencies: GuardedBashDependencies = {
    ...createDependencies(`http://127.0.0.1:${address.port}/v1/intercept/tool-call`),
    requestIdFactory: (() => {
      let index = 0
      return () => `req_7000000${String(++index)}`
    })(),
  }

  try {
    let pendingApproval: ApprovalRequired | undefined

    try {
      await guardedBash(dependencies, "git push --dry-run origin main")
      assert.fail("expected guardedBash to require approval")
    } catch (error) {
      assert.ok(error instanceof ApprovalRequired)
      pendingApproval = error
    }

    const plan = await approveAndResumeGuardedBash(
      dependencies,
      "git push --dry-run origin main",
      pendingApproval,
      "u_admin",
    )

    assert.deepEqual(plan.argv, ["git", "push", "--dry-run", "origin", "main"])
    assert.equal(plan.decisionId, "a9908a15-feb4-4057-bfc4-1ab0ec4366ff")
    assert.equal(plan.decisionToken, "decision-token-456")
    assert.equal(plan.constraints?.network_mode, "egress_proxy")

    assert.equal(requests.length, 3)
    const firstIntercept = getCapturedRequestAt(requests, 0)
    const approvalBody = getCapturedRequestAt(requests, 1)
    const secondIntercept = getCapturedRequestAt(requests, 2)
    assert.equal(firstIntercept["request_id"], "req_70000001")
    assert.equal(approvalBody["decision"], "approved")
    assert.equal(approvalBody["approver_user_id"], "u_admin")
    assert.equal(secondIntercept["request_id"], "req_70000002")
    const authorization = getNestedRecord(secondIntercept, "authorization")
    assert.equal(authorization["approval_id"], "6d0c8663-0204-4965-bc6c-2f1bfa7cf24f")
    assert.equal(authorization["approval_token"], "one-use-token")
  } finally {
    await new Promise<void>((resolve, reject) => {
      server.close((error) => {
        if (error !== undefined) {
          reject(error)
          return
        }
        resolve()
      })
    })
  }
})

test("Given an allowed shell plan when runGuardedBash executes Then it posts an executed tool result", async () => {
  const harness = createFetchHarness({
    interceptResponse: {
      decision: "allow",
      decision_id: "8d76c6b7-b739-42a3-a7ef-a42b284b830f",
      reason: "permitted by policy",
      reason_code: "allowed",
      decision_token: createDecisionToken(),
      constraints: {
        network_mode: "none",
        timeout_ms: 30_000,
        max_output_bytes: 200_000,
      },
    },
  })

  const dependencies: GuardedBashDependencies = {
    ...createDependencies("http://actantos.test/v1/intercept/tool-call"),
    fetchImpl: harness.fetchImpl,
  }

  const spawnHandlers = [
    (child: FakeChildProcess) => {
      setImmediate(() => {
        child.emit("exit", 0)
      })
    },
    (child: FakeChildProcess) => {
      setImmediate(() => {
        child.stdout.emit("data", Buffer.from("hello\n"))
        child.emit("exit", 0)
      })
    },
  ]

  const result = await runGuardedBash(
    dependencies,
    "printf hello",
    {
      hmacSecret: "adapter-secret",
      spawnCommand: (_command, _args) => {
        const child = new FakeChildProcess()
        const handler = spawnHandlers.shift()
        if (handler === undefined) {
          throw new Error("unexpected spawn call")
        }
        handler(child)
        return child as never
      },
    },
  )

  assert.equal(result.status, "executed")
  assert.equal(harness.toolResults.length, 1)
  assert.equal(harness.toolResults[0]?.["status"], "executed")
  assert.equal(harness.toolResults[0]?.["decision_id"], "8d76c6b7-b739-42a3-a7ef-a42b284b830f")
  assert.equal(typeof harness.toolResults[0]?.["decision_token"], "string")
})

test("Given a non-zero exit shell command when runGuardedBash executes Then it posts a failed tool result", async () => {
  const harness = createFetchHarness({
    interceptResponse: {
      decision: "allow",
      decision_id: "3fec4ca8-42c5-4853-9c28-d73c8b9222dd",
      reason: "permitted by policy",
      reason_code: "allowed",
      decision_token: createDecisionToken(),
      constraints: {
        network_mode: "none",
        timeout_ms: 30_000,
        max_output_bytes: 200_000,
      },
    },
  })

  const dependencies: GuardedBashDependencies = {
    ...createDependencies("http://actantos.test/v1/intercept/tool-call"),
    fetchImpl: harness.fetchImpl,
  }

  const spawnHandlers = [
    (child: FakeChildProcess) => {
      setImmediate(() => {
        child.emit("exit", 0)
      })
    },
    (child: FakeChildProcess) => {
      setImmediate(() => {
        child.stderr.emit("data", Buffer.from("boom"))
        child.emit("exit", 5)
      })
    },
  ]

  const result = await runGuardedBash(
    dependencies,
    "printf hello",
    {
      hmacSecret: "adapter-secret",
      spawnCommand: (_command, _args) => {
        const child = new FakeChildProcess()
        const handler = spawnHandlers.shift()
        if (handler === undefined) {
          throw new Error("unexpected spawn call")
        }
        handler(child)
        return child as never
      },
    },
  )

  assert.equal(result.status, "failed")
  assert.equal(harness.toolResults[0]?.["status"], "failed")
  assert.equal(
    (harness.toolResults[0]?.["result"] as Record<string, unknown>)["error_message"],
    "docker command exited with code 5",
  )
})

test("Given a timed out shell command when runGuardedBash executes Then it posts a timeout tool result", async () => {
  const harness = createFetchHarness({
    interceptResponse: {
      decision: "allow",
      decision_id: "4ea4e795-f42c-472f-8d94-45152c3b53ae",
      reason: "permitted by policy",
      reason_code: "allowed",
      decision_token: createDecisionToken(),
      constraints: {
        network_mode: "none",
        timeout_ms: 5,
        max_output_bytes: 200_000,
      },
    },
  })

  const dependencies: GuardedBashDependencies = {
    ...createDependencies("http://actantos.test/v1/intercept/tool-call"),
    fetchImpl: harness.fetchImpl,
  }

  const spawnHandlers = [
    (child: FakeChildProcess) => {
      setImmediate(() => {
        child.emit("exit", 0)
      })
    },
    (child: FakeChildProcess) => {
      child.setOnKill(() => {
        setImmediate(() => {
          child.emit("exit", null)
        })
      })
    },
  ]

  const result = await runGuardedBash(
    dependencies,
    "printf hello",
    {
      hmacSecret: "adapter-secret",
      spawnCommand: (_command, _args) => {
        const child = new FakeChildProcess()
        const handler = spawnHandlers.shift()
        if (handler === undefined) {
          throw new Error("unexpected spawn call")
        }
        handler(child)
        return child as never
      },
    },
  )

  assert.equal(result.status, "timeout")
  assert.equal(harness.toolResults[0]?.["status"], "timeout")
  assert.equal(
    (harness.toolResults[0]?.["result"] as Record<string, unknown>)["error_message"],
    "docker execution timed out",
  )
})

test("Given an approval-required shell command when runGuardedBash executes Then it posts a blocked tool result and rethrows", async () => {
  const harness = createFetchHarness({
    interceptResponse: {
      decision: "approval_required",
      decision_id: "8b93f97f-ea12-440a-a2d2-fdb0c2946de5",
      reason: "risk.shell.git_push - approval required",
      reason_code: "approval_required",
      approval: {
        approval_id: "3f5a1d16-bfe5-4ea3-b450-b9f16e2ff8a9",
      },
    },
  })

  const dependencies: GuardedBashDependencies = {
    ...createDependencies("http://actantos.test/v1/intercept/tool-call"),
    fetchImpl: harness.fetchImpl,
  }

  await assert.rejects(
    runGuardedBash(
      dependencies,
      "git push --dry-run origin main",
      {
        hmacSecret: "adapter-secret",
      },
    ),
    (error: unknown) =>
      error instanceof ApprovalRequired &&
      error.approvalId === "3f5a1d16-bfe5-4ea3-b450-b9f16e2ff8a9",
  )

  assert.equal(harness.toolResults.length, 1)
  assert.equal(harness.toolResults[0]?.["status"], "blocked")
  assert.equal(harness.toolResults[0]?.["decision_id"], "8b93f97f-ea12-440a-a2d2-fdb0c2946de5")
  assert.equal(harness.toolResults[0]?.["decision_token"], undefined)
})
