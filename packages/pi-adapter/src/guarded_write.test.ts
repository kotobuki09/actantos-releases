import assert from "node:assert/strict"
import fs from "node:fs"
import http from "node:http"
import type { AddressInfo } from "node:net"
import os from "node:os"
import path from "node:path"
import test from "node:test"

import { ApprovalRequired, GuardedAccessDenied } from "./errors.ts"
import { guardedWrite, type GuardedWriteDependencies } from "./guarded_write.ts"

type CapturedRequest = Record<string, unknown>

type StubServer = {
  readonly url: string
  readonly requests: CapturedRequest[]
  readonly toolResults: CapturedRequest[]
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

const createWorkspace = () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pi-adapter-write-"))
  const workspaceRoot = path.join(root, "workspace")
  const siblingRoot = path.join(root, "workspace2")
  fs.mkdirSync(workspaceRoot, { recursive: true })
  fs.mkdirSync(siblingRoot, { recursive: true })
  return { root, workspaceRoot, siblingRoot }
}

const withStubServer = async (responseBody: object): Promise<StubServer> => {
  const requests: CapturedRequest[] = []
  const toolResults: CapturedRequest[] = []

  const server = http.createServer((request, response) => {
    const chunks: Buffer[] = []
    request.on("data", (chunk: Buffer) => {
      chunks.push(chunk)
    })
    request.on("end", () => {
      const payload = parseCapturedRequest(JSON.parse(Buffer.concat(chunks).toString("utf8")))
      if (request.url?.endsWith("/v1/tool-result")) {
        toolResults.push(payload)
      } else {
        requests.push(payload)
      }
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
    toolResults,
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

const createDependencies = (
  workspaceRoot: string,
  interceptUrl: string,
): GuardedWriteDependencies => ({
  workspaceRoot,
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
    cwd: workspaceRoot,
    budget_remaining_cents: 10_000,
  },
  requestIdFactory: () => "req_00000002",
})

test("Given a safe workspace target when guardedWrite runs Then it writes after an allow decision", async () => {
  const { workspaceRoot } = createWorkspace()
  const server = await withStubServer({
    decision: "allow",
    decision_id: "cd3af89a-10b8-42b7-946b-2e1da7c2843b",
    reason: "permitted by policy",
    reason_code: "allowed",
    decision_token: "write-token-123",
  })

  try {
    await guardedWrite(createDependencies(workspaceRoot, server.url), "todo.txt", "ship it")

    assert.equal(fs.readFileSync(path.join(workspaceRoot, "todo.txt"), "utf8"), "ship it")
    assert.equal(server.requests.length, 1)
    assert.equal(server.toolResults.length, 1)
    const request = getCapturedRequest(server.requests)
    assert.equal(getNestedRecord(request, "resource")["path"], "/workspace/todo.txt")
    assert.equal(getNestedRecord(getNestedRecord(request, "action"), "args")["path"], "/workspace/todo.txt")
    assert.equal(getNestedRecord(request, "normalized")["mutation"], true)
    assert.equal(getNestedRecord(request, "normalized")["credential_access"], false)
    assert.equal(server.toolResults[0]?.["status"], "executed")
    assert.equal(server.toolResults[0]?.["decision_id"], "cd3af89a-10b8-42b7-946b-2e1da7c2843b")
  } finally {
    await server.close()
  }
})

test("Given a credential target when guardedWrite runs Then it blocks without writing bytes", async () => {
  const { workspaceRoot } = createWorkspace()
  const server = await withStubServer({
    decision: "deny",
    decision_id: "1ba2f94a-9dae-403d-a9d4-7a6e2a6b99e2",
    reason: "blocked by policy",
    reason_code: "policy_forbid.credential_path",
  })

  try {
    await assert.rejects(
      guardedWrite(createDependencies(workspaceRoot, server.url), ".env", "SECRET=1"),
      (error: unknown) =>
        error instanceof GuardedAccessDenied &&
        error.reasonCode === "policy_forbid.credential_path",
    )

    assert.equal(fs.existsSync(path.join(workspaceRoot, ".env")), false)
    assert.equal(server.requests.length, 1)
    assert.equal(server.toolResults.length, 1)
    assert.equal(
      getNestedRecord(getCapturedRequest(server.requests), "normalized")["credential_access"],
      true,
    )
    assert.equal(server.toolResults[0]?.["status"], "blocked")
  } finally {
    await server.close()
  }
})

test("Given a traversal target when guardedWrite runs Then it denies before calling the intercept service", async () => {
  const { workspaceRoot } = createWorkspace()
  const server = await withStubServer({
    decision: "allow",
    decision_id: "8320837d-fb1c-4129-afad-b7ead108187a",
    reason: "permitted by policy",
    reason_code: "allowed",
    decision_token: "write-token-234",
  })

  try {
    await assert.rejects(
      guardedWrite(createDependencies(workspaceRoot, server.url), path.join("..", "outside.txt"), "nope"),
      (error: unknown) =>
        error instanceof GuardedAccessDenied &&
        error.reasonCode === "canonicalization_failed",
    )

    assert.equal(server.requests.length, 0)
    assert.equal(fs.existsSync(path.join(workspaceRoot, "..", "outside.txt")), false)
  } finally {
    await server.close()
  }
})

test("Given an approval-required decision when guardedWrite runs Then it blocks without writing", async () => {
  const { workspaceRoot } = createWorkspace()
  const targetPath = path.join(workspaceRoot, "risky.txt")
  const server = await withStubServer({
    decision: "approval_required",
    decision_id: "e8f907a6-3d2c-47f1-ac89-c443bcba7600",
    reason: "manual approval required",
    reason_code: "approval_required",
    approval: {
      approval_id: "f2527d69-7d2d-4272-9b3f-c21de76a6a33",
    },
  })

  try {
    await assert.rejects(
      guardedWrite(createDependencies(workspaceRoot, server.url), "risky.txt", "pending"),
      (error: unknown) =>
        error instanceof ApprovalRequired &&
        error.approvalId === "f2527d69-7d2d-4272-9b3f-c21de76a6a33",
    )

    assert.equal(fs.existsSync(targetPath), false)
    assert.equal(server.toolResults.length, 1)
    assert.equal(server.toolResults[0]?.["status"], "blocked")
  } finally {
    await server.close()
  }
})
