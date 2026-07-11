import assert from "node:assert/strict"
import fs from "node:fs"
import http from "node:http"
import type { AddressInfo } from "node:net"
import os from "node:os"
import path from "node:path"
import test from "node:test"

import { ApprovalRequired, GuardedAccessDenied } from "./errors.ts"
import { guardedEdit, type GuardedEditDependencies } from "./guarded_edit.ts"

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
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pi-adapter-edit-"))
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
  fetchImpl?: GuardedEditDependencies["fetchImpl"],
): GuardedEditDependencies => {
  return {
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
    requestIdFactory: () => "req_00000003",
    ...(fetchImpl === undefined ? {} : { fetchImpl }),
  }
}

test("Given a safe workspace file when guardedEdit runs Then it updates content and records a redacted diff preview", async () => {
  const { workspaceRoot } = createWorkspace()
  const filePath = path.join(workspaceRoot, "todo.txt")
  fs.writeFileSync(filePath, "hello world", "utf8")
  const server = await withStubServer({
    decision: "allow",
    decision_id: "092e070c-a394-41ff-9806-57888ca88c49",
    reason: "permitted by policy",
    reason_code: "allowed",
    decision_token: "edit-token-123",
  })

  try {
    await guardedEdit(createDependencies(workspaceRoot, server.url), "todo.txt", "SECRET=next")

    assert.equal(fs.readFileSync(filePath, "utf8"), "SECRET=next")
    assert.equal(server.requests.length, 1)
    assert.equal(server.toolResults.length, 1)
    const request = getCapturedRequest(server.requests)
    assert.equal(getNestedRecord(request, "resource")["path"], "/workspace/todo.txt")
    assert.equal(getNestedRecord(request, "normalized")["mutation"], true)
    assert.equal(getNestedRecord(request, "normalized")["credential_access"], false)

    const result = getNestedRecord(server.toolResults[0] ?? {}, "result")
    assert.equal(server.toolResults[0]?.["status"], "executed")
    assert.match(String(result["redacted_preview"]), /--- before/)
    assert.match(String(result["redacted_preview"]), /\+\+\+ after/)
    assert.match(String(result["redacted_preview"]), /hello world/)
    assert.doesNotMatch(String(result["redacted_preview"]), /SECRET=next/)
    assert.match(String(result["redacted_preview"]), /SECRET=\[REDACTED\]/)
  } finally {
    await server.close()
  }
})

test("Given a credential target when guardedEdit runs Then it blocks without changing the file", async () => {
  const { workspaceRoot } = createWorkspace()
  const filePath = path.join(workspaceRoot, ".env")
  fs.writeFileSync(filePath, "SECRET=1", "utf8")
  const server = await withStubServer({
    decision: "deny",
    decision_id: "6a67317a-bb22-4de7-a7e7-63ff8be315b8",
    reason: "blocked by policy",
    reason_code: "policy_forbid.credential_path",
  })

  try {
    await assert.rejects(
      guardedEdit(createDependencies(workspaceRoot, server.url), ".env", "SECRET=2"),
      (error: unknown) =>
        error instanceof GuardedAccessDenied &&
        error.reasonCode === "policy_forbid.credential_path",
    )

    assert.equal(fs.readFileSync(filePath, "utf8"), "SECRET=1")
    assert.equal(server.toolResults.length, 1)
    assert.equal(server.toolResults[0]?.["status"], "blocked")
  } finally {
    await server.close()
  }
})

test("Given a traversal target when guardedEdit runs Then it denies before calling the intercept service", async () => {
  const { workspaceRoot, siblingRoot } = createWorkspace()
  const siblingFile = path.join(siblingRoot, "outside.txt")
  fs.writeFileSync(siblingFile, "outside workspace", "utf8")
  const server = await withStubServer({
    decision: "allow",
    decision_id: "0459c52b-fadb-4a1d-8b17-2b89c09e5454",
    reason: "permitted by policy",
    reason_code: "allowed",
    decision_token: "edit-token-234",
  })

  try {
    await assert.rejects(
      guardedEdit(createDependencies(workspaceRoot, server.url), siblingFile, "nope"),
      (error: unknown) =>
        error instanceof GuardedAccessDenied &&
        error.reasonCode === "canonicalization_failed",
    )

    assert.equal(server.requests.length, 0)
    assert.equal(fs.readFileSync(siblingFile, "utf8"), "outside workspace")
  } finally {
    await server.close()
  }
})

test("Given an approval-required decision when guardedEdit runs Then it blocks without changing bytes", async () => {
  const { workspaceRoot } = createWorkspace()
  const filePath = path.join(workspaceRoot, "risky.txt")
  fs.writeFileSync(filePath, "before", "utf8")
  const server = await withStubServer({
    decision: "approval_required",
    decision_id: "072f9412-e754-4b32-a7cc-7e2b1d1f2670",
    reason: "manual approval required",
    reason_code: "approval_required",
    approval: {
      approval_id: "9f8d33f7-9d77-4b67-9720-cd8b2e840e97",
    },
  })

  try {
    await assert.rejects(
      guardedEdit(createDependencies(workspaceRoot, server.url), "risky.txt", "after"),
      (error: unknown) =>
        error instanceof ApprovalRequired &&
        error.approvalId === "9f8d33f7-9d77-4b67-9720-cd8b2e840e97",
    )

    assert.equal(fs.readFileSync(filePath, "utf8"), "before")
    assert.equal(server.toolResults.length, 1)
    assert.equal(server.toolResults[0]?.["status"], "blocked")
  } finally {
    await server.close()
  }
})

test("Given a file changed after decision when guardedEdit runs Then it blocks instead of overwriting newer content", async () => {
  const { workspaceRoot } = createWorkspace()
  const filePath = path.join(workspaceRoot, "shared.txt")
  fs.writeFileSync(filePath, "before", "utf8")
  const dependencies = createDependencies(
    workspaceRoot,
    "http://127.0.0.1:1/v1/intercept/tool-call",
    async (input, init) => {
      const body = init?.body
      if (typeof body !== "string") {
        throw new Error("expected string body")
      }

      if (String(input).endsWith("/v1/intercept/tool-call")) {
        fs.writeFileSync(filePath, "someone else changed this", "utf8")
        return new Response(JSON.stringify({
          decision: "allow",
          decision_id: "86f47570-c888-431e-acdf-1a4ad2072a79",
          reason: "permitted by policy",
          reason_code: "allowed",
          decision_token: "edit-token-345",
        }), {
          status: 200,
          headers: { "content-type": "application/json" },
        })
      }

      return new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { "content-type": "application/json" },
      })
    },
  )

  await assert.rejects(
    guardedEdit(dependencies, "shared.txt", "after"),
    (error: unknown) =>
      error instanceof GuardedAccessDenied &&
      error.reasonCode === "concurrent_modification",
  )

  assert.equal(fs.readFileSync(filePath, "utf8"), "someone else changed this")
})
