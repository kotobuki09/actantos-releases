import assert from "node:assert/strict"
import fs from "node:fs"
import http from "node:http"
import type { AddressInfo } from "node:net"
import os from "node:os"
import path from "node:path"
import test from "node:test"

import { ApprovalRequired, GuardedAccessDenied } from "./errors.ts"
import { guardedFind, type GuardedFindDependencies } from "./guarded_find.ts"

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
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pi-adapter-find-"))
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
): GuardedFindDependencies => ({
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
  requestIdFactory: () => "req_00000006",
})

test("Given a safe workspace directory when guardedFind runs Then it returns discovered paths after an allow decision", async () => {
  const { workspaceRoot } = createWorkspace()
  fs.mkdirSync(path.join(workspaceRoot, "docs"), { recursive: true })
  fs.writeFileSync(path.join(workspaceRoot, "docs", "keep.txt"), "x", "utf8")
  fs.writeFileSync(path.join(workspaceRoot, "docs", "skip.md"), "x", "utf8")
  fs.writeFileSync(path.join(workspaceRoot, "docs", "notes.txt"), "x", "utf8")
  const server = await withStubServer({
    decision: "allow",
    decision_id: "91db578f-8653-4255-b856-5ec6d9f8feee",
    reason: "permitted by policy",
    reason_code: "allowed",
    decision_token: "find-token-123",
  })

  try {
    const matches = await guardedFind(
      createDependencies(workspaceRoot, server.url),
      "docs",
      ".txt",
    )

    assert.deepEqual(matches, [
      "/workspace/docs/keep.txt",
      "/workspace/docs/notes.txt",
    ])
    assert.equal(server.requests.length, 1)
    assert.equal(server.toolResults.length, 1)
    const request = getCapturedRequest(server.requests)
    assert.equal(getNestedRecord(request, "resource")["path"], "/workspace/docs")
    assert.equal(getNestedRecord(request, "normalized")["credential_access"], false)
    assert.equal(server.toolResults[0]?.["status"], "executed")
  } finally {
    await server.close()
  }
})

test("Given a safe workspace find with a max_output_bytes limit Then guardedFind truncates returned paths", async () => {
  const { workspaceRoot } = createWorkspace()
  fs.mkdirSync(path.join(workspaceRoot, "docs"), { recursive: true })
  fs.writeFileSync(path.join(workspaceRoot, "docs", "a.txt"), "x", "utf8")
  fs.writeFileSync(path.join(workspaceRoot, "docs", "b.txt"), "x", "utf8")
  fs.writeFileSync(path.join(workspaceRoot, "docs", "c.txt"), "x", "utf8")
  const server = await withStubServer({
    decision: "allow",
    decision_id: "2a7aa419-23a6-4f2d-ab95-f24aa82a1f3f",
    reason: "permitted by policy",
    reason_code: "allowed",
    decision_token: "find-token-234",
    constraints: {
      max_output_bytes: 21,
    },
  })

  try {
    const matches = await guardedFind(
      createDependencies(workspaceRoot, server.url),
      "docs",
      ".txt",
    )

    assert.deepEqual(matches, ["/workspace/docs/a.txt"])
    const result = getNestedRecord(server.toolResults[0] ?? {}, "result")
    assert.match(String(result["redacted_preview"]), /\/workspace\/docs\/a\.txt/)
  } finally {
    await server.close()
  }
})

test("Given a credential target when guardedFind runs Then it blocks without returning discovered paths", async () => {
  const { workspaceRoot } = createWorkspace()
  fs.mkdirSync(path.join(workspaceRoot, ".aws"), { recursive: true })
  fs.writeFileSync(path.join(workspaceRoot, ".aws", "credentials"), "x", "utf8")
  const server = await withStubServer({
    decision: "deny",
    decision_id: "3b86342c-cdb1-43c2-b787-cd875987325d",
    reason: "blocked by policy",
    reason_code: "policy_forbid.credential_path",
  })

  try {
    await assert.rejects(
      guardedFind(createDependencies(workspaceRoot, server.url), ".aws", "cred"),
      (error: unknown) =>
        error instanceof GuardedAccessDenied &&
        error.reasonCode === "policy_forbid.credential_path",
    )

    assert.equal(server.requests.length, 1)
    assert.equal(server.toolResults.length, 1)
    assert.equal(server.toolResults[0]?.["status"], "blocked")
  } finally {
    await server.close()
  }
})

test("Given a traversal target when guardedFind runs Then it denies before calling the intercept service", async () => {
  const { workspaceRoot, siblingRoot } = createWorkspace()
  fs.mkdirSync(path.join(siblingRoot, "outside"), { recursive: true })
  fs.writeFileSync(path.join(siblingRoot, "outside", "leak.txt"), "x", "utf8")
  const server = await withStubServer({
    decision: "allow",
    decision_id: "bd480f0e-bd25-43ed-9961-a2fa3265c2ed",
    reason: "permitted by policy",
    reason_code: "allowed",
    decision_token: "find-token-345",
  })

  try {
    await assert.rejects(
      guardedFind(createDependencies(workspaceRoot, server.url), path.join(siblingRoot, "outside"), ".txt"),
      (error: unknown) =>
        error instanceof GuardedAccessDenied &&
        error.reasonCode === "canonicalization_failed",
    )

    assert.equal(server.requests.length, 0)
  } finally {
    await server.close()
  }
})

test("Given an approval-required decision when guardedFind runs Then it blocks without returning discovered paths", async () => {
  const { workspaceRoot } = createWorkspace()
  fs.mkdirSync(path.join(workspaceRoot, "drafts"), { recursive: true })
  fs.writeFileSync(path.join(workspaceRoot, "drafts", "draft.txt"), "x", "utf8")
  const server = await withStubServer({
    decision: "approval_required",
    decision_id: "8bf8d25b-6686-4ffe-9ae4-8af6152e9863",
    reason: "manual approval required",
    reason_code: "approval_required",
    approval: {
      approval_id: "673f8a87-23ac-4060-a5c4-898cb3c7e1b9",
    },
  })

  try {
    await assert.rejects(
      guardedFind(createDependencies(workspaceRoot, server.url), "drafts", ".txt"),
      (error: unknown) =>
        error instanceof ApprovalRequired &&
        error.approvalId === "673f8a87-23ac-4060-a5c4-898cb3c7e1b9",
    )

    assert.equal(server.toolResults.length, 1)
    assert.equal(server.toolResults[0]?.["status"], "blocked")
  } finally {
    await server.close()
  }
})
