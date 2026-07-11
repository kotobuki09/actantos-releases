import assert from "node:assert/strict"
import fs from "node:fs"
import http from "node:http"
import type { AddressInfo } from "node:net"
import os from "node:os"
import path from "node:path"
import test from "node:test"

import { ApprovalRequired, GuardedAccessDenied } from "./errors.ts"
import { guardedGrep, type GuardedGrepDependencies } from "./guarded_grep.ts"

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
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pi-adapter-grep-"))
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
): GuardedGrepDependencies => ({
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
  requestIdFactory: () => "req_00000005",
})

test("Given a safe workspace file when guardedGrep runs Then it returns matching lines after an allow decision", async () => {
  const { workspaceRoot } = createWorkspace()
  const filePath = path.join(workspaceRoot, "notes.txt")
  fs.writeFileSync(filePath, "alpha\nbeta line\nbeta second\ngamma", "utf8")
  const server = await withStubServer({
    decision: "allow",
    decision_id: "40c9358a-8733-45e1-a91a-29fc9d4d4f5a",
    reason: "permitted by policy",
    reason_code: "allowed",
    decision_token: "grep-token-123",
  })

  try {
    const matches = await guardedGrep(
      createDependencies(workspaceRoot, server.url),
      "notes.txt",
      "beta",
    )

    assert.deepEqual(matches, ["beta line", "beta second"])
    assert.equal(server.requests.length, 1)
    assert.equal(server.toolResults.length, 1)
    const request = getCapturedRequest(server.requests)
    assert.equal(getNestedRecord(request, "resource")["path"], "/workspace/notes.txt")
    assert.equal(getNestedRecord(request, "normalized")["credential_access"], false)
    assert.equal(server.toolResults[0]?.["status"], "executed")
  } finally {
    await server.close()
  }
})

test("Given a safe workspace grep with a max_output_bytes limit Then guardedGrep truncates returned matches", async () => {
  const { workspaceRoot } = createWorkspace()
  const filePath = path.join(workspaceRoot, "notes.txt")
  fs.writeFileSync(filePath, "beta one\nbeta two\nbeta three", "utf8")
  const server = await withStubServer({
    decision: "allow",
    decision_id: "ee1d43e7-b0b9-48c7-b235-c33692d2f35c",
    reason: "permitted by policy",
    reason_code: "allowed",
    decision_token: "grep-token-234",
    constraints: {
      max_output_bytes: 12,
    },
  })

  try {
    const matches = await guardedGrep(
      createDependencies(workspaceRoot, server.url),
      "notes.txt",
      "beta",
    )

    assert.deepEqual(matches, ["beta one"])
    const result = getNestedRecord(server.toolResults[0] ?? {}, "result")
    assert.match(String(result["redacted_preview"]), /beta one/)
  } finally {
    await server.close()
  }
})

test("Given a credential target when guardedGrep runs Then it blocks without returning matching lines", async () => {
  const { workspaceRoot } = createWorkspace()
  const filePath = path.join(workspaceRoot, ".env")
  fs.writeFileSync(filePath, "SECRET=1\nTOKEN=beta", "utf8")
  const server = await withStubServer({
    decision: "deny",
    decision_id: "e5174d99-2a35-4327-aa80-1ea7ebcb9a14",
    reason: "blocked by policy",
    reason_code: "policy_forbid.credential_path",
  })

  try {
    await assert.rejects(
      guardedGrep(createDependencies(workspaceRoot, server.url), ".env", "beta"),
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

test("Given a traversal target when guardedGrep runs Then it denies before calling the intercept service", async () => {
  const { workspaceRoot, siblingRoot } = createWorkspace()
  const siblingFile = path.join(siblingRoot, "outside.txt")
  fs.writeFileSync(siblingFile, "beta outside", "utf8")
  const server = await withStubServer({
    decision: "allow",
    decision_id: "14f91968-a74a-4adf-bf63-d13d53cf8899",
    reason: "permitted by policy",
    reason_code: "allowed",
    decision_token: "grep-token-345",
  })

  try {
    await assert.rejects(
      guardedGrep(createDependencies(workspaceRoot, server.url), siblingFile, "beta"),
      (error: unknown) =>
        error instanceof GuardedAccessDenied &&
        error.reasonCode === "canonicalization_failed",
    )

    assert.equal(server.requests.length, 0)
  } finally {
    await server.close()
  }
})

test("Given an approval-required decision when guardedGrep runs Then it blocks without returning matching lines", async () => {
  const { workspaceRoot } = createWorkspace()
  const filePath = path.join(workspaceRoot, "drafts.txt")
  fs.writeFileSync(filePath, "beta draft", "utf8")
  const server = await withStubServer({
    decision: "approval_required",
    decision_id: "a6b24c14-79d7-4f89-af66-32c55f778f10",
    reason: "manual approval required",
    reason_code: "approval_required",
    approval: {
      approval_id: "0a9987fe-bafc-46b0-a5c7-77d4a657beca",
    },
  })

  try {
    await assert.rejects(
      guardedGrep(createDependencies(workspaceRoot, server.url), "drafts.txt", "beta"),
      (error: unknown) =>
        error instanceof ApprovalRequired &&
        error.approvalId === "0a9987fe-bafc-46b0-a5c7-77d4a657beca",
    )

    assert.equal(server.toolResults.length, 1)
    assert.equal(server.toolResults[0]?.["status"], "blocked")
  } finally {
    await server.close()
  }
})
