import assert from "node:assert/strict"
import fs from "node:fs"
import http from "node:http"
import type { AddressInfo } from "node:net"
import os from "node:os"
import path from "node:path"
import test from "node:test"

import { ApprovalRequired, GuardedAccessDenied } from "./errors.ts"
import { guardedLs, type GuardedLsDependencies } from "./guarded_ls.ts"

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
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pi-adapter-ls-"))
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
): GuardedLsDependencies => ({
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
  requestIdFactory: () => "req_00000004",
})

test("Given a safe workspace directory when guardedLs runs Then it returns sorted entry names after an allow decision", async () => {
  const { workspaceRoot } = createWorkspace()
  fs.mkdirSync(path.join(workspaceRoot, "docs"))
  fs.writeFileSync(path.join(workspaceRoot, "README.md"), "hello", "utf8")
  fs.writeFileSync(path.join(workspaceRoot, "notes.txt"), "notes", "utf8")

  const server = await withStubServer({
    decision: "allow",
    decision_id: "14bb172a-2b11-4e75-a47d-a5c6fcd3d25f",
    reason: "permitted by policy",
    reason_code: "allowed",
    decision_token: "ls-token-123",
  })

  try {
    const entries = await guardedLs(createDependencies(workspaceRoot, server.url), ".")

    assert.deepEqual(entries, ["README.md", "docs", "notes.txt"])
    assert.equal(server.requests.length, 1)
    assert.equal(server.toolResults.length, 1)
    const request = getCapturedRequest(server.requests)
    assert.equal(getNestedRecord(request, "resource")["path"], "/workspace")
    assert.equal(getNestedRecord(request, "normalized")["credential_access"], false)
    assert.equal(server.toolResults[0]?.["status"], "executed")
  } finally {
    await server.close()
  }
})

test("Given a credential directory when guardedLs runs Then it blocks without returning file names", async () => {
  const { workspaceRoot } = createWorkspace()
  const sshDir = path.join(workspaceRoot, ".ssh")
  fs.mkdirSync(sshDir)
  fs.writeFileSync(path.join(sshDir, "id_rsa"), "secret", "utf8")

  const server = await withStubServer({
    decision: "deny",
    decision_id: "4ab7d860-6c60-4a43-99cb-627ed9c680c8",
    reason: "blocked by policy",
    reason_code: "policy_forbid.credential_path",
  })

  try {
    await assert.rejects(
      guardedLs(createDependencies(workspaceRoot, server.url), ".ssh"),
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

test("Given a traversal target when guardedLs runs Then it denies before calling the intercept service", async () => {
  const { workspaceRoot, siblingRoot } = createWorkspace()
  fs.mkdirSync(path.join(siblingRoot, "outside"))

  const server = await withStubServer({
    decision: "allow",
    decision_id: "01a7d529-7bdd-474c-9486-2913ba61e42d",
    reason: "permitted by policy",
    reason_code: "allowed",
    decision_token: "ls-token-234",
  })

  try {
    await assert.rejects(
      guardedLs(createDependencies(workspaceRoot, server.url), siblingRoot),
      (error: unknown) =>
        error instanceof GuardedAccessDenied &&
        error.reasonCode === "canonicalization_failed",
    )

    assert.equal(server.requests.length, 0)
  } finally {
    await server.close()
  }
})

test("Given an approval-required decision when guardedLs runs Then it blocks without returning names", async () => {
  const { workspaceRoot } = createWorkspace()
  fs.mkdirSync(path.join(workspaceRoot, "drafts"))
  fs.writeFileSync(path.join(workspaceRoot, "drafts", "secret.txt"), "draft", "utf8")

  const server = await withStubServer({
    decision: "approval_required",
    decision_id: "dfe237df-2cab-4f46-a663-7231d3d5da48",
    reason: "manual approval required",
    reason_code: "approval_required",
    approval: {
      approval_id: "876d8ac9-f14f-476a-82f0-bd686ecaeeb6",
    },
  })

  try {
    await assert.rejects(
      guardedLs(createDependencies(workspaceRoot, server.url), "drafts"),
      (error: unknown) =>
        error instanceof ApprovalRequired &&
        error.approvalId === "876d8ac9-f14f-476a-82f0-bd686ecaeeb6",
    )

    assert.equal(server.toolResults.length, 1)
    assert.equal(server.toolResults[0]?.["status"], "blocked")
  } finally {
    await server.close()
  }
})
