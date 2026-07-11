import assert from "node:assert/strict"
import fs from "node:fs"
import os from "node:os"
import path from "node:path"
import test from "node:test"
import http from "node:http"
import type { AddressInfo } from "node:net"

import { ApprovalRequired, GuardedAccessDenied } from "./errors.ts"
import { guardedRead, type GuardedReadDependencies } from "./guarded_read.ts"

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
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pi-adapter-"))
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
): GuardedReadDependencies => ({
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
  requestIdFactory: () => "req_00000001",
})

test("Given a README under the workspace when guardedRead runs Then it returns content and sends the canonical path", async () => {
  const { workspaceRoot } = createWorkspace()
  const filePath = path.join(workspaceRoot, "README.md")
  fs.writeFileSync(filePath, "hello from workspace", "utf8")

  const server = await withStubServer({
    decision: "allow",
    decision_id: "c132cb5f-50d5-4105-a399-8cdb8c1f4f7d",
    reason: "permitted by policy",
    reason_code: "allowed",
    decision_token: "read-token-123",
  })

  try {
    const content = await guardedRead(
      createDependencies(workspaceRoot, server.url),
      "README.md",
    )

    assert.equal(content, "hello from workspace")
    assert.equal(server.requests.length, 1)
    assert.equal(server.toolResults.length, 1)
    const request = getCapturedRequest(server.requests)
    assert.equal(getNestedRecord(request, "resource")["path"], "/workspace/README.md")
    assert.equal(getNestedRecord(getNestedRecord(request, "action"), "args")["path"], "/workspace/README.md")
    assert.equal(getNestedRecord(request, "normalized")["credential_access"], false)
    assert.equal(server.toolResults[0]?.["status"], "executed")
    assert.equal(server.toolResults[0]?.["decision_id"], "c132cb5f-50d5-4105-a399-8cdb8c1f4f7d")
  } finally {
    await server.close()
  }
})

test("Given a credential file when guardedRead runs Then it throws GuardedAccessDenied with the policy reason code", async () => {
  const { workspaceRoot } = createWorkspace()
  const envPath = path.join(workspaceRoot, ".env")
  fs.writeFileSync(envPath, "SECRET=1", "utf8")

  const server = await withStubServer({
    decision: "deny",
    decision_id: "c6c8e97f-e7ff-4784-93f1-7fa596dca14a",
    reason: "blocked by policy",
    reason_code: "policy_forbid.credential_path",
  })

  try {
    await assert.rejects(
      guardedRead(createDependencies(workspaceRoot, server.url), ".env"),
      (error: unknown) =>
        error instanceof GuardedAccessDenied &&
        error.reasonCode === "policy_forbid.credential_path",
    )

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

test("Given a traversal path when guardedRead runs Then it denies before calling the intercept service", async () => {
  const { workspaceRoot } = createWorkspace()
  const server = await withStubServer({
    decision: "allow",
    decision_id: "e58006d7-1eca-4a59-b4cf-3eb14c2b8ec5",
    reason: "permitted by policy",
    reason_code: "allowed",
    decision_token: "read-token-234",
  })

  try {
    await assert.rejects(
      guardedRead(
        createDependencies(workspaceRoot, server.url),
        path.join("..", "..", "outside.txt"),
      ),
      (error: unknown) =>
        error instanceof GuardedAccessDenied &&
        error.reasonCode === "canonicalization_failed",
    )

    assert.equal(server.requests.length, 0)
  } finally {
    await server.close()
  }
})

test("Given a symlink to a credential file when guardedRead runs Then it resolves the symlink and denies with the policy reason code", async () => {
  const { workspaceRoot } = createWorkspace()
  const envPath = path.join(workspaceRoot, ".env")
  const linkPath = path.join(workspaceRoot, "linked.env")
  fs.writeFileSync(envPath, "SECRET=1", "utf8")
  fs.symlinkSync(envPath, linkPath, "file")

  const server = await withStubServer({
    decision: "deny",
    decision_id: "18a16a4d-a0ef-4b3c-af6d-f52efa4effdd",
    reason: "blocked by policy",
    reason_code: "policy_forbid.credential_path",
  })

  try {
    await assert.rejects(
      guardedRead(createDependencies(workspaceRoot, server.url), "linked.env"),
      (error: unknown) =>
        error instanceof GuardedAccessDenied &&
        error.reasonCode === "policy_forbid.credential_path",
    )

    assert.equal(server.requests.length, 1)
    assert.equal(server.toolResults.length, 1)
    const request = getCapturedRequest(server.requests)
    assert.equal(getNestedRecord(request, "resource")["path"], "/workspace/.env")
    assert.equal(getNestedRecord(request, "normalized")["credential_access"], true)
    assert.equal(server.toolResults[0]?.["status"], "blocked")
  } finally {
    await server.close()
  }
})

test("Given a workspace2 sibling path when guardedRead runs Then it denies with canonicalization_failed", async () => {
  const { workspaceRoot, siblingRoot } = createWorkspace()
  const siblingFile = path.join(siblingRoot, "file.txt")
  fs.writeFileSync(siblingFile, "outside workspace", "utf8")

  const server = await withStubServer({
    decision: "allow",
    decision_id: "03fca95a-d719-43d9-9669-b96ae16762e6",
    reason: "permitted by policy",
    reason_code: "allowed",
    decision_token: "read-token-345",
  })

  try {
    await assert.rejects(
      guardedRead(createDependencies(workspaceRoot, server.url), siblingFile),
      (error: unknown) =>
        error instanceof GuardedAccessDenied &&
        error.reasonCode === "canonicalization_failed",
    )

    assert.equal(server.requests.length, 0)
  } finally {
    await server.close()
  }
})

test("Given a missing file when guardedRead runs Then it denies safely without returning content", async () => {
  const { workspaceRoot } = createWorkspace()
  const server = await withStubServer({
    decision: "allow",
    decision_id: "6fd6ab8e-a9c2-42ae-9316-e79fa5de31b5",
    reason: "permitted by policy",
    reason_code: "allowed",
    decision_token: "read-token-456",
  })

  try {
    await assert.rejects(
      guardedRead(createDependencies(workspaceRoot, server.url), "missing.txt"),
      (error: unknown) =>
        error instanceof GuardedAccessDenied &&
        error.reasonCode === "canonicalization_failed",
    )

    assert.equal(server.requests.length, 0)
  } finally {
    await server.close()
  }
})

test("Given an approval-required intercept response when guardedRead runs Then it throws ApprovalRequired with the approval id", async () => {
  const { workspaceRoot } = createWorkspace()
  const filePath = path.join(workspaceRoot, "README.md")
  fs.writeFileSync(filePath, "hello from workspace", "utf8")

  const server = await withStubServer({
    decision: "approval_required",
    decision_id: "4ab6f823-e2b7-4542-b9a4-86401e4e59f6",
    reason: "manual approval required",
    reason_code: "approval_required",
    approval: {
      approval_id: "1cf5765d-91f1-45ab-8186-3b70fb89ad96",
    },
  })

  try {
    await assert.rejects(
      guardedRead(createDependencies(workspaceRoot, server.url), "README.md"),
      (error: unknown) =>
        error instanceof ApprovalRequired &&
        error.approvalId === "1cf5765d-91f1-45ab-8186-3b70fb89ad96",
    )
    assert.equal(server.toolResults.length, 1)
    assert.equal(server.toolResults[0]?.["status"], "blocked")
  } finally {
    await server.close()
  }
})
