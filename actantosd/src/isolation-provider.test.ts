import assert from "node:assert/strict"
import test from "node:test"

import {
  clearUsedExecutionTokens,
  createFakeIsolationProvider,
  signExecutionSpec,
  verifyAndConsumeExecutionToken,
  type ExecutionSpec,
} from "./isolation-provider.ts"

const baseSpec = (): ExecutionSpec => ({
  tenantId: "t_alpha",
  agentId: "agent_1",
  sessionId: "session_1",
  toolCallId: "tc_1",
  requestId: "req_1",
  provider: "fake",
  imageDigest: "sha256:deadbeef",
  workspacePath: "/workspace",
  argv: ["echo", "hi"],
  networkMode: "none",
  networkAllowlist: [],
  timeoutMs: 5_000,
  maxOutputBytes: 10_000,
  readOnlyRoot: true,
  credentialGrants: [],
  exp: Math.floor(Date.now() / 1000) + 60,
})

test("signed execution tokens are single-use and reject tamper/expiry/replay", async () => {
  clearUsedExecutionTokens()
  const secret = "exec-secret"
  const spec = baseSpec()
  const token = signExecutionSpec(spec, secret)
  const verified = verifyAndConsumeExecutionToken(token, secret)
  assert.equal(verified.tenantId, "t_alpha")

  assert.throws(() => verifyAndConsumeExecutionToken(token, secret), /already consumed/u)
  assert.throws(
    () => verifyAndConsumeExecutionToken({ ...token, signature: `${token.signature}x` }, secret),
    /invalid execution token signature/u,
  )

  clearUsedExecutionTokens()
  const expired = signExecutionSpec({ ...spec, exp: Math.floor(Date.now() / 1000) - 1 }, secret)
  assert.throws(() => verifyAndConsumeExecutionToken(expired, secret), /expired/u)

  clearUsedExecutionTokens()
  const provider = createFakeIsolationProvider()
  const fresh = verifyAndConsumeExecutionToken(signExecutionSpec(spec, secret), secret)
  const result = await provider.execute(fresh)
  assert.equal(result.status, "executed")
  assert.equal(provider.invocations.length, 1)
})

test("tampered tenant never reaches provider", async () => {
  clearUsedExecutionTokens()
  const secret = "exec-secret"
  const token = signExecutionSpec(baseSpec(), secret)
  const tamperedPayload = Buffer.from(
    JSON.stringify({ ...baseSpec(), tenantId: "t_evil" }),
    "utf8",
  ).toString("base64url")
  const provider = createFakeIsolationProvider()
  assert.throws(
    () => verifyAndConsumeExecutionToken({ payload: tamperedPayload, signature: token.signature }, secret),
    /invalid execution token signature/u,
  )
  assert.equal(provider.invocations.length, 0)
})
