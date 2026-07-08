import assert from "node:assert/strict"
import test from "node:test"

import {
  toolCallInterceptionRequestSchema,
  type ToolCallInterceptionRequest,
} from "./contracts.ts"
import { safeReadRequest } from "./intercept-test-fixtures.ts"
import { DefaultUrlTargetGuard } from "./url-target-guard.ts"

const createUrlRequest = (url: string): ToolCallInterceptionRequest =>
  toolCallInterceptionRequestSchema.parse({
    ...safeReadRequest(`req_url_guard_${url}`),
    tool: {
      kind: "http",
      name: "guarded_fetch",
      operation: "GET",
      schema_hash: "",
    },
    resource: {
      id: url,
      kind: "url",
      url,
    },
    action: {
      operation: "GET",
      args: { url },
    },
    normalized: {
      verb: "network",
      mutation: false,
      destructive: false,
      network: true,
      credential_access: false,
      risk_class: "high",
    },
  })

test("DefaultUrlTargetGuard allows public HTTPS targets", async () => {
  const guard = new DefaultUrlTargetGuard()

  const result = await guard.evaluate(createUrlRequest("https://example.com/docs"))

  assert.deepEqual(result, { allowed: true })
})

test("DefaultUrlTargetGuard denies invalid URLs", async () => {
  const guard = new DefaultUrlTargetGuard()

  const result = await guard.evaluate(createUrlRequest("http://%zz"))

  assert.equal(result.allowed, false)
  assert.equal(result.reasonCode, "policy_forbid")
})

test("DefaultUrlTargetGuard denies private, metadata, and link-local targets", async () => {
  const guard = new DefaultUrlTargetGuard()
  const blockedUrls = [
    "http://localhost:8080/secret",
    "http://127.0.0.1:8080/secret",
    "http://10.0.0.5/admin",
    "http://192.168.1.10/admin",
    "http://172.16.0.10/admin",
    "http://169.254.42.42/admin",
    "http://169.254.169.254/latest/meta-data",
    "http://metadata.google.internal/computeMetadata/v1",
    "http://[::1]/secret",
    "http://[fe80::1]/secret",
    "http://[fc00::1]/secret",
    "http://[fd12::abcd]/secret",
  ] as const

  for (const blockedUrl of blockedUrls) {
    const result = await guard.evaluate(createUrlRequest(blockedUrl))
    assert.equal(result.allowed, false, blockedUrl)
    if (result.allowed) {
      continue
    }
    assert.equal(result.reasonCode, "policy_forbid", blockedUrl)
  }
})
