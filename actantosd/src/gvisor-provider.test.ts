import assert from "node:assert/strict"
import test from "node:test"

import { createGvisorIsolationProvider } from "./gvisor-provider.ts"
import type { ExecutionSpec } from "./isolation-provider.ts"

const healthyConfig = {
  runtime: "runsc" as const,
  imageDigest: "sha256:abc123",
  requireProxy: true,
  proxyEndpoint: "http://proxy.internal:3128",
  runtimeAvailable: true,
  seccompProfilePresent: true,
  apparmorProfilePresent: true,
}

const baseSpec = (): ExecutionSpec => ({
  tenantId: "t_alpha",
  agentId: "a1",
  sessionId: "s1",
  toolCallId: "tc1",
  requestId: "r1",
  provider: "gvisor",
  imageDigest: "sha256:abc123",
  workspacePath: "/workspace",
  argv: ["uname", "-a"],
  networkMode: "egress_proxy",
  networkAllowlist: ["https://api.example.com"],
  timeoutMs: 10_000,
  maxOutputBytes: 50_000,
  readOnlyRoot: true,
  credentialGrants: [],
  exp: Math.floor(Date.now() / 1000) + 30,
})

test("gvisor readiness fails closed without runtime/profiles/proxy/digest", async () => {
  const provider = createGvisorIsolationProvider(healthyConfig)
  assert.deepEqual(await provider.readiness(), { ready: true })

  assert.equal(
    (await createGvisorIsolationProvider({ ...healthyConfig, runtimeAvailable: false }).readiness()).ready,
    false,
  )
  assert.equal(
    (await createGvisorIsolationProvider({ ...healthyConfig, seccompProfilePresent: false }).readiness()).ready,
    false,
  )
  const { proxyEndpoint: _ignored, ...withoutProxy } = healthyConfig
  assert.equal(
    (await createGvisorIsolationProvider({ ...withoutProxy, requireProxy: true }).readiness()).ready,
    false,
  )
  assert.equal(
    (await createGvisorIsolationProvider({ ...healthyConfig, imageDigest: "latest" }).readiness()).ready,
    false,
  )
})

test("gvisor denies metadata targets, writable roots, and docker fallback", async () => {
  const provider = createGvisorIsolationProvider(healthyConfig)
  const metadata = await provider.execute({
    ...baseSpec(),
    networkAllowlist: ["http://169.254.169.254/latest/meta-data"],
  })
  assert.equal(metadata.status, "denied")

  const writable = await provider.execute({ ...baseSpec(), readOnlyRoot: false })
  assert.equal(writable.status, "denied")

  const wrongProvider = await provider.execute({ ...baseSpec(), provider: "docker" })
  assert.equal(wrongProvider.status, "denied")

  let dockerInvoked = false
  const withSpy = createGvisorIsolationProvider(healthyConfig, {
    async executeCommand() {
      dockerInvoked = true
      return {
        status: "executed",
        exitCode: 0,
        stdout: "",
        stderr: "",
        provider: "gvisor",
        startedAt: new Date().toISOString(),
        finishedAt: new Date().toISOString(),
      }
    },
  })
  await withSpy.execute({ ...baseSpec(), provider: "docker" })
  assert.equal(dockerInvoked, false)

  const ok = await provider.execute(baseSpec())
  assert.equal(ok.status, "executed")
  assert.equal(ok.provider, "gvisor")
})
