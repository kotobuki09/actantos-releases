import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { mkdtempSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import { join } from "node:path"

import test from "node:test"

import type { PolicyBundleBody } from "./v2/signed-policy-bundle.ts"

const CLI = new URL("./cli-emit-tetragon.ts", import.meta.url).pathname.replace(
  /^\/([A-Za-z]:)/,
  "$1",
)

const bundleBody = {
  bundle_id: "b1",
  tenant_id: "t_demo",
  version: 1,
  issued_at: "2026-10-03T00:00:00.000Z",
  expires_at: "2026-10-03T01:00:00.000Z",
  policies: [],
  agent_profile: { agent_id: "reviewer", allowed_tools: [] },
  tool_manifest: [],
  network_rules: [
    { host: "api.github.com", action: "allow_via_egress_gateway" },
    { host: "github.com", port: 22, action: "deny" },
  ],
  data_clearance: "CONFIDENTIAL",
  risk_profile: { risk_level: "low", requires_effect_permit: [] },
  trusted_issuers: ["issuer-demo"],
} satisfies PolicyBundleBody

const run = (bundle: unknown, deployment: unknown) => {
  const dir = mkdtempSync(join(tmpdir(), "actant-emit-tetragon-"))
  const bundlePath = join(dir, "bundle.json")
  const deploymentPath = join(dir, "deployment.json")

  writeFileSync(bundlePath, JSON.stringify(bundle))
  writeFileSync(deploymentPath, JSON.stringify(deployment))

  try {
    const stdout = execFileSync(
      process.execPath,
      ["--experimental-strip-types", CLI, bundlePath, deploymentPath],
      { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
    )
    return { stdout }
  } catch (error) {
    const failure = error as { status: number; stdout: string; stderr: string }
    return { status: failure.status, stdout: failure.stdout, stderr: failure.stderr }
  }
}

test("emit-tetragon compiles a bundle into the validated TracingPolicy shape", () => {
  const { stdout } = run({ body: bundleBody }, {
    policyName: "actant-agent-reviewer",
    deniedBinaries: ["/usr/bin/curl", "/usr/bin/wget"],
    deniedWritePaths: [],
  })

  assert.match(stdout, /^apiVersion: cilium\.io\/v1alpha1\nkind: TracingPolicy\n/)
  assert.match(stdout, /  name: actant-agent-reviewer/)
  assert.match(stdout, /- call: "security_bprm_check"/)
  assert.match(stdout, /- call: "tcp_connect"/)
  assert.match(stdout, /- "- "22"\n|                - "22"/)
  assert.equal(stdout.includes("labels"), false)
})

test("emit-tetragon accepts a bare policy body as well as a signed bundle", () => {
  const { stdout } = run(bundleBody, {
    policyName: "actant-agent-reviewer",
    deniedBinaries: ["/usr/bin/curl"],
    deniedWritePaths: [],
  })

  assert.match(stdout, /name: actant-agent-reviewer/)
})

test("emit-tetragon still emits a port selector from bundle rules alone", () => {
  // `bundleBody` has a `deny github.com:22` rule, so the profile is non-empty even with
  // no deployment-supplied binaries or paths.
  const { stdout } = run({ body: bundleBody }, {
    policyName: "actant-agent-reviewer",
    deniedBinaries: [],
    deniedWritePaths: [],
  })

  assert.match(stdout, /- call: "tcp_connect"/)
  assert.equal(stdout.includes('call: "security_bprm_check"'), false)
})

test("emit-tetragon fails closed on a profile that selects nothing", () => {
  const result = run(
    {
      body: {
        ...bundleBody,
        network_rules: [{ host: "api.github.com", action: "allow_via_egress_gateway" }],
      },
    },
    {
      policyName: "actant-agent-reviewer",
      deniedBinaries: [],
      deniedWritePaths: [],
    },
  )

  assert.equal(result.status, 1)
  assert.match(result.stderr, /at least one of deniedBinaries/)
})

test("emit-tetragon fails closed on an invalid bundle", () => {
  const result = run({ body: { ...bundleBody, tenant_id: undefined } }, {
    policyName: "actant-agent-reviewer",
    deniedBinaries: ["/usr/bin/curl"],
    deniedWritePaths: [],
  })

  assert.equal(result.status, 1)
  assert.match(result.stderr, /policy bundle body is invalid/)
})