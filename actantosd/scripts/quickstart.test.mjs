import assert from "node:assert/strict"
import test from "node:test"

import { createQuickstartPlan } from "./quickstart-lib.mjs"

test("creates a locked portable agent-test plan for a Git clone", () => {
  // Given: a free local port selected for the quickstart.
  const port = 4310

  // When: the portable workflow is planned.
  const plan = createQuickstartPlan(port, { hasPackageLock: true, hasSource: true })

  // Then: it installs, builds, starts in memory, and tests the agent path.
  assert.deepEqual(plan, {
    install: ["npm", ["ci"]],
    build: ["npm", ["run", "build"]],
    server: ["node", ["dist/index.js"]],
    readinessUrl: "http://127.0.0.1:4310/health/ready",
    agentTest: ["node", ["scripts/portable-agent-test.mjs", "--url", "http://127.0.0.1:4310"]],
  })
})

test("creates an install-based portable agent-test plan for a release tarball", () => {
  // Given: npm excluded package-lock.json from a packed release.
  const hasPackageLock = false

  // When: the portable workflow is planned.
  const plan = createQuickstartPlan(4310, { hasPackageLock, hasSource: false })

  // Then: npm installs from package metadata instead of failing npm ci.
  assert.deepEqual(plan.install, ["npm", ["install"]])
  assert.equal(plan.build, undefined)
})
