import test from "node:test"
import assert from "node:assert/strict"

import {
  createFreshInstallCommandPlan,
  runFreshInstallSmoke,
} from "./fresh-install-smoke-lib.mjs"

test("createFreshInstallCommandPlan resets compose volumes before booting the stack", () => {
  assert.deepEqual(createFreshInstallCommandPlan("http://localhost:3100"), [
    ["npm", ["ci"]],
    ["npm", ["run", "build"]],
    ["docker", ["compose", "down", "-v", "--remove-orphans"]],
    ["docker", ["compose", "up", "-d", "--build"]],
    ["npm", ["run", "demo", "--", "--url", "http://localhost:3100"]],
  ])
})

test("runFreshInstallSmoke always tears down compose volumes after the demo", async () => {
  const calls = []

  await assert.rejects(
    runFreshInstallSmoke({
      demoUrl: "http://localhost:3100",
      ensureEnvFile: () => calls.push(["ensureEnvFile"]),
      runCommand: (...args) => calls.push(args),
      waitForReady: async () => {
        throw new Error("demo failed")
      },
    }),
    /demo failed/u,
  )

  assert.deepEqual(calls, [
    ["ensureEnvFile"],
    ["npm", ["ci"]],
    ["npm", ["run", "build"]],
    ["docker", ["compose", "down", "-v", "--remove-orphans"]],
    ["docker", ["compose", "up", "-d", "--build"]],
    ["docker", ["compose", "down", "-v", "--remove-orphans"]],
  ])
})
