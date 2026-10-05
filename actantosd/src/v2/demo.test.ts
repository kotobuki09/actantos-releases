import assert from "node:assert/strict"
import { test } from "node:test"

import { runDemo } from "./demo.ts"

/**
 * The §21 demonstration is a claim in the docs, so it is tested like any other claim: every
 * attack in the narrative must actually be blocked, and the evidence it produces must verify.
 */

test("demo: every attack in the demonstration is blocked", async () => {
  const result = await runDemo()

  const attacks = result.steps.filter((step) => step.label.startsWith("ATTACK"))

  assert.ok(attacks.length >= 6, `expected at least 6 attacks, found ${attacks.length}`)

  const unblocked = attacks.filter((step) => !step.blocked).map((step) => step.label)

  assert.deepEqual(unblocked, [])
})

test("demo: the six named attacks are all present", async () => {
  const result = await runDemo()
  const labels = result.steps.map((step) => step.label).join("\n")

  for (const expected of [
    "injection asks the broker for the token",
    "raw Python socket",
    "child shell running curl",
    "changes the merge method after authorization",
    "replays the permit",
    "external sink",
  ]) {
    assert.ok(labels.includes(expected), `demo is missing the "${expected}" attack`)
  }
})

test("demo: legitimate work still succeeds", async () => {
  const result = await runDemo()

  assert.equal(result.fileReadWithValidPermit, true)

  const read = result.steps.find((step) => step.label.includes("reads issues"))

  assert.equal(read?.blocked, false)
})

test("demo: no production credential reaches the agent context", async () => {
  const result = await runDemo()

  assert.equal(result.orchestratorTokenSeenByAgent, false)

  const serialized = JSON.stringify(result.evidence)

  // The evidence chain is also an output that must not carry credentials.
  assert.equal(/ghp_|access_token|secretAccessKey/.test(serialized), false)
})

test("demo: the evidence chain verifies offline", async () => {
  const result = await runDemo()

  assert.equal(result.evidenceValid, true)
  assert.ok(result.evidenceRecordCount > 0)
})