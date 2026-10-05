import assert from "node:assert/strict"
import { test } from "node:test"

import { runBench, runScenario } from "./harness.ts"
import { SCENARIOS } from "./scenarios.ts"

/**
 * The bench is a gate, not a report. This test fails the build when any scenario produces a
 * prohibited external effect, when a scenario throws, or when an attack is dropped.
 */

const ATTACK_IDS = [
  "1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12", "13",
  "14", "15", "16", "17", "18", "19", "20", "21", "22", "23", "24", "25", "26",
]

test("security-bench: all 26 required attack scenarios are present", () => {
  const ids = SCENARIOS.filter((scenario) => scenario.isControl !== true).map(
    (scenario) => scenario.id,
  )

  assert.deepEqual(ids, ATTACK_IDS)
})

test("security-bench: controls exist so a deny-everything fabric cannot pass", () => {
  const controls = SCENARIOS.filter((scenario) => scenario.isControl === true)

  assert.equal(controls.length, 2)
})

test("security-bench: every attack is blocked or escalated, with no external effect", async () => {
  const report = await runBench(SCENARIOS)

  const failures = report.scenarios
    .filter((scenario) => !scenario.passed)
    .map(
      (scenario) =>
        `${scenario.id} ${scenario.name}: outcome=${scenario.actualResult} effectObserved=${scenario.prohibitedEffectObserved} detail=${scenario.detail ?? ""}`,
    )

  assert.deepEqual(failures, [], failures.join("\n"))
  assert.equal(report.externalEffectsObserved, 0)
  assert.equal(report.failed, 0)
})

test("security-bench: every scenario generated evidence", async () => {
  const report = await runBench(SCENARIOS)

  const withoutEvidence = report.scenarios
    .filter((scenario) => !scenario.evidenceGenerated)
    .map((scenario) => `${scenario.id} ${scenario.name}`)

  assert.deepEqual(withoutEvidence, [])
})

test("security-bench: a scenario that throws is a failure, not a pass", async () => {
  const scenario = {
    id: "X",
    name: "throwing scenario",
    attack: "throws",
    expectedBoundary: "none",
    prohibitedEffect: { kind: "none", detail: "none" },
    run: async () => {
      throw new Error("boom")
    },
  }

  const report = await runScenario(scenario)

  assert.equal(report.passed, false)
  assert.equal(report.actualResult, "not_applicable")
})