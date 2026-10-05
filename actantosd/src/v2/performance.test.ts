import assert from "node:assert/strict"
import { test } from "node:test"

import { runPerformance, summarize } from "./performance.ts"

/**
 * These assertions are deliberately loose. The point is not to pin a machine's speed, it is
 * to catch a change that makes enforcement orders of magnitude more expensive — for example
 * re-deriving keys inside a decision loop.
 */

test("performance: percentiles are nearest-rank over observed samples", () => {
  const summary = summarize("test", "ms", [1, 2, 3, 4, 5, 6, 7, 8, 9, 10])

  assert.equal(summary.p50, 5)
  assert.equal(summary.p95, 10)
  assert.equal(summary.p99, 10)
  assert.equal(summary.max, 10)
  assert.equal(summary.mean, 5.5)
  assert.equal(summary.samples, 10)
})

test("performance: an empty sample set reports zero rather than NaN", () => {
  const summary = summarize("empty", "ms", [])

  assert.equal(summary.p50, 0)
  assert.equal(summary.mean, 0)
})

test("performance: every enforcement path is measured and stays cheap", async () => {
  const report = await runPerformance(300)

  const measured = report.summaries.map((summary) => summary.name)

  for (const expected of [
    "sidecar CheckAction (allow)",
    "sidecar CheckAction (deny)",
    "workload identity verify",
    "effect permit issuance (sign)",
    "evidence append (hash + sign)",
    "broker grant (no-op tool)",
  ]) {
    assert.ok(measured.includes(expected), `no measurement for "${expected}"`)
  }

  for (const summary of report.summaries) {
    assert.ok(
      Number.isFinite(summary.p99),
      `${summary.name} produced a non-finite p99`,
    )
    // Generous by two orders of magnitude: this catches a structural regression, not noise.
    assert.ok(
      summary.p99 < 25,
      `${summary.name} p99 was ${summary.p99}ms, which is far outside the expected range`,
    )
  }
})

test("performance: the report states what the numbers do not include", async () => {
  const report = await runPerformance(100)

  assert.ok(report.notes.some((note) => note.includes("no transport")))
  assert.ok(report.notes.some((note) => note.includes("Unix domain socket")))
})