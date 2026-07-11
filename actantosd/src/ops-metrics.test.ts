import assert from "node:assert/strict"
import test from "node:test"

import { buildOpsHomeSummary, computeDecisionRates } from "./ops-metrics.ts"

test("computeDecisionRates returns zero rates when no decisions", () => {
  const rates = computeDecisionRates({
    decision_count: 0,
    allow_count: 0,
    deny_count: 0,
    approval_required_count: 0,
    active_kill_switch_count: 0,
  })
  assert.deepEqual(rates, {
    allow_rate: 0,
    deny_rate: 0,
    approval_required_rate: 0,
  })
})

test("computeDecisionRates and buildOpsHomeSummary reflect real decision mix", () => {
  const summary = {
    decision_count: 10,
    allow_count: 5,
    deny_count: 3,
    approval_required_count: 2,
    active_kill_switch_count: 1,
  }
  const rates = computeDecisionRates(summary)
  assert.equal(rates.allow_rate, 0.5)
  assert.equal(rates.deny_rate, 0.3)
  assert.equal(rates.approval_required_rate, 0.2)

  const home = buildOpsHomeSummary(summary)
  assert.equal(home.kill_switch_armed, true)
  assert.equal(home.active_kill_switch_count, 1)
  assert.equal(home.allow_rate, 0.5)
})
