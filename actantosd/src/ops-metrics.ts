export type DecisionCountSummary = {
  readonly decision_count: number
  readonly allow_count: number
  readonly deny_count: number
  readonly approval_required_count: number
  readonly active_kill_switch_count: number
}

export type DecisionRates = {
  readonly allow_rate: number
  readonly deny_rate: number
  readonly approval_required_rate: number
}

const ratio = (numerator: number, denominator: number): number =>
  denominator <= 0 ? 0 : numerator / denominator

/** Pure rate math for operator metrics home (S2-1). */
export const computeDecisionRates = (summary: DecisionCountSummary): DecisionRates => {
  const total = summary.decision_count
  return {
    allow_rate: ratio(summary.allow_count, total),
    deny_rate: ratio(summary.deny_count, total),
    approval_required_rate: ratio(summary.approval_required_count, total),
  }
}

export const buildOpsHomeSummary = (summary: DecisionCountSummary) => ({
  ...computeDecisionRates(summary),
  decision_count: summary.decision_count,
  allow_count: summary.allow_count,
  deny_count: summary.deny_count,
  approval_required_count: summary.approval_required_count,
  active_kill_switch_count: summary.active_kill_switch_count,
  kill_switch_armed: summary.active_kill_switch_count > 0,
})
