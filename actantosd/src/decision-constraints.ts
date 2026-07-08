export type DecisionConstraints = {
  readonly timeout_ms: number
  readonly max_output_bytes: number
  readonly network_mode: "none" | "egress_proxy"
  readonly network_allowlist: readonly string[]
}

export const DEFAULT_DECISION_CONSTRAINTS = {
  timeout_ms: 30_000,
  max_output_bytes: 200_000,
  network_mode: "none",
  network_allowlist: [],
} as const satisfies DecisionConstraints

export const createDecisionConstraints = (
  options: {
    readonly networkMode: DecisionConstraints["network_mode"]
    readonly timeoutMs?: number
    readonly maxOutputBytes?: number
    readonly networkAllowlist?: readonly string[]
  },
): DecisionConstraints => ({
  ...DEFAULT_DECISION_CONSTRAINTS,
  timeout_ms: options.timeoutMs ?? DEFAULT_DECISION_CONSTRAINTS.timeout_ms,
  max_output_bytes: options.maxOutputBytes ?? DEFAULT_DECISION_CONSTRAINTS.max_output_bytes,
  network_mode: options.networkMode,
  network_allowlist: [...(options.networkAllowlist ?? DEFAULT_DECISION_CONSTRAINTS.network_allowlist)],
})
