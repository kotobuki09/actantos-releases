import { z } from "zod"

import { DATA_LABELS, type DataLabel } from "./signed-policy-bundle.ts"

/**
 * Boundary information-flow control (invariant S10).
 *
 * Data may not flow from a source label into a sink whose clearance is lower. This is
 * deliberately *boundary* IFC rather than whole-program taint tracking: labels are attached
 * at ingestion and at sinks, and enforcement happens where the two meet. Claiming full
 * taint tracking here would be a claim the tests cannot support.
 *
 * Downgrade happens only through an explicit, signed declassification rule. There is no
 * implicit path from a higher label to a lower clearance.
 */

export const SINK_TYPES = [
  "external_http",
  "internal_http",
  "email",
  "mcp_server",
  "another_agent",
  "model_provider",
  "file_store",
  "database",
] as const

export const sinkTypeSchema = z.enum(SINK_TYPES)

export type SinkType = z.infer<typeof sinkTypeSchema>

/**
 * Rank order, taken directly from the v2 specification. A higher rank is more sensitive.
 */
export const LABEL_RANK: Readonly<Record<DataLabel, number>> = {
  PUBLIC: 0,
  INTERNAL: 1,
  CONFIDENTIAL: 2,
  PII: 3,
  SECRET: 4,
  CREDENTIAL: 5,
}

/** Clearance each sink type grants by default. A sink may be lowered, never raised implicitly. */
export const DEFAULT_SINK_CLEARANCE: Readonly<Record<SinkType, DataLabel>> = {
  external_http: "PUBLIC",
  internal_http: "INTERNAL",
  email: "INTERNAL",
  mcp_server: "INTERNAL",
  another_agent: "INTERNAL",
  model_provider: "PUBLIC",
  file_store: "CONFIDENTIAL",
  database: "CONFIDENTIAL",
}

export const highestLabel = (labels: readonly DataLabel[]): DataLabel => {
  let highest: DataLabel = "PUBLIC"

  for (const label of labels) {
    if (LABEL_RANK[label] > LABEL_RANK[highest]) {
      highest = label
    }
  }

  return highest
}

export const declassificationRuleSchema = z.object({
  rule_id: z.string().min(1),
  sink_type: sinkTypeSchema,
  /** Labels this rule may permit to cross. */
  permitted_labels: z.array(z.enum(DATA_LABELS)).min(1),
  justification: z.string().min(1),
  approved_by: z.string().min(1),
})

export type DeclassificationRule = z.infer<typeof declassificationRuleSchema>

export type IfcDecision =
  | { readonly allowed: true; readonly requiredClearance: DataLabel }
  | {
      readonly allowed: false
      readonly reason: "clearance_violation"
      readonly dataLabel: DataLabel
      readonly sinkClearance: DataLabel
      readonly sinkType: SinkType
    }

/**
 * Decide whether `dataLabels` may flow into a sink.
 *
 * A declassification rule can permit a flow that the default clearance would deny, but only
 * when the rule explicitly lists the label. Absent a matching rule the answer is deny.
 */
export const evaluateIfc = (
  dataLabels: readonly DataLabel[],
  sinkType: SinkType,
  options: {
    readonly sinkClearance?: DataLabel | undefined
    readonly declassificationRules?: readonly DeclassificationRule[] | undefined
  } = {},
): IfcDecision => {
  const sinkClearance = options.sinkClearance ?? DEFAULT_SINK_CLEARANCE[sinkType]
  const dataLabel = highestLabel(dataLabels)

  if (LABEL_RANK[dataLabel] <= LABEL_RANK[sinkClearance]) {
    return { allowed: true, requiredClearance: sinkClearance }
  }

  const rule = (options.declassificationRules ?? []).find(
    (candidate) =>
      candidate.sink_type === sinkType &&
      candidate.permitted_labels.includes(dataLabel),
  )

  if (rule !== undefined) {
    return { allowed: true, requiredClearance: sinkClearance }
  }

  return {
    allowed: false,
    reason: "clearance_violation",
    dataLabel,
    sinkClearance,
    sinkType,
  }
}