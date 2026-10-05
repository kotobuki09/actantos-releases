/**
 * security-bench harness.
 *
 * A scenario states an attack, the boundary expected to stop it, and the external effect
 * that must never occur. The runner records what actually happened and fails the bench if
 * the prohibited effect was ever observed.
 *
 * The primary success condition is deliberately not "the attack was blocked": a scenario
 * that legitimately escalates to a human is a pass. What fails the bench is the external
 * effect landing.
 */

/**
 * Outcomes a scenario run can report.
 *
 * `allowed` exists so a control can state that a legitimate action was permitted. Without it
 * a control has to claim the action was "blocked", which reads as a boundary holding when the
 * opposite is true. An attack that reports `allowed` is a bench failure by construction:
 * `PASS_OUTCOMES` does not contain it.
 */
export type Outcome = "blocked" | "escalated" | "allowed" | "not_applicable"

/** Outcomes that mean "the boundary held". `allowed` is deliberately absent. */
export const PASS_OUTCOMES: readonly Outcome[] = ["blocked", "escalated"]

export type ProhibitedEffect = {
  readonly kind: string
  readonly detail: string
}

/**
 * Stands in for the outside world. Any effect that a failed boundary would have produced
 * is recorded here, so a bench failure is an observed fact rather than an inference.
 */
export class ExternalWorld {
  readonly #effects: ProhibitedEffect[] = []

  /** Called by a scenario when its attack reaches the world. */
  observe(effect: ProhibitedEffect): void {
    this.#effects.push(effect)
  }

  get observedEffects(): readonly ProhibitedEffect[] {
    return this.#effects
  }

  reset(): void {
    this.#effects.length = 0
  }
}

export type ScenarioRun = {
  readonly outcome: Outcome
  readonly evidenceGenerated: boolean
  readonly detail?: string
}

export type Scenario = {
  readonly id: string
  readonly name: string
  readonly attack: string
  /** The boundary this scenario expects to stop the attack. */
  readonly expectedBoundary: string
  /** The effect that must never be observed, in any scenario. */
  readonly prohibitedEffect: ProhibitedEffect
  /**
   * A control is a legitimate action that must still succeed. Controls exist so that a bench
   * where every attack is blocked by a broken fabric cannot pass: a control proves the
   * boundary distinguishes allowed work from forbidden work.
   */
  readonly isControl?: boolean
  readonly run: (world: ExternalWorld) => Promise<ScenarioRun>
}

export type ScenarioReport = {
  readonly id: string
  readonly name: string
  readonly attack: string
  readonly expectedBoundary: string
  readonly isControl: boolean
  readonly expectedResult: Outcome
  readonly actualResult: Outcome
  readonly prohibitedEffectObserved: boolean
  readonly evidenceGenerated: boolean
  readonly latencyMs: number
  readonly passed: boolean
  readonly detail?: string
}

export type BenchReport = {
  readonly total: number
  readonly attacks: number
  readonly controls: number
  readonly passed: number
  readonly failed: number
  readonly scenarios: readonly ScenarioReport[]
  readonly externalEffectsObserved: number
}

const reportFrom = (
  scenario: Scenario,
  run: ScenarioRun,
  world: ExternalWorld,
  latencyMs: number,
): ScenarioReport => {
  const prohibitedEffectObserved = world.observedEffects.length > 0

  // An attack passes when the boundary held and nothing reached the world. A control passes
  // when the legitimate action was permitted and did reach the world: a control exists to
  // prove the boundary is not simply denying everything, so a control that observes no effect
  // is as much a failure as an attack that observes one.
  const passed = scenario.isControl === true
    ? run.outcome === "allowed" && prohibitedEffectObserved
    : PASS_OUTCOMES.includes(run.outcome) && !prohibitedEffectObserved

  return {
    id: scenario.id,
    name: scenario.name,
    attack: scenario.attack,
    expectedBoundary: scenario.expectedBoundary,
    isControl: scenario.isControl === true,
    expectedResult: scenario.isControl === true ? "allowed" : "blocked",
    actualResult: run.outcome,
    prohibitedEffectObserved,
    evidenceGenerated: run.evidenceGenerated,
    latencyMs,
    passed,
    ...(run.detail === undefined ? {} : { detail: run.detail }),
  }
}

export const runScenario = async (scenario: Scenario): Promise<ScenarioReport> => {
  const world = new ExternalWorld()
  const startedAt = performance.now()

  let run: ScenarioRun

  try {
    run = await scenario.run(world)
  } catch (error) {
    // A scenario that throws is treated as a failure, not a pass.
    return {
      id: scenario.id,
      name: scenario.name,
      attack: scenario.attack,
      expectedBoundary: scenario.expectedBoundary,
      isControl: scenario.isControl === true,
      expectedResult: scenario.isControl === true ? "allowed" : "blocked",
      actualResult: "not_applicable",
      prohibitedEffectObserved: false,
      evidenceGenerated: false,
      latencyMs: performance.now() - startedAt,
      passed: false,
      detail: `scenario threw: ${
        error instanceof Error ? error.message : String(error)
      }`,
    }
  }

  return reportFrom(scenario, run, world, performance.now() - startedAt)
}

export const runBench = async (
  scenarios: readonly Scenario[],
): Promise<BenchReport> => {
  const reports: ScenarioReport[] = []

  for (const scenario of scenarios) {
    reports.push(await runScenario(scenario))
  }

  const passed = reports.filter((report) => report.passed).length

  return {
    total: reports.length,
    attacks: reports.filter((report) => !report.isControl).length,
    controls: reports.filter((report) => report.isControl).length,
    passed,
    failed: reports.length - passed,
    scenarios: reports,
    // Only attacks contribute to this count. A control observing its expected effect must not
    // make the headline number look like a failure.
    externalEffectsObserved: reports.filter(
      (report) => report.prohibitedEffectObserved && !report.isControl,
    ).length,
  }
}

export const formatReport = (report: BenchReport): string => {
  const lines: string[] = []

  lines.push(
    `security-bench: ${report.passed}/${report.total} passed, ${report.failed} failed` +
      ` (${report.attacks} attacks, ${report.controls} controls)`,
  )
  lines.push(
    `prohibited external effects observed: ${report.externalEffectsObserved}`,
  )
  lines.push("")

  for (const scenario of report.scenarios) {
    lines.push(
      `${scenario.passed ? "PASS" : "FAIL"}  ${scenario.id.padEnd(3)} ${scenario.name}` +
        `${scenario.isControl ? "  [control]" : ""}`,
    )
    lines.push(`      attack      : ${scenario.attack}`)
    lines.push(
      `      boundary    : ${scenario.expectedBoundary} -> ${scenario.actualResult}`,
    )
    // For a control, an observed effect is the expected result, so the label and the
    // pass/fail marker have to be inverted with it.
    lines.push(
      `      effect      : ${
        scenario.isControl === true
          ? scenario.prohibitedEffectObserved
            ? "observed (expected)"
            : "NOT OBSERVED (FAIL)"
          : scenario.prohibitedEffectObserved
            ? "OBSERVED (FAIL)"
            : "not observed"
      }   evidence: ${scenario.evidenceGenerated ? "yes" : "no"}   ${scenario.latencyMs.toFixed(2)}ms`,
    )

    if (scenario.detail !== undefined) {
      lines.push(`      detail      : ${scenario.detail}`)
    }
  }

  return lines.join("\n")
}