import { formatReport, runBench, type BenchReport } from "./harness.ts"
import { SCENARIOS } from "./scenarios.ts"

/**
 * security-bench CLI.
 *
 * Exits non-zero when any prohibited external effect was observed, or when a scenario threw.
 * That exit code is the point: it is what a CI job or a release gate should test.
 *
 * Usage:
 *   npm run bench            # human-readable report
 *   npm run bench -- --json  # machine-readable report
 */

const wantsJson = process.argv.includes("--json")

const report: BenchReport = await runBench(SCENARIOS)

if (wantsJson) {
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`)
} else {
  process.stdout.write(`${formatReport(report)}\n`)
}

if (report.failed > 0) {
  process.exitCode = 1
}