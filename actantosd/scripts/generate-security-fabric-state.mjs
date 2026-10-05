#!/usr/bin/env node
// Regenerate `docs/security-fabric-current-state.json` from a real run.
//
// The benchmark is actually executed here rather than read from a previous log, so the recorded
// prohibited-effect count describes this commit and not some earlier one. Everything else is
// derived from the files on disk.
//
// Usage: node scripts/generate-security-fabric-state.mjs [--no-bench] [--check]

import { execFileSync } from "node:child_process"
import { readFileSync, writeFileSync } from "node:fs"
import { join } from "node:path"

import { DAEMON_ROOT, collectState, stableView, statePath } from "./security-fabric-state.mjs"

const args = new Set(process.argv.slice(2))

const runBench = () => {
  if (args.has("--no-bench")) return null

  try {
    return execFileSync(
      process.execPath,
      ["--experimental-strip-types", join("..", "security-bench", "src", "bench.ts")],
      { cwd: DAEMON_ROOT, encoding: "utf8", timeout: 300000, stdio: ["ignore", "pipe", "pipe"] },
    )
  } catch (error) {
    // A failing benchmark must not be recorded as a clean one. Record the failure instead.
    process.stderr.write(`bench did not complete cleanly:\n${error.stdout ?? ""}${error.stderr ?? ""}\n`)
    return null
  }
}

const state = collectState({ benchOutput: runBench() })
const serialized = `${JSON.stringify(state, null, 2)}\n`
const target = statePath()

if (args.has("--check")) {
  let current
  try {
    current = JSON.parse(readFileSync(target, "utf8"))
  } catch {
    process.stderr.write(`${target} does not exist or is not valid JSON. Run: node scripts/generate-security-fabric-state.mjs\n`)
    process.exit(1)
  }

  // Compare only the machine-independent half. `generated_at`, `commit` and `environment`
  // describe this moment and this host; requiring them to match a committed file would make
  // the check impossible to ever satisfy.
  const expected = stableView(state)
  const actual = stableView(current)
  const drift = Object.keys(expected).filter((key) => {
    const a = JSON.stringify(actual[key])
    const b = JSON.stringify(expected[key])
    return a !== b
  })

  if (drift.length > 0) {
    process.stderr.write(
      `${target} is stale in: ${drift.join(", ")}\n` +
        `Run: node scripts/generate-security-fabric-state.mjs\n`,
    )
    for (const key of drift) {
      process.stderr.write(`\n--- ${key} (committed) ---\n${JSON.stringify(actual[key], null, 2).slice(0, 900)}\n`)
      process.stderr.write(`--- ${key} (actual) ---\n${JSON.stringify(expected[key], null, 2).slice(0, 900)}\n`)
    }
    process.exit(1)
  }

  process.stdout.write("security fabric state is current\n")
} else {
  writeFileSync(target, serialized, "utf8")
  process.stdout.write(
    [
      `wrote ${target}`,
      `  unit tests          ${state.unit_suite.daemon_total} (src ${state.unit_suite.daemon_src}, v2 ${state.unit_suite.v2_fabric}, scripts ${state.unit_suite.release_scripts})`,
      `  security bench      ${state.security_bench.ran ? `${state.security_bench.passed}/${state.security_bench.scenarios}` : "NOT RUN"}`,
      `  prohibited effects  ${state.security_bench.prohibited_external_effects ?? "unknown"}`,
      `  maturity            ${state.product.maturity_label} / ${state.product.active_implementation_maturity}`,
      "",
    ].join("\n"),
  )
}