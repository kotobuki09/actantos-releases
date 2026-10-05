// Guards against the exact drift this repository already suffered once.
//
// `docs/SECURITY_TEST_MATRIX.md` claimed 378 tests while `node --test` reported 401, and the
// commit message said 401. Nothing reconciled them, so for a while no source could be trusted.
// These tests make the machine-readable file authoritative and check it against a fresh
// derivation, so a hand-edited number cannot survive a commit.

import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { existsSync, readFileSync, readdirSync } from "node:fs"
import { join } from "node:path"
import { test } from "node:test"

import {
  DAEMON_ROOT,
  REPO_ROOT,
  SUBSTRATE_REQUIREMENTS,
  collectState,
  countLoopGeneratedTests,
  countTests,
  parseBenchOutput,
  stableView,
  statePath,
} from "./security-fabric-state.mjs"

const stateFile = statePath()
const readState = () => JSON.parse(readFileSync(stateFile, "utf8"))

/**
 * Run the benchmark for real rather than trusting a recorded log.
 *
 * It takes under a second, and a count read from a previous run would be exactly the kind of
 * transcribed number this file exists to eliminate.
 */
const runBench = () =>
  execFileSync(
    process.execPath,
    ["--experimental-strip-types", join("..", "security-bench", "src", "bench.ts")],
    { cwd: DAEMON_ROOT, encoding: "utf8", timeout: 300000, stdio: ["ignore", "pipe", "pipe"] },
  )

test("security fabric state: the committed file matches a fresh derivation", () => {
  const fresh = collectState({ benchOutput: runBench() })

  assert.deepEqual(
    stableView(readState()),
    stableView(fresh),
    `${stateFile} is stale. Run: node scripts/generate-security-fabric-state.mjs`,
  )
})

test("security fabric state: static test counts sum to the daemon total", () => {
  const { unit_suite: suite } = readState()

  assert.equal(
    suite.daemon_src + suite.v2_fabric + suite.release_scripts,
    suite.daemon_total,
    "the three buckets must add up to the daemon total",
  )

  assert.equal(
    suite.daemon_src + suite.v2_fabric + suite.release_scripts + suite.security_bench_package,
    suite.daemon_total + suite.security_bench_package,
    "adding the bench package must stay consistent",
  )
})

test("security fabric state: the static count plus the loop overcount is what the runner reports", () => {
  // `countTests` sees a `test(` inside a `for` body once; the runner registers it once per
  // element. Only the files that actually have such a site need running, so this compares
  // against a real `node --test` rather than asserting a transcribed total.
  const directories = [
    { dir: join(DAEMON_ROOT, "src"), ext: ".test.ts" },
    { dir: join(DAEMON_ROOT, "src", "v2"), ext: ".test.ts" },
    { dir: join(DAEMON_ROOT, "scripts"), ext: ".test.mjs" },
  ]
  const looped = []

  for (const { dir, ext } of directories) {
    for (const name of readdirSync(dir).filter((entry) => entry.endsWith(ext))) {
      const source = readFileSync(join(dir, name), "utf8")

      if (countLoopGeneratedTests(source) > 0) {
        looped.push({ path: join(dir, name), source })
      }
    }
  }

  assert.ok(looped.length > 0, "the overcount must be exercised by at least one real file")

  for (const { path, source } of looped) {
    // A nested runner inherits NODE_TEST_CONTEXT from the outer one, which makes it report over
    // the parent's IPC channel and write nothing to stdout. Clearing it is what makes the
    // summary this test parses actually appear.
    const env = { ...process.env }
    delete env["NODE_TEST_CONTEXT"]

    const output = execFileSync(
      process.execPath,
      ["--experimental-strip-types", "--test", path],
      { encoding: "utf8", timeout: 300000, stdio: ["ignore", "pipe", "pipe"], env },
    )
    const registered = Number(/tests (\d+)/u.exec(output)?.[1])

    assert.equal(
      countTests(source) + countLoopGeneratedTests(source),
      registered,
      `${path}: static count plus overcount must equal what node --test registers`,
    )
  }
})

test("security fabric state: the recorded benchmark ran and blocked every prohibited effect", () => {
  const { security_bench: bench } = readState()

  assert.equal(bench.ran, true, "the recorded benchmark must come from a real run, not a null")
  assert.equal(bench.failed, 0)
  assert.equal(bench.prohibited_external_effects, 0, "prohibited external effects must be zero")
  assert.equal(
    bench.scenarios,
    bench.attacks + bench.controls,
    "every scenario is either an attack or a control",
  )
  assert.ok(bench.controls > 0, "controls must exist, or a deny-everything fabric would score well")
})

test("security fabric state: every invariant is backed by a test file that exists", () => {
  const { invariants } = readState()

  assert.deepEqual(invariants.cited_without_tests, [], "an invariant citing no test proves nothing")
  assert.ok(invariants.declared >= 14, `expected at least S1-S14, found ${invariants.declared}`)
})

test("security fabric state: a real substrate gate is classified, and the classification is honest", () => {
  const classified = new Set(
    Object.values(SUBSTRATE_REQUIREMENTS).flatMap((requirement) => requirement.test_files),
  )

  // Deliberately narrow. An earlier version of this test flagged any file containing the word
  // "cedar", which caught type-only imports and prose comments and would have filled the
  // registry with noise until people stopped reading it. The real risk is a gate that actually
  // skips, because that is where a test silently stops running.
  const GATE = /\bt\.skip\(|\{\s*skip:/u

  const gatedFiles = []
  for (const directory of ["src", "src/v2", "scripts"]) {
    const absolute = join(DAEMON_ROOT, directory)
    if (!existsSync(absolute)) continue

    for (const name of readdirSync(absolute).filter((n) => /\.test\.[cm]?[jt]s$/u.test(n))) {
      const relativePath = `${directory}/${name}`
      const source = readFileSync(join(absolute, name), "utf8")
      if (GATE.test(source)) gatedFiles.push([relativePath, source])
    }
  }

  // Nothing in the repository currently skips. If that stops being true, the new gate must be
  // registered so the state file can report it as unavailable rather than quietly counting zero.
  for (const [relativePath] of gatedFiles) {
    assert.ok(
      classified.has(relativePath),
      `${relativePath} skips tests but is absent from SUBSTRATE_REQUIREMENTS, so a missing substrate would silently go unrecorded`,
    )
  }

  for (const [name, requirement] of Object.entries(SUBSTRATE_REQUIREMENTS)) {
    if (requirement.level === "NOT_IMPLEMENTED") {
      assert.equal(
        requirement.gated_tests,
        0,
        `${name} is ${requirement.level} and must not also claim tests that wait on a substrate`,
      )
      continue
    }

    // SIMULATED falls through to the skip-site check rather than being exempted. A simulated
    // integration is exactly what a gated substrate test is for — spire-workload-identity is
    // simulated because a live SPIRE refuses it, and counting its five skip sites is how the
    // report stays honest about work that did not happen.

    // The claimed number of skipped tests must match the skip sites actually in the file.
    // An inflated number would report missing coverage that does not exist; a deflated one
    // would hide coverage that really is missing.
    const source = requirement.test_files
      .map((file) => readFileSync(join(DAEMON_ROOT, file), "utf8"))
      .join("\n")
    const actual = source.match(/\bt\.skip\(|\{\s*skip:/gu)?.length ?? 0

    assert.equal(
      actual,
      requirement.gated_tests,
      `${name} claims ${requirement.gated_tests} gated tests but its files contain ${actual} skip sites`,
    )
  }
})

test("security fabric state: no gate is claimed as covered while its substrate is absent", () => {
  const state = readState()

  for (const [name, requirement] of Object.entries(SUBSTRATE_REQUIREMENTS)) {
    // NOT_IMPLEMENTED means nothing was built, so there is nothing to gate.
    if (requirement.level === "NOT_IMPLEMENTED") {
      assert.equal(
        requirement.gated_tests,
        0,
        `${name} is ${requirement.level}, so it cannot also have tests waiting on a substrate`,
      )
      continue
    }

    // SIMULATED is deliberately *not* excluded. It previously was, on the assumption that a
    // simulated group has nothing waiting on a real substrate. That assumption is false, and
    // spire-workload-identity is the counterexample: the product's SPIRE integration is simulated
    // because a live SPIRE refuses it, and the file that found that out is a gated test. The
    // check below therefore applies to it too, which is stricter than before — a SIMULATED group
    // with gated tests must now report them as unavailable rather than merely omitting them.
    if (requirement.gated_tests > 0 && !state.substrate_run.substrates[requirement.substrate]) {
      const reported = state.substrate_run.substrate_tests_unavailable.some((u) => u.group === name)
      assert.ok(
        reported,
        `${name} needs ${requirement.substrate} and it is absent, so it must appear in substrate_tests_unavailable`,
      )
    }
  }
})

test("security fabric state: the bench output parser rejects a partial or missing run", () => {
  assert.equal(parseBenchOutput(undefined).ran, false)
  assert.equal(parseBenchOutput("").ran, false, "empty output is not a passing benchmark")
  assert.equal(parseBenchOutput(undefined).prohibited_external_effects, null)

  const complete = parseBenchOutput(
    "security-bench: 28/28 passed, 0 failed (26 attacks, 2 controls)\nprohibited external effects observed: 0\n",
  )
  assert.equal(complete.prohibited_external_effects, 0)
  assert.equal(complete.attacks, 26)

  // A truncated log must not be read as a clean run with zero prohibited effects.
  const truncated = parseBenchOutput("security-bench: 28/28 passed, 0 failed (26 attacks, 2 controls)\n")
  assert.equal(truncated.prohibited_external_effects, null)
})

test("security fabric state: countTests ignores non-test declarations", () => {
  assert.equal(countTests('test("a", () => {})\n'), 1)
  assert.equal(countTests('  test("nested", () => {})\n'), 1)
  assert.equal(countTests('const x = test("not a call", () => {})\n'), 0)
  assert.equal(countTests("// test('in a comment', () => {})\n"), 0)
  assert.equal(countTests(""), 0)
})

test("security fabric state: maturity is not overstated beyond the release truth file", () => {
  const { product } = readState()
  const truth = JSON.parse(
    readFileSync(join(DAEMON_ROOT, "release-maturity-truth.json"), "utf8"),
  )

  assert.equal(product.package_version, truth.package_version)
  assert.equal(product.maturity_label, truth.maturity_label)
  assert.equal(
    product.active_implementation_maturity,
    "implemented",
    "v2 modules exist; that is 'implemented', not 'production-qualified' or 'released'",
  )
  assert.notEqual(product.maturity_label, "production-qualified")
})

test("security fabric state: the state file exists, parses, and records the run", () => {
  assert.ok(existsSync(stateFile), `${stateFile} is missing. Run: node scripts/generate-security-fabric-state.mjs`)

  const state = readState()
  assert.equal(state.schema_version, 1)
  assert.match(state.generated_at, /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/u, "generated_at must be an ISO timestamp")
  assert.match(state.commit, /^[0-9a-f]{40}$/u, "commit must be the full SHA it was generated from")

  // The two properties the whole document exists to state.
  assert.equal(state.security_bench.prohibited_external_effects, 0)
  assert.equal(
    state.product.active_implementation_maturity,
    "implemented",
    "having v2 modules is not the same as being production-qualified",
  )
})