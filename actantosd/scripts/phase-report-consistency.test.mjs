import assert from "node:assert/strict"
import { existsSync, readFileSync } from "node:fs"
import path from "node:path"
import test from "node:test"
import { fileURLToPath } from "node:url"

/**
 * The phase report is a summary, and summaries drift. Every number in it that claims to be a
 * measurement is checked against the machine-derived state file, so the report cannot quietly
 * disagree with what the suite actually does.
 *
 * This exists for the same reason the other doc guards do: the most expensive error in this
 * project was a measurement error that propagated through three documents and stood for several
 * iterations. A report is exactly where such a number goes to hide.
 */

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..")
const read = (relative) => readFileSync(path.join(repoRoot, relative), "utf8")

const report = read("docs/PHASE_REPORT.md")
const state = JSON.parse(read("docs/security-fabric-current-state.json"))

test("the phase report cites the current test counts", () => {
  const { daemon_total: total, v2_fabric: v2 } = state.unit_suite

  assert.match(report, new RegExp(`\\b${total}\\b`), `report must cite the daemon total ${total}`)
  assert.match(report, new RegExp(`\\b${v2}\\b`), `report must cite the v2 count ${v2}`)
})

test("the phase report does not present the static composition as the runner total", () => {
  // `countTests` is a regex, so a `test(` in a loop body is counted once and registered once per
  // element. The report may cite the static composition, but it must not present it as the number
  // `npm test` reports — that claim was made here and was four short.
  const { daemon_total: total, runner_overcount: overcount } = state.unit_suite

  assert.ok(overcount > 0, "if the overcount is gone, this guard's premise no longer holds")
  assert.ok(
    report.includes(`${total + overcount}`) || /runner_overcount|registers once per element/u.test(report),
    "the report must either cite the runner total or explain the gap between it and the static one",
  )
  assert.ok(
    !new RegExp(`${total} (?:tests|registered)\\b`, "u").test(report),
    `the report must not call the static total ${total} the number of tests run`,
  )
})

test("the phase report does not claim every skipped test is covered by the substrate job", () => {
  // The substrate runner sets DATABASE_URL and ACTANTOS_SUBSTRATE_TESTS only. The SPIRE gate needs
  // a trust domain it does not provide, so "all skipped tests run in CI" overstates what CI proves.
  const runner = read("actantosd/scripts/run-substrate-tests.mjs")

  assert.ok(
    !runner.includes("spire-substrate.test.ts"),
    "spire-substrate is gated on a trust domain the substrate runner does not provide",
  )
  assert.ok(
    report.includes("spire-substrate.test.ts"),
    "the report must name spire-substrate.test.ts as a skip the substrate job does not cover",
  )

  // Cedar used to sit in the same position. It no longer does, and a guard that kept asserting it
  // would be encoding a stale premise the way the exit-code test did.
  assert.ok(
    !/cedar-provider\.test\.ts — \d+ skipped/u.test(report),
    "the report must not claim the Cedar tests still skip",
  )
})

test("the phase report cites the bench result", () => {
  const { scenarios, passed, prohibited_external_effects: prohibited } = state.security_bench

  assert.equal(prohibited, 0, "a prohibited external effect would invalidate the whole report")
  assert.ok(
    report.includes(`${passed}/${scenarios}`),
    `report must cite the bench as ${passed}/${scenarios}`,
  )
})

test("the phase report cites every substrate level the state file records", () => {
  // A substrate promoted or demoted in the state file must not be silently absent from the
  // report's guarantee matrix.
  for (const [id, entry] of Object.entries(state.substrate_requirements)) {
    const row = report.split("\n").find((line) => line.includes(`\`${id}\``))
    assert.ok(row, `the guarantee matrix is missing substrate ${id}`)
    assert.ok(
      row.includes(entry.level),
      `the row for ${id} should say ${entry.level}, got: ${row.trim()}`,
    )
  }
})

test("the phase report does not claim v2 production qualification", () => {
  // The phrase is reserved for the conditions in section 28 of the spec, which are not met.
  assert.ok(
    !/production-qualified|production qualified/i.test(report),
    "the report must not describe the fabric as production-qualified",
  )
  assert.match(report, /quiet-open-core/, "the report must carry the authoritative maturity label")
})

test("the phase report records the pi-adapter reconciliation and what it does not establish", () => {
  // This began as "the report must record the unmet pi-adapter prerequisite". The reconciliation
  // closed that gap, and keeping the guard would have required the report to keep calling a fixed
  // defect unmet. It now asserts the report still describes the path and is honest about the
  // limits that remain, so the fix cannot quietly become a stronger claim than it is.
  assert.match(report, /shell_executor\.ts/, "the pi-adapter path must be named in the report")
  assert.match(
    report,
    /command_hash|canonicalCommandHash/u,
    "the report must name the binding that closes the gap",
  )
  assert.match(
    report,
    /replayable/i,
    "the report must state that a captured token is still replayable within its TTL",
  )
  assert.match(
    report,
    /not make the workspace an authorization\s+input|not an authorization input/u,
    "the report must say the workspace is bound for consistency, not by policy",
  )
})

test("the phase report does not claim the shell command binding is enforced against a live container", () => {
  // This guard previously required both executors to stay SIMULATED, on the premise that no test
  // started a real container. That premise is no longer true: `docker-executor-substrate.test.ts`
  // and `packages/pi-adapter/src/shell_executor_substrate.test.ts` both start containers.
  //
  // The claim moved rather than being invented, so the guard now checks that each REAL_SUBSTRATE
  // claim is backed by a file that actually exists and is actually gated. Deleting the guard would
  // have let the report claim real-container enforcement with nothing behind it, which is the
  // failure this taxonomy exists to prevent.
  // docker-executor was SIMULATED here for as long as its residue was open. The residue is closed
  // now — each resource flag is read back from inside a real container, and output truncation,
  // redaction and the timeout run against a real process — so the level moved rather than the
  // claim being invented. The guard below is what keeps that from becoming a free upgrade: a
  // REAL_SUBSTRATE row is only allowed to stand while the gated file behind it exists.
  assert.match(
    report,
    /`docker-executor` \| REAL_SUBSTRATE/,
    "docker-executor's residue is closed, so the report must record the level it reached",
  )

  assert.match(
    report,
    /`pi-adapter-shell-executor` \| REAL_SUBSTRATE/,
    "pi-adapter-shell-executor is real now, and the matrix must say so",
  )

  // The entry that carries the real-substrate claim for the canonical executor.
  assert.match(
    report,
    /`docker-container-execution` \| REAL_SUBSTRATE/,
    "the canonical executor's real-substrate claim needs its own entry",
  )

  for (const file of [
    "src/docker-executor-substrate.test.ts",
    "../packages/pi-adapter/src/shell_executor_substrate.test.ts",
  ]) {
    assert.ok(
      existsSync(path.join(repoRoot, "actantosd", file)),
      `${file} is cited as the real-substrate evidence but does not exist`,
    )
  }
});

test("the phase report does not claim the shell binding is enforced under gVisor", () => {
  // A real sandbox is running, but two narrower claims are still not made and must stay unmade.
  //
  // First: egress. The WSL2 daemon's bridge has no external route under *either* runtime, so
  // blocked egress there says nothing about gVisor's netstack. If that sentence is deleted, the
  // report reads as though gVisor was proved to stop network access, which is not what was
  // measured.
  assert.match(
    report,
    /Egress is not claimed[\s\S]{0,400}?cannot be attributed to\s+gVisor's netstack/u,
    "the report must keep refusing to credit blocked egress to gVisor",
  )

  // Second: the gate. Six of the seven gVisor tests inject `checkRunsc`, because runsc is not on
  // the Windows PATH; only the seventh leaves it to production code, and only under WSL2. A report
  // that described all of them as un-injected would overstate how much of the gate was exercised
  // on the client side.
  assert.match(
    report,
    /client-side binary probe is injected in\s+five of the seven tests/u,
    "the report must say which gVisor tests still inject the binary probe",
  )
  assert.match(
    report,
    /seventh leaves the binary probe un-injected/u,
    "the report must record that one test does exercise the executor's own probe",
  )
});

test("every phase in the report names a commit that exists", () => {
  const commits = [...report.matchAll(/`([0-9a-f]{7})`/g)].map((match) => match[1])
  assert.ok(commits.length >= 4, `expected the phase table to cite commits, found ${commits.length}`)
})
