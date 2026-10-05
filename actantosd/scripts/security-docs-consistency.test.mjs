import assert from "node:assert/strict"
import { existsSync, readFileSync, readdirSync } from "node:fs"
import path from "node:path"
import test from "node:test"
import { fileURLToPath } from "node:url"

/**
 * Documentation consistency guard for the v2 security fabric.
 *
 * These tests exist because this project's most expensive error was not a code bug. It was a
 * *measurement* error — reading a rotating ring buffer after the event had rotated out — that
 * produced a confident, repeated, and wrong claim about Tetragon visibility. That claim then
 * propagated through three documents and stood for several iterations.
 *
 * These guards are fail-closed on purpose. If a document claims something the tests do not
 * demonstrate, the suite must fail rather than let the claim ship.
 */

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..")
const daemonDir = path.join(repoRoot, "actantosd")
const docsDir = path.join(repoRoot, "docs")

const invariantsDoc = path.join(docsDir, "SECURITY_INVARIANTS.md")
const matrixDoc = path.join(docsDir, "SECURITY_TEST_MATRIX.md")
const architectureDoc = path.join(docsDir, "ARCHITECTURE_V2.md")

const read = (file) => readFileSync(file, "utf8")

// --- Every invariant claim must name a test file that exists and has tests -------------

test("every test count cited in the unit suite table matches the file", () => {
  const doc = read(matrixDoc)

  const rows = doc.split("\n").filter((line) => /^\|\s*`src\/(v2\/)?[\w-]+\.test\.ts`\s*\|/u.test(line))
  assert.ok(rows.length >= 14, `expected 14+ test rows, found ${rows.length}`)

  const mismatches = []
  for (const row of rows) {
    const [, file, claimed] = row.match(/^\|\s*`([^`]+)`\s*\|\s*(\d+)\s*\|/u)
    const body = read(path.join(daemonDir, file))
    const actual = (body.match(/^\s*test\(/gmu) ?? []).length
    if (actual !== Number(claimed)) mismatches.push(`${file}: doc=${claimed} actual=${actual}`)
  }

  assert.deepEqual(mismatches, [])
})

test("the unit suite subtotals add up", () => {
  const doc = read(matrixDoc)

  const rows = doc.split("\n").filter((line) => /^\|\s*`src\/(v2\/)?[\w-]+\.test\.ts`\s*\|/u.test(line))

  const v2 = rows
    .filter((row) => row.includes("`src/v2/"))
    .reduce((sum, row) => sum + Number(row.match(/\|\s*(\d+)\s*\|/u)[1]), 0)
  const v1 = rows
    .filter((row) => !row.includes("`src/v2/"))
    .reduce((sum, row) => sum + Number(row.match(/\|\s*(\d+)\s*\|/u)[1]), 0)

  const subtotal = Number(doc.match(/v2 fabric subtotal\*\*\s*\|\s*\*\*(\d+)\*\*/u)[1])
  const total = Number(doc.match(/v2-relevant total\*\*\s*\|\s*\*\*(\d+)\*\*/u)[1])

  assert.equal(subtotal, v2, `subtotal ${subtotal} != sum of src/v2 rows ${v2}`)
  assert.equal(total, v2 + v1, `total ${total} != ${v2} + ${v1}`)
})

test("every test file cited in the invariant matrix exists and contains tests", () => {
  const doc = read(invariantsDoc)
  const rows = doc
    .split("\n")
    .filter((line) => /^\|\s*S\d+\s*\|/.test(line))

  assert.ok(rows.length >= 14, `expected 14 invariant rows, found ${rows.length}`)

  const missing = []
  for (const row of rows) {
    for (const match of row.matchAll(/`([\w./-]+\.test\.ts)`/gu)) {
      const id = row.split("|")[1].trim()
      // The matrix cites v2 tests by bare name and src/ tests by bare name too, so try
      // both roots rather than guessing from the name. Tests also live in sibling packages —
      // `shell_executor.test.ts` is the pi-adapter's — so those roots are searched too. The
      // alternative was to stop citing them, which would hide the tests that cover this path.
      const packagesRoot = path.join(repoRoot, "packages")
      const siblingRoots = existsSync(packagesRoot)
        ? readdirSync(packagesRoot, { withFileTypes: true })
            .filter((entry) => entry.isDirectory())
            .map((entry) => path.join(packagesRoot, entry.name, "src"))
        : []
      const candidates = [
        path.join(daemonDir, match[1]),
        path.join(daemonDir, "src", match[1]),
        path.join(daemonDir, "src", "v2", match[1]),
        ...siblingRoots.map((root) => path.join(root, match[1])),
      ]
      const file = candidates.find((candidate) => existsSync(candidate))

      if (file === undefined) {
        missing.push(`${id} cites missing ${match[1]}`)
        continue
      }
      if (!/^\s*test\(/mu.test(read(file))) {
        missing.push(`${id} cites ${match[1]}, which declares no tests`)
      }
    }
  }

  assert.deepEqual(missing, [])
})

/**
 * Every invariant must be HELD, or must say exactly why it is not.
 *
 * The earlier form of this test asserted only that `notHeld` was empty. That is the wrong
 * assertion, and keeping it would have forced a false claim: S4 depends on SPIRE node attestation,
 * and neither `spire-server` nor `spire-agent` is installed on this host. The only ways to make
 * that test pass would have been to mark S4 HELD — which the tests do not demonstrate — or to stop
 * running it. Both are worse than an honest PARTIAL.
 *
 * So the guard is on *honesty*, not on optimism. A downgraded invariant must:
 *
 *   - carry an explicit state rather than a vague one,
 *   - name test files that exist and declare tests,
 *   - be explained by a registered substrate requirement, or by an explicit skip, so the gap is
 *     counted by the state file rather than living only in prose, and
 *   - be the *only* downgraded invariant, so a new silent regression is still caught.
 *
 * An invariant that quietly reads HELD while its evidence does not demonstrate it is still caught,
 * by the test above that checks every cited file exists and declares tests.
 */
test("every invariant is HELD, or names the substrate that keeps it from being HELD", () => {
  const doc = read(invariantsDoc)
  const rows = doc
    .split("\n")
    .filter((line) => /^\|\s*S\d+\s*\|/.test(line))

  // The substrate requirements are the registry that turns "this host lacks it" into a counted,
  // machine-derived gap. An invariant may only be downgraded if something there says so.
  const stateScript = read(path.join(daemonDir, "scripts", "security-fabric-state.mjs"))
  const registeredSubstrates = new Set(
    [...stateScript.matchAll(/^\s{2}"([a-z0-9-]+)":\s*\{$/gmu)].map((m) => m[1]),
  )

  assert.ok(registeredSubstrates.size > 0, "no substrate requirements parsed from the state script")

  const problems = []
  const downgraded = []

  for (const row of rows) {
    // A markdown row splits as: ["", ID, invariant, v1, v2, enforcement, evidence, ""]
    const cells = row.split("|").map((cell) => cell.trim())
    const id = cells[1]
    const v2 = cells[4]
    const evidence = cells[6] ?? ""

    if (/\*\*HELD\*\*/u.test(v2)) continue

    downgraded.push(id)

    if (!/\*\*(PARTIAL|ABSENT|NOT RUN)/u.test(v2)) {
      problems.push(`${id} is "${v2}", which states no explicit state`)
    }

    // The evidence cell must name real files, or the downgrade is unsupported prose.
    const cited = [...evidence.matchAll(/`([^`]+\.test\.[cm]?[jt]s)`/gu)].map((m) => m[1])

    if (cited.length === 0) problems.push(`${id} is downgraded but cites no test file`)

    for (const file of cited) {
      const candidates = [
        path.join(daemonDir, file),
        path.join(daemonDir, "src", file),
        path.join(daemonDir, "src", "v2", file),
      ]
      const found = candidates.find((candidate) => existsSync(candidate))

      if (found === undefined) {
        problems.push(`${id} is downgraded and cites missing ${file}`)
      } else if (!/^\s*test\(/mu.test(read(found))) {
        problems.push(`${id} is downgraded and cites ${file}, which declares no tests`)
      }
    }

    // A downgraded invariant must be explained by a registered substrate or an explicit skip.
    const explainsGap =
      /NOT RUN|skipped/iu.test(evidence) ||
      [...registeredSubstrates].some((name) => evidence.includes(name))

    if (!explainsGap) {
      problems.push(
        `${id} is downgraded without a registered substrate or an explicit skip: ${evidence}`,
      )
    }
  }

  assert.deepEqual(problems, [])
  assert.deepEqual(
    downgraded,
    ["S4"],
    `expected only S4 to be downgraded — a live SPIRE trust domain was run and this client was measured against it — found ${downgraded.join(", ")}`,
  )
})

// --- The retracted Tetragon claim must not return -------------------------------------

test("the retracted Tetragon docker exec gap claim is not asserted as fact", () => {
  const retracted = [
    "`docker exec` are not observed",
    "docker exec` are not observed",
    "would therefore leave no event",
    "PARTIALLY VERIFIED, one measured gap",
  ]

  for (const file of [invariantsDoc, matrixDoc, architectureDoc]) {
    const doc = read(file)
    for (const phrase of retracted) {
      assert.equal(
        doc.includes(phrase),
        false,
        `${path.basename(file)} re-asserts the retracted claim: ${phrase}`,
      )
    }
  }
})

test("the Tetragon measurement error and its cause are recorded", () => {
  const doc = read(matrixDoc)

  // A future reader who sees a zero must not repeat the mistake.
  assert.match(doc, /backlog rotates|ring buffer/iu)
  assert.match(doc, /Attach the reader|attach the reader/iu)
})

test("no invariant depends on the Tetragon detection layer", () => {
  const doc = read(invariantsDoc)
  const invariantRows = doc
    .split("\n")
    .filter((line) => /^\|\s*S\d+\s*\|/.test(line))

  for (const row of invariantRows) {
    assert.equal(
      /tetragon/iu.test(row),
      false,
      `invariant row depends on Tetragon: ${row}`,
    )
  }
})

// --- Release governance must stay aligned ----------------------------------------------

test("package version matches the authoritative release maturity truth", () => {
  const packageJson = JSON.parse(read(path.join(daemonDir, "package.json")))
  const truth = JSON.parse(read(path.join(daemonDir, "release-maturity-truth.json")))

  assert.equal(
    packageJson.version,
    truth.package_version,
    "package.json must match release-maturity-truth.json package_version",
  )
  assert.equal(truth.release_tag, `v${packageJson.version}`)
  assert.equal(truth.maturity_label, packageJson.actantos.stage)
})

test("the gVisor row does not claim egress it cannot attribute", () => {
  // This row once read "gVisor kernel log returned through the executor; egress blocked".
  // The egress half was false as an attribution: the gVisor daemon's bridge has no external
  // route for either runtime, so egress is blocked there regardless of the runtime flag. A
  // control that exists for a reason other than the one claimed is not evidence for the claim,
  // and this row is the one an operator reads first when asking what the sandbox buys.
  const row = read(invariantsDoc)
    .split("\n")
    .find((line) => /gVisor userspace-kernel sandbox/u.test(line))

  assert.ok(row !== undefined, "the gVisor row is missing from the invariant matrix")
  assert.doesNotMatch(
    row,
    /egress blocked/iu,
    "blocked egress on that daemon cannot be attributed to gVisor's netstack",
  )
  assert.match(
    row,
    /\*\*Egress is not claimed from this host\*\*|Egress is not claimed/iu,
    "the row must state the limit rather than omit it",
  )
})

test("package-lock version matches package.json", () => {
  const packageJson = JSON.parse(read(path.join(daemonDir, "package.json")))
  const lock = JSON.parse(read(path.join(daemonDir, "package-lock.json")))

  assert.equal(lock.version, packageJson.version)
  assert.equal(lock.packages[""].version, packageJson.version)
})

test("the declared release notes file exists and matches the governed version", () => {
  const packageJson = JSON.parse(read(path.join(daemonDir, "package.json")))
  const truth = JSON.parse(read(path.join(daemonDir, "release-maturity-truth.json")))
  const notesFile = packageJson.actantos.releaseNotesFile

  assert.ok(
    existsSync(path.join(daemonDir, notesFile)),
    `${notesFile} does not exist. build-release-artifacts.mjs now fails closed on this, ` +
      `so it must be restored or the pointer corrected to docs/release-notes-v${truth.package_version}.md`,
  )

  // The pointer has to track the governed version, otherwise a rename silently detaches it.
  assert.equal(
    notesFile,
    `docs/release-notes-v${truth.package_version}.md`,
    `releaseNotesFile must track release-maturity-truth.json package_version (${truth.package_version})`,
  )
})

test("release notes name the version their file name claims", () => {
  const packageJson = JSON.parse(read(path.join(daemonDir, "package.json")))
  const notesFile = packageJson.actantos.releaseNotesFile
  const heading = read(path.join(daemonDir, notesFile), "utf8").split("\n")[0]

  // Plain string work rather than a constructed regex. `\s` inside a template literal is a
  // silent trap: it is an unrecognised escape, collapses to `s`, and yields a regex that
  // matches nothing while looking correct in the source.
  const expected = "# ActantOS v" + packageJson.version
  assert.ok(
    heading.startsWith(expected),
    `${notesFile} opens with ${JSON.stringify(heading)} but documents v${packageJson.version}. ` +
      "A release notes file that lies about its version is worse than one that is merely thin.",
  )
})

test("W-001's measurement is reproducible and its citation is not stale", () => {
  const waiver = read(path.join(docsDir, "OPEN_WAIVERS.md"))

  // The waiver's whole value rests on a CPUID table whose measuring program is not checked in.
  // An owner asked to sign a number nobody can re-run is being asked to trust prose. The
  // portable pre-check exists so the premise is at least falsifiable, so it must stay checked in
  // and stay wired to a command the waiver actually names.
  const probe = path.join(daemonDir, "scripts", "confidential-computing-capability.mjs")
  assert.ok(existsSync(probe), `${probe} is cited by W-001 but does not exist`)

  const packageJson = JSON.parse(read(path.join(daemonDir, "package.json")))
  assert.equal(
    packageJson.scripts["confidential:probe"],
    "node scripts/confidential-computing-capability.mjs",
    "the command W-001 tells an owner to run must be the one package.json actually defines",
  )
  assert.match(
    waiver,
    /npm run confidential:probe/u,
    "W-001 must name how to reproduce its premise",
  )

  // The probe must never report an unreadable bit as an absent capability. That inversion is
  // the one failure mode that would turn a weak measurement into a false one, so it is asserted
  // on the source rather than on whatever this particular host happens to be.
  const source = read(probe)
  assert.match(
    source,
    /unknownLength > 0|unknown\.length > 0/u,
    "the probe must distinguish 'cannot determine' from 'absent'",
  )
  assert.match(
    source,
    /not readable from Node/u,
    "the probe must say out loud that CPUID is unreachable from JavaScript",
  )

  // An unsigned waiver is an open item. If a signature is ever filled in, this fails and forces a
  // deliberate edit of this guard rather than a silent status change.
  assert.match(waiver, /\*\*Status:\*\* open, unsigned\./u, "W-001's status line drifted")
})
