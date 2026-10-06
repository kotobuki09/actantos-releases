import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { mkdtempSync, readFileSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import path from "node:path"
import test from "node:test"
import { fileURLToPath } from "node:url"

import { validateTruthDocument } from "./validate-release-maturity-truth.mjs"

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const truthPath = path.join(rootDir, "release-maturity-truth.json")

const loadTruth = () => JSON.parse(readFileSync(truthPath, "utf8"))

const basePackage = () => ({
  version: "1.2.0",
  actantos: { stage: "quiet-open-core" },
})

const baseManifest = () => ({
  release_version: "v1.2.0",
  stage: "quiet-open-core",
})

test("authoritative truth source validates against package and manifest", () => {
  const truth = loadTruth()
  const errors = validateTruthDocument(truth, {
    packageJson: basePackage(),
    manifest: baseManifest(),
  })
  assert.deepEqual(errors, [])
})

test("CLI validator exits 0 for the in-repo truth source", () => {
  const output = execFileSync("node", ["scripts/validate-release-maturity-truth.mjs"], {
    cwd: rootDir,
    encoding: "utf8",
  })
  assert.match(output, /OK truth:/)
  assert.match(output, /package=1\.2\.0/)
  assert.match(output, /maturity=quiet-open-core/)
})

test("unknown maturity_label is rejected", () => {
  const truth = loadTruth()
  truth.maturity_label = "stage3-done-vibes"
  const errors = validateTruthDocument(truth, {
    packageJson: { version: "1.0.1", actantos: { stage: "stage3-done-vibes" } },
  })
  assert.ok(errors.some((e) => /unknown maturity_label/.test(e)))
})

test("unknown claim_level is rejected", () => {
  const truth = loadTruth()
  truth.claim_entries[0].claim_level = "battle-tested"
  const errors = validateTruthDocument(truth, {
    packageJson: basePackage(),
  })
  assert.ok(errors.some((e) => /claim_level unknown/.test(e)))
})

test("package version mismatch fails validation", () => {
  const truth = loadTruth()
  const errors = validateTruthDocument(truth, {
    packageJson: { version: "0.9.0", actantos: { stage: "quiet-open-core" } },
    manifest: baseManifest(),
  })
  assert.ok(errors.some((e) => /package\.json version/.test(e)))
})

test("manifest stage mismatch fails validation", () => {
  const truth = loadTruth()
  const errors = validateTruthDocument(truth, {
    packageJson: basePackage(),
    manifest: { release_version: "v1.0.1", stage: "stage3-governed-enterprise-autonomy" },
  })
  assert.ok(errors.some((e) => /release-manifest stage/.test(e)))
})

test("CLI fails when pointed at a drifted truth file", () => {
  const dir = mkdtempSync(path.join(tmpdir(), "actantos-truth-"))
  const driftedPath = path.join(dir, "release-maturity-truth.json")
  const truth = loadTruth()
  truth.package_version = "9.9.9"
  truth.release_tag = "v9.9.9"
  writeFileSync(driftedPath, `${JSON.stringify(truth, null, 2)}\n`)

  assert.throws(
    () =>
      execFileSync("node", ["scripts/validate-release-maturity-truth.mjs", "--truth", driftedPath], {
        cwd: rootDir,
        encoding: "utf8",
      }),
    (error) => {
      assert.equal(error.status, 1)
      assert.match(String(error.stderr ?? error.stdout ?? error.message), /FAIL:/)
      return true
    },
  )
})

test("truth source forbids Mode A Stage 3 / v1.1.0 public baseline claim", () => {
  const truth = loadTruth()
  const stage3 = truth.claim_entries.find((e) => e.id === "stage3-v1.1.0-mode-a-public-baseline")
  assert.ok(stage3, "expected deferred Stage 3 baseline claim entry")
  assert.equal(stage3.claim_level, "unsupported")
  assert.equal(truth.maturity_label, "quiet-open-core")
  assert.equal(truth.package_version, "1.2.0")
  assert.ok(truth.forbidden_maturity_encodings.includes("v1.1.0-production"))
})
