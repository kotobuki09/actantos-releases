import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { copyFileSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import { tmpdir } from "node:os"
import path from "node:path"
import test from "node:test"
import { fileURLToPath } from "node:url"

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const script = path.join(rootDir, "scripts", "verify-release-artifacts.mjs")

test("verify-release-artifacts accepts matching assets and rejects tampered tarball", () => {
  // Private output directory: `build-release-artifacts.test.mjs` builds at the same time under
  // the concurrent Node test runner, and a shared `artifacts/` directory let the two runs
  // delete each other's shrinkwrap mid-pack.
  const artifactsDir = mkdtempSync(path.join(tmpdir(), "actantos-build-"))

  execFileSync("node", ["scripts/build-release-artifacts.mjs"], {
    cwd: rootDir,
    stdio: "pipe",
    env: { ...process.env, ACTANTOS_ARTIFACTS_DIR: artifactsDir },
  })

  const packageJson = JSON.parse(readFileSync(path.join(rootDir, "package.json"), "utf8"))
  const tarballName = `${packageJson.name}-${packageJson.version}.tgz`
  const dir = mkdtempSync(path.join(tmpdir(), "actantos-verify-"))

  try {
    copyFileSync(path.join(artifactsDir, "npm", tarballName), path.join(dir, tarballName))
    copyFileSync(
      path.join(artifactsDir, "release-manifest.json"),
      path.join(dir, "release-manifest.json"),
    )

    const ok = execFileSync("node", [script, "--dir", dir], { encoding: "utf8" })
    assert.match(ok, /VERIFY_PASS/)
    assert.match(ok, /OK digest/)

    const badDir = mkdtempSync(path.join(tmpdir(), "actantos-verify-bad-"))
    try {
      copyFileSync(path.join(dir, "release-manifest.json"), path.join(badDir, "release-manifest.json"))
      writeFileSync(path.join(badDir, tarballName), "not-a-real-tarball")
      let failed = false
      try {
        execFileSync("node", [script, "--dir", badDir], { encoding: "utf8", stdio: "pipe" })
      } catch (error) {
        failed = true
        const output = `${error.stderr || ""}${error.stdout || ""}${error}`
        assert.match(output, /sha256 mismatch|FAIL/)
      }
      assert.equal(failed, true, "tampered tarball must fail verification")
    } finally {
      rmSync(badDir, { recursive: true, force: true })
    }
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})
