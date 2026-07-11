import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { readFileSync } from "node:fs"
import path from "node:path"
import test from "node:test"
import { fileURLToPath } from "node:url"

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")

test("release artifact includes the deterministic install lockfile", () => {
  execFileSync("node", ["scripts/build-release-artifacts.mjs"], {
    cwd: rootDir,
    stdio: "pipe",
  })

  const packageJson = JSON.parse(readFileSync(path.join(rootDir, "package.json"), "utf8"))
  const tarballPath = path.join(
    rootDir,
    "artifacts",
    "npm",
    `${packageJson.name}-${packageJson.version}.tgz`,
  )
  const entries = execFileSync("tar", ["-tzf", tarballPath], { encoding: "utf8" })
    .split(/\r?\n/u)
    .filter(Boolean)

  assert.ok(
    entries.includes("package/npm-shrinkwrap.json"),
    "npm ci requires npm-shrinkwrap.json in the published tarball",
  )
})
