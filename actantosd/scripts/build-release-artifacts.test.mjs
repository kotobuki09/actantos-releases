import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { existsSync, mkdtempSync, readFileSync } from "node:fs"
import { tmpdir } from "node:os"
import path from "node:path"
import test from "node:test"
import { fileURLToPath } from "node:url"

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")

test("release artifact packs installable Quiet Open-Core tree", () => {
  // A private output directory. `verify-release-artifacts.test.mjs` builds too, and the Node
  // runner executes files concurrently; sharing `artifacts/` made both runs delete each
  // other's shrinkwrap mid-pack, failing intermittently with "npm ci requires
  // npm-shrinkwrap.json".
  const artifactsDir = mkdtempSync(path.join(tmpdir(), "actantos-release-"))

  execFileSync("node", ["scripts/build-release-artifacts.mjs"], {
    cwd: rootDir,
    stdio: "pipe",
    env: { ...process.env, ACTANTOS_ARTIFACTS_DIR: artifactsDir },
  })

  const packageJson = JSON.parse(readFileSync(path.join(rootDir, "package.json"), "utf8"))
  assert.equal(packageJson.version, "1.2.0")
  assert.equal(packageJson.actantos?.stage, "quiet-open-core")

  const truth = JSON.parse(readFileSync(path.join(rootDir, "release-maturity-truth.json"), "utf8"))
  assert.equal(truth.package_version, packageJson.version)
  assert.equal(truth.maturity_label, packageJson.actantos.stage)
  assert.equal(truth.release_tag, `v${packageJson.version}`)

  const tarballPath = path.join(
    artifactsDir,
    "npm",
    `${packageJson.name}-${packageJson.version}.tgz`,
  )
  assert.ok(existsSync(tarballPath), `missing packed tarball at ${tarballPath}`)

  // Feed the archive to tar over stdin rather than by path: GNU tar parses a
  // Windows "D:\..." argument as host:path and fails with "Cannot connect to D".
  // stdin keeps this correct on Windows, Linux, and BSD tar alike.
  const tarballBytes = readFileSync(tarballPath)
  const entries = execFileSync("tar", ["-tzf", "-"], {
    encoding: "utf8",
    input: tarballBytes,
  })
    .split(/\r?\n/u)
    .filter(Boolean)

  // Real public smoke path: npm ci + npm run build + docker build.
  assert.ok(
    entries.includes("package/npm-shrinkwrap.json"),
    "npm ci requires npm-shrinkwrap.json in the published tarball",
  )
  assert.ok(
    entries.includes("package/src/index.ts"),
    "fresh-install smoke rebuild requires src/ in the published tarball",
  )
  assert.ok(
    entries.includes("package/docker/cedar-cli"),
    "Docker image build requires vendored cedar-cli (no in-image cargo compile)",
  )
  assert.ok(
    entries.includes("package/Dockerfile"),
    "Docker build context requires Dockerfile in the published tarball",
  )

  const dockerfile = execFileSync("tar", ["-xOzf", "-", "package/Dockerfile"], {
    encoding: "utf8",
    input: tarballBytes,
  })
  assert.match(dockerfile, /npm-shrinkwrap\.json\*/)
  assert.match(dockerfile, /docker\/cedar-cli/)
  assert.doesNotMatch(dockerfile, /cargo install/)

  const manifest = JSON.parse(
    readFileSync(path.join(artifactsDir, "release-manifest.json"), "utf8"),
  )
  assert.equal(manifest.release_version, `v${packageJson.version}`)
  assert.equal(manifest.stage, packageJson.actantos.stage)
  assert.equal(manifest.npm_package.file, `npm/${packageJson.name}-${packageJson.version}.tgz`)
  assert.match(manifest.npm_package.sha256, /^[a-f0-9]{64}$/u)
})
