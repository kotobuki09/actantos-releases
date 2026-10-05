import { execFileSync } from "node:child_process"
import { createHash } from "node:crypto"
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  readFileSync,
  rmSync,
  statSync,
  writeFileSync,
} from "node:fs"
import path from "node:path"
import process from "node:process"
import { fileURLToPath } from "node:url"

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")

// Two test files build artifacts, and the Node test runner executes files concurrently. Sharing
// one output directory meant one file could delete the shrinkwrap while the other was packing,
// which showed up as an intermittent "npm ci requires npm-shrinkwrap.json" failure roughly one
// run in three. A per-invocation output directory removes the shared state entirely.
const artifactsDirOverride = process.env["ACTANTOS_ARTIFACTS_DIR"]
const artifactsDir =
  typeof artifactsDirOverride === "string" && artifactsDirOverride !== ""
    ? path.resolve(artifactsDirOverride)
    : path.join(rootDir, "artifacts")
const npmArtifactsDir = path.join(artifactsDir, "npm")
const manifestPath = path.join(artifactsDir, "release-manifest.json")
const packageLockPath = path.join(rootDir, "package-lock.json")

// `npm pack` only includes npm-shrinkwrap.json when it sits at the package root, so this file
// cannot be moved out of the way per-invocation. Two test files build concurrently under the
// Node test runner, and one deleting the shrinkwrap mid-pack produced an intermittent
// "npm ci requires npm-shrinkwrap.json" failure in roughly one run of three. `mkdir` is atomic
// on every supported platform, which makes it a usable mutex here.
const shrinkwrapPath = path.join(rootDir, "npm-shrinkwrap.json")
// One lock regardless of output directory: a per-invocation lock would not exclude anything.
const lockPath = path.join(rootDir, ".build-lock")

// A synchronous sleep. This code runs top to bottom and cannot await, and Atomics.wait is
// the only blocking primitive available in the standard library across platforms.
const sleepMs = (ms) => {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms)
}

const acquireLock = () => {
  for (let attempt = 0; attempt < 600; attempt += 1) {
    try {
      mkdirSync(lockPath, { recursive: false })
      return
    } catch (error) {
      if (error.code !== "EEXIST") throw error
      // A build abandoned mid-pack leaves the lock behind. Break it rather than hang.
      try {
        const ageMs = Date.now() - statSync(lockPath).mtimeMs
        if (ageMs > 120000) {
          rmSync(lockPath, { recursive: true, force: true })
          continue
        }
      } catch {
        // The holder released it between our mkdir and our stat. Retry immediately.
      }
      sleepMs(100)
    }
  }
  throw new Error(`could not acquire build lock at ${lockPath}`)
}

const releaseLock = () => rmSync(lockPath, { recursive: true, force: true })

const packageJson = JSON.parse(readFileSync(path.join(rootDir, "package.json"), "utf8"))
const packageName = packageJson.name
const npmVersion = packageJson.version
const releaseVersion = `v${npmVersion}`
const tarballName = `${packageName}-${npmVersion}.tgz`
const stage = packageJson.actantos?.stage ?? "quiet-open-core"
const notesFile =
  packageJson.actantos?.releaseNotesFile ?? `docs/release-notes-v${npmVersion}.md`

// Fail closed: refuse to pack when Mode A truth source and package identity drift.
const truthRel = packageJson.actantos?.maturityTruthFile ?? "release-maturity-truth.json"
const truthPath = path.join(rootDir, truthRel)
const truth = JSON.parse(readFileSync(truthPath, "utf8"))
if (truth.package_version !== npmVersion) {
  throw new Error(
    `release maturity truth package_version ${truth.package_version} != package.json ${npmVersion}`,
  )
}
if (truth.release_tag !== releaseVersion) {
  throw new Error(
    `release maturity truth release_tag ${truth.release_tag} != derived ${releaseVersion}`,
  )
}
if (truth.maturity_label !== stage) {
  throw new Error(
    `release maturity truth maturity_label ${truth.maturity_label} != package actantos.stage ${stage}`,
  )
}

// Fail closed: a release manifest that names release notes which do not exist is a broken
// release. This was previously copied through verbatim, which is how
// `docs/release-notes-v1.0.1.md` shipped in a manifest while no such file was ever written.
const notesPath = path.join(rootDir, notesFile)
if (!existsSync(notesPath)) {
  throw new Error(
    `actantos.releaseNotesFile points at ${notesFile}, which does not exist. ` +
      `Either restore the file or set releaseNotesFile to docs/release-notes-v${npmVersion}.md`,
  )
}

const runCommand = (command, args) => {
  execFileSync(command, args, {
    cwd: rootDir,
    stdio: "inherit",
    shell: process.platform === "win32",
  })
}

const sha256File = (filePath) =>
  createHash("sha256").update(readFileSync(filePath)).digest("hex")

// Wipe only generated npm packs; rewrite manifest in place (do not delete sibling evidence).
rmSync(npmArtifactsDir, { recursive: true, force: true })
mkdirSync(npmArtifactsDir, { recursive: true })
mkdirSync(artifactsDir, { recursive: true })

// The shrinkwrap lives at the package root and is only meaningful while `npm pack` reads it,
// so the copy/pack/delete triple is the section that must not interleave with another build.
acquireLock()
try {
  copyFileSync(packageLockPath, shrinkwrapPath)
  try {
    runCommand("npm", ["pack", "--pack-destination", npmArtifactsDir])
  } finally {
    rmSync(shrinkwrapPath, { force: true })
  }
} finally {
  releaseLock()
}

const packagePath = path.join(npmArtifactsDir, tarballName)
try {
  readFileSync(packagePath)
} catch {
  throw new Error(`expected packed tarball missing: ${tarballName}`)
}

writeFileSync(
  manifestPath,
  `${JSON.stringify(
    {
      release_version: releaseVersion,
      stage,
      generated_at: new Date().toISOString(),
      npm_package: {
        file: `npm/${tarballName}`,
        sha256: sha256File(packagePath),
      },
      docker_image: {
        image: `${packageName}:${releaseVersion}`,
        build_command: `docker build -t ${packageName}:${releaseVersion} .`,
      },
      github_release: {
        tag: releaseVersion,
        notes_file: notesFile,
      },
    },
    null,
    2,
  )}\n`,
)
