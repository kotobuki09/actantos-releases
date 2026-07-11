import { execFileSync } from "node:child_process"
import { createHash } from "node:crypto"
import { copyFileSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import path from "node:path"
import process from "node:process"
import { fileURLToPath } from "node:url"

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const artifactsDir = path.join(rootDir, "artifacts")
const npmArtifactsDir = path.join(artifactsDir, "npm")
const manifestPath = path.join(artifactsDir, "release-manifest.json")
const packageLockPath = path.join(rootDir, "package-lock.json")
const shrinkwrapPath = path.join(rootDir, "npm-shrinkwrap.json")

const packageJson = JSON.parse(readFileSync(path.join(rootDir, "package.json"), "utf8"))
const packageName = packageJson.name
const npmVersion = packageJson.version
const releaseVersion = `v${npmVersion}`
const tarballName = `${packageName}-${npmVersion}.tgz`
const stage = packageJson.actantos?.stage ?? "quiet-open-core"
const notesFile =
  packageJson.actantos?.releaseNotesFile ?? `docs/release-notes-v${npmVersion}.md`

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

copyFileSync(packageLockPath, shrinkwrapPath)
try {
  runCommand("npm", ["pack", "--pack-destination", npmArtifactsDir])
} finally {
  rmSync(shrinkwrapPath, { force: true })
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
