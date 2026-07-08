import { execFileSync } from "node:child_process"
import { createHash } from "node:crypto"
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import path from "node:path"
import process from "node:process"
import { fileURLToPath } from "node:url"

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const artifactsDir = path.join(rootDir, "artifacts")
const npmArtifactsDir = path.join(artifactsDir, "npm")
const releaseVersion = "v1.0.0-production"

const runCommand = (command, args) => {
  execFileSync(command, args, {
    cwd: rootDir,
    stdio: "inherit",
    shell: process.platform === "win32",
  })
}

const sha256File = (filePath) =>
  createHash("sha256").update(readFileSync(filePath)).digest("hex")

rmSync(artifactsDir, { recursive: true, force: true })
mkdirSync(npmArtifactsDir, { recursive: true })

runCommand("npm", ["pack", "--pack-destination", npmArtifactsDir])

const packageName = "actantosd-0.1.0.tgz"
const packagePath = path.join(npmArtifactsDir, packageName)
const manifestPath = path.join(artifactsDir, "release-manifest.json")

writeFileSync(
  manifestPath,
  `${JSON.stringify({
    release_version: releaseVersion,
    generated_at: new Date().toISOString(),
    npm_package: {
      file: `npm/${packageName}`,
      sha256: sha256File(packagePath),
    },
    docker_image: {
      image: "actantosd:v1.0.0-production",
      build_command: "docker build -t actantosd:v1.0.0-production .",
    },
    github_release: {
      tag: "v1.0.0-production",
      notes_file: "docs/release-notes-v1.0.0-production.md",
    },
  }, null, 2)}\n`,
)
