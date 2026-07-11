import { execFileSync } from "node:child_process"
import { createHash } from "node:crypto"
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs"
import path from "node:path"
import process from "node:process"
import { fileURLToPath } from "node:url"

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const artifactsDir = path.join(rootDir, "artifacts")
const npmArtifactsDir = path.join(artifactsDir, "npm")
const packageJson = JSON.parse(readFileSync(path.join(rootDir, "package.json"), "utf8"))
const releaseVersion = `v${packageJson.version}`

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

const packageName = `actantosd-${packageJson.version}.tgz`
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
      image: `actantosd:${releaseVersion}`,
      build_command: `docker build -t actantosd:${releaseVersion} .`,
    },
    github_release: {
      tag: releaseVersion,
      notes_file: `docs/release-notes-${releaseVersion}.md`,
    },
  }, null, 2)}\n`,
)
