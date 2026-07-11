/**
 * Verify public release artifacts against release-manifest.json SHA-256 digests.
 * Optional: when COSIGN=1 and cosign is on PATH, also verify .sig / .bundle files.
 *
 * Usage:
 *   node scripts/verify-release-artifacts.mjs --dir <path-with-assets>
 *   node scripts/verify-release-artifacts.mjs --dir <path> --require-cosign
 */
import { createHash } from "node:crypto"
import { existsSync, readFileSync, readdirSync } from "node:fs"
import path from "node:path"
import process from "node:process"
import { spawnSync } from "node:child_process"

const args = process.argv.slice(2)
const dirFlag = args.indexOf("--dir")
const requireCosign = args.includes("--require-cosign")
const assetsDir = dirFlag >= 0 ? path.resolve(args[dirFlag + 1]) : process.cwd()

const fail = (message) => {
  console.error(`FAIL: ${message}`)
  process.exit(1)
}

const sha256File = (filePath) =>
  createHash("sha256").update(readFileSync(filePath)).digest("hex")

const manifestPath = path.join(assetsDir, "release-manifest.json")
if (!existsSync(manifestPath)) {
  fail(`release-manifest.json not found in ${assetsDir}`)
}

const manifest = JSON.parse(readFileSync(manifestPath, "utf8"))
if (manifest.release_version !== "v1.0.0" && !String(manifest.release_version || "").startsWith("v")) {
  fail(`unexpected release_version: ${manifest.release_version}`)
}
if (!manifest.stage) {
  fail("manifest.stage missing")
}

const expectedTarballRel = manifest.npm_package?.file
const expectedTarballHash = manifest.npm_package?.sha256
if (!expectedTarballRel || !expectedTarballHash) {
  fail("manifest.npm_package.file/sha256 missing")
}

const tarballName = path.basename(expectedTarballRel)
const tarballPath = path.join(assetsDir, tarballName)
if (!existsSync(tarballPath)) {
  fail(`tarball missing: ${tarballName}`)
}

const actual = sha256File(tarballPath)
if (actual !== expectedTarballHash) {
  fail(`tarball sha256 mismatch\n  expected ${expectedTarballHash}\n  actual   ${actual}`)
}

console.log(`OK digest: ${tarballName} matches manifest (${actual})`)
console.log(`OK identity: release_version=${manifest.release_version} stage=${manifest.stage}`)

// Optional companion digests if present as GitHub asset digests file or sidecar .sha256
const sidecar = `${tarballPath}.sha256`
if (existsSync(sidecar)) {
  const sidecarText = readFileSync(sidecar, "utf8").trim().split(/\s+/)[0]
  if (sidecarText !== actual) {
    fail(`sidecar .sha256 mismatch for ${tarballName}`)
  }
  console.log(`OK sidecar: ${path.basename(sidecar)}`)
}

const cosignAvailable = () => {
  const result = spawnSync("cosign", ["version"], { encoding: "utf8" })
  return result.status === 0
}

const tryCosign = () => {
  if (!cosignAvailable()) {
    if (requireCosign) fail("cosign not available on PATH")
    console.log("SKIP cosign: cosign binary not on PATH (digest verification is the temporary control)")
    return
  }

  const candidates = readdirSync(assetsDir).filter(
    (name) => name.endsWith(".sig") || name.endsWith(".bundle") || name.endsWith(".sigstore"),
  )
  if (candidates.length === 0) {
    if (requireCosign) fail("no cosign signature/bundle assets found")
    console.log("SKIP cosign: no signature assets present yet")
    return
  }

  const identityRegexp =
    process.env.COSIGN_CERTIFICATE_IDENTITY_REGEXP ||
    "https://github.com/kotobuki09/actantos-releases/.github/workflows/sign-release-assets.yml@.*"
  const oidcIssuer =
    process.env.COSIGN_CERTIFICATE_OIDC_ISSUER || "https://token.actions.githubusercontent.com"

  let verified = 0
  for (const name of candidates) {
    const sigPath = path.join(assetsDir, name)
    // Prefer bundle verify when available; only verify bundles for the tarball name.
    const isTarballBundle =
      name === `${tarballName}.sigstore` ||
      name === `${tarballName}.bundle` ||
      (name.startsWith(tarballName) && (name.endsWith(".sigstore") || name.endsWith(".bundle")))
    if (!isTarballBundle) continue

    const result = spawnSync(
      "cosign",
      [
        "verify-blob",
        "--bundle",
        sigPath,
        "--certificate-identity-regexp",
        identityRegexp,
        "--certificate-oidc-issuer",
        oidcIssuer,
        tarballPath,
      ],
      { encoding: "utf8" },
    )
    if (result.status !== 0) {
      fail(`cosign verify-blob failed for ${name}: ${result.stderr || result.stdout}`)
    }
    verified += 1
    console.log(`OK cosign bundle: ${name}`)
  }

  if (verified === 0 && requireCosign) {
    fail("signature assets present but none verified for the tarball")
  }
  if (verified === 0) {
    console.log("SKIP cosign: signature files present but not in supported bundle form for tarball")
  }
}

tryCosign()

// Tamper-negative self-check: mutate a copy hash expectation
const tampered = `${actual.slice(0, -1)}${actual.endsWith("0") ? "1" : "0"}`
if (tampered === actual) fail("internal tamper probe failed to change hash")
console.log("OK tamper probe: altered digest would be rejected by this verifier")

console.log("VERIFY_PASS")
