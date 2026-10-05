/**
 * Validate release-maturity-truth.json schema and drift against package/manifest.
 *
 * Usage:
 *   node scripts/validate-release-maturity-truth.mjs
 *   node scripts/validate-release-maturity-truth.mjs --truth <path>
 *
 * Exit 0 on success; exit 1 on any schema or drift failure (fail closed).
 */
import { existsSync, readFileSync } from "node:fs"
import path from "node:path"
import process from "node:process"
import { fileURLToPath } from "node:url"

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")

const ALLOWED_MATURITY = new Set([
  "quiet-open-core",
  "design-partner-window",
  "production-qualified",
])

const ALLOWED_CLAIM_LEVELS = new Set([
  "claimed",
  "implemented",
  "locally-verified",
  "integration-verified",
  "release-verified",
  "production-qualified",
  "unsupported",
  "planned",
  "conditional",
  "deprecated",
])

const fail = (message) => {
  console.error(`FAIL: ${message}`)
  process.exit(1)
}

const parseArgs = (argv) => {
  const truthFlag = argv.indexOf("--truth")
  return {
    truthPath:
      truthFlag >= 0
        ? path.resolve(argv[truthFlag + 1])
        : path.join(rootDir, "release-maturity-truth.json"),
  }
}

const loadJson = (filePath, label) => {
  if (!existsSync(filePath)) {
    fail(`${label} missing: ${filePath}`)
  }
  try {
    return JSON.parse(readFileSync(filePath, "utf8"))
  } catch (error) {
    fail(`${label} is not valid JSON (${filePath}): ${error.message}`)
  }
}

const assertString = (value, label) => {
  if (typeof value !== "string" || value.trim() === "") {
    fail(`${label} must be a non-empty string`)
  }
}

const assertArray = (value, label) => {
  if (!Array.isArray(value)) {
    fail(`${label} must be an array`)
  }
}

export const validateTruthDocument = (truth, { packageJson, manifest } = {}) => {
  const errors = []
  const push = (message) => errors.push(message)

  if (truth.schema_version !== 1) {
    push(`schema_version must be 1 (got ${JSON.stringify(truth.schema_version)})`)
  }

  assertOr(push, typeof truth.package_version === "string" && /^\d+\.\d+\.\d+/.test(truth.package_version),
    `package_version must be semver without leading v (got ${JSON.stringify(truth.package_version)})`)
  assertOr(push, typeof truth.release_tag === "string" && truth.release_tag.startsWith("v"),
    `release_tag must start with v (got ${JSON.stringify(truth.release_tag)})`)
  if (typeof truth.package_version === "string" && typeof truth.release_tag === "string") {
    if (truth.release_tag !== `v${truth.package_version}`) {
      push(`release_tag must equal v\${package_version} (got ${truth.release_tag} vs v${truth.package_version})`)
    }
  }

  if (!ALLOWED_MATURITY.has(truth.maturity_label)) {
    push(`unknown maturity_label: ${JSON.stringify(truth.maturity_label)}`)
  }
  if (!ALLOWED_CLAIM_LEVELS.has(truth.validation_class)) {
    push(`unknown validation_class: ${JSON.stringify(truth.validation_class)}`)
  }

  if (truth.maturity_label === "production-qualified" && truth.validation_class !== "production-qualified") {
    push("maturity_label production-qualified requires validation_class production-qualified")
  }

  if (typeof truth.evidence_date !== "string" || !/^\d{4}-\d{2}-\d{2}$/.test(truth.evidence_date)) {
    push(`evidence_date must be YYYY-MM-DD (got ${JSON.stringify(truth.evidence_date)})`)
  }

  if (!Array.isArray(truth.supported_deployments) || truth.supported_deployments.length === 0) {
    push("supported_deployments must be a non-empty array")
  }
  if (!Array.isArray(truth.public_artifact_urls)) {
    push("public_artifact_urls must be an array")
  }
  if (!Array.isArray(truth.claim_entries) || truth.claim_entries.length === 0) {
    push("claim_entries must be a non-empty array")
  } else {
    const ids = new Set()
    for (const [index, entry] of truth.claim_entries.entries()) {
      if (!entry || typeof entry !== "object") {
        push(`claim_entries[${index}] must be an object`)
        continue
      }
      if (typeof entry.id !== "string" || entry.id.trim() === "") {
        push(`claim_entries[${index}].id must be a non-empty string`)
      } else if (ids.has(entry.id)) {
        push(`duplicate claim_entries id: ${entry.id}`)
      } else {
        ids.add(entry.id)
      }
      if (typeof entry.statement !== "string" || entry.statement.trim() === "") {
        push(`claim_entries[${index}].statement must be a non-empty string`)
      }
      if (!ALLOWED_CLAIM_LEVELS.has(entry.claim_level)) {
        push(`claim_entries[${index}].claim_level unknown: ${JSON.stringify(entry.claim_level)}`)
      }
    }
  }

  if (!Array.isArray(truth.forbidden_maturity_encodings)) {
    push("forbidden_maturity_encodings must be an array")
  } else if (!truth.forbidden_maturity_encodings.includes("v1.1.0-production")) {
    push('forbidden_maturity_encodings must include "v1.1.0-production"')
  }

  if (!truth.precedence || typeof truth.precedence.rule !== "string") {
    push("precedence.rule must be a non-empty string")
  }

  if (packageJson) {
    if (packageJson.version !== truth.package_version) {
      push(
        `package.json version ${JSON.stringify(packageJson.version)} does not match truth package_version ${JSON.stringify(truth.package_version)}`,
      )
    }
    const stage = packageJson.actantos?.stage
    if (stage !== truth.maturity_label) {
      push(
        `package.json actantos.stage ${JSON.stringify(stage)} does not match truth maturity_label ${JSON.stringify(truth.maturity_label)}`,
      )
    }
  }

  if (manifest) {
    if (manifest.release_version !== truth.release_tag) {
      push(
        `release-manifest release_version ${JSON.stringify(manifest.release_version)} does not match truth release_tag ${JSON.stringify(truth.release_tag)}`,
      )
    }
    if (manifest.stage !== truth.maturity_label) {
      push(
        `release-manifest stage ${JSON.stringify(manifest.stage)} does not match truth maturity_label ${JSON.stringify(truth.maturity_label)}`,
      )
    }
  }

  // Fail closed: truth itself must not use forbidden encodings as maturity.
  const blob = JSON.stringify(truth)
  for (const banned of truth.forbidden_maturity_encodings ?? []) {
    if (typeof banned === "string" && blob.includes(banned) && banned.includes("production")) {
      // Allowed only inside forbidden_maturity_encodings list itself.
      const outsideList = blob.replace(JSON.stringify(truth.forbidden_maturity_encodings), "")
      if (outsideList.includes(banned)) {
        push(`truth source embeds forbidden maturity encoding outside the ban list: ${banned}`)
      }
    }
  }

  return errors
}

const assertOr = (push, condition, message) => {
  if (!condition) push(message)
}

const main = () => {
  const { truthPath } = parseArgs(process.argv.slice(2))
  const truth = loadJson(truthPath, "truth source")
  const packageJson = loadJson(path.join(rootDir, "package.json"), "package.json")
  const manifestPath = path.join(rootDir, "artifacts", "release-manifest.json")
  const manifest = existsSync(manifestPath)
    ? loadJson(manifestPath, "release-manifest.json")
    : undefined

  // Basic type guards for CLI path (validateTruthDocument also checks).
  assertString(truth.package_version ?? "", "package_version")
  assertArray(truth.claim_entries ?? null, "claim_entries")

  const errors = validateTruthDocument(truth, { packageJson, manifest })
  if (errors.length > 0) {
    for (const error of errors) {
      console.error(`FAIL: ${error}`)
    }
    process.exit(1)
  }

  console.log(`OK truth: ${truthPath}`)
  console.log(
    `OK identity: package=${truth.package_version} tag=${truth.release_tag} maturity=${truth.maturity_label} validation=${truth.validation_class}`,
  )
  console.log(`OK claims: ${truth.claim_entries.length} entries`)
  if (manifest) {
    console.log(`OK manifest: ${manifestPath}`)
  } else {
    console.log("SKIP manifest: artifacts/release-manifest.json not present")
  }
}

const isDirectRun = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)

if (isDirectRun) {
  main()
}
