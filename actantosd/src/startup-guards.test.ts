import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import test from "node:test"

/**
 * Runs the bootstrap (index.ts) in a clean subprocess with the given env overrides.
 * Strips the parent's HMAC_SECRET / ACTANTOS_HMAC_SECRET so they cannot contaminate
 * the child process.
 */
const runIndex = (env: Record<string, string | undefined>): { code: number; stderr: string } => {
  // Build a clean base: strip any HMAC-related secrets from the parent env
  // so we can control exactly what the child sees.
  const baseEnv: Record<string, string> = {}
  for (const [key, value] of Object.entries(process.env)) {
    if (
      key === "HMAC_SECRET" ||
      key === "ACTANTOS_HMAC_SECRET" ||
      key === "DATABASE_URL" ||
      key === "PORT"
    ) {
      continue
    }
    if (value !== undefined) {
      baseEnv[key] = value
    }
  }

  // Apply test-specific overrides (skip undefined values = delete)
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) {
      delete baseEnv[key]
    } else {
      baseEnv[key] = value
    }
  }

  try {
    execFileSync(
      process.execPath,
      ["--experimental-strip-types", "src/index.ts"],
      {
        env: baseEnv,
        stdio: ["ignore", "ignore", "pipe"],
        timeout: 8_000,
      },
    )
    return { code: 0, stderr: "" }
  } catch (error: any) {
    const stderr: string =
      error.stderr instanceof Buffer
        ? error.stderr.toString("utf8")
        : typeof error.stderr === "string"
        ? error.stderr
        : ""
    const code: number = typeof error.status === "number" ? error.status : 1
    return { code, stderr }
  }
}

test("bootstrap exits 1 in NODE_ENV=production with unset ACTANTOS_HMAC_SECRET", () => {
  const result = runIndex({
    NODE_ENV: "production",
    ACTANTOS_EVALUATOR_MODE: "development",
    // HMAC_SECRET and ACTANTOS_HMAC_SECRET are stripped by runIndex base
  })
  assert.equal(result.code, 1, "should exit with code 1")
  assert.match(
    result.stderr,
    /FATAL.*ACTANTOS_HMAC_SECRET/u,
    "should log a FATAL message about ACTANTOS_HMAC_SECRET",
  )
})

test("bootstrap exits 1 in NODE_ENV=production with default dev ACTANTOS_HMAC_SECRET", () => {
  const result = runIndex({
    NODE_ENV: "production",
    ACTANTOS_HMAC_SECRET: "actantos-dev-secret",
    ACTANTOS_EVALUATOR_MODE: "development",
  })
  assert.equal(result.code, 1, "should exit with code 1 when using the insecure dev secret")
  assert.match(result.stderr, /FATAL.*ACTANTOS_HMAC_SECRET/u)
})

test("bootstrap does NOT exit with FATAL message when a strong ACTANTOS_HMAC_SECRET is set in NODE_ENV=production", () => {
  const result = runIndex({
    NODE_ENV: "production",
    ACTANTOS_HMAC_SECRET: "a-very-strong-production-secret-that-is-long-enough",
    ACTANTOS_EVALUATOR_MODE: "development",
    // No DATABASE_URL → server tries to start but does not hit the HMAC gate
    PORT: "0",
  })
  // The FATAL HMAC message must NOT appear regardless of how the process exits
  assert.doesNotMatch(
    result.stderr,
    /FATAL.*ACTANTOS_HMAC_SECRET/u,
    "should NOT log a FATAL HMAC message when a strong secret is set",
  )
})
