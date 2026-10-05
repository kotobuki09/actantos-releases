import { execFileSync } from "node:child_process"
import * as os from "node:os"

const checkCommand = (cmd: string, args: string[], name: string): boolean => {
  try {
    const output = execFileSync(cmd, args, { encoding: "utf8", stdio: ["ignore", "pipe", "ignore"] })
    console.log(`[OK] ${name} found: ${output.split("\n")[0]}`)
    return true
  } catch {
    console.error(`[FAIL] ${name} is missing. Please ensure '${cmd}' is installed and on your PATH.`)
    return false
  }
}

const checkEnv = (name: string, required: boolean, secure: boolean = false): boolean => {
  const value = process.env[name]
  if (value === undefined || value.trim() === "") {
    if (required) {
      console.error(`[FAIL] Environment variable ${name} is required but not set.`)
      return false
    } else {
      console.log(`[INFO] Environment variable ${name} is not set.`)
      return true
    }
  }

  if (secure && value === "actantos-dev-secret") {
    console.warn(`[WARN] ${name} is using the insecure default ('actantos-dev-secret'). Do not use in production.`)
    return true
  }

  console.log(`[OK] ${name} is set.`)
  return true
}

const runPreflight = () => {
  console.log("=== ActantOS Install Preflight Check ===\n")
  let allGood = true

  // 1. Check OS
  console.log(`[OK] OS: ${os.platform()} ${os.release()} (${os.arch()})`)

  // 2. Check Docker
  if (!checkCommand("docker", ["--version"], "Docker")) {
    allGood = false
  }

  // 3. Check Cedar CLI
  if (process.env["ACTANTOS_EVALUATOR_MODE"] === "production" || process.env["NODE_ENV"] === "production") {
    const cedarCmd = process.env["CEDAR_CLI_PATH"] ?? "cedar"
    if (!checkCommand(cedarCmd, ["--version"], "Cedar CLI")) {
      allGood = false
    }
  } else {
    console.log("[INFO] Cedar CLI check skipped (evaluator mode is not production).")
  }

  // 4. Check gVisor if enabled
  if (process.env["ACTANTOS_USE_GVISOR"] === "true") {
    if (!checkCommand("runsc", ["--version"], "gVisor (runsc)")) {
      allGood = false
    }
  }

  // 5. Check Env Vars
  const isProd = process.env["ACTANTOS_EVALUATOR_MODE"] === "production" || process.env["NODE_ENV"] === "production"
  if (!checkEnv("ACTANTOS_API_KEY", false)) {
    console.log("[INFO] ActantOS API will be unauthenticated. Set ACTANTOS_API_KEY to secure it.")
  }
  
  if (isProd) {
    if (!checkEnv("ACTANTOS_HMAC_SECRET", true, true) && !checkEnv("HMAC_SECRET", true, true)) {
      allGood = false
    }
  } else {
    checkEnv("ACTANTOS_HMAC_SECRET", false, true)
  }

  console.log("\n==========================================")
  if (allGood) {
    console.log("✅ Preflight checks passed! ActantOS is ready to run.")
    process.exitCode = 0
  } else {
    console.error("❌ Preflight checks failed. Please resolve the issues above before starting ActantOS.")
    process.exitCode = 1
  }
}

runPreflight()
