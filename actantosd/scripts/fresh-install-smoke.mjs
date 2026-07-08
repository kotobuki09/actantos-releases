import { spawnSync } from "node:child_process"
import { copyFileSync, existsSync } from "node:fs"
import path from "node:path"
import process from "node:process"
import { fileURLToPath } from "node:url"
import { setTimeout as delay } from "node:timers/promises"

import { runFreshInstallSmoke } from "./fresh-install-smoke-lib.mjs"

const rootDir = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")
const envExamplePath = path.join(rootDir, ".env.example")
const envPath = path.join(rootDir, ".env")
const readinessUrl = process.env.ACTANTOS_READY_URL ?? "http://localhost:3100/health/ready"
const demoUrl = process.env.ACTANTOS_DEMO_URL ?? "http://localhost:3100"

const runCommand = (command, args) => {
  const result = spawnSync(command, args, {
    cwd: rootDir,
    stdio: "inherit",
    shell: process.platform === "win32",
  })

  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed with exit code ${result.status ?? 1}`)
  }
}

const ensureEnvFile = () => {
  if (!existsSync(envPath)) {
    copyFileSync(envExamplePath, envPath)
  }
}

const waitForReady = async () => {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    try {
      const response = await fetch(readinessUrl)
      if (response.ok) {
        return
      }
    } catch {}

    await delay(1_000)
  }

  throw new Error(`readiness check did not succeed at ${readinessUrl}`)
}

await runFreshInstallSmoke({
  demoUrl,
  ensureEnvFile,
  runCommand,
  waitForReady,
})
