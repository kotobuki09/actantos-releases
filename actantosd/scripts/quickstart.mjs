import { spawn, spawnSync } from "node:child_process"
import { existsSync } from "node:fs"
import process from "node:process"
import { setTimeout as delay } from "node:timers/promises"

import { createQuickstartPlan } from "./quickstart-lib.mjs"

const port = Number.parseInt(process.env.ACTANTOS_QUICKSTART_PORT ?? "4310", 10)
if (!Number.isInteger(port) || port < 1 || port > 65_535) {
  throw new Error("ACTANTOS_QUICKSTART_PORT must be an integer from 1 to 65535")
}

const plan = createQuickstartPlan(port, {
  hasPackageLock: existsSync("package-lock.json"),
  hasSource: existsSync("src/index.ts"),
})

const runCommand = ([command, args]) => {
  const result = spawnSync(command, args, {
    stdio: "inherit",
    shell: process.platform === "win32",
  })

  if (result.status !== 0) {
    throw new Error(`${command} ${args.join(" ")} failed with exit code ${result.status ?? 1}`)
  }
}

const waitForReady = async (server) => {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    if (server.exitCode !== null) {
      throw new Error(`actantosd exited before becoming ready with code ${server.exitCode}`)
    }

    try {
      const response = await fetch(plan.readinessUrl)
      if (response.ok) {
        return
      }
    } catch (error) {
      if (!(error instanceof Error)) {
        throw error
      }
    }

    await delay(500)
  }

  throw new Error(`actantosd did not become ready at ${plan.readinessUrl}`)
}

console.log("ActantOS portable agent test")
console.log("Requirements: Node.js 22+; Docker is not required.")

runCommand(plan.install)
if (plan.build !== undefined) {
  runCommand(plan.build)
}

const server = spawn(...plan.server, {
  env: {
    ...process.env,
    HOST: "127.0.0.1",
    PORT: String(port),
  },
  stdio: "inherit",
  shell: false,
})

try {
  await waitForReady(server)
  runCommand(plan.agentTest)
  console.log(`ActantOS passed the portable agent test at http://127.0.0.1:${port}`)
} finally {
  server.kill()
}
