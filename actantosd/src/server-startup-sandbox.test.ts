import assert from "node:assert/strict"
import { spawn, spawnSync, type ChildProcess } from "node:child_process"
import { join } from "node:path"

import test from "node:test"

const INDEX = join(process.cwd(), "src", "index.ts")

const BASE_ENV = {
  PATH: process.env["PATH"] ?? "",
  NODE_ENV: "development",
  ACTANTOS_EVALUATOR_MODE: "development",
}

/**
 * Run the entry point and resolve as soon as it either starts listening or exits.
 *
 * Deliberately not `spawnSync` with a long timeout: the point of the non-strict cases is
 * that the process *keeps running*, so waiting it out costs tens of seconds per test and
 * proves nothing extra.
 */
const startUntilListening = async (
  env: Record<string, string>,
  readyLine: string,
  readyTimeoutMs: number,
): Promise<{ readonly exited: boolean; readonly status: number | null; readonly output: string }> => {
  const child: ChildProcess = spawn(
    process.execPath,
    ["--experimental-strip-types", INDEX],
    { env: { ...BASE_ENV, ...env }, stdio: ["ignore", "pipe", "pipe"] },
  )

  let output = ""

  const collect = (chunk: Buffer | string): void => {
    output += chunk.toString()
  }

  child.stdout?.on("data", collect)
  child.stderr?.on("data", collect)

  const exited = new Promise<number | null>((resolve) => {
    child.once("exit", (code) => resolve(code))
  })

  const ready = new Promise<boolean>((resolve) => {
    const timer = setTimeout(() => resolve(false), readyTimeoutMs)
    child.stdout?.on("data", () => {
      if (output.includes(readyLine)) {
        clearTimeout(timer)
        resolve(true)
      }
    })
    child.stderr?.on("data", () => {
      if (output.includes(readyLine)) {
        clearTimeout(timer)
        resolve(true)
      }
    })
  })

  const stillRunning = await Promise.race([
    ready,
    exited.then(() => false),
  ])

  child.kill()

  if (stillRunning) {
    await exited
    return { exited: false, status: null, output }
  }

  return { exited: true, status: await exited, output }
}

/**
 * Runs the real entry point rather than a helper, because the thing under test is "does the
 * process exit, or does it keep listening". A unit test on the helper cannot observe that.
 */
const startServer = (env: Record<string, string>) => {
  const result = spawnSync(process.execPath, ["--experimental-strip-types", INDEX], {
    encoding: "utf8",
    timeout: 30_000,
    env: { ...BASE_ENV, ...env },
  })

  return { status: result.status, output: `${result.stdout}${result.stderr}` }
}

test("S12: strict mode refuses to start when a required gVisor runtime is missing", () => {
  const { status, output } = startServer({
    ACTANTOS_USE_GVISOR: "true",
    ACTANTOS_GVISOR_STRICT: "true",
  })

  assert.equal(status, 1, `expected a hard exit, got ${status}\n${output}`)
  assert.match(output, /FATAL/)
  assert.match(output, /runsc/)
  assert.equal(
    /Server listening/.test(output),
    false,
    "the server must not begin listening when it cannot honour its sandbox policy",
  )
})

test("S12: strict mode is implied by NODE_ENV=production", () => {
  const { status, output } = startServer({
    ACTANTOS_USE_GVISOR: "true",
    NODE_ENV: "production",
  })

  assert.equal(status, 1, `expected a hard exit, got ${status}\n${output}`)
  assert.match(output, /FATAL/)
})

test("non-strict mode warns, keeps running, and does not claim a downgrade happens", async () => {
  const result = await startUntilListening(
    { ACTANTOS_USE_GVISOR: "true", ACTANTOS_GVISOR_STRICT: "false" },
    "Server listening",
    20_000,
  )

  assert.equal(
    result.exited,
    false,
    `expected the server to keep running\n${result.output}`,
  )
  assert.match(result.output, /WARNING/)
  assert.match(result.output, /runsc/)
  // The old message told operators containers "will fall back" to runc. That never happened
  // and is no longer claimed.
  assert.equal(
    /will fall back/i.test(result.output),
    false,
    "the startup message must not describe a silent downgrade",
  )
})

test("no gVisor warning when gVisor was not requested", async () => {
  const result = await startUntilListening({}, "Server listening", 20_000)

  assert.equal(
    result.exited,
    false,
    `expected the server to start normally\n${result.output}`,
  )
  assert.equal(/runsc/.test(result.output), false)
})