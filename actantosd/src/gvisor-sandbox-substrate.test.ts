import assert from "node:assert/strict"
import { execFileSync } from "node:child_process"
import { randomUUID } from "node:crypto"
import fs from "node:fs"
import path from "node:path"
import test from "node:test"

import { createDecisionConstraints } from "./decision-constraints.ts"
import { canonicalCommandHash } from "./decision-command.ts"
import { executeDockerCommand } from "./docker-executor.ts"
import { InMemoryDecisionNonceStore } from "./decision-nonce-store.ts"
import { canonicalHash, signDecisionToken } from "./hash.ts"
import { resolveSandboxRuntimeFlags } from "./sandbox-runtime.ts"

/**
 * gVisor, against a real daemon that actually registers `runsc`.
 *
 * Everything else about gVisor in this repository is a decision: the executor's gate, the argv,
 * and the refusal when the runtime is missing. Those are proved in `docker-executor.test.ts` and
 * `sandbox-runtime.test.ts`. This file is the other half — it proves the runtime is real, so
 * that "the executor asked for runsc" and "the container got a sandbox" are the same statement
 * rather than two unconnected ones.
 *
 * Three measurement facts about this host shaped the code below. None of them are product
 * behaviour, and all three would silently produce a green test that proves nothing:
 *
 * 1. `runsc` lives in the WSL2 distro, not on the Windows client. So the client-side binary probe
 *    (`execFileSync("runsc", ["--version"])`) is injected below. The probe that actually decides
 *    usability — the daemon's own runtime registry — is NOT injected; it is the real default
 *    probe against the live daemon.
 *
 * 2. `docker run`'s attached stream is unusable across the WSL2 TCP boundary on this host: it
 *    exits 0 and delivers nothing. `create` + `start` + `logs` works. So output is observed that
 *    way. The container, the runtime and the flags are identical either way; only the plumbing
 *    for reading stdout differs.
 *
 * 3. This daemon's bridge has no external route for *either* runtime (`nslookup` gets
 *    "Network unreachable" under runsc and under the default runtime alike). So egress is NOT
 *    claimed here. The claim below is kernel isolation, which is attributable: the same
 *    container, same image, same daemon, differing only in the runtime flag, runs on a different
 *    kernel. That difference is what proves the flag is honoured rather than silently ignored.
 *
 * Gated on `ACTANTOS_GVISOR_DOCKER_HOST` naming a daemon that reports `runsc`. Everything skips
 * elsewhere, so `npm test` and `npm run test:substrate` are both safe without it.
 */

const SUBSTRATE_PASS = process.env["ACTANTOS_SUBSTRATE_TESTS"] === "1"
const GVISOR_HOST = process.env["ACTANTOS_GVISOR_DOCKER_HOST"]

if (SUBSTRATE_PASS && GVISOR_HOST !== undefined && GVISOR_HOST !== "") {
  process.env["DOCKER_HOST"] = GVISOR_HOST
}

const IMAGE = "alpine:3.20"

/**
 * The workspace the executor bind-mounts at /workspace.
 *
 * Deliberately under /mnt/d so this test — which runs on Windows — can read back what the
 * container wrote. The kernel string the container sees is the only way to tell from outside
 * whether `--runtime=runsc` was actually applied, and asserting merely that the executor
 * "executed" would pass just as happily with the flag dropped.
 *
 * It is not `process.cwd()` for a second reason: this daemon is a bare `dockerd` inside the WSL2
 * distro, not Docker Desktop, so it has no path translation for `D:/...` and rejects the bind
 * mount outright with `invalid mode: /workspace`.
 */
const WORKSPACE = "/mnt/d/ActantOS/.tmp-gvisor-workspace"

/**
 * The same directory as *this* process sees it, which is not the daemon's `/mnt/d` spelling.
 *
 * The executor is handed `WORKSPACE` because that is what the WSL2 daemon can bind-mount, but the
 * assertions read the file back through `node:fs`, which on the Windows client needs `D:\...` and
 * inside WSL needs `/mnt/d/...`. Running this file on both sides is what lets the executor's own
 * `which runsc` probe decide the flag: runsc is installed in the WSL2 distro and not on the
 * Windows client, so only the WSL2 side can leave that probe un-injected.
 */
const WORKSPACE_HOST =
  process.platform === "win32" ? "D:\\ActantOS\\.tmp-gvisor-workspace" : WORKSPACE
const KERNEL_PROBE = path.join(WORKSPACE_HOST, "kernel.txt")

const docker = (args: readonly string[]): string =>
  execFileSync("docker", args as string[], {
    encoding: "utf8",
    timeout: 180_000,
    stdio: ["ignore", "pipe", "pipe"],
  })

/** True when the daemon named by ACTANTOS_GVISOR_DOCKER_HOST really offers runsc. */
const gvisorDaemonAvailable = ((): boolean => {
  if (!SUBSTRATE_PASS || GVISOR_HOST === undefined || GVISOR_HOST === "") {
    return false
  }
  try {
    const runtimes = docker(["info", "--format", "{{json .Runtimes}}"])
    const parsed: unknown = JSON.parse(runtimes)
    return (
      typeof parsed === "object" &&
      parsed !== null &&
      !Array.isArray(parsed) &&
      Object.hasOwn(parsed, "runsc")
    )
  } catch {
    return false
  }
})()

const skip = !gvisorDaemonAvailable
const todo = skip
  ? "set ACTANTOS_GVISOR_DOCKER_HOST to a daemon whose `docker info` lists a runsc runtime"
  : undefined

/**
 * Run a command in a real container and return its output.
 *
 * `create`/`start`/`logs` rather than `docker run`, per measurement fact 2 above.
 */
const observe = (runtimeArgs: readonly string[], script: string): string => {
  const containerId = docker([
    "create",
    ...runtimeArgs,
    IMAGE,
    "sh",
    "-c",
    script,
  ]).trim()
  try {
    docker(["start", containerId])
    return docker(["logs", containerId])
  } finally {
    try {
      docker(["rm", "-f", containerId])
    } catch {
      // The container is already gone; failing to clean up must not mask the real assertion.
    }
  }
}

const secret = "gvisor-substrate-test-secret"

const constraints = createDecisionConstraints({
  networkMode: "none",
  timeoutMs: 120_000,
  maxOutputBytes: 64_000,
})

const baseRequest = (argv: readonly string[]) => ({
  decisionToken: signDecisionToken(
    JSON.stringify({
      decision_id: "dec_gvisor_001",
      tool_call_id: "tc_gvisor_001",
      request_id: "req_gvisor_001",
      tenant_id: "t_gvisor",
      agent_id: "pi_gvisor",
      session_id: "s_gvisor",
      tool_name: "guarded_bash",
      scope_hash: "scope-gvisor",
      constraints_hash: canonicalHash(constraints),
      command_hash: canonicalCommandHash(argv, WORKSPACE),
      nonce: randomUUID(),
      decision: "allow",
      exp: Math.floor(Date.now() / 1_000) + 600,
    }),
    secret,
  ),
  hmacSecret: secret,
  requestId: "req_gvisor_001",
  tenantId: "t_gvisor",
  agentId: "pi_gvisor",
  sessionId: "s_gvisor",
  toolName: "guarded_bash",
  scopeHash: "scope-gvisor",
  workspacePath: WORKSPACE,
  argv,
  networkMode: "none" as const,
  timeoutMs: constraints.timeout_ms,
  maxOutputBytes: constraints.max_output_bytes,
})

test("gvisor substrate: the named daemon really registers runsc", { skip: todo }, () => {
  const runtimes: unknown = JSON.parse(docker(["info", "--format", "{{json .Runtimes}}"]))
  assert.equal(typeof runtimes, "object")
  assert.notEqual(runtimes, null)
  assert.notEqual(Array.isArray(runtimes), true)
  assert.ok(
    Object.hasOwn(runtimes as Record<string, unknown>, "runsc"),
    "the gate would never open on this daemon, so every test below would be vacuous",
  )
})

/**
 * Run `body` with gVisor demanded by policy.
 *
 * Without `ACTANTOS_USE_GVISOR=true` the resolver returns `[]` before it consults any probe at
 * all, because policy has not asked for a sandbox. A test that forgot this would see no flags,
 * conclude the gate is broken, and be wrong about why.
 */
const withGvisorRequired = async <T>(body: () => T): Promise<T> => {
  const previous = process.env["ACTANTOS_USE_GVISOR"]
  process.env["ACTANTOS_USE_GVISOR"] = "true"
  try {
    return await body()
  } finally {
    if (previous === undefined) {
      delete process.env["ACTANTOS_USE_GVISOR"]
    } else {
      process.env["ACTANTOS_USE_GVISOR"] = previous
    }
  }
}

test(
  "gvisor substrate: the live registry probe opens the gate without any injection",
  { skip: todo },
  async () => {
    // registryCheck is deliberately not passed, so the real default probe queries the live
    // daemon. Only the client-side binary probe is supplied, because runsc is in WSL2 (fact 1).
    const flags = await withGvisorRequired(() => resolveSandboxRuntimeFlags(() => true))
    assert.deepEqual(flags, ["--runtime", "runsc"])
  },
)

test(
  "gvisor substrate: the gate still refuses when the live daemon has no runsc",
  { skip: todo },
  async (t) => {
    // The same real probe, pointed at the default daemon. If that daemon also offers runsc there
    // is nothing to prove here, so the test says so instead of asserting something untrue.
    //
    // The same applies when there is no default daemon to point at. Inside WSL there is none —
    // that distro's daemon is reachable only over TCP, so the default is a `unix:///var/run/…`
    // socket that does not exist. Failing there would report a product defect that is really a
    // property of this host.
    const previous = process.env["DOCKER_HOST"]
    delete process.env["DOCKER_HOST"]
    let defaultHasRunsc: boolean
    try {
      defaultHasRunsc = JSON.parse(docker(["info", "--format", "{{json .Runtimes}}"])).runsc !== undefined
    } catch {
      t.skip("no default Docker daemon on this host, so there is no runsc-free daemon to compare against")
      return
    } finally {
      if (previous !== undefined) {
        process.env["DOCKER_HOST"] = previous
      }
    }
    if (defaultHasRunsc) {
      return
    }

    await withGvisorRequired(() => {
      assert.throws(
        () => {
          delete process.env["DOCKER_HOST"]
          try {
            resolveSandboxRuntimeFlags(() => true)
          } finally {
            if (previous !== undefined) {
              process.env["DOCKER_HOST"] = previous
            }
          }
        },
        (error: unknown) =>
          error instanceof Error && /no runtime registered under that name/u.test(error.message),
      )
    })
  },
)

test(
  "gvisor substrate: the same container runs on a different kernel when runsc is used",
  { skip: todo },
  () => {
    const underDefault = observe([], "cat /proc/version").trim()
    const underRunsc = observe(["--runtime=runsc"], "cat /proc/version").trim()

    assert.ok(underDefault.length > 0, "the default-runtime probe returned nothing")
    assert.ok(underRunsc.length > 0, "the runsc probe returned nothing")
    assert.notEqual(
      underDefault,
      underRunsc,
      "identical /proc/version means --runtime=runsc was ignored and the host kernel was used",
    )
    assert.match(underRunsc, /gvisor/u)
    assert.doesNotMatch(underDefault, /gvisor/u)
  },
)

test(
  "gvisor substrate: dmesg reads the sandbox kernel under runsc and the host's is refused otherwise",
  { skip: todo },
  () => {
    const underDefault = observe([], "dmesg 2>&1 | head -2").trim()
    const underRunsc = observe(["--runtime=runsc"], "dmesg 2>&1 | head -2").trim()

    assert.match(
      underDefault,
      /Operation not permitted/iu,
      "the default runtime should be refused the host kernel ring buffer",
    )
    assert.match(
      underRunsc,
      /gVisor/iu,
      "runsc should hand back its own userspace kernel boot log",
    )
  },
)

test(
  "gvisor substrate: the executor runs a container under runsc on the live daemon",
  { skip: todo },
  async () => {
    fs.mkdirSync(WORKSPACE_HOST, { recursive: true })
    fs.rmSync(KERNEL_PROBE, { force: true })

    // checkRunscRegistry is deliberately NOT passed: the executor's own default probe queries the
    // live daemon. Only the client-side binary probe is injected (fact 1).
    try {
      const result = await withGvisorRequired(() =>
        executeDockerCommand(
          baseRequest(["sh", "-c", "cat /proc/version > /workspace/kernel.txt"]) as never,
          {
            checkRunsc: () => true,
            nonceStore: new InMemoryDecisionNonceStore(),
          },
        ),
      )

      assert.equal(result.status, "executed")
      assert.equal(result.exitCode, 0)

      // The decisive assertion. If the executor had silently dropped --runtime runsc, the
      // container would still have run and still written this file — with the *host* kernel in
      // it. Asserting only on status/exitCode would have passed.
      assert.ok(
        fs.existsSync(KERNEL_PROBE),
        "the container did not write through the bind mount, so nothing was proved",
      )
      const kernel = fs.readFileSync(KERNEL_PROBE, "utf8")
      assert.match(
        kernel,
        /gvisor/iu,
        `the executor ran the container without gVisor; /proc/version was: ${kernel.trim()}`,
      )
    } finally {
      fs.rmSync(KERNEL_PROBE, { force: true })
    }
  },
)

test(
  "gvisor substrate: the executor's own runsc probe is what adds the flag, with nothing injected",
  { skip: todo },
  async (t) => {
    // The test above injects `checkRunsc: () => true` because runsc is installed in WSL2 and not on
    // the Windows client, so the real probe would answer false here (fact 1). That injection leaves
    // one seam unproved: nothing yet shows that the executor's *own* decision — `which runsc` in
    // `defaultCheckRunsc` — is what turns the flag on. A gate that is always stubbed true proves
    // the argv, not the wiring.
    //
    // This closes it by leaving `checkRunsc` unset entirely, so production code runs the probe.
    // It can only do so on the side where runsc is genuinely installed, which is why this file is
    // now runnable on both hosts.
    const runscOnPath = ((): boolean => {
      try {
        execFileSync("which", ["runsc"], { stdio: "ignore" })
        return true
      } catch {
        return false
      }
    })()

    if (!runscOnPath) {
      t.skip("runsc is not on the PATH of the process running this test, so the executor's own probe would refuse")
      return
    }

    fs.mkdirSync(WORKSPACE_HOST, { recursive: true })
    fs.rmSync(KERNEL_PROBE, { force: true })

    try {
      const result = await withGvisorRequired(() =>
        executeDockerCommand(
          baseRequest(["sh", "-c", "cat /proc/version > /workspace/kernel.txt"]) as never,
          // Nothing injected: no checkRunsc, no checkRunscRegistry.
          { nonceStore: new InMemoryDecisionNonceStore() },
        ),
      )

      assert.equal(result.status, "executed")
      assert.ok(fs.existsSync(KERNEL_PROBE), "the container did not write through the bind mount, so nothing was proved")

      const kernel = fs.readFileSync(KERNEL_PROBE, "utf8")
      assert.match(
        kernel,
        /gvisor/iu,
        `the executor's own probe found runsc but the container ran on the host kernel; /proc/version was: ${kernel.trim()}`,
      )
    } finally {
      fs.rmSync(KERNEL_PROBE, { force: true })
    }
  },
)