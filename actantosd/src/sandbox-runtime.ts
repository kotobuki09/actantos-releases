/**
 * Sandbox runtime selection (invariant S12).
 *
 * One module so the three places that care — the executor, the server startup, and the
 * preflight check — cannot drift apart. They previously did: preflight failed hard on a
 * missing `runsc`, while startup and the executor warned and carried on with the default
 * Docker runtime. An operator who read the preflight output and the startup log would have
 * been told two different things about the same host.
 *
 * The rule, stated once: **if a policy asks for gVisor, the request runs under gVisor or it
 * does not run at all.** There is no warn-and-degrade path.
 */

import { execFileSync } from "node:child_process"

/**
 * Raised when a policy requires gVisor isolation and the runtime is unavailable.
 *
 * A distinct class rather than a bare Error so a caller can tell "this environment is not
 * strong enough for this request" apart from "the command failed". The distinction matters:
 * the first must never be retried against the default runtime, the second may be.
 */
export class SandboxRuntimeUnavailableError extends Error {
  constructor(runtime: string, reason?: string) {
    super(
      `Sandbox runtime "${runtime}" is required by policy but is not usable on this host` +
        `${reason === undefined ? "" : ` (${reason})`}. ` +
        `Refusing to execute: falling back to the default Docker runtime would silently ` +
        `weaken isolation, so the request is refused instead. ` +
        `Install ${runtime} (https://gvisor.dev/docs/user_guide/install/), or unset ` +
        `ACTANTOS_USE_GVISOR to accept the weaker runtime deliberately.`,
    )
    this.name = "SandboxRuntimeUnavailableError"
  }
}

export type RunscAvailability = {
  readonly available: boolean
  /** Why not, in operator terms. Absent when available. */
  readonly reason?: string
}

/**
 * Diagnose gVisor readiness rather than answering yes/no.
 *
 * The reason exists because the two preconditions have two different fixes. "runsc is not on
 * PATH" and "the Docker daemon has no runtime registered under that name" send an operator to
 * completely different places — install a package, versus edit `daemon.json` and restart Docker —
 * and a gate that reported only "unavailable" for both sent them to the wrong one every time.
 */
const diagnoseRunsc = (
  check: (() => boolean) | undefined,
  registryCheck: (() => boolean) | undefined,
): RunscAvailability => {
  if (!(check ?? defaultRunscCheck)()) {
    return {
      available: false,
      reason: "the runsc binary was not found on PATH",
    }
  }

  if (!(registryCheck ?? defaultRunscRegistryCheck)()) {
    return {
      available: false,
      reason:
        "runsc is on PATH but the Docker daemon has no runtime registered under that name, " +
        'so `docker run --runtime=runsc` would be rejected; add {"runtimes": {"runsc": ' +
        '{"path": "..."}}} to daemon.json and restart Docker',
    }
  }

  return { available: true }
}

/** True when the operator has asked for gVisor isolation. */
export const isSandboxRuntimeRequired = (): boolean =>
  process.env["ACTANTOS_USE_GVISOR"] === "true"

/**
 * True when gVisor isolation has been explicitly demanded rather than merely requested.
 *
 * `ACTANTOS_USE_GVISOR=true` already refuses to execute. Strict mode extends the same
 * refusal to server startup: a process that cannot honour its own sandbox policy should not
 * come up and accept traffic it cannot enforce.
 */
export const isStrictSandboxMode = (): boolean =>
  process.env["ACTANTOS_GVISOR_STRICT"] === "true" ||
  process.env["NODE_ENV"] === "production"

/**
 * Decide whether a `docker info` `.Runtimes` payload registers a runtime named `runsc`.
 *
 * `.Runtimes` is an object keyed by the name `--runtime` accepts, each entry carrying the binary
 * `path` — verified against `docker info --format "{{json .Runtimes}}"` on a real daemon, not
 * assumed. On the machine this was written on it renders as
 * `{"io.containerd.runc.v2":{"path":"runc",...},"nvidia":{...},"runc":{"path":"runc",...}}`, so
 * the name to look for is a *key*, and a value whose `path` happens to end in `runsc` is not the
 * same thing as a runtime Docker will dispatch to.
 *
 * Exported so the parsing can be tested against real output without a running daemon.
 */
export const dockerRegistersRunsc = (dockerInfoRuntimes: string): boolean => {
  let parsed: unknown
  try {
    parsed = JSON.parse(dockerInfoRuntimes)
  } catch {
    // Output we cannot read is not evidence of a registered runtime.
    return false
  }

  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return false
  }

  return Object.hasOwn(parsed, "runsc")
}

const defaultRunscRegistryCheck = (): boolean => {
  try {
    const output = execFileSync("docker", ["info", "--format", "{{json .Runtimes}}"], {
      stdio: ["ignore", "pipe", "ignore"],
      encoding: "utf8",
    })
    return dockerRegistersRunsc(output)
  } catch {
    // No docker CLI, or no reachable daemon. Either way the runtime cannot be used.
    return false
  }
}

const defaultRunscCheck = (): boolean => {
  try {
    execFileSync("runsc", ["--version"], { stdio: "ignore" })
    return true
  } catch {
    return false
  }
}

/**
 * Whether this host can actually run a container under gVisor.
 *
 * Two things have to hold, and checking only the first was the bug.
 *
 * 1. `runsc` is on PATH. Without the binary there is nothing to invoke.
 * 2. The Docker daemon has a runtime registered under the name `runsc`.
 *
 * These are genuinely independent. A host can have gVisor installed and yet be talking to a
 * daemon that was never configured to offer it — that is the default on a stock install, and it
 * is exactly the state of the machine this module was written on. The old check passed in that
 * situation, the executor emitted `--runtime=runsc`, and the refusal arrived from `docker` as an
 * opaque daemon error rather than as the `SandboxRuntimeUnavailableError` that names the cause
 * and says how to fix it.
 *
 * The outcome was never a silently unisolated execution — Docker rejects an unknown runtime
 * name — but it was a refusal at the wrong layer, with a message that pointed at the command
 * rather than at the daemon configuration.
 *
 * Either check may be injected, so a test can present a host with the binary but no registration
 * and assert the gate still refuses.
 */
export const isRunscAvailable = (
  check: (() => boolean) | undefined = undefined,
  registryCheck: (() => boolean) | undefined = undefined,
): boolean => diagnoseRunsc(check, registryCheck).available

/**
 * Docker flags for the requested runtime, or a refusal.
 *
 * Empty means the default runtime was not overridden, which is the only case in which no
 * gVisor check runs.
 */
export const resolveSandboxRuntimeFlags = (
  check?: (() => boolean) | undefined,
  registryCheck?: (() => boolean) | undefined,
): readonly string[] => {
  if (!isSandboxRuntimeRequired()) {
    return []
  }

  const availability = diagnoseRunsc(check, registryCheck)
  if (!availability.available) {
    throw new SandboxRuntimeUnavailableError("runsc", availability.reason)
  }

  return ["--runtime", "runsc"]
}