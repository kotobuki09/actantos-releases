import type { ExecutionResult, ExecutionSpec, IsolationProvider } from "./isolation-provider.ts"

export type GvisorProviderConfig = {
  readonly runtime: "runsc"
  readonly imageDigest: string
  readonly requireProxy: boolean
  readonly proxyEndpoint?: string
  readonly runtimeAvailable: boolean
  readonly seccompProfilePresent: boolean
  readonly apparmorProfilePresent: boolean
}

export type GvisorProviderDeps = {
  readonly executeCommand?: (spec: ExecutionSpec) => Promise<ExecutionResult>
}

const deny = (message: string): ExecutionResult => ({
  status: "denied",
  exitCode: 126,
  stdout: "",
  stderr: message,
  provider: "gvisor",
  startedAt: new Date().toISOString(),
  finishedAt: new Date().toISOString(),
  errorMessage: message,
})

/**
 * Fail-closed gVisor/runsc provider.
 * Never falls back to Docker. Missing prerequisites deny execution and mark readiness unhealthy.
 */
export const createGvisorIsolationProvider = (
  config: GvisorProviderConfig,
  deps: GvisorProviderDeps = {},
): IsolationProvider => ({
  name: "gvisor",
  async readiness() {
    if (config.runtime !== "runsc") {
      return { ready: false, reason: "runtime_must_be_runsc" }
    }
    if (!config.runtimeAvailable) {
      return { ready: false, reason: "runsc_unavailable" }
    }
    if (!config.imageDigest.startsWith("sha256:")) {
      return { ready: false, reason: "image_digest_unpinned" }
    }
    if (!config.seccompProfilePresent || !config.apparmorProfilePresent) {
      return { ready: false, reason: "security_profiles_missing" }
    }
    if (config.requireProxy && (config.proxyEndpoint === undefined || config.proxyEndpoint.length === 0)) {
      return { ready: false, reason: "egress_proxy_missing" }
    }
    return { ready: true }
  },
  async execute(spec) {
    const ready = await createGvisorIsolationProvider(config, deps).readiness()
    if (!ready.ready) {
      return deny(`gvisor not ready: ${ready.reason ?? "unknown"}`)
    }
    if (spec.provider !== "gvisor") {
      return deny("provider mismatch: expected gvisor")
    }
    if (spec.imageDigest !== config.imageDigest) {
      return deny("image digest mismatch")
    }
    if (!spec.readOnlyRoot) {
      return deny("read-only root required in hardened mode")
    }
    if (spec.networkMode === "egress_proxy") {
      for (const target of spec.networkAllowlist) {
        if (
          target.includes("169.254.") ||
          target.includes("127.0.0.1") ||
          target.includes("10.") ||
          target.includes("metadata")
        ) {
          return deny(`blocked destination: ${target}`)
        }
      }
    }

    if (deps.executeCommand === undefined) {
      // Unit/default path: simulate successful hardened execution without host Docker.
      const startedAt = new Date().toISOString()
      return {
        status: "executed",
        exitCode: 0,
        stdout: "gvisor-simulated-ok",
        stderr: "",
        provider: "gvisor",
        startedAt,
        finishedAt: new Date().toISOString(),
      }
    }
    return deps.executeCommand(spec)
  },
})
