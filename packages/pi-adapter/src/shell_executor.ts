import { spawn, execFileSync } from "node:child_process"
import { createHash, createHmac, createPublicKey, verify } from "node:crypto"

type SpawnCommand = (
  command: string,
  args: readonly string[],
  options?: Parameters<typeof spawn>[2],
) => ReturnType<typeof spawn>

type NetworkMode = "none" | "egress_proxy"

type DecisionTokenClaims = {
  readonly request_id: string
  readonly tenant_id: string
  readonly agent_id: string
  readonly session_id: string
  readonly tool_name: string
  readonly scope_hash: string
  readonly constraints_hash: string
  readonly command_hash: string
  readonly nonce: string
  readonly exp: number
}

/** Bound into the token envelope so the verifier picks the algorithm, not the token. */
export const ASYMMETRIC_TOKEN_ALGORITHM = "ed25519"

/**
 * How to verify a decision token.
 *
 * With `hmac` the verifier also holds the signing key and can mint. With `ed25519` it holds only
 * a public key and cannot.
 */
export type DecisionTokenVerification =
  | { readonly kind: "hmac"; readonly secret: string }
  | { readonly kind: "ed25519"; readonly publicKeyPem: string }

/**
 * Single-use tracking for the token nonce (S9).
 *
 * Structurally identical to `DecisionNonceStore` in `actantosd/src/decision-nonce-store.ts`, and
 * restated here for the same reason the canonical hash is: pi-adapter does not depend on
 * actantosd. The actantosd implementation satisfies this interface directly, so a caller wires
 * one store to both executors rather than maintaining two.
 */
export type DecisionNonceEntry = {
  readonly tenantId: string
  readonly permitId: string
  readonly nonce: string
  readonly expiresAt: Date
}

export type DecisionNonceStore = {
  /**
   * Returns true only for the first caller for a given nonce.
   *
   * Async because the durable implementation claims first use in PostgreSQL. Two callers racing
   * the same token are resolved by the database, not by this process, and anything that is not an
   * explicit success is a refusal — including a store that cannot answer.
   */
  consume(entry: DecisionNonceEntry): Promise<boolean>
  /** Read-only. Never used to authorise. */
  isConsumed(entry: DecisionNonceEntry): Promise<boolean>
}

/**
 * Sorted-key JSON, matching `canonicalStringify` in `actantosd/src/hash.ts`.
 *
 * pi-adapter does not depend on actantosd, so the canonical hash is restated here. That is a
 * drift risk, so `shell_executor.test.ts` imports the actantosd implementations and asserts
 * this produces identical digests; if either side changes, that test fails.
 */
const sortJson = (value: unknown): unknown => {
  if (Array.isArray(value)) {
    return value.map(sortJson)
  }

  if (isRecord(value)) {
    const sorted: Record<string, unknown> = {}
    for (const key of Object.keys(value).sort()) {
      sorted[key] = sortJson(value[key])
    }
    return sorted
  }

  return value
}

const canonicalHash = (value: unknown): string =>
  createHash("sha256")
    .update(JSON.stringify(sortJson(value)), "utf8")
    .digest("hex")

/**
 * Digest over the command about to run and the host directory it will mount (S8).
 *
 * Equivalent to `canonicalCommandHash` in `actantosd/src/decision-command.ts`. Without it a
 * token issued for one command authorised any other: this path verified only identity claims,
 * so the argv passed straight through to `docker run`.
 */
export const canonicalCommandHash = (
  argv: readonly string[],
  workspacePath: string,
): string =>
  canonicalHash({
    // Order is significant: ["rm","-rf","x"] and ["rm","-x","-rf"] are different commands.
    argv: [...argv],
    workspace_path: workspacePath,
  })

export type ShellExecutionResult = {
  readonly status: "executed" | "failed" | "timeout"
  readonly exitCode: number
  readonly stdout: string
  readonly stderr: string
  readonly stdoutHash: string | null
  readonly stderrHash: string | null
  readonly redactedPreview: string
  readonly errorMessage?: string
  readonly startedAt: string
  readonly finishedAt: string
}

export type ShellExecutionRequest = {
  readonly decisionToken: string
  readonly hmacSecret: string
  readonly requestId: string
  readonly tenantId: string
  readonly agentId: string
  readonly sessionId: string
  readonly toolName: string
  readonly workspacePath: string
  readonly argv: readonly string[]
  readonly networkMode: NetworkMode
  readonly timeoutMs: number
  readonly maxOutputBytes: number
}

export type ShellExecutorDependencies = {
  readonly spawnCommand?: SpawnCommand
  /** Override the runsc binary check — return true if runsc is on PATH. */
  readonly checkRunsc?: () => boolean
  /**
   * Override the daemon-registration check — return true if the daemon offers a `runsc` runtime.
   *
   * Separate from `checkRunsc` because the two fail independently and an operator fixes them in
   * different places.
   */
  readonly checkRunscRegistry?: () => boolean
  /**
   * Single-use tracking for the token nonce (S9). Required for the same reason as in actantosd:
   * an executor that cannot distinguish a first use from a replay cannot enforce S9.
   */
  readonly nonceStore: DecisionNonceStore
  /**
   * How to verify decision tokens. Defaults to HMAC with `request.hmacSecret`.
   *
   * Pass `{ kind: "ed25519", publicKeyPem }` to make the executor a verifier that cannot also
   * mint.
   */
  readonly tokenVerification?: DecisionTokenVerification
}

/** Raised when policy requires gVisor isolation and runsc is not usable. */
export class SandboxRuntimeUnavailableError extends Error {
  constructor(reason?: string) {
    super(
      'Sandbox runtime "runsc" is required by policy but is not usable on this host' +
        `${reason === undefined ? "" : ` (${reason})`}. ` +
        "Refusing to execute: falling back to the default Docker runtime would silently " +
        "weaken isolation, so the request is refused instead. Install runsc " +
        "(https://gvisor.dev/docs/user_guide/install/), or unset ACTANTOS_USE_GVISOR to " +
        "accept the weaker runtime deliberately.",
    )
    this.name = "SandboxRuntimeUnavailableError"
  }
}

const isSandboxRuntimeRequired = (): boolean =>
  process.env["ACTANTOS_USE_GVISOR"] === "true"

const defaultRunscCheck = (): boolean => {
  try {
    execFileSync("runsc", ["--version"], { stdio: "ignore" })
    return true
  } catch {
    return false
  }
}

/**
 * Decide whether a `docker info` `.Runtimes` payload registers a runtime named `runsc`.
 *
 * Restated from `dockerRegistersRunsc` in `actantosd/src/sandbox-runtime.ts`, for the same reason
 * the canonical hash is restated: pi-adapter does not depend on actantosd. `shell_executor.test.ts`
 * imports the actantosd function and asserts the two agree on the same inputs.
 */
export const dockerRegistersRunsc = (dockerInfoRuntimes: string): boolean => {
  let parsed: unknown
  try {
    parsed = JSON.parse(dockerInfoRuntimes)
  } catch {
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
    return false
  }
}

/**
 * Docker flags for the requested runtime, or a refusal.
 *
 * Equivalent to `resolveSandboxRuntimeFlags` in `actantosd/src/sandbox-runtime.ts`; kept
 * separate because pi-adapter does not depend on actantosd. The rule is the same: no
 * warn-and-degrade path, because degrading here would be invisible to the operator.
 *
 * Two probes, not one. A host can have the gVisor binary installed and still be talking to a
 * Docker daemon that was never configured to offer it, which is the stock state. The executor
 * would then emit `--runtime=runsc` and the refusal would arrive from the daemon as an opaque
 * error instead of here, where it can say which of the two is missing.
 */
export const resolveSandboxRuntimeFlags = (
  check?: (() => boolean) | undefined,
  registryCheck?: (() => boolean) | undefined,
): readonly string[] => {
  if (!isSandboxRuntimeRequired()) {
    return []
  }

  if (!(check ?? defaultRunscCheck)()) {
    throw new SandboxRuntimeUnavailableError("the runsc binary was not found on PATH")
  }

  if (!(registryCheck ?? defaultRunscRegistryCheck)()) {
    throw new SandboxRuntimeUnavailableError(
      "runsc is on PATH but the Docker daemon has no runtime registered under that name, " +
        'so `docker run --runtime=runsc` would be rejected; add {"runtimes": {"runsc": ' +
        '{"path": "..."}}} to daemon.json and restart Docker',
    )
  }

  return ["--runtime", "runsc"]
}

const DEFAULT_IMAGE = "alpine:3.20"
const GIT_IMAGE = "alpine/git:latest"

const sha256Text = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex")

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null

const verifyDecisionToken = (
  token: string,
  secret: string,
): { readonly valid: true; readonly payload: string } | { readonly valid: false } => {
  const [encodedPayload, signature] = token.split(".")

  if (encodedPayload === undefined || signature === undefined) {
    return { valid: false }
  }

  let payload: string

  try {
    payload = Buffer.from(encodedPayload, "base64url").toString("utf8")
  } catch {
    return { valid: false }
  }

  const expectedSignature = createHmac("sha256", secret)
    .update(payload)
    .digest("base64url")

  if (signature !== expectedSignature) {
    return { valid: false }
  }

  return { valid: true, payload }
}

/**
 * Ed25519 verification, restated for the same reason `verifyDecisionToken` is: pi-adapter does
 * not depend on actantosd. It calls `node:crypto` directly, which is the same primitive
 * `actantosd/src/v2/signature.ts` wraps — the point is not to reimplement a signature scheme, and
 * `shell_executor.test.ts` imports the actantosd implementation to assert the two agree on real
 * tokens.
 *
 * Ed25519 signs the message directly, so the algorithm argument must be `null`. That is the same
 * constraint the actantosd wrapper documents.
 */
const verifyDecisionTokenEd25519 = (
  token: string,
  publicKeyPem: string,
): { readonly valid: true; readonly payload: string } | { readonly valid: false } => {
  const parts = token.split(".")

  if (parts.length !== 3) {
    return { valid: false }
  }

  const [algorithm, encodedPayload, encodedSignature] = parts
  if (
    algorithm !== ASYMMETRIC_TOKEN_ALGORITHM ||
    encodedPayload === undefined ||
    encodedSignature === undefined
  ) {
    return { valid: false }
  }

  let payload: string
  try {
    payload = Buffer.from(encodedPayload, "base64url").toString("utf8")
  } catch {
    return { valid: false }
  }

  try {
    const ok = verify(
      null,
      Buffer.from(payload, "utf8"),
      createPublicKey(publicKeyPem),
      Buffer.from(encodedSignature, "base64url"),
    )
    return ok ? { valid: true, payload } : { valid: false }
  } catch {
    // A malformed key is a verification failure, not an error. A caller must not be able to reach
    // a success path by catching.
    return { valid: false }
  }
}

export const verifyDecisionTokenWith = (
  token: string,
  verification: DecisionTokenVerification,
): { readonly valid: true; readonly payload: string } | { readonly valid: false } => {
  if (verification.kind === "ed25519") {
    return verifyDecisionTokenEd25519(token, verification.publicKeyPem)
  }

  // Two components means an HMAC token; three means an asymmetric one. A caller that passed an HMAC
  // verifier did not ask for Ed25519, and an asymmetric token must not be checked as one.
  if (token.split(".").length !== 2) {
    return { valid: false }
  }

  return verifyDecisionToken(token, verification.secret)
}

const parseDecisionTokenClaims = (
  token: string,
  tokenVerification: DecisionTokenVerification,
): DecisionTokenClaims => {
  const verification = verifyDecisionTokenWith(token, tokenVerification)

  if (!verification.valid) {
    throw new Error("invalid decision token")
  }

  const payload = JSON.parse(verification.payload) as unknown

  if (!isRecord(payload)) {
    throw new Error("invalid decision token payload")
  }

  const requestId = payload["request_id"]
  const tenantId = payload["tenant_id"]
  const agentId = payload["agent_id"]
  const sessionId = payload["session_id"]
  const toolName = payload["tool_name"]
  const scopeHash = payload["scope_hash"]
  const constraintsHash = payload["constraints_hash"]
  const commandHash = payload["command_hash"]
  const nonce = payload["nonce"]
  const exp = payload["exp"]

  if (
    typeof requestId !== "string" ||
    typeof tenantId !== "string" ||
    typeof agentId !== "string" ||
    typeof sessionId !== "string" ||
    typeof toolName !== "string" ||
    typeof scopeHash !== "string" ||
    typeof constraintsHash !== "string" ||
    typeof commandHash !== "string" ||
    // S9: a token with no nonce cannot be made single-use, so it is refused rather than
    // exempted.
    typeof nonce !== "string" ||
    nonce.length === 0 ||
    typeof exp !== "number"
  ) {
    throw new Error("invalid decision token claims")
  }

  return {
    request_id: requestId,
    tenant_id: tenantId,
    agent_id: agentId,
    session_id: sessionId,
    tool_name: toolName,
    scope_hash: scopeHash,
    constraints_hash: constraintsHash,
    command_hash: commandHash,
    nonce,
    exp,
  }
}

const assertClaimsMatch = (
  claims: DecisionTokenClaims,
  request: ShellExecutionRequest,
): void => {
  if (
    claims.request_id !== request.requestId ||
    claims.tenant_id !== request.tenantId ||
    claims.agent_id !== request.agentId ||
    claims.session_id !== request.sessionId ||
    claims.tool_name !== request.toolName
  ) {
    throw new Error("decision token claims mismatch")
  }

  if (claims.exp <= Math.floor(Date.now() / 1_000)) {
    throw new Error("decision token expired")
  }

  // The execution envelope is authorized too: an agent that widened max_output_bytes or
  // escalated to egress_proxy after the decision changed what the token permits.
  const constraintsHash = canonicalHash({
    max_output_bytes: request.maxOutputBytes,
    network_allowlist: [],
    network_mode: request.networkMode,
    timeout_ms: request.timeoutMs,
  })
  if (claims.constraints_hash !== constraintsHash) {
    throw new Error("decision token constraints mismatch")
  }

  // S8: the token must describe the command actually being run.
  if (claims.command_hash !== canonicalCommandHash(request.argv, request.workspacePath)) {
    throw new Error("decision token command mismatch")
  }
}

const truncateOutput = (value: string, maxOutputBytes: number): string => {
  const buffer = Buffer.from(value, "utf8")
  if (buffer.byteLength <= maxOutputBytes) {
    return value
  }
  return buffer.subarray(0, maxOutputBytes).toString("utf8")
}

const scrubSensitiveText = (value: string): string =>
  value
    .replaceAll(/ghp_[A-Za-z0-9]+/g, "[REDACTED_GITHUB_TOKEN]")
    .replaceAll(/SECRET=[^\s]+/g, "SECRET=[REDACTED]")
    .replaceAll(/AWS_[A-Z_]+=([^\s]+)/g, (_match, _capture) => "AWS_[REDACTED]=[REDACTED]")

const buildPreview = (stdout: string, stderr: string): string =>
  scrubSensitiveText([stdout, stderr].filter((entry) => entry.length > 0).join("\n")).slice(0, 200)

const planDockerCommand = (argv: readonly string[]): {
  readonly image: string
  readonly containerArgv: readonly string[]
  readonly dockerFlags: readonly string[]
} => {
  const commandFamily = argv[0]

  if (commandFamily === undefined) {
    throw new Error("docker command argv must not be empty")
  }

  if (commandFamily === "git") {
    return {
      image: GIT_IMAGE,
      containerArgv: [
        "-lc",
        "git config --global --add safe.directory \"*\" && exec git \"$@\"",
        "sh",
        ...argv.slice(1),
      ],
      dockerFlags: [
        "--entrypoint",
        "sh",
        "--env",
        "HOME=/tmp",
      ],
    }
  }

  return {
    image: DEFAULT_IMAGE,
    containerArgv: argv,
    dockerFlags: [],
  }
}

/**
 * The internal cell network shared with the egress proxy, and nothing else.
 *
 * Must match `EGRESS_CELL_NETWORK` in `actantosd/src/v2/egress-cell.ts`. This path used to
 * reference a network called `actantos_egress` and create it if missing — a plain bridge with
 * no proxy attached and no `--internal` flag. Attaching the workload to that is not a weaker
 * cell; it is unrestricted egress to every routable host, which is what S2 forbids.
 */
export const EGRESS_CELL_NETWORK = "actantos_egress_cell"

const ensureDockerNetwork = async (
  networkMode: NetworkMode,
  spawnCommand: SpawnCommand,
): Promise<void> => {
  if (networkMode !== "egress_proxy") {
    return
  }

  await new Promise<void>((resolve, reject) => {
    const child = spawnCommand(
      "docker",
      ["network", "inspect", EGRESS_CELL_NETWORK],
      { stdio: "ignore", windowsHide: true },
    )

    child.once("exit", (code) => {
      if (code === 0) {
        resolve()
        return
      }

      // Created `--internal`: no gateway, no route off the host. The only peer reachable from
      // the workload is the egress proxy, which authenticates and filters destinations.
      const createChild = spawnCommand(
        "docker",
        ["network", "create", "--internal", EGRESS_CELL_NETWORK],
        { stdio: "ignore", windowsHide: true },
      )

      createChild.once("exit", (createCode) => {
        if (createCode === 0) {
          resolve()
          return
        }
        reject(new Error(`failed to create ${EGRESS_CELL_NETWORK} network`))
      })
      createChild.once("error", reject)
    })

    child.once("error", reject)
  })
}

const ensureDockerImage = async (
  image: string,
  spawnCommand: SpawnCommand,
): Promise<void> => {
  await new Promise<void>((resolve, reject) => {
    const inspectChild = spawnCommand("docker", ["image", "inspect", image], {
      stdio: "ignore",
      windowsHide: true,
    })

    inspectChild.once("exit", (code) => {
      if (code === 0) {
        resolve()
        return
      }

      const pullChild = spawnCommand("docker", ["pull", image], {
        stdio: "ignore",
        windowsHide: true,
      })

      pullChild.once("exit", (pullCode) => {
        if (pullCode === 0) {
          resolve()
          return
        }
        reject(new Error(`failed to pull docker image ${image}`))
      })
      pullChild.once("error", reject)
    })

    inspectChild.once("error", reject)
  })
}

export const executeShellCommand = async (
  request: ShellExecutionRequest,
  dependencies: ShellExecutorDependencies,
): Promise<ShellExecutionResult> => {
  const spawnCommand = dependencies.spawnCommand ?? (spawn as SpawnCommand)
  const tokenVerification = dependencies.tokenVerification ?? {
    kind: "hmac" as const,
    secret: request.hmacSecret,
  }
  const claims = parseDecisionTokenClaims(request.decisionToken, tokenVerification)
  assertClaimsMatch(claims, request)

  // S9: claim the token before the gVisor resolution and before any Docker network or image
  // work, so a replay is refused without touching the host at all. Ordering matches
  // `executeDockerCommand` in actantosd: claim validation first, then the nonce, then mutation.
  const claimed = await dependencies.nonceStore.consume({
    tenantId: claims.tenant_id,
    permitId: claims.decision_id,
    nonce: claims.nonce,
    expiresAt: new Date(claims.exp * 1000),
  })

  if (!claimed) {
    throw new Error("decision token already used")
  }

  // S12: if policy asked for gVisor, run under gVisor or do not run. This path previously had
  // no runtime resolution at all, so a host configured for gVisor silently used the default
  // Docker runtime here — the same drift `actantosd/src/sandbox-runtime.ts` exists to prevent.
  const runtimeFlags = resolveSandboxRuntimeFlags(
    dependencies.checkRunsc,
    dependencies.checkRunscRegistry,
  )

  await ensureDockerNetwork(request.networkMode, spawnCommand)

  const startedAt = new Date().toISOString()
  const commandPlan = planDockerCommand(request.argv)
  await ensureDockerImage(commandPlan.image, spawnCommand)
  const dockerNetwork = request.networkMode === "egress_proxy" ? EGRESS_CELL_NETWORK : "none"
  const args = [
    "run",
    "--rm",
    "--user",
    "1001:1001",
    "--read-only",
    "--tmpfs",
    "/tmp:size=64m",
    "--volume",
    `${request.workspacePath}:/workspace`,
    "--workdir",
    "/workspace",
    "--cap-drop",
    "ALL",
    "--security-opt",
    "no-new-privileges",
    "--memory",
    "512m",
    "--cpus",
    "0.5",
    "--pids-limit",
    "64",
    ...runtimeFlags,
    ...commandPlan.dockerFlags,
    "--network",
    dockerNetwork,
    "--stop-timeout",
    "30",
    commandPlan.image,
    ...commandPlan.containerArgv,
  ]

  const execution = await new Promise<{
    readonly exitCode: number
    readonly stdout: string
    readonly stderr: string
    readonly timedOut: boolean
  }>((resolve, reject) => {
    const child = spawnCommand("docker", args, {
      windowsHide: true,
    })

    let stdout = ""
    let stderr = ""
    let timedOut = false

    const timer = setTimeout(() => {
      timedOut = true
      child.kill("SIGKILL")
    }, request.timeoutMs)

    child.stdout?.on("data", (chunk: Buffer | string) => {
      stdout += chunk.toString()
    })

    child.stderr?.on("data", (chunk: Buffer | string) => {
      stderr += chunk.toString()
    })

    child.once("error", (error) => {
      clearTimeout(timer)
      reject(error)
    })

    child.once("exit", (code) => {
      clearTimeout(timer)
      resolve({
        exitCode: code ?? -1,
        stdout: truncateOutput(stdout, request.maxOutputBytes),
        stderr: truncateOutput(stderr, request.maxOutputBytes),
        timedOut,
      })
    })
  })

  const finishedAt = new Date().toISOString()
  const stdoutHash = execution.stdout.length === 0 ? null : sha256Text(execution.stdout)
  const stderrHash = execution.stderr.length === 0 ? null : sha256Text(execution.stderr)
  const redactedPreview = buildPreview(execution.stdout, execution.stderr)

  if (execution.timedOut) {
    return {
      status: "timeout",
      exitCode: -1,
      stdout: execution.stdout,
      stderr: execution.stderr,
      stdoutHash,
      stderrHash,
      redactedPreview,
      errorMessage: "docker execution timed out",
      startedAt,
      finishedAt,
    }
  }

  if (execution.exitCode !== 0) {
    return {
      status: "failed",
      exitCode: execution.exitCode,
      stdout: execution.stdout,
      stderr: execution.stderr,
      stdoutHash,
      stderrHash,
      redactedPreview,
      errorMessage: `docker command exited with code ${String(execution.exitCode)}`,
      startedAt,
      finishedAt,
    }
  }

  return {
    status: "executed",
    exitCode: execution.exitCode,
    stdout: execution.stdout,
    stderr: execution.stderr,
    stdoutHash,
    stderrHash,
    redactedPreview,
    startedAt,
    finishedAt,
  }
}
