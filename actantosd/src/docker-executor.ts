import { execSync, spawn } from "node:child_process"
import { createHash } from "node:crypto"

import { createDecisionConstraints } from "./decision-constraints.ts"
import { canonicalCommandHash } from "./decision-command.ts"
import type { DecisionNonceStore } from "./decision-nonce-store.ts"
import { canonicalHash } from "./hash.ts"
import { planDockerCommand } from "./docker-command-plan.ts"
import { resolveSandboxRuntimeFlags } from "./sandbox-runtime.ts"
import {
  type DecisionTokenVerification,
  verifyDecisionTokenWith,
} from "./decision-token-signature.ts"
import { EGRESS_CELL_NETWORK } from "./v2/egress-cell.ts"

/**
 * Sandbox network selection.
 *
 * - `none`: Docker `--network none`. No network at all.
 * - `egress_proxy`: the internal cell network `actantos_egress_cell`, whose only reachable peer is
 *   the egress proxy. The proxy authenticates the connection and enforces destinations at connect
 *   time — see `src/v2/egress-proxy.ts`.
 *
 * This value used to select a plain bridge called `actantos_egress`, which had no proxy on it, no
 * internal flag, and no destination check. It was not a weaker cell; it was no cell at all.
 */
type NetworkMode = "none" | "egress_proxy"
type SpawnCommand = (
  command: string,
  args: readonly string[],
  options?: Parameters<typeof spawn>[2],
) => ReturnType<typeof spawn>

type DecisionTokenClaims = {
  readonly decision_id: string
  readonly tool_call_id: string
  readonly request_id: string
  readonly tenant_id: string
  readonly agent_id: string
  readonly session_id: string
  readonly tool_name: string
  readonly scope_hash: string
  readonly constraints_hash: string
  readonly command_hash: string
  readonly nonce: string
  readonly decision: "allow"
  readonly exp: number
  readonly approved?: boolean
}

type DockerExecutionRequest = {
  readonly decisionToken: string
  readonly hmacSecret: string
  readonly requestId: string
  readonly tenantId: string
  readonly agentId: string
  readonly sessionId: string
  readonly toolName: string
  readonly scopeHash: string
  readonly workspacePath: string
  readonly argv: readonly string[]
  readonly networkMode: NetworkMode
  readonly timeoutMs: number
  readonly maxOutputBytes: number
}

type DockerExecutorDependencies = {
  readonly spawnCommand?: SpawnCommand
  /**
   * Override the runsc binary probe — return true if runsc is on PATH.
   *
   * Separate from `checkRunscRegistry` because the two fail independently and an operator fixes
   * them in different places: one by installing gVisor, one by editing the Docker daemon's
   * `daemon.json`. Injecting only one of them asserts that one probe is sufficient, which is the
   * bug this split exists to prevent.
   */
  readonly checkRunsc?: () => boolean
  /** Override the daemon-registration probe — return true if the daemon offers a `runsc` runtime. */
  readonly checkRunscRegistry?: () => boolean
  /**
   * Single-use tracking for the token nonce (S9). Required: an executor with no store cannot tell
   * a first use from a replay, so it is safer to refuse to start than to start unprotected.
   */
  readonly nonceStore: DecisionNonceStore
  /**
   * How to verify decision tokens. Defaults to HMAC with `request.hmacSecret`.
   *
   * Pass `{ kind: "ed25519", publicKeyPem }` to make the executor a verifier that cannot also
   * mint. That is the only way the "holder of the shared secret can mint tokens" limitation goes
   * away: with HMAC, every component that verifies a token also holds the signing key.
   */
  readonly tokenVerification?: DecisionTokenVerification
}

export type DockerExecutionResult = {
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

const sha256Text = (value: string): string =>
  createHash("sha256").update(value, "utf8").digest("hex")

const isRecord = (value: unknown): value is Record<string, unknown> =>
  typeof value === "object" && value !== null

const parseDecisionTokenClaims = (
  token: string,
  verification: DecisionTokenVerification,
): DecisionTokenClaims => {
  const result = verifyDecisionTokenWith(token, verification)

  if (!result.valid) {
    throw new Error("invalid decision token")
  }

  let payload: unknown

  try {
    payload = JSON.parse(result.payload) as unknown
  } catch {
    throw new Error("invalid decision token")
  }

  if (!isRecord(payload)) {
    throw new Error("invalid decision token payload")
  }

  const requestId = payload["request_id"]
  const tenantId = payload["tenant_id"]
  const agentId = payload["agent_id"]
  const sessionId = payload["session_id"]
  const toolName = payload["tool_name"]
  const scopeHash = payload["scope_hash"]
  const decisionId = payload["decision_id"]
  const toolCallId = payload["tool_call_id"]
  const constraintsHash = payload["constraints_hash"]
  const commandHash = payload["command_hash"]
  const nonce = payload["nonce"]
  const decision = payload["decision"]
  const exp = payload["exp"]
  const approved = payload["approved"]

  if (
    typeof decisionId !== "string" ||
    typeof toolCallId !== "string" ||
    typeof requestId !== "string" ||
    typeof tenantId !== "string" ||
    typeof agentId !== "string" ||
    typeof sessionId !== "string" ||
    typeof toolName !== "string" ||
    typeof scopeHash !== "string" ||
    typeof constraintsHash !== "string" ||
    typeof commandHash !== "string" ||
    // S9: a token with no nonce cannot be made single-use, so it is rejected rather than treated
    // as exempt. Exempting it would give an attacker a way to mint replayable tokens.
    typeof nonce !== "string" ||
    nonce.length === 0 ||
    decision !== "allow" ||
    typeof exp !== "number"
  ) {
    throw new Error("invalid decision token claims")
  }

  if (approved !== undefined && typeof approved !== "boolean") {
    throw new Error("invalid approved claim")
  }

  const claims: {
    decision_id: string
    tool_call_id: string
    request_id: string
    tenant_id: string
    agent_id: string
    session_id: string
    tool_name: string
    scope_hash: string
    constraints_hash: string
    command_hash: string
    nonce: string
    decision: "allow"
    exp: number
    approved?: boolean
  } = {
    decision_id: decisionId,
    tool_call_id: toolCallId,
    request_id: requestId,
    tenant_id: tenantId,
    agent_id: agentId,
    session_id: sessionId,
    tool_name: toolName,
    scope_hash: scopeHash,
    constraints_hash: constraintsHash,
    command_hash: commandHash,
    nonce,
    decision,
    exp,
  }

  if (typeof approved === "boolean") {
    claims.approved = approved
  }

  return claims
}

const assertClaimsMatch = (
  claims: DecisionTokenClaims,
  request: DockerExecutionRequest,
): void => {
  if (
    claims.request_id !== request.requestId ||
    claims.tenant_id !== request.tenantId ||
    claims.agent_id !== request.agentId ||
    claims.session_id !== request.sessionId ||
    claims.tool_name !== request.toolName ||
    claims.scope_hash !== request.scopeHash
  ) {
    throw new Error("decision token claims mismatch")
  }

  if (claims.exp <= Math.floor(Date.now() / 1_000)) {
    throw new Error("decision token expired")
  }

  const constraintsHash = canonicalHash(
    createDecisionConstraints({
      networkMode: request.networkMode,
      timeoutMs: request.timeoutMs,
      maxOutputBytes: request.maxOutputBytes,
    }),
  )
  if (claims.constraints_hash !== constraintsHash) {
    throw new Error("decision token constraints mismatch")
  }

  // S8: the token must describe the command actually being run. Without this the argv passed
  // straight through to `docker run`, so a token for one command authorised any other.
  const commandHash = canonicalCommandHash(request.argv, request.workspacePath)
  if (claims.command_hash !== commandHash) {
    throw new Error("decision token command mismatch")
  }
}

const GITHUB_TOKEN_PATTERN = /\bgh[pousr]_[A-Za-z0-9_]+\b/g
const AWS_ACCESS_KEY_ID_PATTERN = /\b(?:AKIA|ASIA|ABIA|AIDA)[A-Z0-9]{16}\b/g
const BEARER_TOKEN_PATTERN = /\b(Bearer\s+)([A-Za-z0-9._-]+)/gi
const PRIVATE_KEY_BLOCK_PATTERN =
  /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g
const SECRET_ENV_PATTERN =
  /\b([A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|ACCESS_KEY|PRIVATE_KEY)[A-Z0-9_]*)=([^\s]+)/g

const scrubSensitiveText = (value: string): string =>
  value
    .replaceAll(GITHUB_TOKEN_PATTERN, "[REDACTED_GITHUB_TOKEN]")
    .replaceAll(AWS_ACCESS_KEY_ID_PATTERN, "[REDACTED_AWS_ACCESS_KEY_ID]")
    .replaceAll(BEARER_TOKEN_PATTERN, "$1[REDACTED]")
    .replaceAll(PRIVATE_KEY_BLOCK_PATTERN, "[REDACTED_PRIVATE_KEY]")
    .replaceAll(SECRET_ENV_PATTERN, (_match, key) => `${String(key)}=[REDACTED]`)

const buildPreview = (stdout: string, stderr: string): string => {
  const combined = scrubSensitiveText([stdout, stderr].filter((value) => value.length > 0).join("\n"))
  return combined.slice(0, 200)
}

const truncateOutput = (value: string, maxOutputBytes: number): string => {
  const buffer = Buffer.from(value, "utf8")
  if (buffer.byteLength <= maxOutputBytes) {
    return value
  }
  return buffer.subarray(0, maxOutputBytes).toString("utf8")
}

/**
 * Make sure the cell network exists, as an *internal* network.
 *
 * `--internal` is the entire security property of this network. Without it the network is an
 * ordinary bridge with a gateway, and a workload attached to it can reach the internet directly —
 * which is what `actantos_egress` did, and why the old `egress_proxy` mode was the absence of a
 * cell rather than a weaker one. Measured on this host against real Docker: a container on an
 * internal bridge gets `EGRESS_BLOCKED` for both `wget https://example.com` and a raw `nc` to a
 * public IP, while still reaching a peer on the same network by name and by IP.
 *
 * The check is `docker network inspect` and only creates when absent, so a network created
 * *without* `--internal` by an earlier version would be reused as-is. That is a real deployment
 * hazard: `inspect` reports `Internal`, and asserting on it here turns an operator mistake into a
 * loud refusal rather than a silently open cell.
 */
/**
 * Did `docker network inspect` report this network as internal?
 *
 * Parsed rather than matched as text. `docker network inspect` emits pretty-printed JSON whose
 * exact spacing is not a contract, and a check of the form `output.includes('"Internal": true')`
 * fails open on any reformatting — which for a security property means it silently stops checking.
 *
 * Unparseable output is treated as "not internal", because the two ways to be wrong here are not
 * symmetric: a false refusal is an operator deleting a network, and a false accept is an open cell.
 */
const inspectReportsInternal = (output: string): boolean => {
  let parsed: unknown

  try {
    parsed = JSON.parse(output)
  } catch {
    return false
  }

  if (!Array.isArray(parsed)) return false

  const [network] = parsed

  if (network === null || typeof network !== "object") return false

  return (network as { Internal?: unknown }).Internal === true
}

const ensureDockerNetwork = async (
  networkMode: NetworkMode,
  spawnCommand: SpawnCommand,
): Promise<void> => {
  if (networkMode !== "egress_proxy") {
    return
  }

  const inspect = (): Promise<{ code: number | null; output: string }> =>
    new Promise((resolve, reject) => {
      const child = spawnCommand("docker", ["network", "inspect", EGRESS_CELL_NETWORK], {
        stdio: ["ignore", "pipe", "ignore"],
        windowsHide: true,
      })

      const chunks: Buffer[] = []

      child.stdout?.on("data", (chunk: Buffer) => chunks.push(chunk))

      child.once("exit", (code) => {
        resolve({ code, output: Buffer.concat(chunks).toString("utf8") })
      })
      child.once("error", reject)
    })

  const existing = await inspect()

  if (existing.code === 0) {
    if (!inspectReportsInternal(existing.output)) {
      throw new Error(
        `docker network ${EGRESS_CELL_NETWORK} exists but is not internal. Refusing to use it: ` +
          "a non-internal cell network has a gateway, and every workload on it can reach the " +
          `internet directly. Remove it with \`docker network rm ${EGRESS_CELL_NETWORK}\` and ` +
          "let this run recreate it correctly.",
      )
    }

    return
  }

  await new Promise<void>((resolve, reject) => {
    const createChild = spawnCommand(
      "docker",
      ["network", "create", "--internal", "--driver", "bridge", EGRESS_CELL_NETWORK],
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

/**
 * Checks whether the 'runsc' (gVisor) binary is available on PATH.
 * Uses 'where' on Windows and 'which' on other platforms.
 */
const defaultCheckRunsc = (): boolean => {
  const cmd = process.platform === "win32" ? "where" : "which"
  try {
    execSync(`${cmd} runsc`, { stdio: "ignore" })
    return true
  } catch {
    return false
  }
}

/**
 * Resolve the sandbox runtime before any side effect occurs.
 *
 * Order is deliberate: this runs before the network is created and before the image is
 * pulled. Both are side effects on the host, and neither should happen for a request that is
 * going to be refused. It also means the refusal arrives immediately instead of after a
 * multi-hundred-megabyte pull, followed by an opaque `Unknown runtime specified runsc` from
 * the Docker daemon.
 */
export const resolveSandboxRuntime = (
  checkRunsc: () => boolean,
  checkRunscRegistry?: (() => boolean) | undefined,
): readonly string[] => resolveSandboxRuntimeFlags(checkRunsc, checkRunscRegistry)

export const executeDockerCommand = async (
  request: DockerExecutionRequest,
  dependencies: DockerExecutorDependencies,
): Promise<DockerExecutionResult> => {
  const spawnCommand = dependencies.spawnCommand ?? (spawn as SpawnCommand)
  const checkRunsc = dependencies.checkRunsc ?? defaultCheckRunsc
  const checkRunscRegistry = dependencies.checkRunscRegistry
  const tokenVerification =
    dependencies.tokenVerification ?? { kind: "hmac", secret: request.hmacSecret }
  const claims = parseDecisionTokenClaims(request.decisionToken, tokenVerification)
  assertClaimsMatch(claims, request)

  // S9: claim the token before anything else happens. A token that is valid, in-window and
  // correctly bound still authorises exactly one execution, so a copy taken from a log, a
  // process listing or a compromised peer is worthless on its second use. This runs after the
  // claim checks (a malformed token is rejected as malformed, not as a replay) and before any
  // host mutation (a refused replay leaves no trace on the host).
  // Awaited, and the spawn below happens strictly after it resolves. A concurrent second caller is
  // resolved by the store rather than by this process, so the await is not a window: if this
  // process died between the claim and the spawn the token would be spent and nothing would have
  // run, which is a wasted authorization rather than a replay.
  const claimed = await dependencies.nonceStore.consume({
    tenantId: claims.tenant_id,
    permitId: claims.decision_id,
    nonce: claims.nonce,
    expiresAt: new Date(claims.exp * 1000),
  })

  if (!claimed) {
    throw new Error("decision token already used")
  }

  // Resolved before any host mutation: see resolveSandboxRuntime.
  const gvisorArgs = resolveSandboxRuntime(checkRunsc, checkRunscRegistry)

  await ensureDockerNetwork(request.networkMode, spawnCommand)

  const startedAt = new Date().toISOString()
  const commandPlan = planDockerCommand(request.argv)
  await ensureDockerImage(commandPlan.image, spawnCommand)
  const networkName = request.networkMode === "egress_proxy" ? EGRESS_CELL_NETWORK : "none"

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
    ...gvisorArgs,
    ...commandPlan.dockerFlags,
    "--network",
    networkName,
    "--stop-timeout",
    "30",
    commandPlan.image,
    ...commandPlan.containerArgv,
  ]

  const execution = await new Promise<{
    readonly exitCode: number
    readonly fullStdout: string
    readonly fullStderr: string
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
        fullStdout: stdout,
        fullStderr: stderr,
        stdout: truncateOutput(stdout, request.maxOutputBytes),
        stderr: truncateOutput(stderr, request.maxOutputBytes),
        timedOut,
      })
    })
  })

  const finishedAt = new Date().toISOString()
  const stdoutHash = execution.fullStdout.length === 0 ? null : sha256Text(execution.fullStdout)
  const stderrHash = execution.fullStderr.length === 0 ? null : sha256Text(execution.fullStderr)
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
