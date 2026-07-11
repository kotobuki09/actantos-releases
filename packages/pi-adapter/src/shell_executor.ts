import { spawn } from "node:child_process"
import { createHash, createHmac } from "node:crypto"

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
}

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

const parseDecisionTokenClaims = (
  token: string,
  secret: string,
): DecisionTokenClaims => {
  const verification = verifyDecisionToken(token, secret)

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

  if (
    typeof requestId !== "string" ||
    typeof tenantId !== "string" ||
    typeof agentId !== "string" ||
    typeof sessionId !== "string" ||
    typeof toolName !== "string"
  ) {
    throw new Error("invalid decision token claims")
  }

  return {
    request_id: requestId,
    tenant_id: tenantId,
    agent_id: agentId,
    session_id: sessionId,
    tool_name: toolName,
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

const ensureDockerNetwork = async (
  networkMode: NetworkMode,
  spawnCommand: SpawnCommand,
): Promise<void> => {
  if (networkMode !== "egress_proxy") {
    return
  }

  await new Promise<void>((resolve, reject) => {
    const child = spawnCommand("docker", ["network", "inspect", "actantos_egress"], {
      stdio: "ignore",
      windowsHide: true,
    })

    child.once("exit", (code) => {
      if (code === 0) {
        resolve()
        return
      }

      const createChild = spawnCommand("docker", ["network", "create", "actantos_egress"], {
        stdio: "ignore",
        windowsHide: true,
      })

      createChild.once("exit", (createCode) => {
        if (createCode === 0) {
          resolve()
          return
        }
        reject(new Error("failed to create actantos_egress network"))
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
  dependencies: ShellExecutorDependencies = {},
): Promise<ShellExecutionResult> => {
  const spawnCommand = dependencies.spawnCommand ?? (spawn as SpawnCommand)
  const claims = parseDecisionTokenClaims(request.decisionToken, request.hmacSecret)
  assertClaimsMatch(claims, request)
  await ensureDockerNetwork(request.networkMode, spawnCommand)

  const startedAt = new Date().toISOString()
  const commandPlan = planDockerCommand(request.argv)
  await ensureDockerImage(commandPlan.image, spawnCommand)
  const dockerNetwork = request.networkMode === "egress_proxy" ? "actantos_egress" : "none"
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
