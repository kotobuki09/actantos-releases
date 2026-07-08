import { spawn } from "node:child_process"
import { createHash } from "node:crypto"

import { createDecisionConstraints } from "./decision-constraints.ts"
import { canonicalHash } from "./hash.ts"
import { planDockerCommand } from "./docker-command-plan.ts"
import { verifyDecisionToken } from "./hash.ts"

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

const parseDecisionTokenClaims = (token: string, secret: string): DecisionTokenClaims => {
  const verification = verifyDecisionToken(token, secret)

  if (!verification.valid) {
    throw new Error("invalid decision token")
  }

  let payload: unknown

  try {
    payload = JSON.parse(verification.payload) as unknown
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

export const executeDockerCommand = async (
  request: DockerExecutionRequest,
  dependencies: DockerExecutorDependencies = {},
): Promise<DockerExecutionResult> => {
  const spawnCommand = dependencies.spawnCommand ?? (spawn as SpawnCommand)
  const claims = parseDecisionTokenClaims(request.decisionToken, request.hmacSecret)
  assertClaimsMatch(claims, request)
  await ensureDockerNetwork(request.networkMode, spawnCommand)

  const startedAt = new Date().toISOString()
  const commandPlan = planDockerCommand(request.argv)
  await ensureDockerImage(commandPlan.image, spawnCommand)
  const networkName = request.networkMode === "egress_proxy" ? "actantos_egress" : "none"
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
