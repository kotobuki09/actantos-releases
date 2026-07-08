import * as crypto from "node:crypto"
import { spawn } from "node:child_process"

import { GuardedAccessDenied, ApprovalRequired } from "./guarded_read.ts"

// ---------------------------------------------------------------------------
// Shell command tokenization / normalization
// ---------------------------------------------------------------------------

/**
 * Simple POSIX-style argv tokenizer.
 * Treats input as shell-split words, no variable expansion.
 * Returns [] if unparseable — caller treats as high-risk.
 */
export const shlexSplit = (command: string): string[] => {
  const tokens: string[] = []
  let current = ""
  let inSingleQuote = false
  let inDoubleQuote = false

  for (let i = 0; i < command.length; i++) {
    const char = command[i]!

    if (inSingleQuote) {
      if (char === "'") {
        inSingleQuote = false
      } else {
        current += char
      }
    } else if (inDoubleQuote) {
      if (char === '"') {
        inDoubleQuote = false
      } else if (char === '\\' && i + 1 < command.length) {
        current += command[++i]
      } else {
        current += char
      }
    } else {
      if (char === "'") {
        inSingleQuote = true
      } else if (char === '"') {
        inDoubleQuote = true
      } else if (char === '\\' && i + 1 < command.length) {
        current += command[++i]
      } else if (/\s/.test(char)) {
        if (current.length > 0) {
          tokens.push(current)
          current = ""
        }
      } else {
        current += char
      }
    }
  }

  if (inSingleQuote || inDoubleQuote) {
    // Unclosed quote — unparseable
    return []
  }

  if (current.length > 0) {
    tokens.push(current)
  }

  return tokens
}

// ---------------------------------------------------------------------------
// Normalized shell command analysis
// ---------------------------------------------------------------------------

type ShellNormalized = {
  readonly command_family: string
  readonly subcommand: string | undefined
  readonly mutation: boolean
  readonly destructive: boolean
  readonly network: boolean
  readonly recursive_delete: boolean
  readonly force: boolean
  readonly risk_class: "low" | "medium" | "high" | "critical"
}

const HIGH_RISK_COMMANDS = new Set([
  "curl", "wget", "npm", "npx", "yarn", "pnpm",
  "docker", "sudo", "su", "chmod", "chown", "git",
  "gh", "terraform", "ansible", "kubectl", "helm",
  "ssh", "scp", "sftp", "rsync",
])

const NETWORK_COMMANDS = new Set([
  "curl", "wget", "ssh", "scp", "sftp", "rsync", "git", "gh",
  "npm", "npx", "yarn", "pnpm", "docker", "kubectl",
])

const MUTATION_COMMANDS = new Set([
  "rm", "mv", "cp", "mkdir", "touch", "chmod", "chown", "ln",
  "git", "gh", "npm", "yarn", "docker", "terraform", "kubectl",
])

const normalizeShell = (argv: string[]): ShellNormalized => {
  const commandFamily = argv[0] ?? "unknown"
  const subcommand = argv[1]

  const isNetwork = NETWORK_COMMANDS.has(commandFamily)
  const isMutation = MUTATION_COMMANDS.has(commandFamily)

  // Destructive: rm -rf or similar
  const isRm = commandFamily === "rm"
  const hasRecursive = argv.some(
    (a) => a === "-r" || a === "-R" || a === "--recursive" || a.includes("r") && a.startsWith("-") && !a.startsWith("--"),
  )
  const hasForce = argv.some((a) => a === "-f" || a === "--force" || a.includes("f") && a.startsWith("-") && !a.startsWith("--"))
  const isDestructive = isRm
  const isRecursiveDelete = isRm && (hasRecursive || argv.some((a) => a.includes("rf") || a.includes("fr")))

  const riskClass: "low" | "medium" | "high" | "critical" =
    HIGH_RISK_COMMANDS.has(commandFamily) ? "high" :
    isDestructive ? "high" :
    isMutation ? "medium" :
    "low"

  return {
    command_family: commandFamily,
    subcommand,
    mutation: isMutation || isNetwork,
    destructive: isDestructive,
    network: isNetwork,
    recursive_delete: isRecursiveDelete,
    force: hasForce,
    risk_class: riskClass,
  }
}

// ---------------------------------------------------------------------------
// Docker sandbox executor
// ---------------------------------------------------------------------------

export type SandboxOptions = {
  readonly workspaceMount: string
  readonly networkMode: "none" | "egress_proxy"
  readonly timeoutMs: number
  readonly maxOutputBytes: number
  readonly envAllowlist: readonly string[]
}

export type ExecutionResult = {
  readonly exit_code: number
  readonly stdout: string
  readonly stderr: string
  readonly stdout_hash: string
  readonly stderr_hash: string
  readonly timed_out: boolean
}

const sha256 = (value: string): string => {
  const hash = crypto.createHash("sha256")
  hash.update(value)
  return `sha256:${hash.digest("hex")}`
}

/**
 * Execute command in Docker sandbox.
 * Uses actantos/sandbox:latest image.
 */
export const executeInSandbox = (
  argv: string[],
  options: SandboxOptions,
): Promise<ExecutionResult> => {
  const dockerArgs = [
    "run", "--rm",
    "--user", "1001:1001",
    "--cap-drop", "ALL",
    "--security-opt", "no-new-privileges",
    "--memory", "512m",
    "--cpus", "0.5",
    "--pids-limit", "64",
    "--volume", `${options.workspaceMount}:/workspace`,
    "--network", options.networkMode === "none" ? "none" : "bridge",
    "actantos/sandbox:latest",
    ...argv,
  ]

  return new Promise((resolve) => {
    const child = spawn("docker", dockerArgs, {
      stdio: ["ignore", "pipe", "pipe"],
    })

    let stdout = ""
    let stderr = ""
    let timedOut = false

    const timer = setTimeout(() => {
      timedOut = true
      child.kill("SIGKILL")
    }, options.timeoutMs)

    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8")
      if (Buffer.byteLength(stdout, "utf8") > options.maxOutputBytes) {
        stdout = stdout.slice(0, options.maxOutputBytes) + "\n[truncated]"
        child.kill("SIGTERM")
      }
    })

    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8")
    })

    child.on("close", (exitCode) => {
      clearTimeout(timer)
      resolve({
        exit_code: exitCode ?? -1,
        stdout,
        stderr,
        stdout_hash: sha256(stdout),
        stderr_hash: sha256(stderr),
        timed_out: timedOut,
      })
    })

    child.on("error", () => {
      clearTimeout(timer)
      resolve({
        exit_code: -1,
        stdout,
        stderr: stderr + "\n[docker spawn failed]",
        stdout_hash: sha256(stdout),
        stderr_hash: sha256(stderr),
        timed_out: false,
      })
    })
  })
}

// ---------------------------------------------------------------------------
// guarded_bash
// ---------------------------------------------------------------------------

export type GuardedBashConfig = {
  readonly actantosUrl: string
  readonly tenantId: string
  readonly agentId: string
  readonly userId: string
  readonly sessionId: string
  readonly workspaceRoot: string
  readonly sandbox?: SandboxOptions
}

type InterceptionResponse = {
  readonly decision: "allow" | "deny" | "approval_required"
  readonly decision_mode: string
  readonly reason: string
  readonly reason_code: string
  readonly audit_event_id: string
  readonly decision_token?: string
  readonly constraints?: {
    readonly timeout_ms?: number
    readonly max_output_bytes?: number
    readonly network_mode?: "none" | "egress_proxy"
  }
  readonly approval?: {
    readonly approval_id: string
    readonly status: string
    readonly expires_at: string
  }
}

const callActantOS = async (
  url: string,
  body: unknown,
): Promise<InterceptionResponse> => {
  const response = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  })

  if (!response.ok) {
    const text = await response.text()
    throw new Error(`ActantOS returned ${response.status}: ${text}`)
  }

  return response.json() as Promise<InterceptionResponse>
}

export const guardedBash = async (
  command: string,
  config: GuardedBashConfig,
  authorization?: {
    prior_decision_id: string
    approval_id: string
    approval_token: string
  },
): Promise<ExecutionResult> => {
  // Step 1: Tokenize the command
  const argv = shlexSplit(command)

  if (argv.length === 0) {
    throw new GuardedAccessDenied("canonicalization_failed", "unparseable command")
  }

  // Step 2: Normalize (compute normalized booleans for Cedar + risk rules)
  const normalized = normalizeShell(argv)

  // Step 3: Build request ID
  const requestId = authorization
    ? `bash_exec_${crypto.randomBytes(8).toString("hex")}`
    : `bash_${crypto.randomBytes(8).toString("hex")}`

  // Step 4: Call ActantOS
  const interceptBody: Record<string, unknown> = {
    request_id: requestId,
    tenant_id: config.tenantId,
    agent: {
      id: config.agentId,
      runtime_type: "pi",
      environment: "dev",
      risk_tier: "low",
    },
    subject: {
      user_id: config.userId,
      role: "developer",
    },
    session: {
      id: config.sessionId,
      cwd: config.workspaceRoot,
      budget_remaining_cents: 10_000,
    },
    tool: {
      kind: "shell",
      name: "guarded_bash",
      operation: "ExecuteShellCommand",
      schema_hash: "",
    },
    resource: {
      id: config.workspaceRoot,
      kind: "process",
      path: config.workspaceRoot,
    },
    action: {
      operation: "ExecuteShellCommand",
      args: { command, argv },
    },
    normalized: {
      verb: "execute",
      mutation: normalized.mutation,
      destructive: normalized.destructive,
      network: normalized.network,
      credential_access: false,
      risk_class: normalized.risk_class,
      command_family: normalized.command_family,
      subcommand: normalized.subcommand,
      recursive_delete: normalized.recursive_delete,
      force: normalized.force,
    },
  }

  if (authorization !== undefined) {
    interceptBody["authorization"] = authorization
  }

  const response = await callActantOS(
    `${config.actantosUrl}/v1/intercept/tool-call`,
    interceptBody,
  )

  if (response.decision === "deny") {
    throw new GuardedAccessDenied(response.reason_code, response.reason)
  }

  if (response.decision === "approval_required") {
    throw new ApprovalRequired(
      response.approval!.approval_id,
      response.approval!.expires_at,
    )
  }

  // Decision is allow — execute in Docker sandbox
  const sandboxOpts: SandboxOptions = config.sandbox ?? {
    workspaceMount: config.workspaceRoot,
    networkMode: response.constraints?.network_mode ?? "none",
    timeoutMs: response.constraints?.timeout_ms ?? 30_000,
    maxOutputBytes: response.constraints?.max_output_bytes ?? 200_000,
    envAllowlist: [],
  }

  // Override network mode from decision constraints
  const effectiveSandboxOpts: SandboxOptions = {
    ...sandboxOpts,
    networkMode: response.constraints?.network_mode ?? "none",
  }

  return executeInSandbox(argv, effectiveSandboxOpts)
}
