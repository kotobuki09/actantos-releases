import { ApprovalRequired, GuardedAccessDenied } from "./errors.ts"
import {
  createRequestId,
  postApprovalDecision,
  postInterceptDecision,
  postToolResult,
  type ApprovalDecisionResponse,
  type InterceptDependencies,
  type ToolResultRequest,
} from "./intercept_client.ts"
import {
  executeShellCommand,
  type ShellExecutionResult,
  type ShellExecutorDependencies,
} from "./shell_executor.ts"

type ShellParseResult =
  | {
      readonly kind: "parsed"
      readonly argv: readonly string[]
    }
  | {
      readonly kind: "ambiguous"
    }

type GuardedBashPlan = {
  readonly requestId: string
  readonly decisionId: string
  readonly argv: readonly string[]
  readonly decisionToken?: string
  readonly constraints?: {
    readonly timeout_ms?: number
    readonly max_output_bytes?: number
    readonly network_mode?: "none" | "egress_proxy"
    readonly network_allowlist?: readonly string[]
  }
}

type GuardedBashExecutionOptions = ShellExecutorDependencies & {
  readonly hmacSecret: string
}

type GuardedBashAuthorization = {
  readonly priorDecisionId: string
  readonly approvalId: string
  readonly approvalToken: string
}

const AMBIGUOUS_META_CHARACTERS = new Set(["|", "&", ";", "<", ">", "$", "`", "\n", "\r"])
const GLOB_CHARACTERS = new Set(["*", "?", "["])
const NETWORK_COMMANDS = new Set(["curl", "docker", "gh", "git", "npm", "pnpm", "wget"])
const MUTATING_COMMANDS = new Set(["docker", "git", "gh", "mv", "npm", "pnpm", "rm", "sudo"])
const SAFE_GIT_SUBCOMMANDS = new Set(["diff", "log", "show", "status"])

const tokenizeCommand = (command: string): ShellParseResult => {
  const argv: string[] = []
  let currentToken = ""
  let activeQuote: "'" | "\"" | undefined
  let escaped = false

  for (const character of command) {
    if (escaped) {
      currentToken += character
      escaped = false
      continue
    }

    if (activeQuote === undefined && character === "\\") {
      escaped = true
      continue
    }

    if (character === "'" || character === "\"") {
      if (activeQuote === undefined) {
        activeQuote = character
        continue
      }
      if (activeQuote === character) {
        activeQuote = undefined
        continue
      }
    }

    if (activeQuote === undefined && AMBIGUOUS_META_CHARACTERS.has(character)) {
      return { kind: "ambiguous" }
    }

    if (activeQuote === undefined && GLOB_CHARACTERS.has(character)) {
      return { kind: "ambiguous" }
    }

    if (activeQuote === undefined && /\s/.test(character)) {
      if (currentToken.length > 0) {
        argv.push(currentToken)
        currentToken = ""
      }
      continue
    }

    currentToken += character
  }

  if (escaped || activeQuote !== undefined) {
    return { kind: "ambiguous" }
  }

  if (currentToken.length > 0) {
    argv.push(currentToken)
  }

  if (argv.length === 0) {
    return { kind: "ambiguous" }
  }

  return { kind: "parsed", argv }
}

const isNetworkCommand = (argv: readonly string[]): boolean => {
  const [commandFamily, subcommand] = argv
  if (commandFamily === undefined) {
    return true
  }
  if (NETWORK_COMMANDS.has(commandFamily)) {
    return true
  }
  return commandFamily === "git" && subcommand === "push"
}

const isMutatingCommand = (argv: readonly string[]): boolean => {
  const [commandFamily, subcommand] = argv
  if (commandFamily === undefined) {
    return true
  }
  if (commandFamily === "git" && subcommand !== undefined) {
    return !SAFE_GIT_SUBCOMMANDS.has(subcommand)
  }
  return MUTATING_COMMANDS.has(commandFamily)
}

const isDestructiveCommand = (argv: readonly string[]): boolean => {
  const [commandFamily] = argv
  return commandFamily === "rm"
}

const isRecursiveDelete = (argv: readonly string[]): boolean =>
  argv.some((argument) => argument === "-r" || argument === "-rf" || argument === "-fr" || argument === "--recursive")

const buildGuardedBashInterceptRequest = (
  dependencies: InterceptDependencies,
  command: string,
  authorization?: GuardedBashAuthorization,
): {
  readonly requestId: string
  readonly argv: readonly string[]
  readonly request: Parameters<typeof postInterceptDecision>[1]
} => {
  const parseResult = tokenizeCommand(command)
  const requestId = createRequestId(dependencies)
  const argv = parseResult.kind === "parsed" ? parseResult.argv : []
  const commandFamily = parseResult.kind === "parsed" ? argv[0] : "__ambiguous__"
  const subcommand = parseResult.kind === "parsed" ? argv[1] : undefined
  const network = parseResult.kind === "ambiguous" ? true : isNetworkCommand(argv)
  const mutation = parseResult.kind === "ambiguous" ? true : isMutatingCommand(argv)
  const destructive = parseResult.kind === "ambiguous" ? false : isDestructiveCommand(argv)
  const recursiveDelete = destructive ? isRecursiveDelete(argv) : false
  const request = {
    requestId,
    tool: {
      kind: "shell",
      name: "guarded_bash",
      operation: "ExecuteShellCommand",
    },
    resource: {
      id: "/workspace",
      kind: "workspace",
      path: "/workspace",
    },
    action: {
      operation: "ExecuteShellCommand",
      args: {
        command,
        argv,
      },
    },
    normalized: {
      verb: "execute",
      mutation,
      destructive,
      network,
      credential_access: false,
      risk_class: parseResult.kind === "ambiguous" ? "high" : "low",
      command_family: commandFamily,
      subcommand,
      target_type: parseResult.kind === "ambiguous" ? "ambiguous_shell" : "argv_command",
      recursive_delete: recursiveDelete,
      force: argv.includes("--force") || argv.includes("-f"),
    },
    ...(authorization === undefined
      ? {}
      : {
          authorization: {
            prior_decision_id: authorization.priorDecisionId,
            approval_id: authorization.approvalId,
            approval_token: authorization.approvalToken,
          },
        }),
  } satisfies Parameters<typeof postInterceptDecision>[1]

  return {
    requestId,
    argv,
    request,
  }
}

export const guardedBash = async (
  dependencies: InterceptDependencies,
  command: string,
  authorization?: GuardedBashAuthorization,
): Promise<GuardedBashPlan> => {
  const { requestId, argv, request } = buildGuardedBashInterceptRequest(
    dependencies,
    command,
    authorization,
  )
  const interceptDecision = await postInterceptDecision(dependencies, request)

  switch (interceptDecision.decision) {
    case "allow": {
      const plan: {
        requestId: string
        decisionId: string
        argv: readonly string[]
        decisionToken?: string
        constraints?: {
          readonly timeout_ms?: number
          readonly max_output_bytes?: number
          readonly network_mode?: "none" | "egress_proxy"
          readonly network_allowlist?: readonly string[]
        }
      } = {
        requestId,
        decisionId: interceptDecision.decision_id,
        argv,
      }
      if (interceptDecision.decision_token !== undefined) {
        plan.decisionToken = interceptDecision.decision_token
      }
      if (interceptDecision.constraints !== undefined) {
        plan.constraints = interceptDecision.constraints
      }
      return plan
    }
    case "deny":
      throw new GuardedAccessDenied(
        interceptDecision.reason_code,
        interceptDecision.reason,
        interceptDecision.decision_id,
        requestId,
      )
    case "approval_required":
      throw new ApprovalRequired(
        interceptDecision.approval.approval_id,
        authorization?.priorDecisionId ?? interceptDecision.approval.approval_id,
        interceptDecision.reason_code,
        interceptDecision.reason,
        interceptDecision.decision_id,
        requestId,
      )
  }
}

export const createGuardedBash = (dependencies: InterceptDependencies) => {
  return async (
    command: string,
    authorization?: GuardedBashAuthorization,
  ): Promise<GuardedBashPlan> => guardedBash(dependencies, command, authorization)
}

export const approveAndResumeGuardedBash = async (
  dependencies: InterceptDependencies,
  command: string,
  approval: ApprovalRequired,
  approverUserId: string,
): Promise<GuardedBashPlan> => {
  const decision = await postApprovalDecision(
    dependencies,
    approval.approvalId,
    approverUserId,
    "approved",
  )

  if (decision.approval_token === undefined) {
    throw new Error("approval decision did not return a one-use token")
  }

  return guardedBash(dependencies, command, {
    priorDecisionId: approval.priorDecisionId,
    approvalId: approval.approvalId,
    approvalToken: decision.approval_token,
  })
}

const createBlockedToolResultPayload = (
  requestId: string,
  decisionId: string,
  error: GuardedAccessDenied | ApprovalRequired,
): ToolResultRequest => {
  const timestamp = new Date().toISOString()

  return {
    request_id: requestId,
    decision_id: decisionId,
    tool_kind: "shell",
    status: "blocked",
    started_at: timestamp,
    finished_at: timestamp,
    result: {
      error_message: error.message,
    },
  }
}

const createExecutedToolResultPayload = (
  plan: GuardedBashPlan,
  result: ShellExecutionResult,
): ToolResultRequest => {
  const payload: {
    request_id: string
    decision_id: string
    decision_token?: string
    tool_kind: "shell"
    status: "executed" | "failed" | "timeout"
    started_at: string
    finished_at: string
    result: {
      exit_code: number
      stdout_hash: string | null
      stderr_hash: string | null
      redacted_preview: string
      error_message?: string
    }
  } = {
    request_id: plan.requestId,
    decision_id: plan.decisionId,
    tool_kind: "shell",
    status: result.status,
    started_at: result.startedAt,
    finished_at: result.finishedAt,
    result: {
      exit_code: result.exitCode,
      stdout_hash: result.stdoutHash,
      stderr_hash: result.stderrHash,
      redacted_preview: result.redactedPreview,
    },
  }

  if (plan.decisionToken !== undefined) {
    payload.decision_token = plan.decisionToken
  }
  if (result.errorMessage !== undefined) {
    payload.result.error_message = result.errorMessage
  }

  return payload
}

export const executeGuardedBashPlan = async (
  dependencies: InterceptDependencies,
  plan: GuardedBashPlan,
  options: GuardedBashExecutionOptions,
): Promise<ShellExecutionResult> => {
  if (plan.decisionToken === undefined) {
    throw new Error("cannot execute a guarded bash plan without a decision token")
  }

  const execution = await executeShellCommand(
    {
      decisionToken: plan.decisionToken,
      hmacSecret: options.hmacSecret,
      requestId: plan.requestId,
      tenantId: dependencies.tenantId,
      agentId: dependencies.agent.id,
      sessionId: dependencies.session.id,
      toolName: "guarded_bash",
      workspacePath: dependencies.workspaceRoot,
      argv: plan.argv,
      networkMode: plan.constraints?.network_mode ?? "none",
      timeoutMs: plan.constraints?.timeout_ms ?? 30_000,
      maxOutputBytes: plan.constraints?.max_output_bytes ?? 200_000,
    },
    options,
  )

  await postToolResult(
    dependencies,
    createExecutedToolResultPayload(plan, execution),
  )

  return execution
}

export const runGuardedBash = async (
  dependencies: InterceptDependencies,
  command: string,
  options: GuardedBashExecutionOptions,
  authorization?: GuardedBashAuthorization,
): Promise<ShellExecutionResult> => {
  try {
    const plan = await guardedBash(dependencies, command, authorization)
    return await executeGuardedBashPlan(dependencies, plan, options)
  } catch (error) {
    if (
      error instanceof GuardedAccessDenied &&
      error.decisionId !== undefined &&
      error.requestId !== undefined
    ) {
      await postToolResult(
        dependencies,
        createBlockedToolResultPayload(error.requestId, error.decisionId, error),
      )
    }

    if (
      error instanceof ApprovalRequired &&
      error.decisionId !== undefined &&
      error.requestId !== undefined
    ) {
      await postToolResult(
        dependencies,
        createBlockedToolResultPayload(error.requestId, error.decisionId, error),
      )
    }

    throw error
  }
}

export const approveResumeAndRunGuardedBash = async (
  dependencies: InterceptDependencies,
  command: string,
  approval: ApprovalRequired,
  approverUserId: string,
  options: GuardedBashExecutionOptions,
): Promise<ShellExecutionResult> => {
  const plan = await approveAndResumeGuardedBash(
    dependencies,
    command,
    approval,
    approverUserId,
  )

  return executeGuardedBashPlan(dependencies, plan, options)
}

export type {
  ApprovalDecisionResponse,
  GuardedBashAuthorization,
  GuardedBashExecutionOptions,
  GuardedBashPlan,
  InterceptDependencies as GuardedBashDependencies,
  ShellExecutionResult,
}
