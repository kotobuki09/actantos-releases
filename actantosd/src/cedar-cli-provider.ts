import { spawn } from "node:child_process"
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"

import type { ToolCallContext } from "./contracts.ts"
import { commandFromRequest } from "./decision-command.ts"
import type { CedarDecision, CedarProvider } from "./fake-cedar-provider.ts"

type CedarCliProviderOptions = {
  readonly binaryPath?: string
  readonly policyPath?: string
  readonly timeoutMs?: number
  readonly maxAttempts?: number
  readonly authorizeCommand?: (
    options: CedarAuthorizeCommandOptions,
  ) => Promise<CedarAuthorizeCommandResult>
}

type CedarAuthorizeResponse = {
  readonly decision: "ALLOW" | "DENY"
  readonly reasonCode?: string
}

type CedarAuthorizeInput = {
  readonly request: {
    readonly principal: string
    readonly action: string
    readonly resource: string
    readonly context: Record<string, never>
  }
  readonly entities: readonly {
    readonly uid: {
      readonly type: string
      readonly id: string
    }
    readonly attrs: Record<string, string | boolean>
    readonly parents: readonly unknown[]
  }[]
}

type CedarAuthorizeCommandOptions = {
  readonly binaryPath: string
  readonly policyPath: string
  readonly entitiesPath: string
  readonly requestPath: string
  readonly requestPayload: string
  readonly entitiesPayload: string
  readonly timeoutMs: number
}

type CedarAuthorizeCommandResult = {
  readonly exitCode: number | null
  readonly stdout: string
  readonly stderr: string
}

const currentDirectory = path.dirname(fileURLToPath(import.meta.url))
const defaultPolicyPath = path.resolve(currentDirectory, "../policies/default.cedar")
const defaultPolicySource = `permit (
  principal,
  action,
  resource
)
when {
  resource.credential_access == false
  && (resource.path == "" || resource.workspace_path == "/workspace")
};`

/**
 * The workspace the shipped policy confines file operations to.
 *
 * It is a constant rather than configuration because the same value is compared here, in the
 * Cedar policy text, and by the built-in evaluator that mirrors it. Three copies of one setting
 * would be three places to forget.
 *
 * The constraint applies only when the resource has a path. A network call carries a `url` and no
 * `path`, and a filesystem boundary is not the right test for it — constraining those to a
 * directory denied every outbound call in the v2 runtime suite.
 */
const defaultWorkspacePath = "/workspace"
const permitAllPolicySource = "permit(principal, action, resource);"
const denyAllPolicySource = "forbid(principal, action, resource);"

export const buildCedarAuthorizeInput = (context: ToolCallContext): CedarAuthorizeInput => {
  const resourcePath = String(context.resource["path"] ?? "")
  const credentialAccess = context.normalized.credential_access

  // The workspace the command will actually be mounted with. This was previously invisible to
  // policy: the executor bound it into the command digest, so a token could not change it after
  // authorization, but nothing stopped an authorizer from approving a command against one
  // resource path while the caller bound an unrelated host directory.
  //
  // Derived through `commandFromRequest` so it is the same value the digest covers. Two separate
  // derivations would be free to disagree, and a disagreement here is exactly the hole the digest
  // closes elsewhere.
  const workspacePath = commandFromRequest(context).workspacePath

  return {
    request: {
      principal: `Agent::"${context.agent.id}"`,
      action: `Action::"${context.tool.operation}"`,
      resource: `File::"${resourcePath}"`,
      context: {},
    },
    entities: [
      {
        uid: {
          type: "Agent",
          id: context.agent.id,
        },
        attrs: {},
        parents: [],
      },
      {
        uid: {
          type: "Action",
          id: context.tool.operation,
        },
        attrs: {},
        parents: [],
      },
      {
        uid: {
          type: "File",
          id: resourcePath,
        },
        attrs: {
          credential_access: credentialAccess,
          path: resourcePath,
          // Additive: a policy that ignores this attribute behaves exactly as before, so no
          // existing policy silently changes meaning.
          workspace_path: workspacePath,
          // Also additive, and for the same reason. These two are what make a read-only grant
          // expressible at all. `policies/templates/mcp-readonly.cedar` has to be able to say
          // "this tool does not mutate", and before this the MCP gateway's mutation and
          // destructive verdicts were computed by `normalizeMcpTool` and then dropped — never
          // reaching the policy engine. The template shipped inert for that reason: it named an
          // action the gateway never produces and could not have consulted the mutation flag
          // even if it had.
          //
          // Absent reads as `true`, not `false`. Both fields are optional in the request schema,
          // and defaulting an unknown mutation status to "does not mutate" would fail OPEN: a
          // policy testing `resource.mutation == false` would permit a call whose mutation
          // status nobody determined. Cedar also declines to decide on a missing attribute, so
          // omitting them would make such a policy permit nothing at all. Reading them as
          // mutating is the direction that denies.
          mutation: context.normalized.mutation ?? true,
          destructive: context.normalized.destructive ?? true,
        },
        parents: [],
      },
    ],
  }
}

export class CedarCliProvider implements CedarProvider {
  readonly #binaryPath: string
  readonly #policyPath: string
  readonly #timeoutMs: number
  readonly #maxAttempts: number
  readonly #authorizeCommand: (
    options: CedarAuthorizeCommandOptions,
  ) => Promise<CedarAuthorizeCommandResult>
  #activePolicySource?: string

  constructor(options: CedarCliProviderOptions = {}) {
    this.#binaryPath = options.binaryPath ?? "cedar"
    this.#policyPath = options.policyPath ?? defaultPolicyPath
    this.#timeoutMs = options.timeoutMs ?? 1_000
    this.#maxAttempts = Math.max(1, options.maxAttempts ?? 3)
    this.#authorizeCommand = options.authorizeCommand ?? runAuthorizeCommand
  }

  reloadPolicy(newPolicyContent: string): void {
    this.#activePolicySource = newPolicyContent
  }

  async evaluate(context: ToolCallContext): Promise<CedarDecision> {
    const policySource = this.#activePolicySource ?? await readFile(this.#policyPath, "utf8")
    const builtInDecision = evaluateBuiltInPolicy(policySource, context)
    if (builtInDecision !== undefined) {
      return builtInDecision
    }

    const workingDirectory = await mkdtemp(path.join(tmpdir(), "cedar-cli-"))

    try {
      const dynamicPolicyPath = path.join(workingDirectory, "policies.cedar")
      const requestPath = path.join(workingDirectory, "request.json")
      const entitiesPath = path.join(workingDirectory, "entities.json")
      const authorizeInput = buildCedarAuthorizeInput(context)
      const requestPayload = JSON.stringify(authorizeInput.request)
      const entitiesPayload = JSON.stringify(authorizeInput.entities)

      await writeFile(dynamicPolicyPath, policySource, "utf8")
      await writeFile(requestPath, requestPayload, "utf8")
      await writeFile(entitiesPath, entitiesPayload, "utf8")

      const output = await this.#runAuthorize(
        dynamicPolicyPath,
        requestPath,
        entitiesPath,
        requestPayload,
        entitiesPayload,
      )
      return {
        decision: output.decision === "ALLOW" ? "permit" : "forbid",
        ...(output.reasonCode !== undefined ? { reasonCode: output.reasonCode } : {})
      } as CedarDecision
    } finally {
      await rm(workingDirectory, { recursive: true, force: true })
    }
  }

  async #runAuthorize(
    dynamicPolicyPath: string,
    requestPath: string,
    entitiesPath: string,
    requestPayload: string,
    entitiesPayload: string,
  ): Promise<CedarAuthorizeResponse> {
    let lastFailure: Error | undefined

    for (let attempt = 0; attempt < this.#maxAttempts; attempt += 1) {
      const result = await this.#authorizeCommand({
        binaryPath: this.#binaryPath,
        policyPath: dynamicPolicyPath,
        entitiesPath,
        requestPath,
        requestPayload,
        entitiesPayload,
        timeoutMs: this.#timeoutMs,
      })

      if (result.exitCode !== 0) {
        // cedar-policy-cli exits 2 for a Deny as well as for a genuine evaluator error, so a
        // non-zero code alone does not mean the policy failed to run. Measured against
        // cedar-policy-cli 4.13.0: Allow exits 0, Deny exits 2 with "DENY" on stdout and an
        // empty stderr.
        //
        // Treating that as a failure made every policy denial that reached the CLI surface as an
        // exception instead of a decision. It went unnoticed because `evaluateBuiltInPolicy`
        // answers the two known policies in-process, so no shipped policy ever reached the CLI
        // to be denied.
        //
        // Only a bare DENY is honoured on a non-zero exit. An ALLOW with a non-zero code is
        // refused, and a DENY carrying a diagnostic stays a failure, so neither an error nor a
        // retryable recursion limit can be mistaken for a decision.
        const decided = parseAuthorizeDecision(result.stdout)

        if (
          decided !== undefined &&
          decided.decision === "DENY" &&
          !carriesDiagnostic(result)
        ) {
          return decided
        }

        lastFailure = createAuthorizeFailure({
          exitCode: result.exitCode,
          stdout: result.stdout,
          stderr: result.stderr,
          binaryPath: this.#binaryPath,
          policyPath: this.#policyPath,
          entitiesPath,
          requestPath,
          requestPayload,
          entitiesPayload,
        })

        if (
          attempt + 1 < this.#maxAttempts &&
          isTransientRecursionFailure(result)
        ) {
          continue
        }

        throw lastFailure
      }

      const parsedDecision = parseAuthorizeDecision(result.stdout)
      if (parsedDecision !== undefined) {
        return parsedDecision
      }

      throw new Error(`unexpected cedar output: ${result.stdout.trim()}`)
    }

    throw lastFailure ?? new Error("cedar authorize failed without an error payload")
  }
}

const parseAuthorizeDecision = (
  stdout: string,
): CedarAuthorizeResponse | undefined => {
  const trimmed = stdout.trim()
  const lines = trimmed.split(/\r?\n/u).map(line => line.trim())
  const firstLine = lines.find(line => line.length > 0)
  
  let decision: "ALLOW" | "DENY" | undefined
  if (firstLine === "Allow" || firstLine === "ALLOW") decision = "ALLOW"
  if (firstLine === "Deny" || firstLine === "DENY") decision = "DENY"
  
  if (!decision) {
    if (trimmed === "ALLOW" || trimmed === "DENY") {
       return { decision: trimmed as "ALLOW" | "DENY" }
    }
    if (trimmed === "Allow" || trimmed === "Deny") {
       return { decision: trimmed === "Allow" ? "ALLOW" : "DENY" }
    }
    return undefined
  }

  let reasonCode: string | undefined
  const noteIndex = lines.findIndex(line => line.startsWith("note: this decision was due to the following policies:"))
  if (noteIndex !== -1 && noteIndex + 1 < lines.length) {
    const nextLine = lines[noteIndex + 1]
    if (nextLine !== undefined) {
      reasonCode = nextLine.trim()
    }
  }

  return {
    decision,
    ...(reasonCode !== undefined ? { reasonCode } : {})
  } as CedarAuthorizeResponse
}

const normalizePolicySource = (source: string): string =>
  source.trim().replaceAll("\r\n", "\n")

const normalizePolicyShape = (source: string): string =>
  normalizePolicySource(source).replaceAll(/\s+/g, "")

const evaluateBuiltInPolicy = (
  source: string,
  context: ToolCallContext,
): CedarDecision | undefined => {
  const normalizedSource = normalizePolicyShape(source)

  if (normalizedSource === normalizePolicyShape(defaultPolicySource)) {
    // Mirrors the shipped policy term for term. `builtInMatchesCedar` in the test file runs the
    // same contexts through the real CLI and fails if these two ever disagree, which is the only
    // reason it is safe to answer the shipped policy without the binary at all.
    if (context.normalized.credential_access) {
      return { decision: "forbid" }
    }

    // `resource.path == ""` is the network-call shape: no path to confine to a workspace.
    const { path: resourcePath } = context.resource
    if (typeof resourcePath !== "string" || resourcePath.length === 0) {
      return { decision: "permit" }
    }

    const { workspacePath } = commandFromRequest(context)

    return { decision: workspacePath === defaultWorkspacePath ? "permit" : "forbid" }
  }

  if (normalizedSource === normalizePolicyShape(permitAllPolicySource)) {
    return { decision: "permit" }
  }

  if (normalizedSource === normalizePolicyShape(denyAllPolicySource)) {
    return { decision: "forbid" }
  }

  return undefined
}

/**
 * Whether a non-zero cedar run carries a diagnostic rather than a decision.
 *
 * cedar-policy-cli prints its decision as the first line and, when it also fails, appends the
 * reason — a `×`-marked diagnostic or an "error while evaluating" line. Measured against
 * cedar-policy-cli 4.13.0: Allow exits 0 with `ALLOW`; Deny exits 2 with a bare `DENY`; a parse
 * error exits 1 with a `× failed to parse policy set`; a missing policy file exits 1 with
 * `× failed to open policy set file`. A bare `DENY` is therefore a decision, while a `DENY`
 * followed by a diagnostic is a failure that happens to start with the same word.
 */
const carriesDiagnostic = (result: CedarAuthorizeCommandResult): boolean => {
  if (result.stderr.trim().length > 0) {
    return true
  }

  return result.stdout
    .split(/\r?\n/u)
    .some(line => /^\s*[×x]\s/u.test(line) || line.includes("error while evaluating"))
}

const isTransientRecursionFailure = (
  result: CedarAuthorizeCommandResult,
): boolean =>
  result.exitCode !== 0 &&
  [result.stdout, result.stderr]
    .join("\n")
    .toLowerCase()
    .includes("recursion limit reached")

const createAuthorizeFailure = (options: {
  readonly exitCode: number | null
  readonly stdout: string
  readonly stderr: string
  readonly binaryPath: string
  readonly policyPath: string
  readonly entitiesPath: string
  readonly requestPath: string
  readonly requestPayload: string
  readonly entitiesPayload: string
}): Error => {
  const detail = options.stderr.trim()
  const stdoutDetail = options.stdout.trim()
  const command = [
    options.binaryPath,
    "authorize",
    "--policies",
    options.policyPath,
    "--entities",
    options.entitiesPath,
    "--request-json",
    options.requestPath,
  ].join(" ")

  return new Error(
    [
      `cedar exited with code ${String(options.exitCode)}`,
      `command: ${command}`,
      `stderr: ${detail.length > 0 ? detail : "<empty>"}`,
      `stdout: ${stdoutDetail.length > 0 ? stdoutDetail : "<empty>"}`,
      `request: ${options.requestPayload}`,
      `entities: ${options.entitiesPayload}`,
    ].join("\n"),
  )
}

const runAuthorizeCommand = async (
  options: CedarAuthorizeCommandOptions,
): Promise<CedarAuthorizeCommandResult> =>
  new Promise((resolve, reject) => {
    const child = spawn(
      options.binaryPath,
      [
        "authorize",
        "--policies",
        options.policyPath,
        "--entities",
        options.entitiesPath,
        "--request-json",
        options.requestPath,
      ],
      {
        stdio: ["ignore", "pipe", "pipe"],
      },
    )

    let stdout = ""
    let stderr = ""

    const timer = setTimeout(() => {
      child.kill()
      reject(new Error("cedar authorize timed out"))
    }, options.timeoutMs)

    child.stdout.on("data", (chunk: Buffer) => {
      stdout += chunk.toString("utf8")
    })

    child.stderr.on("data", (chunk: Buffer) => {
      stderr += chunk.toString("utf8")
    })

    child.on("error", (error) => {
      clearTimeout(timer)
      reject(error)
    })

    child.on("close", (exitCode) => {
      clearTimeout(timer)
      resolve({
        exitCode,
        stdout,
        stderr,
      })
    })
  })
