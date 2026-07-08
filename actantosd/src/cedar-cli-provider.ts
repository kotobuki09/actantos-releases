import { spawn } from "node:child_process"
import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { fileURLToPath } from "node:url"

import type { ToolCallContext } from "./contracts.ts"
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
};`
const permitAllPolicySource = "permit(principal, action, resource);"
const denyAllPolicySource = "forbid(principal, action, resource);"

export const buildCedarAuthorizeInput = (context: ToolCallContext): CedarAuthorizeInput => {
  const resourcePath = String(context.resource["path"] ?? "")
  const credentialAccess = context.normalized.credential_access

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

  constructor(options: CedarCliProviderOptions = {}) {
    this.#binaryPath = options.binaryPath ?? "cedar"
    this.#policyPath = options.policyPath ?? defaultPolicyPath
    this.#timeoutMs = options.timeoutMs ?? 1_000
    this.#maxAttempts = Math.max(1, options.maxAttempts ?? 3)
    this.#authorizeCommand = options.authorizeCommand ?? runAuthorizeCommand
  }

  async evaluate(context: ToolCallContext): Promise<CedarDecision> {
    const policySource = await readFile(this.#policyPath, "utf8")
    const builtInDecision = evaluateBuiltInPolicy(policySource, context)
    if (builtInDecision !== undefined) {
      return builtInDecision
    }

    const workingDirectory = await mkdtemp(path.join(tmpdir(), "cedar-cli-"))

    try {
      const requestPath = path.join(workingDirectory, "request.json")
      const entitiesPath = path.join(workingDirectory, "entities.json")
      const authorizeInput = buildCedarAuthorizeInput(context)
      const requestPayload = JSON.stringify(authorizeInput.request)
      const entitiesPayload = JSON.stringify(authorizeInput.entities)

      await writeFile(requestPath, requestPayload, "utf8")
      await writeFile(entitiesPath, entitiesPayload, "utf8")

      const output = await this.#runAuthorize(
        requestPath,
        entitiesPath,
        requestPayload,
        entitiesPayload,
      )
      return output.decision === "ALLOW" ? "permit" : "forbid"
    } finally {
      await rm(workingDirectory, { recursive: true, force: true })
    }
  }

  async #runAuthorize(
    requestPath: string,
    entitiesPath: string,
    requestPayload: string,
    entitiesPayload: string,
  ): Promise<CedarAuthorizeResponse> {
    let lastFailure: Error | undefined

    for (let attempt = 0; attempt < this.#maxAttempts; attempt += 1) {
      const result = await this.#authorizeCommand({
        binaryPath: this.#binaryPath,
        policyPath: this.#policyPath,
        entitiesPath,
        requestPath,
        requestPayload,
        entitiesPayload,
        timeoutMs: this.#timeoutMs,
      })

      if (result.exitCode !== 0) {
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
        return { decision: parsedDecision }
      }

      throw new Error(`unexpected cedar output: ${result.stdout.trim()}`)
    }

    throw lastFailure ?? new Error("cedar authorize failed without an error payload")
  }
}

const parseAuthorizeDecision = (
  stdout: string,
): CedarAuthorizeResponse["decision"] | undefined => {
  const trimmed = stdout.trim()
  const firstLine = trimmed
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .find((line) => line.length > 0)

  if (trimmed === "Allow" || trimmed === "Deny") {
    return trimmed === "Allow" ? "ALLOW" : "DENY"
  }

  if (trimmed === "ALLOW" || trimmed === "DENY") {
    return trimmed
  }

  if (firstLine === "Allow" || firstLine === "Deny") {
    return firstLine === "Allow" ? "ALLOW" : "DENY"
  }

  if (firstLine === "ALLOW" || firstLine === "DENY") {
    return firstLine
  }

  return undefined
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
    return context.normalized.credential_access ? "forbid" : "permit"
  }

  if (normalizedSource === normalizePolicyShape(permitAllPolicySource)) {
    return "permit"
  }

  if (normalizedSource === normalizePolicyShape(denyAllPolicySource)) {
    return "forbid"
  }

  return undefined
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
