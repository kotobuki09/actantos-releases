import { spawnSync } from "node:child_process"

import { CedarCliProvider } from "./cedar-cli-provider.ts"
import { FakeCedarProvider, type CedarProvider } from "./fake-cedar-provider.ts"

/** Runtime evaluator profile. Production must never silently use FakeCedar. */
export type EvaluatorMode = "production" | "development" | "test"

export class AuthoritativeEvaluatorUnavailableError extends Error {
  readonly mode: EvaluatorMode
  readonly binaryPath: string

  constructor(message: string, mode: EvaluatorMode, binaryPath: string) {
    super(message)
    this.name = "AuthoritativeEvaluatorUnavailableError"
    this.mode = mode
    this.binaryPath = binaryPath
  }
}

type CreateConfiguredCedarProviderOptions = {
  readonly probeBinary?: (binaryPath: string) => boolean
  /** Override env-derived mode (tests). */
  readonly mode?: EvaluatorMode
}

type RunCheckParseOptions = {
  readonly binaryPath: string
  readonly sourceText: string
}

type RunCheckParseResult = {
  readonly status: number | null
  readonly stdout: string
  readonly stderr: string
}

export type CedarPolicyValidationResult =
  | { readonly ok: true }
  | { readonly ok: false; readonly message: string }

export type CedarPolicyValidator = (
  sourceText: string,
) => Promise<CedarPolicyValidationResult>

type CreateConfiguredCedarPolicyValidatorOptions = {
  readonly probeBinary?: (binaryPath: string) => boolean
  readonly runCheckParse?: (options: RunCheckParseOptions) => RunCheckParseResult
  readonly mode?: EvaluatorMode
}

/**
 * Resolve evaluator mode from environment.
 * - ACTANTOS_EVALUATOR_MODE=production|development|test (highest priority)
 * - ACTANTOS_REQUIRE_CEDAR=1|true forces production
 * - NODE_ENV=production → production; NODE_ENV=test → test; else development
 */
export const resolveEvaluatorMode = (
  env: NodeJS.ProcessEnv = process.env,
): EvaluatorMode => {
  const explicit = env["ACTANTOS_EVALUATOR_MODE"]?.trim().toLowerCase()
  if (explicit === "production" || explicit === "development" || explicit === "test") {
    return explicit
  }

  const requireCedar = env["ACTANTOS_REQUIRE_CEDAR"]?.trim().toLowerCase()
  if (requireCedar === "1" || requireCedar === "true" || requireCedar === "yes") {
    return "production"
  }

  if (env["NODE_ENV"] === "production") {
    return "production"
  }
  if (env["NODE_ENV"] === "test") {
    return "test"
  }
  return "development"
}

const requiresAuthoritativeEvaluator = (mode: EvaluatorMode): boolean =>
  mode === "production"

const canUseBinary = (binaryPath: string): boolean => {
  const result = spawnSync(binaryPath, ["--version"], {
    stdio: "ignore",
    timeout: 1_000,
  })

  return result.status === 0
}

const runCheckParse = (
  options: RunCheckParseOptions,
): RunCheckParseResult => {
  const result = spawnSync(
    options.binaryPath,
    ["check-parse", "--error-format", "plain"],
    {
      encoding: "utf8",
      input: options.sourceText,
      timeout: 1_000,
    },
  )

  return {
    status: result.status,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  }
}

const summarizeParseFailure = (output: RunCheckParseResult): string => {
  const detail = [output.stderr, output.stdout]
    .join("\n")
    .split(/\r?\n/u)
    .map((line) => line.trim())
    .find((line) => line.length > 0)

  return detail ?? "cedar could not parse the supplied policy source"
}

export const createConfiguredCedarProvider = (
  options: CreateConfiguredCedarProviderOptions = {},
): CedarProvider => {
  const binaryPath = process.env["CEDAR_CLI_PATH"]?.trim() || "cedar"
  const policyPath = process.env["CEDAR_POLICY_PATH"]?.trim()
  const probeBinary = options.probeBinary ?? canUseBinary
  const mode = options.mode ?? resolveEvaluatorMode()

  if (!probeBinary(binaryPath)) {
    if (requiresAuthoritativeEvaluator(mode)) {
      throw new AuthoritativeEvaluatorUnavailableError(
        `Authoritative Cedar evaluator unavailable (mode=${mode}, binary=${binaryPath}). Refusing FakeCedar silent fallback.`,
        mode,
        binaryPath,
      )
    }
    // development/test only — explicit non-production FakeCedar
    return new FakeCedarProvider()
  }

  return new CedarCliProvider({
    binaryPath,
    ...(policyPath === undefined || policyPath.length === 0 ? {} : { policyPath }),
  })
}

export const createConfiguredCedarPolicyValidator = (
  options: CreateConfiguredCedarPolicyValidatorOptions = {},
): CedarPolicyValidator => {
  const binaryPath = process.env["CEDAR_CLI_PATH"]?.trim() || "cedar"
  const probeBinary = options.probeBinary ?? canUseBinary
  const parseChecker = options.runCheckParse ?? runCheckParse
  const mode = options.mode ?? resolveEvaluatorMode()

  if (!probeBinary(binaryPath)) {
    if (requiresAuthoritativeEvaluator(mode)) {
      return async () => ({
        ok: false,
        message: `Authoritative Cedar policy validator unavailable (mode=${mode}, binary=${binaryPath})`,
      })
    }
    // development/test: skip parse validation when cedar missing (local DX only)
    return async () => ({ ok: true })
  }

  return async (sourceText) => {
    const result = parseChecker({ binaryPath, sourceText })
    if (result.status === 0) {
      return { ok: true }
    }

    return {
      ok: false,
      message: summarizeParseFailure(result),
    }
  }
}
