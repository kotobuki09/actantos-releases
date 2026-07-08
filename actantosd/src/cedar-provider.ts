import { spawnSync } from "node:child_process"

import { CedarCliProvider } from "./cedar-cli-provider.ts"
import { FakeCedarProvider, type CedarProvider } from "./fake-cedar-provider.ts"

type CreateConfiguredCedarProviderOptions = {
  readonly probeBinary?: (binaryPath: string) => boolean
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
}

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

  if (!probeBinary(binaryPath)) {
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

  if (!probeBinary(binaryPath)) {
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
