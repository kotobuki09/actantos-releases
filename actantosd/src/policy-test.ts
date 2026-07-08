import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import path from "node:path"
import { pathToFileURL } from "node:url"

import { CedarCliProvider } from "./cedar-cli-provider.ts"
import {
  createConfiguredCedarPolicyValidator,
} from "./cedar-provider.ts"
import {
  type ToolCallInterceptionRequest,
  toolCallInterceptionRequestSchema,
} from "./contracts.ts"
import { createDatabase, type Database } from "./database.ts"
import { createInterceptService } from "./intercept-service.ts"
import { RiskEngine } from "./risk-engine.ts"
import { InMemoryToolCallRepository } from "./tool-call-repository.ts"

export type PolicyTestCommand = {
  readonly requestFile: string
  readonly tenantId: string
  readonly policyFile?: string
  readonly bundleId?: string
  readonly databaseUrl?: string
}

type PolicyBundleRow = {
  readonly id: string
  readonly version: string
  readonly source_text: string
}

export type PolicyTestPolicySource =
  | { readonly kind: "policy_file"; readonly path: string }
  | { readonly kind: "bundle"; readonly id: string; readonly version: string }
  | { readonly kind: "active_bundle"; readonly id: string; readonly version: string }

export type PolicyTestResult = {
  readonly policySource: PolicyTestPolicySource
  readonly response: Awaited<ReturnType<ReturnType<typeof createInterceptService>["intercept"]>>
}

const requireOptionValue = (
  option: string,
  value: string | undefined,
): string => {
  if (value !== undefined && value.length > 0) {
    return value
  }

  throw new Error(`${option} requires a value`)
}

export const parsePolicyTestCommand = (
  args: readonly string[],
): PolicyTestCommand => {
  let requestFile: string | undefined
  let policyFile: string | undefined
  let bundleId: string | undefined
  let tenantId = "t_demo"
  let databaseUrl: string | undefined

  for (let index = 0; index < args.length; index += 1) {
    const arg = args[index]
    if (arg === "--request-file") {
      requestFile = requireOptionValue(arg, args[index + 1])
      index += 1
      continue
    }
    if (arg === "--policy-file") {
      policyFile = requireOptionValue(arg, args[index + 1])
      index += 1
      continue
    }
    if (arg === "--bundle-id") {
      bundleId = requireOptionValue(arg, args[index + 1])
      index += 1
      continue
    }
    if (arg === "--tenant-id") {
      tenantId = requireOptionValue(arg, args[index + 1])
      index += 1
      continue
    }
    if (arg === "--database-url") {
      databaseUrl = requireOptionValue(arg, args[index + 1])
      index += 1
      continue
    }

    throw new Error(`Unsupported option: ${arg}`)
  }

  if (requestFile === undefined) {
    throw new Error("--request-file is required")
  }
  if (policyFile !== undefined && bundleId !== undefined) {
    throw new Error("--policy-file and --bundle-id are mutually exclusive")
  }

  return {
    requestFile,
    tenantId,
    ...(policyFile === undefined ? {} : { policyFile }),
    ...(bundleId === undefined ? {} : { bundleId }),
    ...(databaseUrl === undefined ? {} : { databaseUrl }),
  }
}

const needsDatabase = (command: PolicyTestCommand): boolean =>
  command.policyFile === undefined || command.bundleId !== undefined

const requireDatabase = (
  command: PolicyTestCommand,
  providedDatabase: Database | undefined,
): Database => {
  if (providedDatabase !== undefined) {
    return providedDatabase
  }

  throw new Error("DATABASE_URL is required when testing the active or stored bundle")
}

const loadRequest = async (requestFile: string): Promise<ToolCallInterceptionRequest> => {
  const raw = await readFile(requestFile, "utf8")
  return toolCallInterceptionRequestSchema.parse(JSON.parse(raw))
}

const loadStoredPolicyBundle = async (
  command: PolicyTestCommand,
  database: Database,
): Promise<PolicyBundleRow | undefined> => {
  if (command.bundleId !== undefined) {
    const bundleRows = await database.query<PolicyBundleRow>(
      `
        SELECT id, version, source_text
        FROM policy_bundles
        WHERE tenant_id = $1
          AND id = $2
      `,
      [command.tenantId, command.bundleId],
    )
    return bundleRows[0]
  }

  const bundleRows = await database.query<PolicyBundleRow>(
    `
      SELECT id, version, source_text
      FROM policy_bundles
      WHERE tenant_id = $1
        AND active = true
      ORDER BY created_at DESC
      LIMIT 1
    `,
    [command.tenantId],
  )
  return bundleRows[0]
}

const validatePolicySource = async (sourceText: string): Promise<void> => {
  const validator = createConfiguredCedarPolicyValidator()
  const validation = await validator(sourceText)
  if (!validation.ok) {
    throw new Error(`policy source failed Cedar validation: ${validation.message}`)
  }
}

const createTemporaryPolicyFile = async (sourceText: string): Promise<string> => {
  const directoryPath = await mkdtemp(path.join(tmpdir(), "actantos-policy-test-"))
  const policyPath = path.join(directoryPath, "candidate.cedar")
  await writeFile(policyPath, sourceText, "utf8")
  return policyPath
}

const formatPolicySource = (policySource: PolicyTestPolicySource): string => {
  if (policySource.kind === "policy_file") {
    return `policy_file ${policySource.path}`
  }

  return `${policySource.kind} ${policySource.id} (${policySource.version})`
}

export const runPolicyTestCommand = async (
  command: PolicyTestCommand,
  options: { readonly database?: Database } = {},
): Promise<PolicyTestResult> => {
  const createdDatabase =
    options.database === undefined && needsDatabase(command)
      ? createDatabase(
          command.databaseUrl ??
            process.env["DATABASE_URL"] ??
            (() => {
              throw new Error("DATABASE_URL is required when testing stored bundles")
            })(),
        )
      : undefined
  const database = options.database ?? createdDatabase
  const request = await loadRequest(command.requestFile)
  let temporaryPolicyDirectory: string | undefined

  try {
    let policyPath: string
    let policySource: PolicyTestPolicySource

    if (command.policyFile !== undefined) {
      policyPath = path.resolve(command.policyFile)
      const sourceText = await readFile(policyPath, "utf8")
      await validatePolicySource(sourceText)
      policySource = { kind: "policy_file", path: policyPath }
    } else {
      const storedBundle = await loadStoredPolicyBundle(
        command,
        requireDatabase(command, database),
      )
      if (storedBundle === undefined) {
        throw new Error("no matching policy bundle found")
      }

      await validatePolicySource(storedBundle.source_text)
      policyPath = await createTemporaryPolicyFile(storedBundle.source_text)
      temporaryPolicyDirectory = path.dirname(policyPath)
      policySource = command.bundleId === undefined
        ? { kind: "active_bundle", id: storedBundle.id, version: storedBundle.version }
        : { kind: "bundle", id: storedBundle.id, version: storedBundle.version }
    }

    const service = createInterceptService({
      repository: new InMemoryToolCallRepository(),
      hmacSecret: "actantos-policy-test",
      cedarProvider: new CedarCliProvider({ policyPath }),
      riskEngine: new RiskEngine({ database, rulesPath: undefined }),
    })
    const response = await service.intercept({
      ...request,
      tenant_id: command.tenantId,
    })

    return { policySource, response }
  } finally {
    if (temporaryPolicyDirectory !== undefined) {
      await rm(temporaryPolicyDirectory, { recursive: true, force: true })
    }
    if (createdDatabase !== undefined) {
      await createdDatabase.close()
    }
  }
}

export const formatPolicyTestResult = (result: PolicyTestResult): string => {
  const lines = [
    `policy_source=${formatPolicySource(result.policySource)}`,
    `decision=${result.response.decision}`,
    `decision_mode=${result.response.decision_mode}`,
    `reason_code=${result.response.reason_code}`,
    `reason=${result.response.reason}`,
  ]

  if (result.response.decision === "approval_required") {
    lines.push(`approval_id=${result.response.approval.approval_id}`)
  }

  return lines.join("\n")
}

const main = async (): Promise<void> => {
  const command = parsePolicyTestCommand(process.argv.slice(2))
  const result = await runPolicyTestCommand(command)
  console.log(formatPolicyTestResult(result))
}

const entrypointPath = process.argv[1]

if (entrypointPath !== undefined && import.meta.url === pathToFileURL(entrypointPath).href) {
  main().catch((error: unknown) => {
    console.error(error)
    process.exitCode = 1
  })
}
