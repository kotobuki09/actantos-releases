import { readFile } from "node:fs/promises"
import { isAbsolute } from "node:path"
import { pathToFileURL } from "node:url"

const capabilityIds = ["foundation", "isolation", "credentials", "evidence", "siem"]
const capabilityStatuses = new Set(["future", "active", "done"])
const aggregateStatuses = new Set(["active", "done"])
const evidenceFields = ["tests", "manualQa", "documentation"]

export class Stage3LedgerError extends Error {
  constructor(message) {
    super(message)
    this.name = "Stage3LedgerError"
  }
}

function objectValue(value, field) {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new Stage3LedgerError(`${field} must be an object`)
  }
  return value
}

function stringValue(value, field) {
  if (typeof value !== "string" || value.length === 0) {
    throw new Stage3LedgerError(`${field} must be a non-empty string`)
  }
  return value
}

function stringArray(value, field) {
  if (!Array.isArray(value) || value.some((item) => typeof item !== "string" || item.length === 0)) {
    throw new Stage3LedgerError(`${field} must be an array of non-empty strings`)
  }
  return value
}

function parseCapability(value, index) {
  const capability = objectValue(value, `capabilities[${index}]`)
  const id = stringValue(capability.id, `capabilities[${index}].id`)
  const status = stringValue(capability.status, `capabilities[${index}].status`)
  if (!capabilityStatuses.has(status)) {
    throw new Stage3LedgerError(`capability ${id} has unsupported status ${status}`)
  }
  const evidence = objectValue(capability.evidence, `capability ${id}.evidence`)
  for (const field of evidenceFields) {
    stringArray(evidence[field], `capability ${id}.evidence.${field}`)
  }
  if (status === "done" && evidenceFields.some((field) => evidence[field].length === 0)) {
    throw new Stage3LedgerError(`done capability ${id} requires tests, manualQa, and documentation evidence`)
  }
  return { id, status }
}

export function validateStage3Ledger(input) {
  let parsed
  try {
    parsed = JSON.parse(input)
  } catch (error) {
    if (error instanceof SyntaxError) {
      throw new Stage3LedgerError("ledger must be valid JSON")
    }
    throw error
  }

  const ledger = objectValue(parsed, "ledger")
  if (ledger.schemaVersion !== 1) {
    throw new Stage3LedgerError("schemaVersion must be 1")
  }
  if (ledger.stage !== "stage3-governed-enterprise-autonomy") {
    throw new Stage3LedgerError("stage must be stage3-governed-enterprise-autonomy")
  }
  const aggregateStatus = stringValue(ledger.aggregateStatus, "aggregateStatus")
  if (!aggregateStatuses.has(aggregateStatus)) {
    throw new Stage3LedgerError(`unsupported aggregateStatus ${aggregateStatus}`)
  }
  if (!Array.isArray(ledger.capabilities) || ledger.capabilities.length !== capabilityIds.length) {
    throw new Stage3LedgerError("ledger must contain exactly five capabilities")
  }

  const capabilities = ledger.capabilities.map(parseCapability)
  const actualIds = capabilities.map(({ id }) => id)
  if (new Set(actualIds).size !== capabilityIds.length || capabilityIds.some((id) => !actualIds.includes(id))) {
    throw new Stage3LedgerError(`capability IDs must be exactly: ${capabilityIds.join(", ")}`)
  }

  const derivedAggregate = capabilities.every(({ status }) => status === "done") ? "done" : "active"
  if (aggregateStatus !== derivedAggregate) {
    throw new Stage3LedgerError(`aggregateStatus must be ${derivedAggregate} for the recorded capability states`)
  }
  return { aggregateStatus: derivedAggregate, capabilityCount: capabilities.length }
}

export async function run(arguments_, baseUrl = import.meta.url) {
  if (arguments_.length !== 1) {
    throw new Stage3LedgerError("usage: node scripts/validate-stage3-ledger.mjs <ledger.json>")
  }
  const ledgerUrl = isAbsolute(arguments_[0]) ? pathToFileURL(arguments_[0]) : new URL(arguments_[0], baseUrl)
  const result = validateStage3Ledger(await readFile(ledgerUrl, "utf8"))
  return `Stage 3 ledger valid: ${result.capabilityCount} capabilities, aggregate ${result.aggregateStatus}`
}

if (process.argv[1] !== undefined && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    console.log(await run(process.argv.slice(2), pathToFileURL(`${process.cwd()}/`)))
  } catch (error) {
    // no-excuse-ok: catch -- CLI trust boundary converts validation failures to an exit status.
    console.error(error instanceof Error ? error.message : "unknown Stage 3 ledger validation failure")
    process.exitCode = 1
  }
}
