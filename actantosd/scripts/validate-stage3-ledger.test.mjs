import assert from "node:assert/strict"
import { mkdtemp, readFile, writeFile } from "node:fs/promises"
import { tmpdir } from "node:os"
import { join } from "node:path"
import { test } from "node:test"

import { validateStage3Ledger } from "./validate-stage3-ledger.mjs"

const productRoot = new URL("../", import.meta.url)

test("Stage 2 inventory remains characterized when Stage 3 ledger is introduced", async () => {
  // Given: the shipped Stage 2 inventory
  const inventory = await readFile(new URL("../../docs/STAGE2_INVENTORY.md", import.meta.url), "utf8")

  // When: its stable capability IDs are inspected
  const capabilityIds = [...inventory.matchAll(/\*\*(S2-[1-5])\*\*/g)].map((match) => match[1])

  // Then: all five shipped capabilities remain represented exactly once
  assert.deepEqual(capabilityIds, ["S2-1", "S2-2", "S2-3", "S2-4", "S2-5"])
})

test("Stage 3 ledger is valid when all capabilities are future and aggregate is active", async () => {
  // Given: the product-owned Stage 3 ledger
  const input = await readFile(new URL("../stage3-capabilities.json", import.meta.url), "utf8")

  // When: the ledger is validated
  const result = validateStage3Ledger(input)

  // Then: it reports the derived active aggregate
  assert.deepEqual(result, { aggregateStatus: "active", capabilityCount: 5 })
})

test("Stage 3 ledger rejects aggregate done when any capability is incomplete", () => {
  // Given: a syntactically complete ledger with a misleading aggregate
  const doneEvidence = { tests: ["test"], manualQa: ["qa"], documentation: ["doc"] }
  const futureEvidence = { tests: [], manualQa: [], documentation: [] }
  const input = JSON.stringify({
    schemaVersion: 1,
    stage: "stage3-governed-enterprise-autonomy",
    aggregateStatus: "done",
    capabilities: [
      { id: "foundation", status: "done", evidence: doneEvidence },
      { id: "isolation", status: "active", evidence: futureEvidence },
      { id: "credentials", status: "done", evidence: doneEvidence },
      { id: "evidence", status: "done", evidence: doneEvidence },
      { id: "siem", status: "done", evidence: doneEvidence },
    ],
  })

  // When / Then: validation rejects the stale aggregate
  assert.throws(() => validateStage3Ledger(input), /aggregateStatus must be active/)
})

test("Stage 3 ledger rejects malformed input and missing stable IDs", () => {
  // Given: malformed JSON and a ledger missing the SIEM capability
  const malformed = "{"
  const incomplete = JSON.stringify({
    schemaVersion: 1,
    stage: "stage3-governed-enterprise-autonomy",
    aggregateStatus: "active",
    capabilities: [],
  })

  // When / Then: both inputs fail at the trust boundary
  assert.throws(() => validateStage3Ledger(malformed), /valid JSON/)
  assert.throws(() => validateStage3Ledger(incomplete), /exactly five capabilities/)
})

test("Stage 3 ledger file can be validated through the CLI", async () => {
  // Given: a temporary copy of the product ledger
  const directory = await mkdtemp(join(tmpdir(), "actantos-stage3-ledger-"))
  const ledger = await readFile(new URL("../stage3-capabilities.json", import.meta.url), "utf8")
  const ledgerPath = join(directory, "ledger.json")
  await writeFile(ledgerPath, ledger)

  // When: the CLI is invoked through its exported boundary
  const { run } = await import("./validate-stage3-ledger.mjs")
  const result = await run([ledgerPath], productRoot)

  // Then: it reports truthful success
  assert.equal(result, "Stage 3 ledger valid: 5 capabilities, aggregate active")
})
