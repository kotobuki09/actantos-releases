import { readFile } from "node:fs/promises"
import path from "node:path"
import { fileURLToPath } from "node:url"

import { riskRulesSchema, type RiskEvaluation, type RiskRule, type ToolCallContext } from "./contracts.ts"
import type { Database } from "./database.ts"

const currentDirectory = path.dirname(fileURLToPath(import.meta.url))
const defaultRiskRulesPath = path.resolve(currentDirectory, "../policies/risk_rules.json")

type RiskRuleSetRow = {
  readonly rules_json: unknown
}

type RiskEngineOptions = {
  readonly database: Database | undefined
  readonly rulesPath: string | undefined
}

const loadRulesFromFile = async (rulesPath: string): Promise<readonly RiskRule[]> => {
  const raw = await readFile(rulesPath, "utf8")
  return riskRulesSchema.parse(JSON.parse(raw))
}

export const loadDefaultRiskRules = async (
  rulesPath: string = defaultRiskRulesPath,
): Promise<readonly RiskRule[]> => loadRulesFromFile(rulesPath)

/**
 * Resolve a dotted path like "normalized.command_family" from context.
 * Returns undefined if any segment is missing.
 */
const resolveContextPath = (context: ToolCallContext, dotPath: string): unknown => {
  const parts = dotPath.split(".")
  let current: unknown = context

  for (const part of parts) {
    if (current === null || current === undefined || typeof current !== "object") {
      return undefined
    }
    current = (current as Record<string, unknown>)[part]
  }

  return current
}

/**
 * Evaluate whether a single rule matches the context.
 * All conditions in rule.when must match (AND semantics).
 */
const matchesRule = (rule: RiskRule, context: ToolCallContext): boolean => {
  for (const [dotPath, expectedValue] of Object.entries(rule.when)) {
    const actual = resolveContextPath(context, dotPath)
    if (actual !== expectedValue) {
      return false
    }
  }
  return true
}

export class RiskEngine {
  readonly #database: Database | undefined
  readonly #rulesPath: string
  #fileRulesCache?: readonly RiskRule[]

  constructor(options: RiskEngineOptions = { database: undefined, rulesPath: undefined }) {
    this.#database = options.database
    this.#rulesPath = options.rulesPath ?? defaultRiskRulesPath
  }

  async #loadDefaultRules(): Promise<readonly RiskRule[]> {
    if (this.#fileRulesCache !== undefined) {
      return this.#fileRulesCache
    }

    const rules = await loadDefaultRiskRules(this.#rulesPath)
    this.#fileRulesCache = rules
    return rules
  }

  async #loadRules(tenantId: string): Promise<readonly RiskRule[]> {
    if (this.#database === undefined) {
      return this.#loadDefaultRules()
    }

    const rows = await this.#database.query<RiskRuleSetRow>(
      `
        SELECT rules_json
        FROM risk_rule_sets
        WHERE tenant_id = $1
      `,
      [tenantId],
    )

    const storedRuleSet = rows[0]
    if (storedRuleSet === undefined) {
      return this.#loadDefaultRules()
    }

    return riskRulesSchema.parse(storedRuleSet.rules_json)
  }

  async evaluate(context: ToolCallContext): Promise<RiskEvaluation> {
    const rules = await this.#loadRules(context.tenant_id)

    for (const rule of rules) {
      if (matchesRule(rule, context)) {
        return {
          approval_required: rule.approval_required,
          risk_class: rule.risk_class,
          matched_rule_id: rule.rule_id,
        }
      }
    }

    // No rule matched — low risk, no approval
    return {
      approval_required: false,
      risk_class: "low",
    }
  }
}
