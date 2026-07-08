import type { Database } from "./database.ts"

export type BudgetCheck = {
  readonly allowed: boolean
}

export type BudgetCheckParams = {
  readonly tenantId: string
  readonly agentId: string
  readonly sessionId: string
  readonly toolName: string
  readonly consume?: boolean
}

export interface BudgetProvider {
  checkAndConsume(params: BudgetCheckParams): Promise<BudgetCheck>
}

export class AllowAllBudgetProvider implements BudgetProvider {
  async checkAndConsume(): Promise<BudgetCheck> {
    return { allowed: true }
  }
}

type BudgetRow = {
  readonly id: string
  readonly current_value: number | string
  readonly limit_value: number | string
  readonly window_seconds: number
  readonly window_start: Date | string
}

type PreparedBudget = {
  readonly id: string
  readonly currentValue: number
  readonly limitValue: number
  readonly expired: boolean
}

const toInteger = (value: number | string): number =>
  typeof value === "number" ? value : Number.parseInt(value, 10)

export class PostgresBudgetProvider implements BudgetProvider {
  readonly #database: Database

  constructor(database: Database) {
    this.#database = database
  }

  async checkAndConsume(params: BudgetCheckParams): Promise<BudgetCheck> {
    return this.#database.transaction(async (client) => {
      const rows = await client.query<BudgetRow>(
        `
          SELECT id, current_value, limit_value, window_seconds, window_start
          FROM budgets
          WHERE tenant_id = $1
            AND metric = 'tool_calls'
            AND (
              (scope_type = 'tenant' AND scope_id = $1) OR
              (scope_type = 'agent' AND scope_id = $2) OR
              (scope_type = 'session' AND scope_id = $3) OR
              (scope_type = 'tool' AND scope_id = $4)
            )
          ORDER BY
            CASE scope_type
              WHEN 'tool' THEN 1
              WHEN 'session' THEN 2
              WHEN 'agent' THEN 3
              ELSE 4
            END
          FOR UPDATE
        `,
        [params.tenantId, params.agentId, params.sessionId, params.toolName],
      )

      if (rows.length === 0) {
        return { allowed: true }
      }

      const preparedBudgets = rows.map((budget): PreparedBudget => {
        const windowStart = new Date(budget.window_start)
        const windowExpiresAt = windowStart.getTime() + budget.window_seconds * 1_000

        return {
          id: budget.id,
          currentValue: toInteger(budget.current_value),
          limitValue: toInteger(budget.limit_value),
          expired: windowExpiresAt <= Date.now(),
        }
      })

      const exhaustedBudget = preparedBudgets.find(
        (budget) => !budget.expired && budget.currentValue >= budget.limitValue,
      )

      if (exhaustedBudget !== undefined) {
        return { allowed: false }
      }

      if (params.consume === false) {
        return { allowed: true }
      }

      for (const budget of preparedBudgets) {
        if (budget.expired) {
          await client.query(
            "UPDATE budgets SET current_value = 1, window_start = now() WHERE id = $1",
            [budget.id],
          )
          continue
        }

        await client.query(
          "UPDATE budgets SET current_value = current_value + 1 WHERE id = $1",
          [budget.id],
        )
      }

      return { allowed: true }
    })
  }
}
