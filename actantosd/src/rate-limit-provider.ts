import type { RiskEvaluation } from "./contracts.ts"
import type { Database } from "./database.ts"

export type RateLimitCheck = {
  readonly allowed: boolean
}

export type RateLimitCheckParams = {
  readonly tenantId: string
  readonly agentId: string
  readonly sessionId: string
  readonly toolName: string
  readonly risk: RiskEvaluation
  readonly consume: boolean
}

export interface RateLimitProvider {
  checkAndConsume(params: RateLimitCheckParams): Promise<RateLimitCheck>
}

type RateLimitRow = {
  readonly id: string
  readonly current_value: number | string
  readonly limit_value: number | string
  readonly window_seconds: number
  readonly window_start: Date | string
}

type PreparedRateLimit = {
  readonly id: string
  readonly currentValue: number
  readonly limitValue: number
  readonly expired: boolean
}

const toInteger = (value: number | string): number =>
  typeof value === "number" ? value : Number.parseInt(value, 10)

const buildActionKey = (risk: RiskEvaluation): string | undefined => {
  if (
    !risk.approval_required &&
    risk.risk_class !== "high" &&
    risk.risk_class !== "critical"
  ) {
    return undefined
  }

  return risk.matched_rule_id
}

export class AllowAllRateLimitProvider implements RateLimitProvider {
  async checkAndConsume(): Promise<RateLimitCheck> {
    return { allowed: true }
  }
}

export class PostgresRateLimitProvider implements RateLimitProvider {
  readonly #database: Database

  constructor(database: Database) {
    this.#database = database
  }

  async checkAndConsume(params: RateLimitCheckParams): Promise<RateLimitCheck> {
    const actionKey = buildActionKey(params.risk)

    if (actionKey === undefined) {
      return { allowed: true }
    }

    return this.#database.transaction(async (client) => {
      const rows = await client.query<RateLimitRow>(
        `
          SELECT id, current_value, limit_value, window_seconds, window_start
          FROM rate_limits
          WHERE tenant_id = $1
            AND action_key = $5
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
        [params.tenantId, params.agentId, params.sessionId, params.toolName, actionKey],
      )

      if (rows.length === 0) {
        return { allowed: true }
      }

      const preparedRateLimits = rows.map((rateLimit): PreparedRateLimit => {
        const windowStart = new Date(rateLimit.window_start)
        const windowExpiresAt = windowStart.getTime() + rateLimit.window_seconds * 1_000

        return {
          id: rateLimit.id,
          currentValue: toInteger(rateLimit.current_value),
          limitValue: toInteger(rateLimit.limit_value),
          expired: windowExpiresAt <= Date.now(),
        }
      })

      const exhaustedRateLimit = preparedRateLimits.find(
        (rateLimit) => !rateLimit.expired && rateLimit.currentValue >= rateLimit.limitValue,
      )

      if (exhaustedRateLimit !== undefined) {
        return { allowed: false }
      }

      if (!params.consume) {
        return { allowed: true }
      }

      for (const rateLimit of preparedRateLimits) {
        if (rateLimit.expired) {
          await client.query(
            "UPDATE rate_limits SET current_value = 1, window_start = now() WHERE id = $1",
            [rateLimit.id],
          )
          continue
        }

        await client.query(
          "UPDATE rate_limits SET current_value = current_value + 1 WHERE id = $1",
          [rateLimit.id],
        )
      }

      return { allowed: true }
    })
  }
}
