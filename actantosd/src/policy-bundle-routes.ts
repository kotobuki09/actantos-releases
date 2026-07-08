import { randomUUID } from "node:crypto"

import type { FastifyInstance, FastifyReply } from "fastify"
import { z, ZodError } from "zod"

import type { CedarPolicyValidator } from "./cedar-provider.ts"
import type { Database } from "./database.ts"
import { sha256 } from "./hash.ts"
import { registerPolicyDashboardRoutes } from "./policy-dashboard-routes.ts"

const policyBundlesQuerySchema = z.object({
  tenant_id: z.string().min(1).optional().default("t_demo"),
})

const createPolicyBundleBodySchema = z.object({
  tenant_id: z.string().min(1).optional().default("t_demo"),
  version: z.string().min(1),
  engine: z.literal("cedar").optional().default("cedar"),
  source_text: z.string().min(1),
  active: z.boolean().optional().default(false),
})

type PolicyBundleRow = {
  readonly id: string
  readonly tenant_id: string
  readonly version: string
  readonly engine: string
  readonly source_hash: string
  readonly source_text: string
  readonly active: boolean
  readonly created_at: string | Date
}

const serializePolicyBundleSummary = (row: PolicyBundleRow) => ({
  id: row.id,
  tenant_id: row.tenant_id,
  version: row.version,
  engine: row.engine,
  source_hash: row.source_hash,
  active: row.active,
  created_at: new Date(row.created_at).toISOString(),
})

const serializePolicyBundle = (row: PolicyBundleRow) => ({
  ...serializePolicyBundleSummary(row),
  source_text: row.source_text,
})

export const registerPolicyBundleRoutes = (
  server: FastifyInstance,
  options: {
    readonly database: Database
    readonly policyValidator: CedarPolicyValidator
  },
): void => {
  registerPolicyDashboardRoutes(server, { database: options.database })

  const activatePolicyBundle = async (
    policyBundleId: string,
    reply: FastifyReply,
  ) => {
    const policyBundleRows = await options.database.query<PolicyBundleRow>(
      `
        SELECT id,
               tenant_id,
               version,
               engine,
               source_hash,
               source_text,
               active,
               created_at
        FROM policy_bundles
        WHERE id = $1
      `,
      [policyBundleId],
    )

    const policyBundle = policyBundleRows[0]
    if (policyBundle === undefined) {
      return reply.code(404).send({ error: "not_found", message: "policy bundle not found" })
    }

    const validation = await options.policyValidator(policyBundle.source_text)
    if (!validation.ok) {
      return reply.code(400).send({
        error: "invalid_policy_bundle",
        message: "policy bundle source failed Cedar syntax validation",
        detail: validation.message,
      })
    }

    const activatedRows = await options.database.transaction(async (client) => {
      await client.query(
        `
          UPDATE policy_bundles
          SET active = false
          WHERE tenant_id = $1
            AND active = true
        `,
        [policyBundle.tenant_id],
      )

      return client.query<PolicyBundleRow>(
        `
          UPDATE policy_bundles
          SET active = true
          WHERE id = $1
          RETURNING id,
                    tenant_id,
                    version,
                    engine,
                    source_hash,
                    source_text,
                    active,
                    created_at
        `,
        [policyBundle.id],
      )
    })

    const activatedPolicyBundle = activatedRows[0]
    if (activatedPolicyBundle === undefined) {
      throw new Error("policy bundle activation returned no row")
    }

    return reply.code(200).send({ policy_bundle: serializePolicyBundle(activatedPolicyBundle) })
  }

  server.get("/v1/policy-bundles", async (request, reply) => {
    try {
      const query = policyBundlesQuerySchema.parse(request.query)
      const rows = await options.database.query<PolicyBundleRow>(
        `
          SELECT id,
                 tenant_id,
                 version,
                 engine,
                 source_hash,
                 source_text,
                 active,
                 created_at
          FROM policy_bundles
          WHERE tenant_id = $1
          ORDER BY active DESC, created_at DESC
        `,
        [query.tenant_id],
      )

      return reply.code(200).send({
        tenant_id: query.tenant_id,
        policy_bundles: rows.map(serializePolicyBundleSummary),
      })
    } catch (error) {
      if (error instanceof ZodError) {
        return reply.code(400).send({ error: "invalid_request", issues: error.issues })
      }
      throw error
    }
  })

  server.get<{ Params: { id: string } }>(
    "/v1/policy-bundles/:id",
    async (request, reply) => {
      const rows = await options.database.query<PolicyBundleRow>(
        `
          SELECT id,
                 tenant_id,
                 version,
                 engine,
                 source_hash,
                 source_text,
                 active,
                 created_at
          FROM policy_bundles
          WHERE id = $1
        `,
        [request.params.id],
      )

      const policyBundle = rows[0]
      if (policyBundle === undefined) {
        return reply.code(404).send({ error: "not_found", message: "policy bundle not found" })
      }

      return reply.code(200).send({ policy_bundle: serializePolicyBundle(policyBundle) })
    },
  )

  server.post("/v1/policy-bundles", async (request, reply) => {
    try {
      const body = createPolicyBundleBodySchema.parse(request.body)
      const validation = await options.policyValidator(body.source_text)
      if (!validation.ok) {
        return reply.code(400).send({
          error: "invalid_policy_bundle",
          message: "policy bundle source failed Cedar syntax validation",
          detail: validation.message,
        })
      }

      const policyBundleId = randomUUID()
      const sourceHash = sha256(body.source_text)

      const rows = await options.database.transaction(async (client) => {
        if (body.active) {
          await client.query(
            `
              UPDATE policy_bundles
              SET active = false
              WHERE tenant_id = $1
                AND active = true
            `,
            [body.tenant_id],
          )
        }

        return client.query<PolicyBundleRow>(
          `
            INSERT INTO policy_bundles (
              id,
              tenant_id,
              version,
              engine,
              source_hash,
              source_text,
              active
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7)
            RETURNING id,
                      tenant_id,
                      version,
                      engine,
                      source_hash,
                      source_text,
                      active,
                      created_at
          `,
          [
            policyBundleId,
            body.tenant_id,
            body.version,
            body.engine,
            sourceHash,
            body.source_text,
            body.active,
          ],
        )
      })

      const policyBundle = rows[0]
      if (policyBundle === undefined) {
        throw new Error("policy bundle insert returned no row")
      }

      return reply.code(201).send({ policy_bundle: serializePolicyBundle(policyBundle) })
    } catch (error) {
      if (error instanceof ZodError) {
        return reply.code(400).send({ error: "invalid_request", issues: error.issues })
      }
      throw error
    }
  })

  server.post<{ Params: { id: string } }>(
    "/v1/policy-bundles/:id/activate",
    async (request, reply) => activatePolicyBundle(request.params.id, reply),
  )
}
