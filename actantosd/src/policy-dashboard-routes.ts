import type { FastifyInstance } from "fastify"
import { z } from "zod"

import type { Database } from "./database.ts"
import { renderPolicyDashboardPage, type PolicyBundleRow } from "./policy-dashboard-page.ts"

const policyDashboardQuerySchema = z.object({
  tenant_id: z.string().min(1),
  api_key: z.string().min(1).optional(),
})

export const registerPolicyDashboardRoutes = (
  server: FastifyInstance,
  options: { readonly database: Database },
): void => {
  server.get("/dashboard/policy", async (request, reply) => {
    const query = policyDashboardQuerySchema.parse(request.query)
    const bundles = await options.database.query<PolicyBundleRow>(
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

    return reply
      .code(200)
      .type("text/html; charset=utf-8")
      .send(
        renderPolicyDashboardPage({
          tenantId: query.tenant_id,
          ...(query.api_key === undefined ? {} : { apiKey: query.api_key }),
          bundles,
        }),
      )
  })
}
