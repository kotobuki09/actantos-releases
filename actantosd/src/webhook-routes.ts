import { createHmac } from "node:crypto"

import type { FastifyInstance } from "fastify"
import { z, ZodError } from "zod"

import type { Database } from "./database.ts"
import { exportEvidencePackage } from "./evidence-export-routes.ts"

const webhookDeliveryBodySchema = z.object({
  tenant_id: z.string().min(1),
  session_id: z.string().min(1).optional(),
  destination_url: z.string().url(),
})

type RegisterWebhookRoutesOptions = {
  readonly database?: Database
  readonly hmacSecret: string
}

export const registerWebhookRoutes = (
  server: FastifyInstance,
  options: RegisterWebhookRoutesOptions,
): void => {
  server.post("/v1/webhooks/evidence", async (request, reply) => {
    try {
      const body = webhookDeliveryBodySchema.parse(request.body)
      const evidencePackage = await exportEvidencePackage(
        options.database,
        body.tenant_id,
        body.session_id,
      )
      const payload = JSON.stringify({
        event: "evidence.exported",
        tenant_id: body.tenant_id,
        session_id: body.session_id ?? null,
        delivered_at: new Date().toISOString(),
        evidence: evidencePackage,
      })
      const signature = createHmac("sha256", options.hmacSecret).update(payload).digest("hex")
      const response = await fetch(body.destination_url, {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "x-actantos-event": "evidence.exported",
          "x-actantos-signature": `sha256=${signature}`,
        },
        body: payload,
      })

      return reply.code(200).send({
        delivered: response.ok,
        status_code: response.status,
        destination_url: body.destination_url,
        event: "evidence.exported",
      })
    } catch (error) {
      if (error instanceof ZodError) {
        return reply.code(400).send({ error: "invalid_request", issues: error.issues })
      }
      throw error
    }
  })
}
