import type { FastifyInstance } from "fastify"
import { z, ZodError } from "zod"
import { toolCallInterceptionRequestSchema } from "./contracts.ts"
import { createToolCallContext } from "./intercept-response.ts"
import type { CedarProvider } from "./fake-cedar-provider.ts"

type RegisterPolicySimulateRoutesOptions = {
  readonly cedarProvider: CedarProvider
}

export const registerPolicySimulateRoutes = (
  server: FastifyInstance,
  options: RegisterPolicySimulateRoutesOptions,
): void => {
  server.post("/v1/policy/simulate", async (request, reply) => {
    try {
      const requestPayload = toolCallInterceptionRequestSchema.parse(request.body)
      const context = createToolCallContext(requestPayload)
      const decision = await options.cedarProvider.evaluate(context)

      return reply.code(200).send({
        decision: decision.decision,
        reason_code: decision.reasonCode ?? null,
      })
    } catch (error) {
      if (error instanceof ZodError) {
        return reply.code(400).send({ error: "invalid_request", issues: error.issues })
      }
      throw error
    }
  })
}
