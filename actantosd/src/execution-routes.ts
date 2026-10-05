import type { FastifyInstance } from "fastify"
import { z, ZodError } from "zod"

import {
  DecisionExecutionRefusal,
  type DecisionExecutionService,
} from "./decision-execution.ts"

/**
 * The route that finally spends an authorization.
 *
 * The route exists only when `ACTANTOS_DECISION_EXECUTION=1` (see `src/index.ts`). A build without
 * that flag has no `/v1/executions` handler at all, so a deployment that never opted in is
 * unaffected — not "denied", but absent.
 *
 * Error mapping is deliberate and per-reason. A refusal is always a refusal, but telling an operator
 * that a command was refused because the nonce was already spent is a different thing from telling
 * them it was refused because the command differs from the authorized one. Collapsing both into 403
 * is what made the earlier "why did nothing happen" questions unanswerable.
 */

const executeBodySchema = z.object({
  tenant_id: z.string().min(1),
  request_id: z.string().min(8).max(128),
  argv: z.array(z.string()).min(1),
  workspace_path: z.string().min(1),
})

type RegisterExecutionRoutesOptions = {
  readonly execution: DecisionExecutionService
}

const REFUSAL_STATUS: Readonly<Record<DecisionExecutionRefusal["reason"], number>> = {
  no_such_authorization: 404,
  not_allowed: 403,
  no_decision_token: 409,
  token_not_ed25519: 409,
}

export const registerExecutionRoutes = (
  server: FastifyInstance,
  options: RegisterExecutionRoutesOptions,
): void => {
  server.post("/v1/executions", async (request, reply) => {
    try {
      const body = executeBodySchema.parse(request.body)
      const result = await options.execution.execute({
        tenantId: body.tenant_id,
        requestId: body.request_id,
        argv: body.argv,
        workspacePath: body.workspace_path,
      })

      return reply.code(200).send({
        request_id: body.request_id,
        status: result.status,
        exit_code: result.exitCode,
        stdout_hash: result.stdoutHash,
        stderr_hash: result.stderrHash,
        redacted_preview: result.redactedPreview,
        started_at: result.startedAt,
        finished_at: result.finishedAt,
      })
    } catch (error) {
      if (error instanceof ZodError) {
        return reply.code(400).send({ error: "invalid_request", issues: error.issues })
      }
      if (error instanceof DecisionExecutionRefusal) {
        return reply
          .code(REFUSAL_STATUS[error.reason])
          .send({ error: error.reason, message: error.message })
      }
      // The executor's own refusals carry a message that names the invariant they protect. Passing
      // them through verbatim is what lets a caller see "decision token already used" instead of an
      // opaque 500, and none of them contain the token or the command.
      if (error instanceof Error) {
        return reply.code(403).send({ error: "execution_refused", message: error.message })
      }
      throw error
    }
  })
}