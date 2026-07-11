import type { FastifyInstance } from "fastify"
import { z, ZodError } from "zod"

import {
  listApprovalChannels,
  notifyApprovalChannels,
  setApprovalChannels,
  verifyWebhookChannelSecret,
  type ApprovalChannel,
} from "./approval-channels.ts"
import type { Database } from "./database.ts"
import type { ToolCallRepository } from "./tool-call-repository.ts"
import { sha256 } from "./hash.ts"
import { randomBytes } from "node:crypto"
import { InMemoryToolCallRepository } from "./tool-call-repository.ts"

const channelSchema = z.discriminatedUnion("kind", [
  z.object({ kind: z.literal("web"), enabled: z.boolean() }),
  z.object({ kind: z.literal("slack"), enabled: z.boolean() }),
  z.object({ kind: z.literal("teams"), enabled: z.boolean() }),
  z.object({
    kind: z.literal("webhook"),
    enabled: z.boolean(),
    target_url: z.string().url(),
    secret: z.string().min(8),
  }),
])

const putChannelsBodySchema = z.object({
  channels: z.array(channelSchema).min(1),
})

const webhookDecideBodySchema = z.object({
  approval_id: z.string().uuid(),
  decision: z.enum(["approved", "denied"]),
  approver_user_id: z.string().min(1),
  secret: z.string().min(8),
})

const notifyBodySchema = z.object({
  approval_id: z.string().uuid(),
  tenant_id: z.string().min(1),
  request_id: z.string().min(1),
  reason_code: z.string().min(1),
  agent_id: z.string().min(1),
  session_id: z.string().min(1),
})

type ApprovalTenantRow = {
  readonly tenant_id: string
  readonly status: "pending" | "approved" | "denied" | "expired"
}

export const registerApprovalChannelRoutes = (
  server: FastifyInstance,
  options: {
    readonly database?: Database
    readonly repository: ToolCallRepository
  },
): void => {
  server.get("/v1/approvals/channels", async (_request, reply) =>
    reply.code(200).send({ channels: listApprovalChannels() }),
  )

  server.put("/v1/approvals/channels", async (request, reply) => {
    try {
      const body = putChannelsBodySchema.parse(request.body)
      const channels = setApprovalChannels(body.channels as ApprovalChannel[])
      return reply.code(200).send({ channels })
    } catch (error) {
      if (error instanceof ZodError) {
        return reply.code(400).send({ error: "invalid_request", issues: error.issues })
      }
      throw error
    }
  })

  server.post("/v1/approvals/channels/notify", async (request, reply) => {
    try {
      const body = notifyBodySchema.parse(request.body)
      const deliveries = await notifyApprovalChannels(body)
      return reply.code(200).send({ deliveries })
    } catch (error) {
      if (error instanceof ZodError) {
        return reply.code(400).send({ error: "invalid_request", issues: error.issues })
      }
      throw error
    }
  })

  server.post("/v1/approvals/channels/webhook/decide", async (request, reply) => {
    try {
      const body = webhookDecideBodySchema.parse(request.body)
      if (!verifyWebhookChannelSecret(body.secret)) {
        return reply.code(401).send({
          error: "unauthorized",
          message: "invalid webhook channel secret",
        })
      }

      const decidedAt = new Date().toISOString()
      const expiresAt = new Date(Date.now() + 10 * 60 * 1000).toISOString()
      const rawToken =
        body.decision === "approved" ? randomBytes(32).toString("base64url") : undefined
      const tokenHash = rawToken === undefined ? null : sha256(rawToken)

      if (options.database !== undefined) {
        const rows = await options.database.query<ApprovalTenantRow>(
          "SELECT tenant_id, status FROM approvals WHERE id = $1",
          [body.approval_id],
        )
        const approval = rows[0]
        if (approval === undefined) {
          return reply.code(404).send({ error: "not_found", message: "approval not found" })
        }
        if (approval.status !== "pending") {
          return reply.code(409).send({
            error: "approval_not_pending",
            message: "approval has already been decided",
          })
        }

        const users = await options.database.query<{ id: string }>(
          "SELECT id FROM users WHERE tenant_id = $1 AND id = $2",
          [approval.tenant_id, body.approver_user_id],
        )
        if (users.length === 0) {
          return reply.code(400).send({
            error: "invalid_request",
            message: "approver_user_id must reference an existing tenant user",
          })
        }

        await options.database.query(
          `
            UPDATE approvals
            SET status = $1,
                approver_user_id = $2,
                decided_by = $2,
                one_use_token_hash = $3,
                decided_at = $4,
                expires_at = $5
            WHERE id = $6
          `,
          [body.decision, body.approver_user_id, tokenHash, decidedAt, expiresAt, body.approval_id],
        )
      } else if (
        options.repository instanceof InMemoryToolCallRepository &&
        body.decision === "approved" &&
        rawToken !== undefined
      ) {
        options.repository.approveRequest(body.approval_id, rawToken)
      }

      return reply.code(200).send({
        channel: "webhook",
        approval_id: body.approval_id,
        decision: body.decision,
        approval_token: rawToken,
        decided_at: decidedAt,
        expires_at: expiresAt,
      })
    } catch (error) {
      if (error instanceof ZodError) {
        return reply.code(400).send({ error: "invalid_request", issues: error.issues })
      }
      throw error
    }
  })
}
