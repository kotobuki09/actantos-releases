import assert from "node:assert/strict"
import test from "node:test"

import {
  listApprovalChannels,
  notifyApprovalChannels,
  resetApprovalChannelsForTests,
  setApprovalChannels,
  verifyWebhookChannelSecret,
} from "./approval-channels.ts"
import { buildServer } from "./server.ts"
import { createTestDatabase } from "./test-database.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"

test("webhook channel notify + decide completes approval without web UI", async () => {
  resetApprovalChannelsForTests()
  const deliveries: { url: string; body: string }[] = []
  setApprovalChannels([
    { kind: "web", enabled: true },
    {
      kind: "webhook",
      enabled: true,
      target_url: "https://hooks.example.test/actantos",
      secret: "webhook-secret-stage2",
    },
  ])

  const notifyResults = await notifyApprovalChannels(
    {
      approval_id: "11111111-1111-1111-1111-111111111111",
      tenant_id: "t_demo",
      request_id: "req_channel_0001",
      reason_code: "approval_required",
      agent_id: "pi_demo",
      session_id: "s_demo",
    },
    {
      fetchImpl: async (url, init) => {
        deliveries.push({ url, body: init.body })
        return { ok: true, status: 200 }
      },
    },
  )
  assert.deepEqual(notifyResults, [{ kind: "webhook", delivered: true }])
  assert.equal(deliveries.length, 1)
  assert.equal(deliveries[0]?.url, "https://hooks.example.test/actantos")
  assert.equal(verifyWebhookChannelSecret("webhook-secret-stage2"), true)
  assert.equal(verifyWebhookChannelSecret("wrong-secret"), false)

  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  const intercept = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call",
    payload: {
      request_id: "req_webhook_decide_0001",
      tenant_id: "t_demo",
      agent: { id: "pi_demo", runtime_type: "pi", environment: "dev", risk_tier: "low" },
      subject: { user_id: "u_demo", role: "developer" },
      session: { id: "s_demo", cwd: "/workspace" },
      tool: { kind: "shell", name: "guarded_bash", operation: "ExecuteShellCommand", schema_hash: "" },
      resource: { id: "git push", kind: "shell_command", path: "git push" },
      action: {
        operation: "ExecuteShellCommand",
        args: { command: "git push --dry-run origin main", argv: ["git", "push", "--dry-run", "origin", "main"] },
      },
      normalized: {
        verb: "execute",
        mutation: true,
        destructive: false,
        network: true,
        credential_access: false,
        risk_class: "high",
        command_family: "git",
        subcommand: "push",
      },
    },
  })
  assert.equal(intercept.statusCode, 200)
  assert.equal(intercept.json().decision, "approval_required")
  const approvalId = intercept.json().approval.approval_id as string

  const denied = await server.inject({
    method: "POST",
    url: "/v1/approvals/channels/webhook/decide",
    payload: {
      approval_id: approvalId,
      decision: "approved",
      approver_user_id: "u_demo",
      secret: "wrong-secret-long",
    },
  })
  assert.equal(denied.statusCode, 401)

  const decided = await server.inject({
    method: "POST",
    url: "/v1/approvals/channels/webhook/decide",
    payload: {
      approval_id: approvalId,
      decision: "approved",
      approver_user_id: "u_demo",
      secret: "webhook-secret-stage2",
    },
  })
  assert.equal(decided.statusCode, 200)
  assert.equal(decided.json().channel, "webhook")
  assert.equal(decided.json().decision, "approved")
  assert.equal(typeof decided.json().approval_token, "string")

  const channels = await server.inject({ method: "GET", url: "/v1/approvals/channels" })
  assert.equal(channels.statusCode, 200)
  assert.ok(listApprovalChannels().some((channel) => channel.kind === "webhook"))

  await server.close()
  await database.close()
  resetApprovalChannelsForTests()
})
