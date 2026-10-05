import { test } from "node:test"
import assert from "node:assert"
import { ActantClient } from "../src/client.ts"
import { wrapTool, GuardedAccessDenied, ApprovalRequired } from "../src/wrapTool.ts"

test("ActantClient interceptToolCall, decideApproval, listPendingApprovals and waitForApproval with mocked fetch", async () => {
  const pendingApprovals: any[] = []
  
  const mockFetch = async (url: string, options: any) => {
    if (url.endsWith("/v1/intercept/tool-call")) {
      const body = JSON.parse(options.body)
      if (body.action.args.command === "secret") {
        return {
          ok: true,
          json: async () => ({
            decision: "deny",
            decision_id: "deny-123",
            reason: "blocked by policy",
            reason_code: "policy_forbid",
          }),
        }
      }
      if (body.action.args.command === "push") {
        const approvalId = "app-123"
        if (!body.authorization) {
          pendingApprovals.push({ approval_id: approvalId, status: "pending" })
          return {
            ok: true,
            json: async () => ({
              decision: "approval_required",
              decision_id: "appreq-123",
              reason: "approval required",
              reason_code: "approval_required",
              approval: { approval_id: approvalId },
            }),
          }
        } else {
          return {
            ok: true,
            json: async () => ({
              decision: "allow",
              decision_id: "allow-123",
              reason: "permitted",
              reason_code: "allowed",
              decision_token: "token-123",
            }),
          }
        }
      }
      return {
        ok: true,
        json: async () => ({
          decision: "allow",
          decision_id: "allow-123",
          reason: "permitted",
          reason_code: "allowed",
          decision_token: "token-123",
        }),
      }
    }
    
    if (url.endsWith("/v1/tool-result")) {
      return { ok: true, json: async () => ({}) }
    }
    
    if (url.includes("/v1/approvals/pending")) {
      return { ok: true, json: async () => ({ approvals: pendingApprovals }) }
    }
    
    if (url.includes("/decide")) {
      const approvalId = url.split("/")[url.split("/").length - 2]
      const index = pendingApprovals.findIndex(a => a.approval_id === approvalId)
      if (index !== -1) {
        pendingApprovals.splice(index, 1)
      }
      return {
        ok: true,
        json: async () => ({
          approval_id: approvalId,
          decision: "approved",
          approval_token: "raw-token-123",
        }),
      }
    }
    
    throw new Error(`Unhandled mock fetch url: ${url}`)
  }

  const client = new ActantClient({
    baseUrl: "http://mock",
    tenantId: "t_demo",
    agentId: "agent_1",
    sessionId: "sess_1",
    fetchImpl: mockFetch as any,
    pollIntervalMs: 10,
  })

  const dummyTool = {
    name: "dummy",
    execute: async (args: any) => `executed ${args.command}`,
  }

  const wrapped = wrapTool(client, dummyTool)

  // 1. Allow path
  const res1 = await wrapped({ command: "ls" })
  assert.strictEqual(res1, "executed ls")

  // 2. Deny path
  try {
    await wrapped({ command: "secret" })
    assert.fail("Should have thrown GuardedAccessDenied")
  } catch (err) {
    assert.ok(err instanceof GuardedAccessDenied)
  }

  // 3. Approval path
  let appError: ApprovalRequired | undefined
  try {
    await wrapped({ command: "push" })
    assert.fail("Should have thrown ApprovalRequired")
  } catch (err) {
    assert.ok(err instanceof ApprovalRequired)
    appError = err as ApprovalRequired
  }

  // 4. Polling for approval and simulating user deciding
  const waitForPromise = client.waitForApproval(appError!.approvalId)
  
  // Simulate user deciding after 50ms
  setTimeout(() => {
    client.decideApproval(appError!.approvalId, "admin", "approved").catch(console.error)
  }, 50)
  
  await waitForPromise // should resolve when decideApproval is called
  
  // 5. Resume execution using the returned token
  const decideRes = await client.decideApproval(appError!.approvalId, "admin", "approved")
  const res2 = await wrapped({ command: "push" }, {
    prior_decision_id: appError!.decisionId,
    approval_id: appError!.approvalId,
    approval_token: "raw-token-123",
  })
  
  assert.strictEqual(res2, "executed push")
})
