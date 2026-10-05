import assert from "node:assert/strict"
import test from "node:test"

import { buildServer } from "./server.ts"
import { createTestDatabase } from "./test-database.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"
import { FakeCedarProvider } from "./fake-cedar-provider.ts"

test("Uploaded and activated policy takes effect immediately", async () => {
  const database = await createTestDatabase()
  const cedarProvider = new FakeCedarProvider()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    policyValidator: async () => ({ ok: true }),
    cedarProvider,
    database,
  })
  await server.ready()

  // First intercept, default behavior (allow)
  const defaultInterceptResponse = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call?tenant_id=t_demo",
    payload: {
      request_id: "req-12345678",
      tenant_id: "t_demo",
      session_id: "22222222-2222-2222-2222-222222222222",
      session: { 
        id: "s_demo",
        external_id: "s_demo" 
      },
      agent_id: "11111111-1111-1111-1111-111111111111",
      agent: { 
        id: "pi_demo",
        name: "test-agent",
        runtime_type: "pi",
        environment: "dev",
        risk_tier: "low"
      },
      subject: { user_id: "u_demo" },
      tool: {
        kind: "shell",
        name: "execute",
        operation: "execute_command",
      },
      // A path inside the approved workspace, with the workspace declared. The bare
      // "hello.txt" this used to be derives the workspace as "." , which the shipped policy
      // denies, so the "allow" asserted below existed only under FakeCedarProvider.
      resource: { path: "/workspace/hello.txt" },
      action: { command: "echo Hello", args: { host_workspace_path: "/workspace" } },
      normalized: { credential_access: false },
    },
  })

  assert.equal(defaultInterceptResponse.statusCode, 200)
  assert.equal(defaultInterceptResponse.json().decision, "allow")

  // Upload and activate a new policy that forbids everything
  const createResponse = await server.inject({
    method: "POST",
    url: "/v1/policy-bundles?tenant_id=t_demo",
    payload: {
      tenant_id: "t_demo",
      version: "0.2.0",
      engine: "cedar",
      source_text: "forbid(principal, action, resource);",
      active: true,
    },
  })

  assert.equal(createResponse.statusCode, 201)

  // Second intercept, should be denied due to new policy
  const newInterceptResponse = await server.inject({
    method: "POST",
    url: "/v1/intercept/tool-call?tenant_id=t_demo",
    payload: {
      request_id: "req-12345679",
      tenant_id: "t_demo",
      session_id: "22222222-2222-2222-2222-222222222222",
      session: { 
        id: "s_demo",
        external_id: "s_demo" 
      },
      agent_id: "11111111-1111-1111-1111-111111111111",
      agent: { 
        id: "pi_demo",
        name: "test-agent",
        runtime_type: "pi",
        environment: "dev",
        risk_tier: "low"
      },
      subject: { user_id: "u_demo" },
      tool: {
        kind: "shell",
        name: "execute",
        operation: "execute_command",
      },
      // A path inside the approved workspace, with the workspace declared. The bare
      // "hello.txt" this used to be derives the workspace as "." , which the shipped policy
      // denies, so the "allow" asserted below existed only under FakeCedarProvider.
      resource: { path: "/workspace/hello.txt" },
      action: { command: "echo Hello", args: { host_workspace_path: "/workspace" } },
      normalized: { credential_access: false },
    },
  })

  assert.equal(newInterceptResponse.statusCode, 200)
  assert.equal(newInterceptResponse.json().decision, "deny")

  await server.close()
  await database.close()
})
