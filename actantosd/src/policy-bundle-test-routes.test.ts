import assert from "node:assert/strict"
import test from "node:test"

import { FakeCedarProvider } from "./fake-cedar-provider.ts"
import { buildServer } from "./server.ts"
import { createTestDatabase } from "./test-database.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"

const safeReadRequest = {
  request_id: "req_policy_bundle_test_allow",
  tenant_id: "t_demo",
  agent: {
    id: "pi_demo",
    runtime_type: "pi",
    environment: "dev",
    risk_tier: "low",
  },
  subject: {
    user_id: "u_demo",
    role: "developer",
  },
  session: {
    id: "s_demo",
    cwd: "/workspace",
    purpose: "Policy dry-run",
    budget_remaining_cents: 10_000,
  },
  tool: {
    kind: "file",
    name: "guarded_read",
    operation: "ReadFile",
    schema_hash: "",
  },
  resource: {
    id: "/workspace/README.md",
    kind: "file",
    path: "/workspace/README.md",
  },
  action: {
    operation: "ReadFile",
    args: { path: "/workspace/README.md" },
  },
  normalized: {
    verb: "read",
    mutation: false,
    destructive: false,
    network: false,
    credential_access: false,
    risk_class: "low",
  },
} as const

const credentialReadRequest = {
  ...safeReadRequest,
  request_id: "req_policy_bundle_test_deny",
  resource: {
    id: "/workspace/.env",
    kind: "file",
    path: "/workspace/.env",
  },
  action: {
    operation: "ReadFile",
    args: { path: "/workspace/.env" },
  },
  normalized: {
    ...safeReadRequest.normalized,
    credential_access: true,
    risk_class: "critical",
  },
} as const

test("POST /v1/policy-bundles/:id/test dry-runs allow and deny without activating", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    policyValidator: async () => ({ ok: true }),
    cedarProvider: new FakeCedarProvider(),
    database,
  })
  await server.ready()

  const createResponse = await server.inject({
    method: "POST",
    url: "/v1/policy-bundles",
    payload: {
      tenant_id: "t_demo",
      version: "0.2.0-test",
      engine: "cedar",
      source_text: "permit(principal, action, resource);",
      active: false,
    },
  })
  assert.equal(createResponse.statusCode, 201)
  const bundleId = createResponse.json().policy_bundle.id as string
  assert.equal(createResponse.json().policy_bundle.active, false)

  const allowResponse = await server.inject({
    method: "POST",
    url: `/v1/policy-bundles/${bundleId}/test`,
    payload: { request: safeReadRequest },
  })
  assert.equal(allowResponse.statusCode, 200)
  assert.equal(allowResponse.json().dry_run, true)
  assert.equal(allowResponse.json().decision_mode, "dry_run")
  assert.equal(allowResponse.json().decision, "allow")
  assert.equal(allowResponse.json().policy_bundle.id, bundleId)
  assert.equal(allowResponse.json().policy_bundle.version, "0.2.0-test")

  const denyResponse = await server.inject({
    method: "POST",
    url: `/v1/policy-bundles/${bundleId}/test`,
    payload: { request: credentialReadRequest },
  })
  assert.equal(denyResponse.statusCode, 200)
  assert.equal(denyResponse.json().decision, "deny")
  assert.equal(denyResponse.json().decision_mode, "dry_run")

  const stillInactive = await server.inject({
    method: "GET",
    url: `/v1/policy-bundles/${bundleId}`,
  })
  assert.equal(stillInactive.statusCode, 200)
  assert.equal(stillInactive.json().policy_bundle.active, false)

  await server.close()
  await database.close()
})

test("POST /v1/policy-bundles/:id/test returns 404 for unknown bundle", async () => {
  const database = await createTestDatabase()
  const server = buildServer({
    hmacSecret: "test-secret",
    repository: new PostgresToolCallRepository(database),
    policyValidator: async () => ({ ok: true }),
    cedarProvider: new FakeCedarProvider(),
    database,
  })
  await server.ready()

  const response = await server.inject({
    method: "POST",
    url: "/v1/policy-bundles/99999999-9999-9999-9999-999999999999/test",
    payload: { request: safeReadRequest },
  })
  assert.equal(response.statusCode, 404)
  assert.equal(response.json().error, "not_found")

  await server.close()
  await database.close()
})
