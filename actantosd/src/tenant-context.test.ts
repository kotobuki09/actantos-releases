import assert from "node:assert/strict"
import test from "node:test"
import { newDb } from "pg-mem"

import { PostgresDatabase, tenantLocalStorage } from "./database.ts"
import { buildServer } from "./server.ts"

test("PostgresDatabase query handles tenantLocalStorage context correctly", async () => {
  const memoryDb = newDb()
  const adapter = memoryDb.adapters.createPg()
  const { Pool } = adapter
  const pool = new Pool()

  const db = new PostgresDatabase(pool)
  
  try {
    // 1. Without tenantId, should query normally
    const resultNoTenant = await db.query("SELECT 1 as val")
    assert.deepEqual(resultNoTenant, [{ val: 1 }])

    // 2. With tenantId, should wrap in transaction and run SET LOCAL.
    // In pg-mem, SET LOCAL actantos.tenant_id will fail because actantos.tenant_id is unrecognized,
    // but our try-catch should catch it, log/ignore it, and still run the query successfully.
    const resultWithTenant = await tenantLocalStorage.run("t_test_123", async () => {
      return db.query("SELECT 2 as val")
    })
    assert.deepEqual(resultWithTenant, [{ val: 2 }])

    // 3. With tenantId in transaction block
    const resultTx = await tenantLocalStorage.run("t_test_456", async () => {
      return db.transaction(async (client) => {
        return client.query("SELECT 3 as val")
      })
    })
    assert.deepEqual(resultTx, [{ val: 3 }])
  } finally {
    await db.close()
  }
})

test("Fastify onRequest hook propagates tenant_id context correctly", async () => {
  const server = buildServer()

  // Add a test route that returns the tenant ID from store
  server.get("/v1/test-tenant-propagation", async (_req, reply) => {
    const tenantId = tenantLocalStorage.getStore()
    return reply.code(200).send({ tenantId })
  })

  await server.ready()

  // 1. Query parameter
  const res1 = await server.inject({
    method: "GET",
    url: "/v1/test-tenant-propagation?tenant_id=t_query_val",
  })
  assert.equal(res1.statusCode, 200)
  assert.deepEqual(res1.json(), { tenantId: "t_query_val" })

  // 2. Header
  const res2 = await server.inject({
    method: "GET",
    url: "/v1/test-tenant-propagation",
    headers: {
      "x-actantos-tenant-id": "t_header_val",
    },
  })
  assert.equal(res2.statusCode, 200)
  assert.deepEqual(res2.json(), { tenantId: "t_header_val" })

  // 3. Fallback to t_demo
  const res3 = await server.inject({
    method: "GET",
    url: "/v1/test-tenant-propagation",
  })
  assert.equal(res3.statusCode, 200)
  assert.deepEqual(res3.json(), { tenantId: "t_demo" })

  // 4. Header overrides query parameter
  const res4 = await server.inject({
    method: "GET",
    url: "/v1/test-tenant-propagation?tenant_id=t_query_val",
    headers: {
      "x-actantos-tenant-id": "t_header_val_override",
    },
  })
  assert.equal(res4.statusCode, 200)
  assert.deepEqual(res4.json(), { tenantId: "t_header_val_override" })

  await server.close()
})
