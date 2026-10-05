import assert from "node:assert/strict"
import test from "node:test"
import { newDb } from "pg-mem"
import { createHmac } from "node:crypto"

import { PostgresDatabase, tenantLocalStorage } from "./database.ts"
import { buildServer } from "./server.ts"
import { PostgresToolCallRepository } from "./tool-call-repository.ts"

// ---------------------------------------------------------------------------
// 1. Helper to build a traced pg-mem pool & database
// ---------------------------------------------------------------------------
type QueryTrace = {
  connectionId: number
  tenantId: string | undefined
  sql: string
  params: any[]
}

const isPgMemUnsupported = (sql: string): boolean =>
  sql.includes("-- actantos-pg-only") ||
  sql.includes("CREATE OR REPLACE FUNCTION enforce_tool_call_state_transitions") ||
  sql.includes("CREATE TRIGGER trg_enforce_tool_call_transitions")

const createTracedDatabase = async (): Promise<{
  database: PostgresDatabase
  getTrace: () => QueryTrace[]
  clearTrace: () => void
}> => {
  const memoryDb = newDb()
  const adapter = memoryDb.adapters.createPg()
  const { Pool } = adapter
  const pool = new Pool()

  const trace: QueryTrace[] = []
  let nextConnectionId = 0

  // Intercept Pool.connect to wrap connections and trace queries
  const originalConnect = pool.connect.bind(pool)
  pool.connect = async function() {
    const client = await originalConnect()
    
    if (!client.__traced__) {
      client.__traced__ = true
      client.__connectionId__ = ++nextConnectionId
      const originalQuery = client.query.bind(client)
      
      client.query = function(sql: any, params?: any, cb?: any) {
        const activeTenant = tenantLocalStorage.getStore()
        const querySql = typeof sql === "string" ? sql : (sql && typeof sql.text === "string" ? sql.text : "")
        
        if (isPgMemUnsupported(querySql)) {
          if (typeof cb === "function") {
            cb(null, { rows: [] })
            return
          }
          return Promise.resolve({ rows: [] })
        }
        
        const queryParams = Array.isArray(params) ? params : []
        trace.push({
          connectionId: client.__connectionId__,
          tenantId: activeTenant,
          sql: querySql,
          params: queryParams
        })
        return originalQuery(sql, params, cb)
      }
    } else {
      // If the client is reused from the pool, give it a new logical connection checkout ID
      client.__connectionId__ = ++nextConnectionId
    }
    
    return client
  }

  // Intercept Pool.query for pool-level queries (usually run outside client transactions)
  const originalPoolQuery = pool.query.bind(pool)
  pool.query = function(sql: any, params?: any, cb?: any) {
    const activeTenant = tenantLocalStorage.getStore()
    const querySql = typeof sql === "string" ? sql : (sql && typeof sql.text === "string" ? sql.text : "")
    
    if (isPgMemUnsupported(querySql)) {
      if (typeof cb === "function") {
        cb(null, { rows: [] })
        return
      }
      return Promise.resolve({ rows: [] })
    }
    
    const queryParams = Array.isArray(params) ? params : []
    trace.push({
      connectionId: 0,
      tenantId: activeTenant,
      sql: querySql,
      params: queryParams
    })
    return originalPoolQuery(sql, params, cb)
  }

  const database = new PostgresDatabase(pool)
  
  // Run migration and seeding to set up the DB schema
  const { migrateDatabase, seedDemoData } = await import("./database.ts")
  await migrateDatabase(database)
  await seedDemoData(database)

  return {
    database,
    getTrace: () => [...trace],
    clearTrace: () => {
      trace.length = 0
    }
  }
}

// ---------------------------------------------------------------------------
// Test 1: Concurrency and Isolation Stress Test
// ---------------------------------------------------------------------------
test("Dynamic tenancy connection context: concurrent queries isolate tenant IDs under RLS", async () => {
  try {
    const { database, getTrace, clearTrace } = await createTracedDatabase()
    const hmacSecret = "test-export-secret-challenger"
    
    const server = buildServer({
      hmacSecret,
      repository: new PostgresToolCallRepository(database),
      database,
    })
    server.log.level = "silent"

    // Add a test endpoint that runs a DB query using request tenant context
    server.get("/v1/test-isolation-stress", async (request, reply) => {
      const tenantId = tenantLocalStorage.getStore()
      // Perform a select query to trigger DB access under the tenant context
      const result = await database.query("SELECT $1::text as tenant_val", [tenantId])
      return reply.code(200).send({
        tenantId,
        dbResult: result[0]?.['tenant_val']
      })
    })

    await server.ready()

    // Clear trace after migrations/seeding
    clearTrace()

    // Spin up 100 concurrent requests with different tenant IDs
    const concurrentCount = 100
    const promises = Array.from({ length: concurrentCount }).map(async (_, idx) => {
      const tenantId = `tenant_stress_${idx}`
      const res = await server.inject({
        method: "GET",
        url: `/v1/test-isolation-stress`,
        headers: {
          "x-actantos-tenant-id": tenantId,
        }
      })
      
      assert.equal(res.statusCode, 200)
      const json = res.json()
      assert.equal(json.tenantId, tenantId)
      assert.equal(json.dbResult, tenantId)
    })

    await Promise.all(promises)

    // Verify that Kysely transaction connection context is completely isolated
    const trace = getTrace()
    
    // Group queries by tenant ID
    const tenantQueries: Record<string, typeof trace> = {}
    for (const item of trace) {
      if (item.tenantId) {
        if (!tenantQueries[item.tenantId]) {
          tenantQueries[item.tenantId] = []
        }
        tenantQueries[item.tenantId]!.push(item)
      }
    }

    // Assertions on RLS configuration sequences
    let totalSets = 0

    for (const [tenantId, queries] of Object.entries(tenantQueries)) {
      // Find the SET LOCAL query in this tenant's queries group
      const setLocalQuery = queries.find(q => q.sql.includes("SET LOCAL actantos.tenant_id"))
      assert.ok(setLocalQuery, `Should have executed SET LOCAL for ${tenantId}`)
      
      const setTenantMatch = setLocalQuery.sql.match(/SET LOCAL actantos\.tenant_id = '([^']+)'/)
      assert.ok(setTenantMatch, "Should be a valid SET LOCAL query format")
      const setTenantId = setTenantMatch![1]
      assert.equal(tenantId, setTenantId, "AsyncLocalStorage active tenant must match the set local value")
      
      totalSets++

      // Verify that every user query run under this tenant context had the correct parameters and matched the tenant ID
      const userQueries = queries.filter(q => !q.sql.includes("SET LOCAL") && !q.sql.includes("BEGIN") && !q.sql.includes("COMMIT") && !q.sql.includes("ROLLBACK"))
      for (const uq of userQueries) {
        assert.equal(uq.tenantId, tenantId, `Crosstalk detected! Query was executed with active tenant ${uq.tenantId} but expected ${tenantId}`)
      }
    }

    assert.ok(totalSets >= concurrentCount, "Should have executed SET LOCAL for all concurrent requests")
    
    await server.close()
    await database.close()
  } catch (err: any) {
    console.error("CONCURRENCY_TEST_ERROR:", err.message, err.stack)
    throw err
  }
})

// ---------------------------------------------------------------------------
// Test 2: Invalidation of Signed Evidence Export Packages
// ---------------------------------------------------------------------------
test("Signed evidence export packages: modifying any field invalidates the signature verification", async () => {
  const { database } = await createTracedDatabase()
  const hmacSecret = "test-export-secret-challenger-2"
  const server = buildServer({
    hmacSecret,
    repository: new PostgresToolCallRepository(database),
    database,
  })
  await server.ready()

  // Export package
  const exportResponse = await server.inject({
    method: "GET",
    url: "/v1/evidence/export?tenant_id=t_demo&session_id=s_demo",
  })
  assert.equal(exportResponse.statusCode, 200)
  const body = exportResponse.json()

  // Confirm signature is present and valid
  assert.equal(typeof body.signature, "string")
  assert.equal(body.signature.length, 64)

  const verifyPackage = (pkg: any, secret: string): boolean => {
    if (!pkg || typeof pkg.signature !== "string") {
      return false
    }
    const signature = pkg.signature
    const copy = { ...pkg }
    delete copy.signature
    const computed = createHmac("sha256", secret)
      .update(JSON.stringify(copy))
      .digest("hex")
    return signature === computed
  }

  // Base signature check
  assert.equal(verifyPackage(body, hmacSecret), true, "Original package must verify successfully")

  // Function to mutate a value based on its type
  const getMutatedValue = (val: any): any => {
    if (typeof val === "string") {
      return val + "_mutated"
    }
    if (typeof val === "number") {
      return val + 1000
    }
    if (typeof val === "boolean") {
      return !val
    }
    if (val === null) {
      return "not_null_anymore"
    }
    return val
  }

  // Recursive invalidation checker
  const testAllMutations = (obj: any, path: string[] = []): void => {
    if (!obj || typeof obj !== "object") {
      return
    }

    const keys = Object.keys(obj)
    for (const key of keys) {
      if (key === "signature") {
        continue // signature field modification is trivial, tested separately
      }

      const currentPath = [...path, key]
      const originalValue = obj[key]

      // 1. Try deleting the property (unless it's an array index)
      if (!Array.isArray(obj)) {
        delete obj[key]
        assert.equal(
          verifyPackage(body, hmacSecret),
          false,
          `Removing key ${currentPath.join(".")} did not invalidate signature`
        )
        obj[key] = originalValue // restore
      }

      // 2. Try modifying the value
      if (typeof originalValue !== "object" || originalValue === null) {
        obj[key] = getMutatedValue(originalValue)
        assert.equal(
          verifyPackage(body, hmacSecret),
          false,
          `Modifying primitive value at ${currentPath.join(".")} did not invalidate signature`
        )
        obj[key] = originalValue // restore
      } else {
        // Recurse into nested object/array
        testAllMutations(originalValue, currentPath)
      }
    }
  }

  // Run the deep traversal mutation test
  testAllMutations(body)

  // 3. Test array-specific mutations: adding an element
  if (Array.isArray(body.sessions)) {
    const originalSessions = [...body.sessions]
    body.sessions.push({ id: "non-existent-session-tamper" })
    assert.equal(verifyPackage(body, hmacSecret), false, "Appending to sessions array did not invalidate signature")
    body.sessions = originalSessions // restore
  }

  // 4. Test modifying the signature itself
  const originalSignature = body.signature
  body.signature = "a".repeat(64)
  assert.equal(verifyPackage(body, hmacSecret), false, "Tampering with signature field directly should fail verification")
  body.signature = originalSignature

  await server.close()
  await database.close()
})
