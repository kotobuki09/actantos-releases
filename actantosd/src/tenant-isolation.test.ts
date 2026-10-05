// PQ-02: Cross-tenant adversarial test suite
// Verifies tenant isolation: one tenant must never see or mutate another
// tenant's rows when the actantos.tenant_id session variable is set correctly.
//
// These tests run only when DATABASE_URL is set (Postgres integration tests).

import assert from "node:assert/strict"
import { test } from "node:test"
import { createDatabase, migrateDatabase, seedDemoData } from "./database.ts"

const DATABASE_URL = process.env["DATABASE_URL"]

// These tests run migrations and seed data, and several other test files do the same. Node runs
// test files concurrently, so under a plain `npm test` with DATABASE_URL exported they deadlock
// against each other on DDL locks. The substrate pass is therefore opt-in and serialized:
// `npm run test:substrate` sets this flag and passes --test-concurrency=1.
const SUBSTRATE_PASS = process.env["ACTANTOS_SUBSTRATE_TESTS"] === "1"

const skip = DATABASE_URL === undefined || !SUBSTRATE_PASS
const todo = skip
  ? "DATABASE_URL not set, or run `npm run test:substrate` — these tests need an exclusive real PostgreSQL"
  : undefined

// ---------------------------------------------------------------------------
// Non-superuser connection
// ---------------------------------------------------------------------------

// Row-level security does not apply to a superuser. `FORCE ROW LEVEL SECURITY` closes the
// table-owner exemption but not the superuser exemption, so a test that connects as the
// migration role proves nothing about isolation: every row is visible to it regardless of the
// policy. These tests therefore assume the role and run the queries as an ordinary role, which
// is the situation a deployment is actually in.

const ISOLATION_ROLE = "actantos_rls_test"

const ensureIsolationRole = async (database: Awaited<ReturnType<typeof createDatabase>>) => {
  await database.query(`
    DO $$
    BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${ISOLATION_ROLE}') THEN
        CREATE ROLE ${ISOLATION_ROLE} NOLOGIN;
      END IF;
    END
    $$;
  `)
  await database.query(`GRANT USAGE ON SCHEMA public TO ${ISOLATION_ROLE}`)
  await database.query(
    `GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO ${ISOLATION_ROLE}`,
  )
}

// ---------------------------------------------------------------------------
// Helper: set tenant context and run a callback
// ---------------------------------------------------------------------------
const withTenantCtx = async (
  database: Awaited<ReturnType<typeof createDatabase>>,
  tenantId: string,
  callback: (db: typeof database) => Promise<void>,
): Promise<void> => {
  // We cannot SET LOCAL outside a transaction, so wrap in one.
  await database.transaction(async (client) => {
    await client.query(`SET LOCAL ROLE ${ISOLATION_ROLE}`)
    await client.query(`SET LOCAL actantos.tenant_id = '${tenantId}'`)
    // Build a thin wrapper that delegates to the txn client
    const wrapped = {
      ...database,
      query: client.query.bind(client),
      transaction: database.transaction.bind(database),
    }
    await callback(wrapped as typeof database)
  })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test("PQ-02: tenant A cannot read tenant B's tool_calls", { skip: todo }, async () => {
  const db = createDatabase(DATABASE_URL!)
  try {
    await migrateDatabase(db)
    await ensureIsolationRole(db)
    await seedDemoData(db)

    // Seed two distinct tenants
    await db.query(`
      INSERT INTO tenants (id, name)
      VALUES ('t_pq02_a', 'Tenant A'), ('t_pq02_b', 'Tenant B')
      ON CONFLICT (id) DO NOTHING
    `)

    // Seed a tool_call row for tenant B (use superuser connection = no RLS)
    // We need a valid session + agent first.
    // The owner and session user must exist: `agents.owner_user_id` and `sessions.user_id` both
    // carry a foreign key into `users`. pg-mem did not enforce that constraint, which is why
    // this was only discovered when the suite was first run against a real PostgreSQL server.
    await db.query(`
      INSERT INTO users (tenant_id, id, name, role, status)
      VALUES ('t_pq02_b', 'u_b', 'User B', 'operator', 'active')
      ON CONFLICT (tenant_id, id) DO NOTHING
    `)
    await db.query(`
      INSERT INTO agents (id, external_id, tenant_id, name, runtime_type, owner_user_id, environment, risk_tier)
      VALUES ('a0000000-0000-0000-0000-000000000001', 'ext-b', 't_pq02_b', 'Agent B', 'pi', 'u_b', 'dev', 'low')
      ON CONFLICT DO NOTHING
    `)
    await db.query(`
      INSERT INTO sessions (id, external_id, tenant_id, agent_id, user_id)
      VALUES ('b0000000-0000-0000-0000-000000000001', 'sess-b', 't_pq02_b', 'a0000000-0000-0000-0000-000000000001', 'u_b')
      ON CONFLICT DO NOTHING
    `)
    await db.query(`
      INSERT INTO tool_calls (
        id, request_id, tenant_id, session_id, agent_id,
        tool_kind, tool_name, operation,
        resource_json, action_json, normalized_json, scope_hash, status
      )
      VALUES (
        'c0000000-0000-0000-0000-000000000001',
        'req-pq02-b-1',
        't_pq02_b',
        'b0000000-0000-0000-0000-000000000001',
        'a0000000-0000-0000-0000-000000000001',
        'file', 'read', 'read',
        '{}', '{}', '{}', 'hash-b', 'pending'
      )
      ON CONFLICT DO NOTHING
    `)

    // Now query as tenant A — should see ZERO rows due to RLS
    await withTenantCtx(db, "t_pq02_a", async (tenantDb) => {
      const rows = await tenantDb.query(
        "SELECT id FROM tool_calls WHERE tenant_id = 't_pq02_b'",
      )
      assert.equal(
        rows.length,
        0,
        "Tenant A must not see tenant B tool_calls via RLS",
      )
    })
  } finally {
    await db.close()
  }
})

test("PQ-02: tenant A cannot insert a row into tenant B's namespace", { skip: todo }, async () => {
  const db = createDatabase(DATABASE_URL!)
  try {
    await migrateDatabase(db)
    await ensureIsolationRole(db)
    await seedDemoData(db)

    await db.query(`
      INSERT INTO tenants (id, name)
      VALUES ('t_pq02_c', 'Tenant C'), ('t_pq02_d', 'Tenant D')
      ON CONFLICT (id) DO NOTHING
    `)

    // Agent and session for tenant D (via superuser / migration path)
    await db.query(`
      INSERT INTO users (tenant_id, id, name, role, status)
      VALUES ('t_pq02_d', 'u_d', 'User D', 'operator', 'active')
      ON CONFLICT (tenant_id, id) DO NOTHING
    `)
    await db.query(`
      INSERT INTO agents (id, external_id, tenant_id, name, runtime_type, owner_user_id, environment, risk_tier)
      VALUES ('a0000000-0000-0000-0000-000000000002', 'ext-d', 't_pq02_d', 'Agent D', 'pi', 'u_d', 'dev', 'low')
      ON CONFLICT DO NOTHING
    `)
    await db.query(`
      INSERT INTO sessions (id, external_id, tenant_id, agent_id, user_id)
      VALUES ('b0000000-0000-0000-0000-000000000002', 'sess-d', 't_pq02_d', 'a0000000-0000-0000-0000-000000000002', 'u_d')
      ON CONFLICT DO NOTHING
    `)

    // Acting as tenant C, try to insert a row with tenant_id = 't_pq02_d'
    await assert.rejects(
      () =>
        withTenantCtx(db, "t_pq02_c", async (tenantDb) => {
          await tenantDb.query(`
            INSERT INTO tool_calls (
              id, request_id, tenant_id, session_id, agent_id,
              tool_kind, tool_name, operation,
              resource_json, action_json, normalized_json, scope_hash, status
            )
            VALUES (
              'c0000000-0000-0000-0000-000000000099',
              'req-cross-insert',
              't_pq02_d',
              'b0000000-0000-0000-0000-000000000002',
              'a0000000-0000-0000-0000-000000000002',
              'file', 'read', 'read',
              '{}', '{}', '{}', 'hash-x', 'pending'
            )
          `)
        }),
      /new row violates row-level security policy/i,
      "Cross-tenant INSERT must be rejected by RLS WITH CHECK",
    )
  } finally {
    await db.close()
  }
})

test("PQ-02: empty tenant_id context sees no rows", { skip: todo }, async () => {
  const db = createDatabase(DATABASE_URL!)
  try {
    await migrateDatabase(db)
    await ensureIsolationRole(db)
    await seedDemoData(db)

    // With no tenant_id set, current_setting returns '' (missing) — no rows visible
    await withTenantCtx(db, "", async (tenantDb) => {
      const rows = await tenantDb.query("SELECT id FROM tool_calls LIMIT 1")
      assert.equal(rows.length, 0, "No tenant context means no rows visible")
    })
  } finally {
    await db.close()
  }
})

test("PQ-02: audit_events are isolated per tenant", { skip: todo }, async () => {
  const db = createDatabase(DATABASE_URL!)
  try {
    await migrateDatabase(db)
    await ensureIsolationRole(db)
    await seedDemoData(db)

    // Insert a synthetic audit event for t_demo (superuser path)
    await db.query(`
      INSERT INTO audit_chain_state (tenant_id, last_hash, seq)
      VALUES ('t_demo', 'genesis', 0)
      ON CONFLICT (tenant_id) DO NOTHING
    `)

    // Query from a different tenant — should see 0 audit events for t_demo
    await withTenantCtx(db, "t_pq02_aud", async (tenantDb) => {
      const rows = await tenantDb.query(
        "SELECT id FROM audit_events WHERE tenant_id = 't_demo'",
      )
      assert.equal(rows.length, 0, "Audit events from t_demo invisible to another tenant")
    })
  } finally {
    await db.close()
  }
})
