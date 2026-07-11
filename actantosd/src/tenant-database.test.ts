import assert from "node:assert/strict"
import { readFile } from "node:fs/promises"
import path from "node:path"
import test from "node:test"
import { fileURLToPath } from "node:url"

import type { Database, DatabaseClient } from "./database.ts"
import { tenantContextSql, withTenantTransaction } from "./tenant-database.ts"

const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..")

test("tenant context is transaction-local and parameterized", async () => {
  // Given: a database recording statements issued by the tenancy boundary
  const statements: { sql: string; params: readonly unknown[] }[] = []
  const database = {
    async query() {
      return []
    },
    async close() {
      return
    },
    async transaction<T>(callback: (client: DatabaseClient) => Promise<T>): Promise<T> {
      const client: DatabaseClient = {
        async query(sql, params = []) {
          statements.push({ sql, params })
          return []
        },
      }
      return callback(client)
    },
  } satisfies Database

  // When: work is executed for a tenant
  await withTenantTransaction(database, "t_alpha", async () => "done")

  // Then: SET LOCAL is the first statement and cannot leak through the pool
  assert.deepEqual(statements[0], { sql: tenantContextSql, params: ["t_alpha"] })
})

test("stage 3 migration protects all tenant-scoped tables and validates legacy links", async () => {
  // Given: identity schema + RLS migrations
  const identity = await readFile(path.join(projectRoot, "sql/migrations/007_tenant_identity.sql"), "utf8")
  const rls = await readFile(path.join(projectRoot, "sql/migrations/008_tenant_rls.sql"), "utf8")

  // When: declared protected tables are inspected
  const protectedTables = [...rls.matchAll(/ALTER TABLE ([a-z_]+) ENABLE ROW LEVEL SECURITY/gu)].map((match) => match[1])

  // Then: every Stage 2 tenant-owned table plus identity tables is protected
  assert.deepEqual(protectedTables.sort(), [
    "agents", "approvals", "audit_chain_state", "audit_events", "budgets",
    "identity_subjects", "kill_switches", "mcp_servers", "mcp_tool_versions",
    "policy_bundles", "policy_decisions", "rate_limits", "risk_rule_sets",
    "service_principals", "sessions", "tenant_memberships", "tool_calls", "users",
  ])
  assert.match(identity, /FOREIGN KEY \(tenant_id, session_id\)/u)
  assert.match(identity, /FOREIGN KEY \(tenant_id, agent_id\)/u)
  assert.match(identity, /CREATE TABLE IF NOT EXISTS identity_subjects/u)
  assert.match(rls, /legacy tenant relationship validation failed/u)
  assert.match(rls, /CREATE ROLE actantos_app/u)
})
