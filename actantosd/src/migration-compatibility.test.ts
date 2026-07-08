import assert from "node:assert/strict"
import { readFile } from "node:fs/promises"
import path from "node:path"
import test from "node:test"
import { fileURLToPath } from "node:url"

import { newDb } from "pg-mem"

import type { Database } from "./database.ts"
import { seedDemoData } from "./database.ts"

const currentDirectory = path.dirname(fileURLToPath(import.meta.url))
const projectRoot = path.resolve(currentDirectory, "..")

const createTestDatabase = async (): Promise<Database> => {
  const memoryDb = newDb()
  const adapter = memoryDb.adapters.createPg()
  const { Pool } = adapter
  const pool = new Pool()

  return {
    async query(sql, params = []) {
      const result = await pool.query(sql, [...params])
      return result.rows
    },
    async transaction(callback) {
      const client = await pool.connect()

      try {
        await client.query("BEGIN")
        const result = await callback({
          async query(sql, params = []) {
            const queryResult = await client.query(sql, [...params])
            return queryResult.rows
          },
        })
        await client.query("COMMIT")
        return result
      } catch (error) {
        await client.query("ROLLBACK")
        throw error
      } finally {
        client.release()
      }
    },
    async close() {
      await pool.end()
    },
  }
}

const readSqlFile = async (relativePath: string): Promise<string> =>
  readFile(path.join(projectRoot, relativePath), "utf8")

const createV07PilotState = async (database: Database): Promise<void> => {
  await database.query(`
    CREATE TABLE agents (
      id UUID PRIMARY KEY,
      external_id TEXT NOT NULL,
      tenant_id TEXT NOT NULL,
      name TEXT NOT NULL,
      runtime_type TEXT NOT NULL,
      owner_user_id TEXT NOT NULL,
      environment TEXT NOT NULL,
      risk_tier TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `)

  await database.query(`
    CREATE TABLE sessions (
      id UUID PRIMARY KEY,
      external_id TEXT NOT NULL,
      tenant_id TEXT NOT NULL,
      agent_id UUID NOT NULL REFERENCES agents(id),
      user_id TEXT NOT NULL,
      purpose TEXT,
      cwd TEXT,
      status TEXT NOT NULL,
      started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
      ended_at TIMESTAMPTZ
    );
  `)

  await database.query(`
    CREATE UNIQUE INDEX uniq_agents_tenant_external
      ON agents (tenant_id, external_id);
  `)

  await database.query(`
    CREATE UNIQUE INDEX uniq_sessions_tenant_external
      ON sessions (tenant_id, external_id);
  `)

  await database.query(`
    CREATE TABLE policy_bundles (
      id UUID PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      version TEXT NOT NULL,
      engine TEXT NOT NULL,
      source_hash TEXT NOT NULL,
      source_text TEXT NOT NULL,
      active BOOLEAN NOT NULL DEFAULT false,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `)

  await database.query(`
    CREATE TABLE tool_calls (
      id UUID PRIMARY KEY,
      request_id TEXT NOT NULL,
      tenant_id TEXT NOT NULL,
      session_id UUID NOT NULL REFERENCES sessions(id),
      agent_id UUID NOT NULL REFERENCES agents(id),
      tool_kind TEXT NOT NULL,
      tool_name TEXT NOT NULL,
      operation TEXT NOT NULL,
      resource_json JSONB NOT NULL,
      action_json JSONB NOT NULL,
      normalized_json JSONB NOT NULL,
      mcp_json JSONB,
      scope_hash TEXT NOT NULL,
      status TEXT NOT NULL,
      result_hash TEXT,
      started_at TIMESTAMPTZ,
      finished_at TIMESTAMPTZ,
      error_code TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `)

  await database.query(`
    CREATE TABLE policy_decisions (
      id UUID PRIMARY KEY,
      request_id TEXT NOT NULL,
      tenant_id TEXT NOT NULL,
      tool_call_id UUID NOT NULL REFERENCES tool_calls(id),
      policy_bundle_id UUID REFERENCES policy_bundles(id),
      cedar_result TEXT NOT NULL,
      risk_class TEXT NOT NULL,
      approval_req BOOLEAN NOT NULL DEFAULT false,
      final_decision TEXT NOT NULL,
      decision_mode TEXT NOT NULL DEFAULT 'enforce',
      reason TEXT NOT NULL,
      reason_code TEXT NOT NULL DEFAULT 'unknown',
      constraints_json JSONB,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `)

  await database.query(`
    CREATE TABLE approvals (
      id UUID PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      decision_id UUID NOT NULL REFERENCES policy_decisions(id),
      tool_call_id UUID NOT NULL REFERENCES tool_calls(id),
      status TEXT NOT NULL,
      approver_user_id TEXT,
      decided_by TEXT,
      one_use_token_hash TEXT,
      scope_hash TEXT NOT NULL,
      expires_at TIMESTAMPTZ NOT NULL,
      decided_at TIMESTAMPTZ,
      used_at TIMESTAMPTZ,
      used_by_request_id TEXT,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `)

  await database.query(`
    CREATE TABLE audit_chain_state (
      tenant_id TEXT PRIMARY KEY,
      last_hash TEXT NOT NULL DEFAULT 'genesis',
      seq BIGINT NOT NULL DEFAULT 0,
      updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `)

  await database.query(`
    CREATE TABLE audit_events (
      id UUID PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      event_type TEXT NOT NULL,
      actor_type TEXT NOT NULL,
      actor_id TEXT NOT NULL,
      session_id UUID REFERENCES sessions(id),
      tool_call_id UUID REFERENCES tool_calls(id),
      decision_id UUID REFERENCES policy_decisions(id),
      seq BIGINT NOT NULL,
      payload_json JSONB NOT NULL,
      prev_hash TEXT NOT NULL,
      event_hash TEXT NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `)

  await database.query(`
    CREATE TABLE budgets (
      id UUID PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      scope_type TEXT NOT NULL,
      scope_id TEXT NOT NULL,
      metric TEXT NOT NULL,
      limit_value BIGINT NOT NULL,
      window_seconds INT NOT NULL,
      current_value BIGINT NOT NULL DEFAULT 0,
      window_start TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `)

  await database.query(`
    CREATE TABLE kill_switches (
      id UUID PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      scope_type TEXT NOT NULL,
      scope_id TEXT NOT NULL,
      reason TEXT NOT NULL,
      enabled BOOLEAN NOT NULL DEFAULT true,
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `)

  await database.query(`
    CREATE TABLE mcp_servers (
      id UUID PRIMARY KEY,
      tenant_id TEXT NOT NULL,
      name TEXT NOT NULL,
      transport TEXT NOT NULL,
      upstream_url TEXT,
      server_identity_hash TEXT NOT NULL,
      status TEXT NOT NULL DEFAULT 'active',
      created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    );
  `)

  await database.query(`
    INSERT INTO agents (
      id,
      external_id,
      tenant_id,
      name,
      runtime_type,
      owner_user_id,
      environment,
      risk_tier,
      status
    )
    VALUES (
      '11111111-1111-1111-1111-111111111111',
      'pi_demo',
      't_demo',
      'Pi Demo Agent',
      'pi',
      'u_demo',
      'dev',
      'low',
      'active'
    );
  `)

  await database.query(`
    INSERT INTO sessions (
      id,
      external_id,
      tenant_id,
      agent_id,
      user_id,
      purpose,
      cwd,
      status
    )
    VALUES (
      '22222222-2222-2222-2222-222222222222',
      's_demo',
      't_demo',
      '11111111-1111-1111-1111-111111111111',
      'u_demo',
      'Pilot workflow carried forward from v0.7',
      '/workspace',
      'active'
    );
  `)

  await database.query(`
    INSERT INTO policy_bundles (
      id,
      tenant_id,
      version,
      engine,
      source_hash,
      source_text,
      active
    )
    VALUES (
      '33333333-3333-3333-3333-333333333333',
      't_demo',
      '0.7.0',
      'cedar',
      'legacy-hash',
      'fake',
      true
    );
  `)

  await database.query(`
    INSERT INTO audit_chain_state (tenant_id, last_hash, seq)
    VALUES ('t_demo', 'genesis', 0);
  `)
}

const applyPostV07Migrations = async (database: Database): Promise<void> => {
  for (const fileName of [
    "002_tenants.sql",
    "003_users.sql",
    "004_risk_rule_sets.sql",
    "005_rate_limits.sql",
    "006_backfill_demo_policy_bundle.sql",
  ]) {
    await database.query(await readSqlFile(`sql/migrations/${fileName}`))
  }
}

test("a v0.7 pilot-shaped database upgrades cleanly through the v1 migration chain", async () => {
  const database = await createTestDatabase()
  await createV07PilotState(database)

  await applyPostV07Migrations(database)

  const tenants = await database.query<{ readonly id: string; readonly name: string }>(
    "SELECT id, name FROM tenants ORDER BY id",
  )
  assert.deepEqual(tenants, [{ id: "t_demo", name: "t_demo" }])

  const users = await database.query<{
    readonly tenant_id: string
    readonly id: string
    readonly role: string
  }>(
    "SELECT tenant_id, id, role FROM users ORDER BY id",
  )
  assert.deepEqual(users, [
    { tenant_id: "t_demo", id: "u_demo", role: "operator" },
  ])

  const bundleRows = await database.query<{
    readonly version: string
    readonly source_hash: string
    readonly source_text: string
  }>(
    "SELECT version, source_hash, source_text FROM policy_bundles WHERE tenant_id = $1",
    ["t_demo"],
  )
  assert.equal(bundleRows[0]?.version, "0.7.0")
  assert.equal(
    bundleRows[0]?.source_hash,
    "5c8533bd835a317b9191d940ea78ef0c3a2f641a45add6affe6897d046989f1a",
  )
  assert.match(bundleRows[0]?.source_text ?? "", /resource\.credential_access == false/u)

  await seedDemoData(database)

  const seededUsers = await database.query<{ readonly count: string }>(
    "SELECT COUNT(*) AS count FROM users WHERE tenant_id = $1",
    ["t_demo"],
  )
  assert.equal(Number(seededUsers[0]?.count ?? "0"), 4)

  const riskRuleSets = await database.query<{ readonly count: string }>(
    "SELECT COUNT(*) AS count FROM risk_rule_sets WHERE tenant_id = $1",
    ["t_demo"],
  )
  assert.equal(Number(riskRuleSets[0]?.count ?? "0"), 0)

  const rateLimits = await database.query<{ readonly count: string }>(
    "SELECT COUNT(*) AS count FROM rate_limits WHERE tenant_id = $1",
    ["t_demo"],
  )
  assert.equal(Number(rateLimits[0]?.count ?? "0"), 0)

  await database.close()
})
