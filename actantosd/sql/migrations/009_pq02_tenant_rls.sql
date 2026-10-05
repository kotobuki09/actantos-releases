-- actantos-pg-only: this file requires a real Postgres instance (pg-mem will skip it)
-- PQ-02: Authenticated Identity and Tenant Isolation
-- Adds Row Level Security (RLS) to all tenant-scoped tables.
-- Rollback: DROP the policies, disable RLS on each table, DROP the role.
-- NOTE: The superuser / migration role retains BYPASSRLS; only the
--       application runtime role is restricted.

-- ---------------------------------------------------------------------------
-- 1. Create non-superuser runtime role if it does not exist
-- ---------------------------------------------------------------------------
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'actantos_runtime') THEN
    CREATE ROLE actantos_runtime LOGIN;
  END IF;
END$$;

-- Grant DML access to all tables for the runtime role.
-- (Adjust schema name to 'public' if not using a named schema.)
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO actantos_runtime;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO actantos_runtime;

-- Explicitly confirm no BYPASSRLS on this role
ALTER ROLE actantos_runtime NOBYPASSRLS;

-- ---------------------------------------------------------------------------
-- 2. Enable RLS on all tenant-scoped tables
-- ---------------------------------------------------------------------------
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;

ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE agents FORCE ROW LEVEL SECURITY;

ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;

ALTER TABLE policy_bundles ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_bundles FORCE ROW LEVEL SECURITY;

ALTER TABLE tool_calls ENABLE ROW LEVEL SECURITY;
ALTER TABLE tool_calls FORCE ROW LEVEL SECURITY;

ALTER TABLE policy_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_decisions FORCE ROW LEVEL SECURITY;

ALTER TABLE approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE approvals FORCE ROW LEVEL SECURITY;

ALTER TABLE audit_chain_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain_state FORCE ROW LEVEL SECURITY;

ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;

ALTER TABLE budgets ENABLE ROW LEVEL SECURITY;
ALTER TABLE budgets FORCE ROW LEVEL SECURITY;

ALTER TABLE kill_switches ENABLE ROW LEVEL SECURITY;
ALTER TABLE kill_switches FORCE ROW LEVEL SECURITY;

ALTER TABLE mcp_servers ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_servers FORCE ROW LEVEL SECURITY;

ALTER TABLE mcp_tool_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_tool_versions FORCE ROW LEVEL SECURITY;

-- ---------------------------------------------------------------------------
-- 3. RLS policies: rows visible/mutable only when current_setting matches
-- ---------------------------------------------------------------------------
-- Convention: callers SET LOCAL actantos.tenant_id = '<id>' at session start.
-- Superusers / migration roles bypass RLS automatically.

-- tenants: the tenant itself
DROP POLICY IF EXISTS tenants_isolation ON tenants;
CREATE POLICY tenants_isolation ON tenants
  USING (id = current_setting('actantos.tenant_id', true))
  WITH CHECK (id = current_setting('actantos.tenant_id', true));

-- users
DROP POLICY IF EXISTS users_isolation ON users;
CREATE POLICY users_isolation ON users
  USING (tenant_id = current_setting('actantos.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('actantos.tenant_id', true));

-- agents
DROP POLICY IF EXISTS agents_isolation ON agents;
CREATE POLICY agents_isolation ON agents
  USING (tenant_id = current_setting('actantos.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('actantos.tenant_id', true));

-- sessions
DROP POLICY IF EXISTS sessions_isolation ON sessions;
CREATE POLICY sessions_isolation ON sessions
  USING (tenant_id = current_setting('actantos.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('actantos.tenant_id', true));

-- policy_bundles
DROP POLICY IF EXISTS policy_bundles_isolation ON policy_bundles;
CREATE POLICY policy_bundles_isolation ON policy_bundles
  USING (tenant_id = current_setting('actantos.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('actantos.tenant_id', true));

-- tool_calls
DROP POLICY IF EXISTS tool_calls_isolation ON tool_calls;
CREATE POLICY tool_calls_isolation ON tool_calls
  USING (tenant_id = current_setting('actantos.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('actantos.tenant_id', true));

-- policy_decisions
DROP POLICY IF EXISTS policy_decisions_isolation ON policy_decisions;
CREATE POLICY policy_decisions_isolation ON policy_decisions
  USING (tenant_id = current_setting('actantos.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('actantos.tenant_id', true));

-- approvals
DROP POLICY IF EXISTS approvals_isolation ON approvals;
CREATE POLICY approvals_isolation ON approvals
  USING (tenant_id = current_setting('actantos.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('actantos.tenant_id', true));

-- audit_chain_state
DROP POLICY IF EXISTS audit_chain_state_isolation ON audit_chain_state;
CREATE POLICY audit_chain_state_isolation ON audit_chain_state
  USING (tenant_id = current_setting('actantos.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('actantos.tenant_id', true));

-- audit_events
DROP POLICY IF EXISTS audit_events_isolation ON audit_events;
CREATE POLICY audit_events_isolation ON audit_events
  USING (tenant_id = current_setting('actantos.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('actantos.tenant_id', true));

-- budgets
DROP POLICY IF EXISTS budgets_isolation ON budgets;
CREATE POLICY budgets_isolation ON budgets
  USING (tenant_id = current_setting('actantos.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('actantos.tenant_id', true));

-- kill_switches
DROP POLICY IF EXISTS kill_switches_isolation ON kill_switches;
CREATE POLICY kill_switches_isolation ON kill_switches
  USING (tenant_id = current_setting('actantos.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('actantos.tenant_id', true));

-- mcp_servers
DROP POLICY IF EXISTS mcp_servers_isolation ON mcp_servers;
CREATE POLICY mcp_servers_isolation ON mcp_servers
  USING (tenant_id = current_setting('actantos.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('actantos.tenant_id', true));

-- mcp_tool_versions: isolate via server's tenant
DROP POLICY IF EXISTS mcp_tool_versions_isolation ON mcp_tool_versions;
CREATE POLICY mcp_tool_versions_isolation ON mcp_tool_versions
  USING (
    server_id IN (
      SELECT id FROM mcp_servers
      WHERE tenant_id = current_setting('actantos.tenant_id', true)
    )
  )
  WITH CHECK (
    server_id IN (
      SELECT id FROM mcp_servers
      WHERE tenant_id = current_setting('actantos.tenant_id', true)
    )
  );

-- ---------------------------------------------------------------------------
-- 4. Allow migration/superuser connections to bypass (already implicit for
--    superusers; this is a reminder comment only).
-- ---------------------------------------------------------------------------
-- To run migrations: connect as a superuser or the schema owner role, which
-- has BYPASSRLS by default. Never use actantos_runtime for migrations.

COMMENT ON TABLE tenants IS 'PQ-02: RLS enforced via actantos.tenant_id session variable';
