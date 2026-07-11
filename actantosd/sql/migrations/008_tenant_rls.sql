-- Stage 3 PostgreSQL RLS + app roles.
-- Requires real PostgreSQL (not pg-mem). Unit tests assert this file via static checks;
-- createTestDatabase skips this file. Production migrateDatabase applies it.

-- legacy tenant relationship validation failed
DO $$
BEGIN
  IF EXISTS (
    SELECT 1 FROM sessions s JOIN agents a ON a.id = s.agent_id
    WHERE s.tenant_id <> a.tenant_id
  ) OR EXISTS (
    SELECT 1 FROM tool_calls tc JOIN sessions s ON s.id = tc.session_id
    WHERE tc.tenant_id <> s.tenant_id
  ) OR EXISTS (
    SELECT 1 FROM tool_calls tc JOIN agents a ON a.id = tc.agent_id
    WHERE tc.tenant_id <> a.tenant_id
  ) OR EXISTS (
    SELECT 1 FROM policy_decisions pd JOIN tool_calls tc ON tc.id = pd.tool_call_id
    WHERE pd.tenant_id <> tc.tenant_id
  ) OR EXISTS (
    SELECT 1 FROM approvals ap JOIN policy_decisions pd ON pd.id = ap.decision_id
    WHERE ap.tenant_id <> pd.tenant_id
  ) OR EXISTS (
    SELECT 1 FROM approvals ap JOIN tool_calls tc ON tc.id = ap.tool_call_id
    WHERE ap.tenant_id <> tc.tenant_id
  ) OR EXISTS (
    SELECT 1 FROM audit_events ae JOIN sessions s ON s.id = ae.session_id
    WHERE ae.tenant_id <> s.tenant_id
  ) OR EXISTS (
    SELECT 1 FROM audit_events ae JOIN tool_calls tc ON tc.id = ae.tool_call_id
    WHERE ae.tenant_id <> tc.tenant_id
  ) OR EXISTS (
    SELECT 1 FROM audit_events ae JOIN policy_decisions pd ON pd.id = ae.decision_id
    WHERE ae.tenant_id <> pd.tenant_id
  ) THEN
    RAISE EXCEPTION 'legacy tenant relationship validation failed';
  END IF;
END $$;

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'actantos_app') THEN
    CREATE ROLE actantos_app NOLOGIN NOBYPASSRLS;
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'actantos_maintenance') THEN
    CREATE ROLE actantos_maintenance NOLOGIN BYPASSRLS;
  END IF;
END $$;

GRANT USAGE ON SCHEMA public TO actantos_app, actantos_maintenance;
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO actantos_app;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO actantos_maintenance;

ALTER TABLE agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_bundles ENABLE ROW LEVEL SECURITY;
ALTER TABLE tool_calls ENABLE ROW LEVEL SECURITY;
ALTER TABLE policy_decisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE approvals ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_chain_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE budgets ENABLE ROW LEVEL SECURITY;
ALTER TABLE kill_switches ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_servers ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_tool_versions ENABLE ROW LEVEL SECURITY;
ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE risk_rule_sets ENABLE ROW LEVEL SECURITY;
ALTER TABLE rate_limits ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE service_principals ENABLE ROW LEVEL SECURITY;
ALTER TABLE identity_subjects ENABLE ROW LEVEL SECURITY;

ALTER TABLE agents FORCE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE ROW LEVEL SECURITY;
ALTER TABLE policy_bundles FORCE ROW LEVEL SECURITY;
ALTER TABLE tool_calls FORCE ROW LEVEL SECURITY;
ALTER TABLE policy_decisions FORCE ROW LEVEL SECURITY;
ALTER TABLE approvals FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_chain_state FORCE ROW LEVEL SECURITY;
ALTER TABLE audit_events FORCE ROW LEVEL SECURITY;
ALTER TABLE budgets FORCE ROW LEVEL SECURITY;
ALTER TABLE kill_switches FORCE ROW LEVEL SECURITY;
ALTER TABLE mcp_servers FORCE ROW LEVEL SECURITY;
ALTER TABLE mcp_tool_versions FORCE ROW LEVEL SECURITY;
ALTER TABLE users FORCE ROW LEVEL SECURITY;
ALTER TABLE risk_rule_sets FORCE ROW LEVEL SECURITY;
ALTER TABLE rate_limits FORCE ROW LEVEL SECURITY;
ALTER TABLE tenant_memberships FORCE ROW LEVEL SECURITY;
ALTER TABLE service_principals FORCE ROW LEVEL SECURITY;
ALTER TABLE identity_subjects FORCE ROW LEVEL SECURITY;

DO $$
DECLARE table_name TEXT;
BEGIN
  FOREACH table_name IN ARRAY ARRAY[
    'agents', 'sessions', 'policy_bundles', 'tool_calls', 'policy_decisions',
    'approvals', 'audit_chain_state', 'audit_events', 'budgets', 'kill_switches',
    'mcp_servers', 'mcp_tool_versions', 'users', 'risk_rule_sets', 'rate_limits',
    'tenant_memberships', 'service_principals'
  ] LOOP
    EXECUTE format('DROP POLICY IF EXISTS tenant_isolation ON %I', table_name);
    EXECUTE format(
      'CREATE POLICY tenant_isolation ON %I TO actantos_app USING (tenant_id = nullif(current_setting(''actantos.tenant_id'', true), '''')) WITH CHECK (tenant_id = nullif(current_setting(''actantos.tenant_id'', true), ''''))',
      table_name
    );
  END LOOP;
END $$;

DROP POLICY IF EXISTS identity_subject_membership ON identity_subjects;
CREATE POLICY identity_subject_membership ON identity_subjects TO actantos_app
  USING (EXISTS (
    SELECT 1 FROM tenant_memberships tm
    WHERE tm.subject_id = identity_subjects.id
      AND tm.tenant_id = nullif(current_setting('actantos.tenant_id', true), '')
  ));
