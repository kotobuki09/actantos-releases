CREATE TABLE IF NOT EXISTS tenants (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO tenants (id, name)
SELECT tenant_id, tenant_id
FROM (
  SELECT tenant_id FROM agents
  UNION
  SELECT tenant_id FROM sessions
  UNION
  SELECT tenant_id FROM policy_bundles
  UNION
  SELECT tenant_id FROM tool_calls
  UNION
  SELECT tenant_id FROM policy_decisions
  UNION
  SELECT tenant_id FROM approvals
  UNION
  SELECT tenant_id FROM audit_chain_state
  UNION
  SELECT tenant_id FROM audit_events
  UNION
  SELECT tenant_id FROM budgets
  UNION
  SELECT tenant_id FROM kill_switches
  UNION
  SELECT tenant_id FROM mcp_servers
) AS existing_tenants
ON CONFLICT (id) DO NOTHING;

ALTER TABLE agents DROP CONSTRAINT IF EXISTS fk_agents_tenant;
ALTER TABLE agents
  ADD CONSTRAINT fk_agents_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

ALTER TABLE sessions DROP CONSTRAINT IF EXISTS fk_sessions_tenant;
ALTER TABLE sessions
  ADD CONSTRAINT fk_sessions_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

ALTER TABLE policy_bundles DROP CONSTRAINT IF EXISTS fk_policy_bundles_tenant;
ALTER TABLE policy_bundles
  ADD CONSTRAINT fk_policy_bundles_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

ALTER TABLE tool_calls DROP CONSTRAINT IF EXISTS fk_tool_calls_tenant;
ALTER TABLE tool_calls
  ADD CONSTRAINT fk_tool_calls_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

ALTER TABLE policy_decisions DROP CONSTRAINT IF EXISTS fk_policy_decisions_tenant;
ALTER TABLE policy_decisions
  ADD CONSTRAINT fk_policy_decisions_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

ALTER TABLE approvals DROP CONSTRAINT IF EXISTS fk_approvals_tenant;
ALTER TABLE approvals
  ADD CONSTRAINT fk_approvals_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

ALTER TABLE audit_chain_state DROP CONSTRAINT IF EXISTS fk_audit_chain_state_tenant;
ALTER TABLE audit_chain_state
  ADD CONSTRAINT fk_audit_chain_state_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS fk_audit_events_tenant;
ALTER TABLE audit_events
  ADD CONSTRAINT fk_audit_events_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

ALTER TABLE budgets DROP CONSTRAINT IF EXISTS fk_budgets_tenant;
ALTER TABLE budgets
  ADD CONSTRAINT fk_budgets_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

ALTER TABLE kill_switches DROP CONSTRAINT IF EXISTS fk_kill_switches_tenant;
ALTER TABLE kill_switches
  ADD CONSTRAINT fk_kill_switches_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);

ALTER TABLE mcp_servers DROP CONSTRAINT IF EXISTS fk_mcp_servers_tenant;
ALTER TABLE mcp_servers
  ADD CONSTRAINT fk_mcp_servers_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);
