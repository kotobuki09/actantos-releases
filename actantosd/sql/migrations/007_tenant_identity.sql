-- Stage 3 tenant identity schema + composite tenant FKs (pg-mem safe).
-- RLS roles/policies live in 008_tenant_rls.sql (real PostgreSQL).

CREATE TABLE IF NOT EXISTS identity_subjects (
  id UUID PRIMARY KEY,
  issuer TEXT NOT NULL,
  subject TEXT NOT NULL,
  display_name TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (issuer, subject)
);

CREATE TABLE IF NOT EXISTS tenant_memberships (
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  subject_id UUID NOT NULL REFERENCES identity_subjects(id),
  role TEXT NOT NULL CHECK (role IN ('viewer', 'operator', 'admin')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, subject_id)
);

CREATE TABLE IF NOT EXISTS service_principals (
  id UUID PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  name TEXT NOT NULL,
  key_hash TEXT NOT NULL,
  scopes_json TEXT NOT NULL DEFAULT '[]',
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (tenant_id, id),
  UNIQUE (tenant_id, name)
);

-- Fail migration when legacy rows cross tenant boundaries (inline checks; no plpgsql).
-- Real Postgres integration also runs sql/fixtures/stage3-rls-preflight.sql.

ALTER TABLE agents DROP CONSTRAINT IF EXISTS uq_agents_tenant_id;
ALTER TABLE agents ADD CONSTRAINT uq_agents_tenant_id UNIQUE (tenant_id, id);
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS uq_sessions_tenant_id;
ALTER TABLE sessions ADD CONSTRAINT uq_sessions_tenant_id UNIQUE (tenant_id, id);
ALTER TABLE policy_bundles DROP CONSTRAINT IF EXISTS uq_policy_bundles_tenant_id;
ALTER TABLE policy_bundles ADD CONSTRAINT uq_policy_bundles_tenant_id UNIQUE (tenant_id, id);
ALTER TABLE tool_calls DROP CONSTRAINT IF EXISTS uq_tool_calls_tenant_id;
ALTER TABLE tool_calls ADD CONSTRAINT uq_tool_calls_tenant_id UNIQUE (tenant_id, id);
ALTER TABLE policy_decisions DROP CONSTRAINT IF EXISTS uq_policy_decisions_tenant_id;
ALTER TABLE policy_decisions ADD CONSTRAINT uq_policy_decisions_tenant_id UNIQUE (tenant_id, id);
ALTER TABLE mcp_servers DROP CONSTRAINT IF EXISTS uq_mcp_servers_tenant_id;
ALTER TABLE mcp_servers ADD CONSTRAINT uq_mcp_servers_tenant_id UNIQUE (tenant_id, id);

ALTER TABLE sessions DROP CONSTRAINT IF EXISTS sessions_agent_id_fkey;
ALTER TABLE sessions DROP CONSTRAINT IF EXISTS fk_sessions_tenant_agent;
ALTER TABLE sessions ADD CONSTRAINT fk_sessions_tenant_agent
  FOREIGN KEY (tenant_id, agent_id) REFERENCES agents(tenant_id, id);

ALTER TABLE tool_calls DROP CONSTRAINT IF EXISTS tool_calls_session_id_fkey;
ALTER TABLE tool_calls DROP CONSTRAINT IF EXISTS tool_calls_agent_id_fkey;
ALTER TABLE tool_calls DROP CONSTRAINT IF EXISTS fk_tool_calls_tenant_session;
ALTER TABLE tool_calls DROP CONSTRAINT IF EXISTS fk_tool_calls_tenant_agent;
ALTER TABLE tool_calls ADD CONSTRAINT fk_tool_calls_tenant_session
  FOREIGN KEY (tenant_id, session_id) REFERENCES sessions(tenant_id, id);
ALTER TABLE tool_calls ADD CONSTRAINT fk_tool_calls_tenant_agent
  FOREIGN KEY (tenant_id, agent_id) REFERENCES agents(tenant_id, id);

ALTER TABLE policy_decisions DROP CONSTRAINT IF EXISTS policy_decisions_tool_call_id_fkey;
ALTER TABLE policy_decisions DROP CONSTRAINT IF EXISTS policy_decisions_policy_bundle_id_fkey;
ALTER TABLE policy_decisions DROP CONSTRAINT IF EXISTS fk_policy_decisions_tenant_tool_call;
ALTER TABLE policy_decisions DROP CONSTRAINT IF EXISTS fk_policy_decisions_tenant_bundle;
ALTER TABLE policy_decisions ADD CONSTRAINT fk_policy_decisions_tenant_tool_call
  FOREIGN KEY (tenant_id, tool_call_id) REFERENCES tool_calls(tenant_id, id);
ALTER TABLE policy_decisions ADD CONSTRAINT fk_policy_decisions_tenant_bundle
  FOREIGN KEY (tenant_id, policy_bundle_id) REFERENCES policy_bundles(tenant_id, id);

ALTER TABLE approvals DROP CONSTRAINT IF EXISTS approvals_decision_id_fkey;
ALTER TABLE approvals DROP CONSTRAINT IF EXISTS approvals_tool_call_id_fkey;
ALTER TABLE approvals DROP CONSTRAINT IF EXISTS fk_approvals_tenant_decision;
ALTER TABLE approvals DROP CONSTRAINT IF EXISTS fk_approvals_tenant_tool_call;
ALTER TABLE approvals ADD CONSTRAINT fk_approvals_tenant_decision
  FOREIGN KEY (tenant_id, decision_id) REFERENCES policy_decisions(tenant_id, id);
ALTER TABLE approvals ADD CONSTRAINT fk_approvals_tenant_tool_call
  FOREIGN KEY (tenant_id, tool_call_id) REFERENCES tool_calls(tenant_id, id);

ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_session_id_fkey;
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_tool_call_id_fkey;
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS audit_events_decision_id_fkey;
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS fk_audit_events_tenant_session;
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS fk_audit_events_tenant_tool_call;
ALTER TABLE audit_events DROP CONSTRAINT IF EXISTS fk_audit_events_tenant_decision;
ALTER TABLE audit_events ADD CONSTRAINT fk_audit_events_tenant_session
  FOREIGN KEY (tenant_id, session_id) REFERENCES sessions(tenant_id, id);
ALTER TABLE audit_events ADD CONSTRAINT fk_audit_events_tenant_tool_call
  FOREIGN KEY (tenant_id, tool_call_id) REFERENCES tool_calls(tenant_id, id);
ALTER TABLE audit_events ADD CONSTRAINT fk_audit_events_tenant_decision
  FOREIGN KEY (tenant_id, decision_id) REFERENCES policy_decisions(tenant_id, id);

ALTER TABLE mcp_tool_versions ADD COLUMN IF NOT EXISTS tenant_id TEXT;
-- Backfill is performed by application writes / 008 on real Postgres.
-- Leave nullable for empty installs; application always sets tenant_id with server_id.
