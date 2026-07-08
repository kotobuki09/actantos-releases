CREATE TABLE IF NOT EXISTS agents (
  id UUID PRIMARY KEY,
  external_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  runtime_type TEXT NOT NULL CHECK (runtime_type IN ('pi', 'mcp', 'langgraph', 'custom')),
  owner_user_id TEXT NOT NULL,
  environment TEXT NOT NULL CHECK (environment IN ('dev', 'staging', 'prod')),
  risk_tier TEXT NOT NULL CHECK (risk_tier IN ('low', 'medium', 'high')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_agents_tenant_external
  ON agents (tenant_id, external_id);

CREATE TABLE IF NOT EXISTS sessions (
  id UUID PRIMARY KEY,
  external_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  agent_id UUID NOT NULL REFERENCES agents(id),
  user_id TEXT NOT NULL,
  purpose TEXT,
  cwd TEXT,
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'ended', 'killed')),
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ended_at TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_sessions_tenant_external
  ON sessions (tenant_id, external_id);

CREATE INDEX IF NOT EXISTS idx_sessions_agent
  ON sessions (agent_id);

CREATE TABLE IF NOT EXISTS policy_bundles (
  id UUID PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  version TEXT NOT NULL,
  engine TEXT NOT NULL DEFAULT 'cedar',
  source_hash TEXT NOT NULL,
  source_text TEXT NOT NULL,
  active BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS tool_calls (
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
  status TEXT NOT NULL DEFAULT 'pending'
    CHECK (status IN (
      'pending', 'decision_created', 'approval_pending',
      'approved', 'denied', 'blocked', 'executing',
      'executed', 'failed', 'timeout'
    )),
  result_hash TEXT,
  started_at TIMESTAMPTZ,
  finished_at TIMESTAMPTZ,
  error_code TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_tool_calls_tenant_request
  ON tool_calls (tenant_id, request_id);

CREATE INDEX IF NOT EXISTS idx_tool_calls_session_created
  ON tool_calls (session_id, created_at DESC);

CREATE TABLE IF NOT EXISTS policy_decisions (
  id UUID PRIMARY KEY,
  request_id TEXT NOT NULL,
  tenant_id TEXT NOT NULL,
  tool_call_id UUID NOT NULL REFERENCES tool_calls(id),
  policy_bundle_id UUID REFERENCES policy_bundles(id),
  cedar_result TEXT NOT NULL CHECK (cedar_result IN ('permit', 'forbid')),
  risk_class TEXT NOT NULL,
  approval_req BOOLEAN NOT NULL DEFAULT false,
  final_decision TEXT NOT NULL CHECK (final_decision IN ('allow', 'deny', 'approval_required')),
  decision_mode TEXT NOT NULL DEFAULT 'enforce' CHECK (decision_mode IN ('enforce', 'dry_run')),
  reason TEXT NOT NULL,
  reason_code TEXT NOT NULL DEFAULT 'unknown',
  constraints_json JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_policy_decisions_tenant_request
  ON policy_decisions (tenant_id, request_id);

CREATE INDEX IF NOT EXISTS idx_decisions_tool_call
  ON policy_decisions (tool_call_id);

CREATE TABLE IF NOT EXISTS approvals (
  id UUID PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  decision_id UUID NOT NULL REFERENCES policy_decisions(id),
  tool_call_id UUID NOT NULL REFERENCES tool_calls(id),
  status TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'approved', 'denied', 'expired')),
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

CREATE INDEX IF NOT EXISTS idx_approvals_status_expires
  ON approvals (tenant_id, status, expires_at);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_approvals_decision
  ON approvals (decision_id);

CREATE TABLE IF NOT EXISTS audit_chain_state (
  tenant_id TEXT PRIMARY KEY,
  last_hash TEXT NOT NULL DEFAULT 'genesis',
  seq BIGINT NOT NULL DEFAULT 0,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS audit_events (
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

CREATE UNIQUE INDEX IF NOT EXISTS uniq_audit_events_tenant_seq
  ON audit_events (tenant_id, seq);

CREATE TABLE IF NOT EXISTS budgets (
  id UUID PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  scope_type TEXT NOT NULL CHECK (scope_type IN ('tenant', 'agent', 'session', 'tool')),
  scope_id TEXT NOT NULL,
  metric TEXT NOT NULL,
  limit_value BIGINT NOT NULL,
  window_seconds INT NOT NULL,
  current_value BIGINT NOT NULL DEFAULT 0,
  window_start TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_budget_lookup
  ON budgets (tenant_id, scope_type, scope_id, metric);

CREATE TABLE IF NOT EXISTS kill_switches (
  id UUID PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  scope_type TEXT NOT NULL CHECK (scope_type IN ('tenant', 'agent', 'session', 'tool')),
  scope_id TEXT NOT NULL,
  reason TEXT NOT NULL,
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_kill_switch_lookup
  ON kill_switches (tenant_id, scope_type, scope_id, enabled);

CREATE TABLE IF NOT EXISTS mcp_servers (
  id UUID PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  name TEXT NOT NULL,
  transport TEXT NOT NULL CHECK (transport IN ('stdio', 'sse', 'http')),
  upstream_url TEXT,
  server_identity_hash TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'active',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS mcp_tool_versions (
  id UUID PRIMARY KEY,
  server_id UUID NOT NULL REFERENCES mcp_servers(id),
  tool_name TEXT NOT NULL,
  schema_hash TEXT NOT NULL,
  description_hash TEXT NOT NULL,
  manifest_json JSONB NOT NULL,
  approved BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
