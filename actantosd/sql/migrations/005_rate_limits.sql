CREATE TABLE IF NOT EXISTS rate_limits (
  id UUID PRIMARY KEY,
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  scope_type TEXT NOT NULL CHECK (scope_type IN ('tenant', 'agent', 'session', 'tool')),
  scope_id TEXT NOT NULL,
  action_key TEXT NOT NULL,
  limit_value BIGINT NOT NULL,
  window_seconds INT NOT NULL,
  current_value BIGINT NOT NULL DEFAULT 0,
  window_start TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_rate_limit_lookup
  ON rate_limits (tenant_id, scope_type, scope_id, action_key);
