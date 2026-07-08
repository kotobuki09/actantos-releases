CREATE TABLE IF NOT EXISTS users (
  tenant_id TEXT NOT NULL REFERENCES tenants(id),
  id TEXT NOT NULL,
  name TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'operator' CHECK (role IN ('operator', 'admin', 'service')),
  status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (tenant_id, id)
);

INSERT INTO users (tenant_id, id, name, role)
SELECT tenant_id, owner_user_id, owner_user_id, 'operator'
FROM agents
ON CONFLICT (tenant_id, id) DO NOTHING;

INSERT INTO users (tenant_id, id, name, role)
SELECT tenant_id, user_id, user_id, 'operator'
FROM sessions
ON CONFLICT (tenant_id, id) DO NOTHING;

INSERT INTO users (tenant_id, id, name, role)
SELECT tenant_id, approver_user_id, approver_user_id, 'admin'
FROM approvals
WHERE approver_user_id IS NOT NULL
ON CONFLICT (tenant_id, id) DO NOTHING;

INSERT INTO users (tenant_id, id, name, role)
SELECT tenant_id, decided_by, decided_by, 'admin'
FROM approvals
WHERE decided_by IS NOT NULL
ON CONFLICT (tenant_id, id) DO NOTHING;

ALTER TABLE agents DROP CONSTRAINT IF EXISTS fk_agents_owner_user;
ALTER TABLE agents
  ADD CONSTRAINT fk_agents_owner_user
  FOREIGN KEY (tenant_id, owner_user_id) REFERENCES users(tenant_id, id);

ALTER TABLE sessions DROP CONSTRAINT IF EXISTS fk_sessions_user;
ALTER TABLE sessions
  ADD CONSTRAINT fk_sessions_user
  FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id);

ALTER TABLE approvals DROP CONSTRAINT IF EXISTS fk_approvals_approver_user;
ALTER TABLE approvals
  ADD CONSTRAINT fk_approvals_approver_user
  FOREIGN KEY (tenant_id, approver_user_id) REFERENCES users(tenant_id, id);

ALTER TABLE approvals DROP CONSTRAINT IF EXISTS fk_approvals_decided_by_user;
ALTER TABLE approvals
  ADD CONSTRAINT fk_approvals_decided_by_user
  FOREIGN KEY (tenant_id, decided_by) REFERENCES users(tenant_id, id);
