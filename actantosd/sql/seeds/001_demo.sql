INSERT INTO tenants (id, name, status)
VALUES ('t_demo', 'Demo Tenant', 'active')
ON CONFLICT (id) DO NOTHING;

INSERT INTO users (tenant_id, id, name, role, status)
VALUES
  ('t_demo', 'u_demo', 'Demo Developer', 'operator', 'active'),
  ('t_demo', 'u_dashboard', 'Dashboard Operator', 'admin', 'active'),
  ('t_demo', 'u_admin', 'Demo Administrator', 'admin', 'active'),
  ('t_demo', 'admin', 'CLI Demo Admin', 'admin', 'active')
ON CONFLICT (tenant_id, id) DO NOTHING;

INSERT INTO agents (
  id, external_id, tenant_id, name, runtime_type, owner_user_id,
  environment, risk_tier, status
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
)
ON CONFLICT (tenant_id, external_id) DO NOTHING;

INSERT INTO sessions (
  id, external_id, tenant_id, agent_id, user_id, purpose, cwd, status
)
VALUES (
  '22222222-2222-2222-2222-222222222222',
  's_demo',
  't_demo',
  '11111111-1111-1111-1111-111111111111',
  'u_demo',
  'Week 1 demo session',
  '/workspace',
  'active'
)
ON CONFLICT (tenant_id, external_id) DO NOTHING;

INSERT INTO policy_bundles (
  id, tenant_id, version, engine, source_hash, source_text, active
)
VALUES (
  '33333333-3333-3333-3333-333333333333',
  't_demo',
  '0.1.0',
  'cedar',
  '5c8533bd835a317b9191d940ea78ef0c3a2f641a45add6affe6897d046989f1a',
  'permit (
  principal,
  action,
  resource
)
when {
  resource.credential_access == false
};',
  true
)
ON CONFLICT (id) DO NOTHING;

INSERT INTO audit_chain_state (tenant_id, last_hash, seq)
VALUES ('t_demo', 'genesis', 0)
ON CONFLICT (tenant_id) DO NOTHING;
