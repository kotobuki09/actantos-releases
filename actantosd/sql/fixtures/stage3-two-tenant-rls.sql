BEGIN;

INSERT INTO tenants (id, name, status)
VALUES
  ('t_stage3_alpha', 'Stage 3 Alpha', 'active'),
  ('t_stage3_beta', 'Stage 3 Beta', 'active')
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, status = EXCLUDED.status;

INSERT INTO users (tenant_id, id, name, role, status)
VALUES
  ('t_stage3_alpha', 'u_stage3_alpha', 'Alpha Fixture User', 'operator', 'active'),
  ('t_stage3_beta', 'u_stage3_beta', 'Beta Fixture User', 'operator', 'active')
ON CONFLICT (tenant_id, id) DO UPDATE SET name = EXCLUDED.name, status = EXCLUDED.status;

INSERT INTO agents (id, tenant_id, external_id, name, runtime_type, owner_user_id, environment, risk_tier, status)
VALUES
  ('00000000-0000-4000-8000-0000000000a1', 't_stage3_alpha', 'fixture-agent', 'Alpha Fixture Agent', 'custom', 'u_stage3_alpha', 'prod', 'high', 'active'),
  ('00000000-0000-4000-8000-0000000000b1', 't_stage3_beta', 'fixture-agent', 'Beta Fixture Agent', 'custom', 'u_stage3_beta', 'prod', 'high', 'active')
ON CONFLICT (id) DO UPDATE SET name = EXCLUDED.name, status = EXCLUDED.status;

INSERT INTO sessions (id, tenant_id, agent_id, external_id, user_id, purpose, status)
VALUES
  ('00000000-0000-4000-8000-0000000000a2', 't_stage3_alpha', '00000000-0000-4000-8000-0000000000a1', 'fixture-session', 'u_stage3_alpha', 'Stage 3 RLS fixture', 'active'),
  ('00000000-0000-4000-8000-0000000000b2', 't_stage3_beta', '00000000-0000-4000-8000-0000000000b1', 'fixture-session', 'u_stage3_beta', 'Stage 3 RLS fixture', 'active')
ON CONFLICT (id) DO UPDATE SET status = EXCLUDED.status;

COMMIT;
