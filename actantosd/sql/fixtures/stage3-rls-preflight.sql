\set ON_ERROR_STOP on
BEGIN;

CREATE TEMP TABLE stage3_rls_probe (
  tenant_id TEXT NOT NULL,
  value TEXT NOT NULL
);
INSERT INTO stage3_rls_probe VALUES
  ('t_stage3_alpha', 'alpha-visible'),
  ('t_stage3_beta', 'beta-visible');

ALTER TABLE stage3_rls_probe ENABLE ROW LEVEL SECURITY;
ALTER TABLE stage3_rls_probe FORCE ROW LEVEL SECURITY;
CREATE POLICY stage3_rls_probe_tenant ON stage3_rls_probe
  USING (tenant_id = current_setting('actantos.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('actantos.tenant_id', true));

SELECT set_config('actantos.tenant_id', 't_stage3_alpha', true);
DO $$
BEGIN
  IF (SELECT count(*) FROM stage3_rls_probe) <> 1 THEN
    RAISE EXCEPTION 'RLS alpha fixture did not isolate exactly one row';
  END IF;
  IF EXISTS (SELECT 1 FROM stage3_rls_probe WHERE tenant_id = 't_stage3_beta') THEN
    RAISE EXCEPTION 'RLS leaked beta fixture into alpha context';
  END IF;
END $$;

SELECT set_config('actantos.tenant_id', 't_stage3_beta', true);
DO $$
BEGIN
  IF (SELECT count(*) FROM stage3_rls_probe) <> 1 THEN
    RAISE EXCEPTION 'RLS beta fixture did not isolate exactly one row';
  END IF;
END $$;

SELECT 'ACTANTOS_RLS_READY';
ROLLBACK;
