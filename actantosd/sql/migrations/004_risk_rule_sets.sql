CREATE TABLE IF NOT EXISTS risk_rule_sets (
  tenant_id TEXT PRIMARY KEY,
  rules_json JSONB NOT NULL,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE risk_rule_sets DROP CONSTRAINT IF EXISTS fk_risk_rule_sets_tenant;
ALTER TABLE risk_rule_sets
  ADD CONSTRAINT fk_risk_rule_sets_tenant FOREIGN KEY (tenant_id) REFERENCES tenants(id);
