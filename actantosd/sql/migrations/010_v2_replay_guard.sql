-- actantos-pg-only: this file requires a real Postgres instance (pg-mem will skip it)
-- v2 durable replay guard (invariant S9)
--
-- The effect gateway used to keep consumed permit nonces in a process-memory Set. Restarting
-- the gateway made every consumed permit usable again. This table makes first-use a durable,
-- database-enforced fact.
--
-- Atomicity is the whole point. `INSERT ... ON CONFLICT DO NOTHING` decides first-use in a
-- single statement, so two gateways racing on one permit produce exactly one winner regardless
-- of ordering, process identity, or host. A read-then-write would not: under READ COMMITTED
-- both replicas can observe an absent row and both proceed.
--
-- Two constraints, deliberately separate:
--   PRIMARY KEY (tenant_id, nonce)    - replaying a nonce is refused
--   UNIQUE      (tenant_id, permit_id) - reusing a permit id under a fresh nonce is refused
--
-- Both are scoped by tenant_id. A tenant cannot consume, probe, or block another tenant's
-- nonces, and cannot learn that a nonce exists elsewhere by attempting to reuse it.
--
-- expires_at is the permit's own expiry, used only for retention cleanup. It never authorises
-- anything: `verifyEffectPermit` rejects an expired permit before this table is consulted.

CREATE TABLE IF NOT EXISTS v2_replay_guard (
  tenant_id   text        NOT NULL,
  nonce       text        NOT NULL,
  permit_id   text        NOT NULL,
  consumed_at timestamptz NOT NULL DEFAULT now(),
  expires_at  timestamptz NOT NULL,

  CONSTRAINT v2_replay_guard_pkey PRIMARY KEY (tenant_id, nonce),
  CONSTRAINT v2_replay_guard_permit_uniq UNIQUE (tenant_id, permit_id),
  CONSTRAINT v2_replay_guard_expiry CHECK (expires_at IS NOT NULL)
);

-- Retention cleanup scans on expiry. Without this the whole table is scanned each sweep.
CREATE INDEX IF NOT EXISTS v2_replay_guard_expires_at_idx ON v2_replay_guard (expires_at);

-- Row Level Security, matching every other tenant-scoped table in this schema. Without it a
-- bug in application code would leak replay state across tenants.
ALTER TABLE v2_replay_guard ENABLE ROW LEVEL SECURITY;
ALTER TABLE v2_replay_guard FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS v2_replay_guard_tenant_isolation ON v2_replay_guard;
CREATE POLICY v2_replay_guard_tenant_isolation ON v2_replay_guard
  USING (tenant_id = current_setting('actantos.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('actantos.tenant_id', true));