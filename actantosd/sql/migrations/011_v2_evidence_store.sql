-- actantos-pg-only: this file requires a real Postgres instance (pg-mem will skip it)
-- v2 durable evidence store (invariant S13)
--
-- Evidence was a hash chain in process memory. Two things follow from that, and both are bad
-- for an audit trail:
--
--   1. A restart resets the chain to its genesis marker and seq 0. The records that existed
--      before the restart are gone, and a later bundle is indistinguishable from a chain that
--      never had them. Evidence of a past effect can simply disappear.
--   2. Nothing below this schema prevented UPDATE or DELETE. A record could be rewritten in
--      place; the hash chain would then verify only if the writer recomputed every subsequent
--      record, and the per-record signature would have to be re-signed with the issuer key.
--      Someone holding database credentials could therefore alter history.
--
-- This table makes history durable and genuinely append-only. `v2_evidence_append_only` is a
-- BEFORE UPDATE OR DELETE trigger rather than a REVOKE, because REVOKE only binds roles that
-- are not the table owner, and the owner is the role migrations run as. The trigger holds even
-- for the owner.
--
-- Checkpoints record a (seq, root_hash) pair at intervals. They let an auditor prove that the
-- prefix of a chain they were shown earlier has not been rewritten, and they make truncation
-- detectable: a chain shorter than its newest checkpoint cannot be a complete history.

CREATE TABLE IF NOT EXISTS v2_evidence (
  tenant_id     text    NOT NULL,
  seq           integer NOT NULL,
  evidence_type text    NOT NULL,
  occurred_at   text    NOT NULL,
  payload       jsonb   NOT NULL,
  prev_hash     text    NOT NULL,
  hash          text    NOT NULL,
  signature     jsonb   NOT NULL,

  CONSTRAINT v2_evidence_pkey PRIMARY KEY (tenant_id, seq),
  -- A record hash identifies exactly one record. This is what turns a duplicated record, spliced
  -- in from another chain or replayed after a purge, into a refused insert rather than a second
  -- copy of the same history.
  CONSTRAINT v2_evidence_hash_uniq UNIQUE (tenant_id, hash),
  CONSTRAINT v2_evidence_seq_nonneg CHECK (seq >= 0)
);

CREATE TABLE IF NOT EXISTS v2_evidence_checkpoint (
  tenant_id   text    NOT NULL,
  seq         integer NOT NULL,
  root_hash   text    NOT NULL,
  created_at  timestamptz NOT NULL DEFAULT now(),

  CONSTRAINT v2_evidence_checkpoint_pkey PRIMARY KEY (tenant_id, seq)
);

-- Append-only, enforced in the database.
--
-- The message is deliberately distinctive: a test asserts on it, so an application that
-- receives "permission denied" knows it hit this and not an unrelated privilege failure.
CREATE OR REPLACE FUNCTION v2_evidence_append_only() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'v2_evidence is append-only; % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS v2_evidence_no_update_delete ON v2_evidence;
CREATE TRIGGER v2_evidence_no_update_delete
  BEFORE UPDATE OR DELETE ON v2_evidence
  FOR EACH ROW EXECUTE FUNCTION v2_evidence_append_only();

DROP TRIGGER IF EXISTS v2_evidence_checkpoint_no_update_delete ON v2_evidence_checkpoint;
CREATE TRIGGER v2_evidence_checkpoint_no_update_delete
  BEFORE UPDATE OR DELETE ON v2_evidence_checkpoint
  FOR EACH ROW EXECUTE FUNCTION v2_evidence_append_only();

-- A checkpoint is a claim about the chain, so it may only be made about a record that exists and
-- whose hash is the one claimed. Without this check a checkpoint is just an assertion a caller
-- can write by hand, which is worse than no checkpoint at all.
CREATE OR REPLACE FUNCTION v2_evidence_checkpoint_guard() RETURNS trigger AS $$
DECLARE
  actual_hash text;
BEGIN
  SELECT hash INTO actual_hash
    FROM v2_evidence
   WHERE tenant_id = NEW.tenant_id AND seq = NEW.seq;

  IF actual_hash IS NULL THEN
    RAISE EXCEPTION 'v2_evidence_checkpoint: no record at seq % for this tenant', NEW.seq;
  END IF;

  IF actual_hash <> NEW.root_hash THEN
    RAISE EXCEPTION 'v2_evidence_checkpoint: root_hash does not match the record at seq %', NEW.seq;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS v2_evidence_checkpoint_validate ON v2_evidence_checkpoint;
CREATE TRIGGER v2_evidence_checkpoint_validate
  BEFORE INSERT ON v2_evidence_checkpoint
  FOR EACH ROW EXECUTE FUNCTION v2_evidence_checkpoint_guard();

-- Reading a tenant's tail must not scan the whole chain.
CREATE INDEX IF NOT EXISTS v2_evidence_tenant_type_idx ON v2_evidence (tenant_id, evidence_type);

-- Row Level Security, matching every other tenant-scoped table in this schema. Evidence is the
-- most sensitive thing this system writes: it records which actions were authorized, by whom,
-- and against which target. A tenant isolation bug here is a tenant isolation bug everywhere.
ALTER TABLE v2_evidence ENABLE ROW LEVEL SECURITY;
ALTER TABLE v2_evidence FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS v2_evidence_tenant_isolation ON v2_evidence;
CREATE POLICY v2_evidence_tenant_isolation ON v2_evidence
  USING (tenant_id = current_setting('actantos.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('actantos.tenant_id', true));

ALTER TABLE v2_evidence_checkpoint ENABLE ROW LEVEL SECURITY;
ALTER TABLE v2_evidence_checkpoint FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS v2_evidence_checkpoint_tenant_isolation ON v2_evidence_checkpoint;
CREATE POLICY v2_evidence_checkpoint_tenant_isolation ON v2_evidence_checkpoint
  USING (tenant_id = current_setting('actantos.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('actantos.tenant_id', true));