-- actantos-pg-only: this file requires a real Postgres instance (pg-mem will skip it)
-- v2 effect commit protocol
--
-- The gateway consumes a permit, records the authorization, calls the executor, then records the
-- outcome. A process that dies between the executor returning and the outcome being written leaves
-- no record of whether the external effect happened. Restarting cannot recover that, because the
-- only witness was in the dead process's memory.
--
-- This table makes the window observable. It answers one question with one word: did this effect
-- finish, fail, or do I not know?
--
-- `uncertain` exists because that third answer must not be collapsed into either of the other two.
-- Treating it as failed invites a retry, and a retry of an effect that actually succeeded applies it
-- twice. Treating it as committed claims a result nobody observed. Both are worse than admitting
-- ignorance, so the state has its own row and its own recovery rule: never retried automatically.
--
-- The action digest is written once and never changeable. Recovery must act on the action that was
-- authorized, not on one an operator or an attacker can rewrite in the row.

CREATE TABLE IF NOT EXISTS v2_effect_journal (
  tenant_id      text        NOT NULL,
  permit_id      text        NOT NULL,
  state          text        NOT NULL,
  action_digest  text        NOT NULL,
  tool           text        NOT NULL,
  resource       text        NOT NULL,
  started_at     timestamptz NOT NULL DEFAULT now(),
  updated_at     timestamptz NOT NULL DEFAULT now(),
  result_digest  text,
  error          text,
  attempts       integer     NOT NULL DEFAULT 0,

  CONSTRAINT v2_effect_journal_pkey PRIMARY KEY (tenant_id, permit_id),
  CONSTRAINT v2_effect_journal_state_valid
    CHECK (state IN ('prepared', 'executing', 'committed', 'failed', 'uncertain')),
  CONSTRAINT v2_effect_journal_attempts_nonneg CHECK (attempts >= 0),
  -- A terminal outcome carries the detail that explains it. `uncertain` is deliberately exempt:
  -- the absence of an outcome is the fact.
  CONSTRAINT v2_effect_journal_outcome_detail
    CHECK (
      state NOT IN ('committed', 'failed')
      OR (state = 'committed' AND result_digest IS NOT NULL)
      OR (state = 'failed' AND error IS NOT NULL)
    )
);

-- Recovery scans for rows that never reached a terminal state. Without this every sweep is a
-- sequential scan of the whole journal.
CREATE INDEX IF NOT EXISTS v2_effect_journal_unfinished_idx
  ON v2_effect_journal (tenant_id, updated_at)
  WHERE state IN ('prepared', 'executing');

-- The legal transitions. Anything else raises. This is the state machine, and it lives in the
-- database rather than in application code because application code is what crashed.
CREATE OR REPLACE FUNCTION v2_effect_journal_transition() RETURNS trigger AS $$
DECLARE
  permitted boolean;
BEGIN
  -- The authorized action is fixed at prepare time and is not a mutable column.
  IF NEW.action_digest IS DISTINCT FROM OLD.action_digest THEN
    RAISE EXCEPTION 'v2_effect_journal: action_digest is fixed at prepare time for permit %', OLD.permit_id;
  END IF;

  IF NEW.tenant_id IS DISTINCT FROM OLD.tenant_id OR NEW.permit_id IS DISTINCT FROM OLD.permit_id
     OR NEW.started_at IS DISTINCT FROM OLD.started_at THEN
    RAISE EXCEPTION 'v2_effect_journal: identity columns are immutable';
  END IF;

  IF NEW.state = OLD.state THEN
    -- A same-state write is bookkeeping: the attempt counter and the timestamp. It is not a
    -- licence to restate the outcome. Once an effect has committed, its result digest is a fact
    -- about the real world, and rewriting it would let the journal disagree with what happened.
    IF OLD.state IN ('committed', 'failed', 'uncertain') THEN
      IF NEW.result_digest IS DISTINCT FROM OLD.result_digest THEN
        RAISE EXCEPTION 'v2_effect_journal: % outcome is final for permit %', OLD.state, OLD.permit_id;
      END IF;
      IF NEW.error IS DISTINCT FROM OLD.error THEN
        RAISE EXCEPTION 'v2_effect_journal: % outcome is final for permit %', OLD.state, OLD.permit_id;
      END IF;
    END IF;

    NEW.updated_at := now();
    RETURN NEW;
  END IF;

  permitted := CASE OLD.state
    WHEN 'prepared'  THEN NEW.state IN ('executing', 'failed', 'uncertain')
    WHEN 'executing' THEN NEW.state IN ('committed', 'failed', 'uncertain')
    ELSE false  -- committed, failed and uncertain are terminal
  END;

  IF NOT permitted THEN
    RAISE EXCEPTION 'v2_effect_journal: illegal transition % -> % for permit %',
      OLD.state, NEW.state, OLD.permit_id;
  END IF;

  NEW.updated_at := now();
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS v2_effect_journal_transition_guard ON v2_effect_journal;
CREATE TRIGGER v2_effect_journal_transition_guard
  BEFORE UPDATE ON v2_effect_journal
  FOR EACH ROW EXECUTE FUNCTION v2_effect_journal_transition();

-- Deleting a journal row would erase the fact that an effect was ever in flight, which is the one
-- fact recovery exists to preserve. Rows are dropped by retention, which is a privileged
-- administrative act rather than something an application bug can do.
CREATE OR REPLACE FUNCTION v2_effect_journal_no_delete() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'v2_effect_journal rows are not deletable; % is not permitted', TG_OP;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS v2_effect_journal_delete_guard ON v2_effect_journal;
CREATE TRIGGER v2_effect_journal_delete_guard
  BEFORE DELETE ON v2_effect_journal
  FOR EACH ROW EXECUTE FUNCTION v2_effect_journal_no_delete();

ALTER TABLE v2_effect_journal ENABLE ROW LEVEL SECURITY;
ALTER TABLE v2_effect_journal FORCE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS v2_effect_journal_tenant_isolation ON v2_effect_journal;
CREATE POLICY v2_effect_journal_tenant_isolation ON v2_effect_journal
  USING (tenant_id = current_setting('actantos.tenant_id', true))
  WITH CHECK (tenant_id = current_setting('actantos.tenant_id', true));
