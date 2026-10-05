CREATE OR REPLACE FUNCTION enforce_tool_call_state_transitions()
RETURNS TRIGGER AS $$
BEGIN
  -- Allow inserts without transition check (assuming valid initial states like pending, decision_created, etc. which are checked by the CHECK constraint)
  IF TG_OP = 'INSERT' THEN
    RETURN NEW;
  END IF;

  -- State transitions
  IF OLD.status = 'pending' THEN
    IF NEW.status NOT IN ('decision_created', 'approval_pending', 'denied') THEN
      RAISE EXCEPTION 'Invalid state transition from % to %', OLD.status, NEW.status;
    END IF;

  ELSIF OLD.status = 'approval_pending' THEN
    IF NEW.status NOT IN ('approved', 'denied') THEN
      RAISE EXCEPTION 'Invalid state transition from % to %', OLD.status, NEW.status;
    END IF;

  ELSIF OLD.status = 'decision_created' THEN
    IF NEW.status NOT IN ('executing', 'blocked') THEN
      RAISE EXCEPTION 'Invalid state transition from % to %', OLD.status, NEW.status;
    END IF;

  ELSIF OLD.status = 'approved' THEN
    IF NEW.status NOT IN ('executing', 'blocked') THEN
      RAISE EXCEPTION 'Invalid state transition from % to %', OLD.status, NEW.status;
    END IF;

  ELSIF OLD.status = 'executing' THEN
    IF NEW.status NOT IN ('executed', 'failed', 'timeout') THEN
      RAISE EXCEPTION 'Invalid state transition from % to %', OLD.status, NEW.status;
    END IF;

  -- Terminal states cannot be changed
  ELSIF OLD.status IN ('denied', 'blocked', 'executed', 'failed', 'timeout') THEN
    IF NEW.status != OLD.status THEN
      RAISE EXCEPTION 'Cannot transition from terminal state % to %', OLD.status, NEW.status;
    END IF;
  END IF;

  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_enforce_tool_call_transitions ON tool_calls;
CREATE TRIGGER trg_enforce_tool_call_transitions
BEFORE UPDATE ON tool_calls
FOR EACH ROW
EXECUTE PROCEDURE enforce_tool_call_state_transitions();
