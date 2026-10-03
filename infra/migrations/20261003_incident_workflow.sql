BEGIN;
-- #105: 배정은 업무 분담이며 기존 조치 권한을 대신하지 않는다.
ALTER TABLE incidents ADD COLUMN IF NOT EXISTS assigned_to text;
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conrelid='incidents'::regclass AND conname='incidents_assigned_to_fkey') THEN
        ALTER TABLE incidents ADD CONSTRAINT incidents_assigned_to_fkey FOREIGN KEY (assigned_to) REFERENCES console_users(username) ON DELETE RESTRICT;
    END IF;
END $$;
CREATE INDEX IF NOT EXISTS idx_inc_assigned ON incidents(assigned_to) WHERE assigned_to IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_actions_workflow ON actions(incident_key, id DESC);
CREATE INDEX IF NOT EXISTS idx_verdicts_workflow ON verdicts(incident_key, id DESC);
ALTER TABLE actions DROP CONSTRAINT IF EXISTS actions_action_check;
ALTER TABLE actions ADD CONSTRAINT actions_action_check CHECK (action IN ('block_ip','unblock_ip','acknowledge','suppress_rule','escalate','note','assign'));
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname='opsloop_console') THEN
        GRANT UPDATE(assigned_to) ON incidents TO opsloop_console;
    END IF;
END $$;
CREATE OR REPLACE FUNCTION console_account_delete(p_username text)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    -- set_config(…, true) 가 끝난 연결에서는 NULL 이 아니라 '' 가 돌아온다
    v_actor text := nullif(current_setting('opsloop.actor', true), '');
    u       console_users%ROWTYPE;
BEGIN
    IF v_actor IS NULL THEN
        RETURN 'no_actor';
    END IF;
    IF p_username = v_actor THEN
        RETURN 'self';
    END IF;
    SELECT * INTO u FROM console_users WHERE username = p_username FOR UPDATE;
    IF NOT FOUND THEN
        RETURN 'not_found';
    END IF;
    IF u.role = 'admin' THEN
        RETURN 'cli_only';
    END IF;
    IF EXISTS (SELECT 1 FROM incidents WHERE assigned_to=p_username) THEN
        RETURN 'assigned';
    END IF;
    IF u.last_login_at IS NOT NULL
       OR EXISTS (SELECT 1 FROM verdicts WHERE operator = p_username)
       OR EXISTS (SELECT 1 FROM actions WHERE operator = p_username)
       OR EXISTS (SELECT 1 FROM blocklist WHERE requested_by = p_username OR released_by = p_username) THEN
        RETURN 'in_use';
    END IF;
    DELETE FROM console_users WHERE username = p_username;
    RETURN 'ok';
END;
$$;
REVOKE ALL ON FUNCTION console_account_delete(text) FROM PUBLIC;
COMMIT;
