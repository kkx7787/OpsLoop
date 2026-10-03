-- #103. 새 콘솔 이미지보다 먼저 적용한다. 콘솔 A/B가 DB 시계·같은 제한을 쓴다.
BEGIN;
CREATE TABLE IF NOT EXISTS console_login_limits (
    key text PRIMARY KEY,
    started_at timestamptz NOT NULL,
    attempts integer NOT NULL CHECK (attempts > 0)
);

CREATE OR REPLACE FUNCTION console_login_take(p_ip text, p_account text, p_pair text)
RETURNS integer
LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public
AS $$
DECLARE
    v_now timestamptz;
    v_keys text[] := ARRAY['ip:' || p_ip, 'account:' || p_account, 'pair:' || p_pair];
    v_caps integer[] := ARRAY[30, 10, 5];
    v_started timestamptz;
    v_count integer;
    v_wait integer := 0;
    j integer;
BEGIN
    IF p_ip IS NULL OR p_account IS NULL OR p_pair IS NULL
       OR p_ip !~ '^[0-9a-f]{64}$' OR p_account !~ '^[0-9a-f]{64}$' OR p_pair !~ '^[0-9a-f]{64}$' THEN
        RAISE EXCEPTION 'invalid login limit key';
    END IF;
    -- 해시 계산·통신은 이 잠금 밖에서 한다. 짧은 3개 카운터 변경만 직렬화해 교착/초과 승인을 막는다.
    PERFORM pg_advisory_xact_lock(103, 1);
    v_now := clock_timestamp();
    DELETE FROM public.console_login_limits WHERE started_at < v_now - interval '10 minutes';
    FOR j IN 1..3 LOOP
        SELECT started_at, attempts INTO v_started, v_count FROM public.console_login_limits WHERE key = v_keys[j];
        IF FOUND AND v_started > v_now - interval '60 seconds' AND v_count >= v_caps[j] THEN
            v_wait := greatest(v_wait, ceil(extract(epoch FROM v_started + interval '60 seconds' - v_now))::integer);
        END IF;
    END LOOP;
    -- 거절을 반복해도 대기 시각을 연장하지 않는다. 존재/비활성 여부와 무관하게 같은 기준이다.
    IF v_wait > 0 THEN RETURN v_wait; END IF;
    FOR j IN 1..3 LOOP
        INSERT INTO public.console_login_limits AS l (key, started_at, attempts) VALUES (v_keys[j], v_now, 1)
        ON CONFLICT (key) DO UPDATE SET
            started_at = CASE WHEN l.started_at <= v_now - interval '60 seconds' THEN v_now ELSE l.started_at END,
            attempts = CASE WHEN l.started_at <= v_now - interval '60 seconds' THEN 1 ELSE l.attempts + 1 END;
    END LOOP;
    RETURN 0;
END;
$$;
REVOKE ALL ON TABLE console_login_limits FROM PUBLIC;
REVOKE ALL ON FUNCTION console_login_take(text, text, text) FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'opsloop_console') THEN
        REVOKE ALL ON TABLE console_login_limits FROM opsloop_console;
        GRANT EXECUTE ON FUNCTION console_login_take(text, text, text) TO opsloop_console;
    END IF;
    IF EXISTS (SELECT FROM pg_roles WHERE rolname = 'opsloop_backup') THEN
        GRANT SELECT ON TABLE console_login_limits TO opsloop_backup;
    END IF;
END $$;
COMMIT;
