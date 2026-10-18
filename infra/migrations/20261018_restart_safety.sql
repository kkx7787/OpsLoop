-- #130: 개별 세션 철회와 구형 집행 결과 보호. 기존 판정·차단 정책은 바꾸지 않는다.
BEGIN;
SET LOCAL lock_timeout = '5s';

CREATE TABLE IF NOT EXISTS console_session_revocations (
    token_hash text PRIMARY KEY CHECK (token_hash ~ '^[0-9a-f]{64}$'),
    expires_at timestamptz NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_console_session_revocations_expiry ON console_session_revocations(expires_at);
CREATE OR REPLACE FUNCTION console_session_revoke(p_hash text, p_expires timestamptz)
RETURNS void LANGUAGE plpgsql SECURITY DEFINER
SET search_path = pg_catalog, public AS $$
BEGIN
    IF p_hash IS NULL OR p_hash !~ '^[0-9a-f]{64}$' OR p_expires IS NULL
       OR p_expires > clock_timestamp() + interval '24 hours' THEN
        RAISE EXCEPTION 'invalid session revocation' USING ERRCODE = '22023';
    END IF;
    DELETE FROM public.console_session_revocations WHERE expires_at < clock_timestamp();
    INSERT INTO public.console_session_revocations(token_hash, expires_at) VALUES (p_hash, p_expires)
        ON CONFLICT (token_hash) DO UPDATE
        SET expires_at = greatest(console_session_revocations.expires_at, EXCLUDED.expires_at);
END $$;
REVOKE ALL ON console_session_revocations FROM PUBLIC;
REVOKE ALL ON FUNCTION console_session_revoke(text,timestamptz) FROM PUBLIC;
DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='opsloop_console') THEN
        REVOKE ALL ON console_session_revocations FROM opsloop_console;
        GRANT SELECT ON console_session_revocations TO opsloop_console;
        GRANT EXECUTE ON FUNCTION console_session_revoke(text,timestamptz) TO opsloop_console;
    END IF;
END $$;

-- enforcement JSON과 마찬가지로 구형 결과 세 열도 집행 역할만 변경한다.
-- 콘솔의 요청·연장·해제는 허용하되, 적용됐다는 증거를 꾸미지는 못한다.
CREATE OR REPLACE FUNCTION blocklist_legacy_enforcement_guard() RETURNS trigger
LANGUAGE plpgsql SET search_path = pg_catalog, public AS $$
BEGIN
    IF (TG_OP='INSERT' AND (NEW.method IS NOT NULL OR NEW.enforced_at IS NOT NULL OR NEW.enforce_note IS NOT NULL))
       OR (TG_OP='UPDATE' AND (NEW.method IS DISTINCT FROM OLD.method
                              OR NEW.enforced_at IS DISTINCT FROM OLD.enforced_at
                              OR NEW.enforce_note IS DISTINCT FROM OLD.enforce_note)) THEN
        IF session_user::text <> 'opsloop_enforcer'
           AND NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname=session_user AND rolsuper) THEN
            RAISE EXCEPTION '차단 적용 결과는 집행기만 쓴다' USING ERRCODE='42501';
        END IF;
    END IF;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION blocklist_legacy_enforcement_guard() FROM PUBLIC;
CREATE OR REPLACE TRIGGER blocklist_legacy_enforcement_guard
    BEFORE INSERT OR UPDATE OF method, enforced_at, enforce_note ON blocklist
    FOR EACH ROW EXECUTE FUNCTION blocklist_legacy_enforcement_guard();
COMMIT;
