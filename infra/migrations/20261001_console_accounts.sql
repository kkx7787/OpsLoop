-- 콘솔 계정 관리 (이슈 #59). schema.sql 의 감사 조회 뷰(audit_log) · 추가만 되는 행 보호(audit_append_only · trg_audit_append_only)
--   문장과 '콘솔 계정 관리 (이슈 #59)' 블록이 글자 그대로 들어 있으며 여러 번 적용해도 같다 (infra/test_console_accounts_db.py 가 대조한다).
--   - console_users 열: disabled_at(비활성 시각, NULL = 활성) · updated_at(역할 · 활성 · 비밀번호가 바뀐 때. 기존 행은 created_at)
--   - console_users_stamp: updated_at 도장 트리거. 로그인 기록(last_login_at) 갱신으로는 돌지 않는다
--   - console_account_set: 콘솔의 관제사 ↔ 조회자 역할 변경 · 비활성 · 재활성 함수(SECURITY DEFINER). 콘솔 역할은 실행 권한만 받는다
--     (계정 표 UPDATE 는 여전히 last_login_at 열뿐이다)
--   - audit_console_users: 계정 변경 감사(console.account.*). 감사 조회 뷰와 추가만 되는 행 보호에 console.account.% 를 더한다
--   콘솔 새 이미지(요청마다 계정 상태를 읽는다)보다 먼저 적용하고, verify-db-roles.sh 로 확인한 뒤 이미지를 올린다.
--   옛 이미지는 새 열을 읽지 않으므로 먼저 적용해도 그대로 돈다(로그인 기록 갱신은 트리거를 부르지 않는다).
--   20260923_console_ops.sql · 20260924_notify.sql 을 다시 적용하면 이 파일도 다시 적용한다(둘 다 감사 조회 뷰와 보호 트리거를
--   계정 조건 없이 다시 만든다. 그러면 계정 감사 행이 감사 화면에서 빠지고 고치거나 지울 수 있게 된다).
--   역할 블록(schema.sql · 20260924_db_roles.sql)은 표 권한만 거두므로 다시 적용해도 콘솔의 함수 실행 권한은 남는다.
-- 적용 (Mac, 저장소 루트):
--   ssh -F ~/.ssh/config.opsloop data01 'sudo -n docker exec -i opsloop-db psql -U opsloop -d opsloop -v ON_ERROR_STOP=1 -q' \
--     < infra/migrations/20261001_console_accounts.sql
-- 확인: infra/vmware/scripts/verify-db-roles.sh 의 '콘솔 계정 관리' 줄
BEGIN;
-- 감사 기록 조회 (S-14). 차단 변경 · 콘솔에서 발급·취소한 노드 토큰 · 알림 채널 변경 · 계정 변경의 메타데이터만 담는다
CREATE OR REPLACE VIEW audit_log AS
SELECT ts, eventid, username AS actor, host(src_ip) AS db_client, input AS detail
  FROM events
 WHERE sensor = 'audit' AND (eventid LIKE 'console.block.%' OR eventid LIKE 'console.node.token.%'
                             OR eventid LIKE 'console.notify.%' OR eventid LIKE 'console.account.%');

-- 차단 변경 · 등록 토큰 · 알림 채널 · 계정 감사 행은 추가만 된다. 적재기 · 다리는 INSERT … DO NOTHING 만 하고,
--   parse_decoy.py 의 출처 재분류는 decoy 행만 고치므로 걸리지 않는다
CREATE OR REPLACE FUNCTION audit_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION '감사 이벤트는 고치거나 지울 수 없다 (%)', OLD.eventid;
END;
$$;
CREATE OR REPLACE TRIGGER trg_audit_append_only
    BEFORE UPDATE OR DELETE ON events
    FOR EACH ROW WHEN (OLD.sensor = 'audit' AND (OLD.eventid LIKE 'console.block.%' OR OLD.eventid LIKE 'console.node.token.%'
                                                 OR OLD.eventid LIKE 'console.notify.%' OR OLD.eventid LIKE 'console.account.%'))
    EXECUTE FUNCTION audit_append_only();

-- 콘솔 계정 관리 (이슈 #59)
--   관리자가 콘솔 화면에서 관제사 ↔ 조회자 역할 변경과 비활성 · 재활성을 한다. 권한을 높이는 일(계정 추가 · 관리자 부여 · 해제 ·
--   관리자 계정 비활성 · 재활성 · 비밀번호)은 명령줄(app/auth.py, 소유자 접속)에만 남겨, 콘솔이 뚫려도 스스로 관리자가 되지 못하게 한다.
--     disabled_at  비활성 시각. NULL 이면 활성이다. 계정은 지우지 않고 비활성으로만 둔다(판정 · 조치 기록이 계정에 귀속된다).
--     updated_at   역할 · 활성 · 비밀번호가 마지막으로 바뀐 때. 콘솔은 요청마다 계정 행을 읽고 이보다 먼저 발급된 쿠키를 무효로 본다
--                  (app/auth.py). 기존 행은 바뀐 때를 모르므로 created_at 으로 채운다(적용만으로 열린 세션을 끊지 않는다).
--     console_users_stamp  updated_at 을 찍는다. 넣을 때와 역할 · 비활성 시각 · 비밀번호 해시가 실제로 바뀐 때만 찍고, 로그인 기록
--                  (last_login_at)으로는 돌지 않는다. 명령줄 · psql 직접 변경도 찍힌다.
--     console_account_set(아이디, 역할, 활성)  콘솔이 계정을 바꾸는 유일한 길이다. 콘솔 역할의 계정 표 UPDATE 는 여전히 last_login_at
--                  열뿐이고, 이 함수(SECURITY DEFINER)의 실행 권한만 받는다. 역할 · 활성 인자가 NULL 이면 그것은 그대로 둔다.
--                  행위자는 콘솔이 같은 트랜잭션에서 set_config('opsloop.actor', <관리자>, true) 로 넘긴다(app/accounts.py). 결과:
--                    no_actor   행위자가 없다
--                    self       행위자 자신의 계정이다
--                    not_found  계정이 없다
--                    cli_only   대상이 관리자이거나 바꿀 역할이 viewer · operator 가 아니다(관리자 부여 · 해제는 명령줄)
--                    unchanged  바뀐 것이 없다
--                    ok         바꿨다
--     audit_console_users  계정 변경을 events 에 남긴다(sensor = 'audit', audit_blocklist 와 같은 방식). 행위자는 콘솔 · 명령줄이
--                  opsloop.actor 로 넘기고(명령줄은 cli:<이름>), 없으면 'db:<DB 역할>' 이다. 같은 값으로 고치면 남지 않는다.
--                    console.account.created           target=<아이디> role=<역할>
--                    console.account.role.changed      target=<아이디> from=<역할> to=<역할>
--                    console.account.disabled          target=<아이디>
--                    console.account.enabled           target=<아이디>
--                    console.account.password.changed  target=<아이디>      바뀐 사실만 남긴다. 해시는 싣지 않는다
--                    console.account.deleted           target=<아이디> role=<역할>
--                  감사 조회 뷰(audit_log)와 추가만 되는 행 보호(trg_audit_append_only)는 제자리(차단 목록 감사 뒤)에서 console.account.% 를 더했다.
--   infra/migrations/20261001_console_accounts.sql 이 이 블록(과 audit_log · trg_audit_append_only 문장)과 같다
--   (infra/test_console_accounts_db.py 가 대조한다). 콘솔 새 이미지보다 먼저 적용한다(콘솔이 요청마다 새 열을 읽는다).
--   함수 실행 권한은 역할 블록(표 권한만 거둔다)을 다시 적용해도 남는다. 여러 번 적용해도 결과가 같다.
-- 열 추가 · 채우기 · NOT NULL 을 DO 블록 하나(한 트랜잭션)로 묶어, 그 사이에 명령줄이 넣은 계정이 비어 실패하는 일이 없게 한다.
-- 두 번째부터는 채울 행이 없다
DO $$
BEGIN
    ALTER TABLE console_users ADD COLUMN IF NOT EXISTS disabled_at timestamptz;
    ALTER TABLE console_users ADD COLUMN IF NOT EXISTS updated_at timestamptz;
    UPDATE console_users SET updated_at = created_at WHERE updated_at IS NULL;
    ALTER TABLE console_users ALTER COLUMN updated_at SET DEFAULT now();
    ALTER TABLE console_users ALTER COLUMN updated_at SET NOT NULL;
END
$$;

-- 도장은 트랜잭션 시작(now())이 아니라 행을 고치는 때(clock_timestamp())다. 행 잠금을 얻은 뒤에 돌므로, 변경 트랜잭션이 시작된 뒤
-- 행을 고치기 전에 로그인한 쿠키(발급 시각 = 로그인 문장의 now())도 이보다 앞서 무효가 된다(비밀번호 재설정 직전 옛 비밀번호 로그인)
CREATE OR REPLACE FUNCTION console_users_stamp() RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        NEW.updated_at := clock_timestamp();
    ELSIF NEW.role IS DISTINCT FROM OLD.role OR NEW.disabled_at IS DISTINCT FROM OLD.disabled_at
          OR NEW.password_hash IS DISTINCT FROM OLD.password_hash THEN
        NEW.updated_at := clock_timestamp();
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION console_users_stamp() FROM PUBLIC;
CREATE OR REPLACE TRIGGER console_users_stamp
    BEFORE INSERT OR UPDATE OF role, disabled_at, password_hash ON console_users
    FOR EACH ROW EXECUTE FUNCTION console_users_stamp();

-- 관리자 · 관리자로 올리기 · 자기 자신은 거부한다. 판단과 변경을 대상 행 잠금(FOR UPDATE) 안에서 한다
CREATE OR REPLACE FUNCTION console_account_set(p_username text, p_role text, p_active boolean)
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
    IF u.role = 'admin' OR (p_role IS NOT NULL AND p_role NOT IN ('viewer', 'operator')) THEN
        RETURN 'cli_only';
    END IF;
    IF (p_role IS NULL OR p_role = u.role) AND (p_active IS NULL OR p_active = (u.disabled_at IS NULL)) THEN
        RETURN 'unchanged';
    END IF;
    UPDATE console_users
       SET role        = coalesce(p_role, role),
           disabled_at = CASE WHEN p_active IS NULL OR p_active = (disabled_at IS NULL) THEN disabled_at
                              WHEN p_active THEN NULL ELSE now() END
     WHERE username = p_username;
    RETURN 'ok';
END;
$$;
REVOKE ALL ON FUNCTION console_account_set(text, text, boolean) FROM PUBLIC;

-- 트리거 함수는 SECURITY DEFINER 에 PUBLIC 실행 권한을 거둔다(audit_blocklist 와 같다). 계정을 고치는 쪽의 events 권한과 상관없이 남고,
-- 직접 부를 수 없어 감사 이벤트를 지어내는 통로가 되지 않는다. 행위자(session_user)는 그대로 호출한 역할이다
CREATE OR REPLACE FUNCTION audit_console_users() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF TG_OP = 'DELETE' THEN
        PERFORM audit_event('console.account.deleted', format('target=%s role=%s', OLD.username, OLD.role));
        RETURN NULL;
    END IF;
    IF TG_OP = 'INSERT' THEN
        PERFORM audit_event('console.account.created', format('target=%s role=%s', NEW.username, NEW.role));
        RETURN NULL;
    END IF;
    IF NEW.role IS DISTINCT FROM OLD.role THEN
        PERFORM audit_event('console.account.role.changed',
                            format('target=%s from=%s to=%s', NEW.username, OLD.role, NEW.role));
    END IF;
    IF OLD.disabled_at IS NULL AND NEW.disabled_at IS NOT NULL THEN
        PERFORM audit_event('console.account.disabled', format('target=%s', NEW.username));
    ELSIF OLD.disabled_at IS NOT NULL AND NEW.disabled_at IS NULL THEN
        PERFORM audit_event('console.account.enabled', format('target=%s', NEW.username));
    END IF;
    IF NEW.password_hash IS DISTINCT FROM OLD.password_hash THEN
        PERFORM audit_event('console.account.password.changed', format('target=%s', NEW.username));
    END IF;
    RETURN NULL;
END;
$$;
REVOKE ALL ON FUNCTION audit_console_users() FROM PUBLIC;
CREATE OR REPLACE TRIGGER trg_audit_console_users
    AFTER INSERT OR UPDATE OF role, disabled_at, password_hash OR DELETE ON console_users
    FOR EACH ROW EXECUTE FUNCTION audit_console_users();

-- 콘솔은 계정 변경 함수만 부른다. 계정 표 권한(SELECT · UPDATE (last_login_at))은 역할 블록 그대로다
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_console') THEN
        GRANT EXECUTE ON FUNCTION console_account_set(text, text, boolean) TO opsloop_console;
    END IF;
END
$$;
COMMIT;
