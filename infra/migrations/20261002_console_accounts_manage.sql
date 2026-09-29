-- 콘솔 계정 추가 · 삭제 · 비밀번호 (이슈 #63). schema.sql 의 '콘솔 계정 추가 · 삭제 · 비밀번호 (이슈 #63)' 블록이 글자 그대로 들어 있으며
--   여러 번 적용해도 같다 (infra/test_console_accounts_manage_db.py 가 대조한다).
--   - console_account_create: 관제사 · 조회자 계정 추가(SECURITY DEFINER). 아이디 · 해시 형식이 아니면 받지 않는다(평문 저장 사고를 막는다)
--   - console_account_delete: 이력(로그인 · 판정 · 조치 · 차단 요청 · 해제)이 없는 관제사 · 조회자 계정 삭제. 이력이 있으면 in_use
--   - console_account_password: 관제사 · 조회자 비밀번호 재설정. 도장(updated_at)이 찍혀 그 계정의 옛 쿠키가 무효가 된다
--   관리자 계정 · 관리자 대상 · 본인은 세 함수 모두 거부한다(cli_only · self). 콘솔 역할은 세 함수의 실행 권한만 받는다
--   (계정 표 INSERT · DELETE 는 여전히 없고 UPDATE 는 last_login_at 열뿐이다). 감사(console.account.created · deleted ·
--   password.changed, 해시 없음)와 도장은 20261001_console_accounts.sql 의 트리거가 남긴다.
--   적용 순서: 20261001_console_accounts.sql 뒤(그 파일의 도장 · 감사 트리거와 updated_at 열을 쓴다). 콘솔 새 이미지(계정 추가 · 삭제 ·
--   비밀번호 재설정 API · 화면)보다 먼저 적용하고, verify-db-roles.sh 로 확인한 뒤 이미지를 올린다. 옛 이미지는 새 함수를 부르지 않으므로
--   먼저 적용해도 그대로 돈다.
--   다시 적용: 콘솔 역할(opsloop_console)이 없을 때 적용했으면 역할을 만든 뒤 다시 적용한다(역할이 있을 때만 실행 권한을 준다).
--   역할 블록(schema.sql · 20260924_db_roles.sql)은 표 권한만 거두고, 20261001_console_accounts.sql 은 이 세 함수를 건드리지 않으므로
--   그것들을 다시 적용한 뒤에는 이 파일을 다시 적용하지 않아도 된다.
-- 적용 (Mac, 저장소 루트):
--   ssh -F ~/.ssh/config.opsloop data01 'sudo -n docker exec -i opsloop-db psql -U opsloop -d opsloop -v ON_ERROR_STOP=1 -q' \
--     < infra/migrations/20261002_console_accounts_manage.sql
-- 확인: infra/vmware/scripts/verify-db-roles.sh 의 '콘솔 계정 추가 · 삭제 · 비밀번호' 줄
BEGIN;
-- 콘솔 계정 추가 · 삭제 · 비밀번호 (이슈 #63)
--   관리자가 콘솔 화면에서 관제사 · 조회자 계정을 만들고, 이력이 없는 계정을 지우고, 비밀번호를 다시 정한다. 관리자 계정 추가 ·
--   관리자 부여 · 관리자 계정의 비밀번호 · 본인 계정 변경은 지금처럼 명령줄(app/auth.py, 소유자 접속)에만 둔다(#59 블록의 원칙).
--   콘솔 역할은 여전히 계정 표를 직접 고치지 못한다(INSERT · DELETE 없음, UPDATE 는 last_login_at 열뿐). 아래 세 함수
--   (SECURITY DEFINER)의 실행 권한만 받는다. 행위자는 console_account_set 과 같이 콘솔이 같은 트랜잭션에서
--   set_config('opsloop.actor', <관리자>, true) 로 넘긴다(app/accounts.py).
--   비밀번호 해시는 콘솔이 만든다(app/auth.py hash_password). 함수는 그 형식(pbkdf2_sha256$<반복 5 ~ 7자리>$<솔트 32자>$<값 64자>,
--   16진수)이 아니면 받지 않는다(평문이 해시 열에 들어가는 사고, 반복 수를 터무니없이 키운 해시로 로그인 한 번에 콘솔을 멈추게 하는 일을 막는다). 도장(updated_at) · 감사(console.account.*)는 #59 블록의 트리거가 그대로
--   남긴다. 감사에는 해시를 싣지 않는다.
--     console_account_create(아이디, 역할, 해시)  계정을 만든다. 결과:
--                    no_actor   행위자가 없다
--                    invalid    아이디가 명령줄과 같은 형식(영문 · 숫자 · ._- 64자 이하)이 아니거나 해시 형식이 아니다
--                    cli_only   역할이 viewer · operator 가 아니다(관리자 계정은 명령줄)
--                    exists     같은 아이디가 이미 있다(비활성 계정 포함). 동시에 같은 아이디를 만들어도 하나만 들어간다
--                    ok         만들었다(console.account.created)
--     console_account_delete(아이디)  이력이 없는 계정을 지운다. 판정 · 조치 기록이 계정에 귀속되므로 이력이 있으면 비활성으로 둔다. 결과:
--                    no_actor · self · not_found  console_account_set 과 같다
--                    cli_only   대상이 관리자다
--                    in_use     이력이 있다. 로그인한 적이 있거나(last_login_at) 판정(verdicts.operator) · 조치(actions.operator) ·
--                               차단 요청 · 해제(blocklist.requested_by · released_by)에 그 아이디가 있다. 콘솔의 다른 기록(흡수
--                               후속 차단 약속 · 노드 토큰 발급 등)은 로그인한 뒤에만 생기므로 로그인 기록으로 잡힌다
--                    ok         지웠다(console.account.deleted)
--     console_account_password(아이디, 해시)  관제사 · 조회자의 비밀번호를 다시 정한다. 결과:
--                    no_actor · invalid(해시 형식) · self · not_found · cli_only(대상이 관리자)
--                    ok         바꿨다(console.account.password.changed). 도장이 updated_at 을 찍어 그 계정의 옛 쿠키가 무효가 된다
--   infra/migrations/20261002_console_accounts_manage.sql 이 이 블록과 같다(infra/test_console_accounts_manage_db.py 가 대조한다).
--   #59 블록(도장 · 감사 트리거) 뒤에 두고, 콘솔 새 이미지보다 먼저 적용한다. 함수 실행 권한은 역할 블록(표 권한만 거둔다)을 다시
--   적용해도 남는다. 여러 번 적용해도 결과가 같다.
-- 형식 · 역할을 먼저 보고, 같은 아이디는 ON CONFLICT DO NOTHING 으로 거른다(동시에 만들어도 고유 키 오류 없이 exists)
CREATE OR REPLACE FUNCTION console_account_create(p_username text, p_role text, p_password_hash text)
RETURNS text
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    -- set_config(…, true) 가 끝난 연결에서는 NULL 이 아니라 '' 가 돌아온다
    v_actor text := nullif(current_setting('opsloop.actor', true), '');
BEGIN
    IF v_actor IS NULL THEN
        RETURN 'no_actor';
    END IF;
    -- NULL 도 형식이 아니다(IS NOT TRUE). ~ 의 $ 는 문자열 끝에서만 맞는다(끝 줄바꿈을 받지 않는다)
    IF (p_username ~ '^[A-Za-z0-9._-]{1,64}$') IS NOT TRUE
       OR (p_password_hash ~ '^pbkdf2_sha256\$[1-9][0-9]{4,6}\$[0-9a-f]{32}\$[0-9a-f]{64}$') IS NOT TRUE THEN
        RETURN 'invalid';
    END IF;
    IF p_role IS NULL OR p_role NOT IN ('viewer', 'operator') THEN
        RETURN 'cli_only';
    END IF;
    INSERT INTO console_users (username, password_hash, role)
    VALUES (p_username, p_password_hash, p_role)
    ON CONFLICT (username) DO NOTHING;
    IF NOT FOUND THEN
        RETURN 'exists';
    END IF;
    RETURN 'ok';
END;
$$;
REVOKE ALL ON FUNCTION console_account_create(text, text, text) FROM PUBLIC;

-- 판단과 삭제를 대상 행 잠금(FOR UPDATE) 안에서 한다. 로그인 기록도 이 행을 고치므로 판단과 삭제 사이에 첫 로그인이 끼지 못한다.
-- 이력을 보는 표(verdicts · actions · blocklist)와 열은 이 블록보다 앞에서 늘 만들어진다
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

-- 해시 형식을 먼저 보고(아이디가 틀려도 평문은 거른다), 판단과 변경을 대상 행 잠금(FOR UPDATE) 안에서 한다
CREATE OR REPLACE FUNCTION console_account_password(p_username text, p_password_hash text)
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
    IF (p_password_hash ~ '^pbkdf2_sha256\$[1-9][0-9]{4,6}\$[0-9a-f]{32}\$[0-9a-f]{64}$') IS NOT TRUE THEN
        RETURN 'invalid';
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
    UPDATE console_users SET password_hash = p_password_hash WHERE username = p_username;
    RETURN 'ok';
END;
$$;
REVOKE ALL ON FUNCTION console_account_password(text, text) FROM PUBLIC;

-- 콘솔은 세 함수만 부른다. 계정 표 권한(SELECT · UPDATE (last_login_at))은 역할 블록 그대로다
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_console') THEN
        GRANT EXECUTE ON FUNCTION console_account_create(text, text, text) TO opsloop_console;
        GRANT EXECUTE ON FUNCTION console_account_delete(text) TO opsloop_console;
        GRANT EXECUTE ON FUNCTION console_account_password(text, text) TO opsloop_console;
    END IF;
END
$$;
COMMIT;
