-- 차단 자동 집행 (이슈 #47). schema.sql 의 audit_blocklist · trg_audit_blocklist 문장과 '차단 집행 (이슈 #47)' 블록이
--   글자 그대로 들어 있으며 여러 번 적용해도 같다 (infra/test_block_enforce_db.py 가 대조한다).
--   - 감사 트리거 확장: console.block.created · rearmed · enforced · unenforced 를 더하고 트리거 함수를 SECURITY DEFINER 로.
--     생성 · 재차단 · 만료 변경 줄에 요청 지점(points=, 이슈 #77)을 싣는다. 열이 없는 DB(20261003 전)에서는 '-' 다
--   - 차단 금지 대역 표(block_exempt)와 초기값, 차단 목록 검사 트리거(blocklist_guard: 주소 하나 · 금지 대역. SECURITY DEFINER 라
--     콘솔에 block_exempt 읽기가 없어도 검사하고 정상 주소는 넣는다)
--   - 만료 기록 함수 note_block_expired, 집행 역할(opsloop_enforcer) 권한, 콘솔의 금지 대역 읽기
--   기존 차단 행은 다시 보지 않는다(검사는 넣을 때 · 주소를 바꿀 때만). 해제 · 만료 변경은 전과 같다.
--   역할 블록(schema.sql · 20260924_db_roles.sql) 뒤에 적용한다. 역할 블록을 다시 적용하면 콘솔의 block_exempt 읽기와
--   집행 역할 권한이 사라지므로 이 파일도 다시 적용한다. opsloop_enforcer 역할은 enforcer/install-enforcer.sh 가 만든다.
--   역할이 없을 때 적용하면 표 · 함수 · 트리거만 생기고, 역할을 만든 뒤 다시 적용하면 권한이 붙는다.
--   앱(콘솔 · triage)보다 먼저 적용해도 된다. 새 앱 전에는 금지 대역 · 대역 주소 요청이 400 이 아니라 오류(500)로 거부된다.
-- 적용 (Mac, 저장소 루트):
--   ssh -F ~/.ssh/config.opsloop data01 'sudo -n docker exec -i opsloop-db psql -U opsloop -d opsloop -v ON_ERROR_STOP=1 -q' \
--     < infra/migrations/20260927_block_enforce.sql
-- 확인: infra/vmware/scripts/verify-db-roles.sh 의 '차단 집행' 줄
BEGIN;
CREATE OR REPLACE FUNCTION audit_blocklist() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    v text;
    p text;
BEGIN
    IF TG_OP = 'DELETE' THEN
        IF OLD.released_at IS NULL THEN          -- 살아 있는 차단을 지우는 것도 해제다
            PERFORM audit_event('console.block.released',
                                format('ip=%s incident=%s how=delete past_expiry=%s', host(OLD.actor_ip),
                                       coalesce(OLD.incident_key, '-'),
                                       CASE WHEN OLD.expires_at <= now() THEN 'yes' ELSE 'no' END));
        END IF;
        RETURN NULL;
    END IF;
    -- 요청 지점(이슈 #77 blocklist.points). 열이 없는 DB(이 함수만 먼저 적용)에서도 돌게 to_jsonb 로 읽고, 없으면 '-' 다
    p := coalesce(nullif(array_to_string(ARRAY(SELECT jsonb_array_elements_text(to_jsonb(NEW) -> 'points')), ','), ''), '-');
    IF TG_OP = 'INSERT' THEN
        -- ON CONFLICT DO UPDATE 로 기존 행을 고친 것은 INSERT 가 아니라 아래 UPDATE 로 온다
        PERFORM audit_event('console.block.created',
                            format('ip=%s incident=%s expires=%s points=%s requested_by=%s', host(NEW.actor_ip),
                                   coalesce(NEW.incident_key, '-'), coalesce(NEW.expires_at::text, 'none'), p,
                                   coalesce(NEW.requested_by, '-')));
        RETURN NULL;
    END IF;
    IF OLD.released_at IS NULL AND NEW.actor_ip IS DISTINCT FROM OLD.actor_ip THEN
        -- 주소를 바꾸면 원래 주소의 차단이 풀린다. 해제 · 만료 변경이 함께 있어도 이 한 줄로 남긴다
        PERFORM audit_event('console.block.released',
                            format('ip=%s incident=%s how=readdress to=%s', host(OLD.actor_ip),
                                   coalesce(OLD.incident_key, '-'), host(NEW.actor_ip)));
    ELSIF OLD.released_at IS NULL AND NEW.released_at IS NOT NULL THEN
        SELECT verdict INTO v FROM verdicts WHERE incident_key = NEW.incident_key
         ORDER BY created_at DESC LIMIT 1;
        PERFORM audit_event('console.block.released',
            format('ip=%s incident=%s verdict=%s past_expiry=%s', host(NEW.actor_ip),
                   coalesce(NEW.incident_key, '-'), coalesce(v, 'none'),
                   CASE WHEN OLD.expires_at <= now() THEN 'yes' ELSE 'no' END));
    ELSIF OLD.released_at IS NULL AND NEW.released_at IS NULL
          AND NEW.expires_at IS DISTINCT FROM OLD.expires_at THEN
        PERFORM audit_event(
            CASE WHEN NEW.expires_at IS NOT NULL AND (OLD.expires_at IS NULL OR NEW.expires_at < OLD.expires_at)
                 THEN 'console.block.shortened' ELSE 'console.block.extended' END,
            format('ip=%s from=%s to=%s points=%s', host(NEW.actor_ip), coalesce(OLD.expires_at::text, 'none'),
                   coalesce(NEW.expires_at::text, 'none'), p));
    ELSIF OLD.released_at IS NOT NULL AND NEW.released_at IS NULL THEN
        PERFORM audit_event('console.block.rearmed',
                            format('ip=%s incident=%s expires=%s points=%s released_by=%s requested_by=%s',
                                   host(NEW.actor_ip), coalesce(NEW.incident_key, '-'),
                                   coalesce(NEW.expires_at::text, 'none'), p,
                                   coalesce(OLD.released_by, '-'), coalesce(NEW.requested_by, '-')));
    END IF;
    -- 집행 기록. 위 분류와 따로 본다(재차단이 집행 기록을 함께 비우면 두 줄이 남는다). 같은 값을 다시 쓰면 남지 않는다
    IF NEW.enforced_at IS NOT NULL AND NEW.enforced_at IS DISTINCT FROM OLD.enforced_at THEN
        PERFORM audit_event('console.block.enforced',
                            format('ip=%s method=%s at=%s note=%s', host(NEW.actor_ip), coalesce(NEW.method, '-'),
                                   NEW.enforced_at::text, coalesce(left(NEW.enforce_note, 200), '-')));
    ELSIF OLD.enforced_at IS NOT NULL AND NEW.enforced_at IS NULL THEN
        PERFORM audit_event('console.block.unenforced',
                            format('ip=%s method=%s was=%s why=%s', host(NEW.actor_ip), coalesce(OLD.method, '-'),
                                   OLD.enforced_at::text,
                                   CASE WHEN NEW.released_at IS NOT NULL THEN 'released'
                                        WHEN NEW.expires_at <= now() THEN 'expired' ELSE 'reset' END));
    END IF;
    RETURN NULL;
END;
$$;
-- 트리거 함수는 직접 부를 수 없지만 SECURITY DEFINER 이므로 PUBLIC 실행 권한도 거둔다 (트리거 발화는 이 권한을 보지 않는다)
REVOKE ALL ON FUNCTION audit_blocklist() FROM PUBLIC;

-- CREATE OR REPLACE TRIGGER 로 바꾼다 (PostgreSQL 14+). DROP 뒤 CREATE 는 그 사이의 해제를 놓친다
CREATE OR REPLACE TRIGGER trg_audit_blocklist
    AFTER INSERT OR UPDATE OF released_at, expires_at, actor_ip, enforced_at OR DELETE ON blocklist
    FOR EACH ROW EXECUTE FUNCTION audit_blocklist();
-- 차단 집행 (이슈 #47)
--   사람이 요청한 차단(콘솔 block_ip · triage threat · 흡수 후속 차단)을 데이터 노드 집행기(enforcer/block_enforcer.py)가
--   S3 block/v1/latest.json 으로 AWS 관문에 넘기고, 관문이 forward 체인(허니팟 DNAT 유입)에서 막는다. 규칙 · 심각도로 무인
--   차단하지 않는다. 이 블록은 그 DB 쪽이다. 여러 번 적용해도 결과가 같다.
--     block_exempt         차단 금지 대역. 콘솔 · triage · 흡수 · psql 어느 경로로도 이 대역의 주소는 차단 목록에 들어가지 않는다.
--                          문서용 대역(192.0.2.0/24 · 198.51.100.0/24 · 203.0.113.0/24)은 넣지 않는다(시험 출발지로 쓴다).
--                          관문 쪽 동기화(infra/aws/gateway/block-sync.py)도 같은 대역을 상수로 한 번 더 거른다.
--     blocklist_guard      넣거나 주소(actor_ip)를 바꿀 때 (1) 주소 하나(IPv4 /32 · IPv6 /128)가 아니면 거부
--                          (23514 blocklist_host_only) (2) 금지 대역에 속하면 거부(23514 blocklist_exempt, 메시지에 걸린 대역).
--                          기존 행의 해제 · 만료 · 집행 열 변경은 막지 않는다. 이미 들어 있던 행은 다시 보지 않는다
--                          (집행기가 '집행 제외 · 금지 대역' · '집행 제외 · 대역 주소' 로 표시하고 넘기지 않는다).
--                          거부는 트랜잭션을 되돌리므로 감사 이벤트가 남지 않는다. 사유는 호출한 쪽(콘솔 400)이 보인다.
--     note_block_expired   만료로 목록에서 빠진 차단을 console.block.expired 로 남긴다. 같은 (ip, 만료)는 한 번만 남는다
--                          (line_hash 가 둘로만 정해진다). 행에 그 만료가 실제로 있고 이미 지났을 때만 남기므로 호출자가
--                          만료를 지어낼 수 없다. 남겼으면 true, 이미 있거나 조건이 맞지 않으면 false 다.
--     opsloop_enforcer     집행기 역할. 차단 목록 읽기와 집행 열(method · enforced_at · enforce_note) 쓰기, 금지 대역 읽기,
--                          note_block_expired 실행뿐이다. 차단을 걸거나 풀거나 만료를 바꾸지 못한다. 집행 열 변경의 감사는
--                          SECURITY DEFINER 트리거(audit_blocklist)가 남긴다. 역할은 비밀번호 때문에 여기서 만들지 않는다
--                          (enforcer/install-enforcer.sh: LOGIN · NOINHERIT · CONNECTION LIMIT 2).
--   enforce_note 값(화면이 읽는다): '관문 반영 · <digest 앞 8자> · <관문 적용 시각 ISO>' · '관문 불일치 · <사유>' ·
--   '집행 제외 · 만료 없음' · '집행 제외 · 금지 대역' · '집행 제외 · 대역 주소'. method 는 관문이 보고한 'fail2ban' · 'nft'.
--   infra/migrations/20260927_block_enforce.sql 이 이 블록(과 위 audit_blocklist · trg_audit_blocklist)과 같다. 역할 블록이
--   모든 표의 권한을 먼저 거두므로 권한은 여기서 다시 준다. 역할 블록 뒤에 있어야 하고, 역할 블록을 다시 적용하면 이 블록도
--   다시 적용한다.
CREATE TABLE IF NOT EXISTS block_exempt (
    cidr       inet        PRIMARY KEY,
    note       text        NOT NULL,
    created_at timestamptz DEFAULT now()
);
-- 초기값. 지운 줄은 다시 적용하면 되살아난다(금지 대역을 푸는 것은 이 파일을 고치는 일이다)
INSERT INTO block_exempt (cidr, note) VALUES
    ('0.0.0.0/8',       '이 네트워크'),
    ('10.0.0.0/8',      '사설 · AWS VPC'),
    ('100.64.0.0/10',   '통신사 NAT · Tailscale'),
    ('127.0.0.0/8',     '루프백'),
    ('169.254.0.0/16',  '링크 로컬 · 인스턴스 메타데이터'),
    ('172.16.0.0/12',   '사설 · 도커 브리지'),
    ('192.0.0.0/24',    'IETF 프로토콜 할당'),
    ('192.168.0.0/16',  '사설 · 관리망 · 서비스망'),
    ('198.18.0.0/15',   '성능 시험 대역'),
    ('224.0.0.0/4',     '멀티캐스트'),
    ('240.0.0.0/4',     '예약 · 브로드캐스트'),
    ('15.164.37.49/32', 'AWS 관문 EIP'),
    ('::1/128',         'IPv6 루프백'),
    ('fc00::/7',        'IPv6 사설(ULA)'),
    ('fe80::/10',       'IPv6 링크 로컬')
ON CONFLICT (cidr) DO NOTHING;

-- 금지 대역 검사는 SECURITY DEFINER 로 돈다(표 소유자 권한으로 block_exempt 를 읽는다). 차단을 넣는 역할(콘솔)에 block_exempt
--   읽기가 없어도 검사는 그대로 되고 정상 주소는 들어간다. 호출자 권한으로 돌리면 역할 블록(20260924_db_roles.sql)만 다시
--   적용해 콘솔의 읽기가 빠진 순간부터 콘솔의 모든 차단(정상 주소까지)이 permission denied 로 막힌다. 콘솔의 읽기 권한은
--   사유(걸린 대역 · 메모)를 보이는 데만 쓴다(app/absorbed.py · triage.py 가 권한이 없으면 사유 없이 거절만 보인다).
--   읽기만 하고 동적 SQL 이 없어 소유자 권한으로 돌아도 새 통로가 생기지 않는다. 트리거 함수는 직접 부를 수 없다
CREATE OR REPLACE FUNCTION blocklist_guard() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    e block_exempt%ROWTYPE;
BEGIN
    IF TG_OP = 'UPDATE' AND NEW.actor_ip IS NOT DISTINCT FROM OLD.actor_ip THEN
        RETURN NEW;
    END IF;
    IF masklen(NEW.actor_ip) <> (CASE WHEN family(NEW.actor_ip) = 4 THEN 32 ELSE 128 END) THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'blocklist_host_only',
            TABLE = 'blocklist', COLUMN = 'actor_ip',
            MESSAGE = format('차단은 주소 하나만 받는다 (IPv4 /32 · IPv6 /128): %s', text(NEW.actor_ip));
    END IF;
    SELECT * INTO e FROM block_exempt WHERE cidr >>= NEW.actor_ip ORDER BY masklen(cidr) DESC LIMIT 1;
    IF FOUND THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'blocklist_exempt',
            TABLE = 'blocklist', COLUMN = 'actor_ip',
            MESSAGE = format('차단 금지 대역 %s (%s) 에 속하는 주소다: %s', text(e.cidr), e.note, host(NEW.actor_ip)),
            DETAIL = format('cidr=%s', text(e.cidr));
    END IF;
    RETURN NEW;
END;
$$;
CREATE OR REPLACE TRIGGER blocklist_guard
    BEFORE INSERT OR UPDATE OF actor_ip ON blocklist
    FOR EACH ROW EXECUTE FUNCTION blocklist_guard();
-- 트리거 함수는 직접 부를 수 없지만 SECURITY DEFINER 이므로 PUBLIC 실행 권한도 거둔다 (audit_blocklist 와 같다)
REVOKE ALL ON FUNCTION blocklist_guard() FROM PUBLIC;

-- 만료 기록. 만료 시각은 세션 시간대와 무관하게 UTC 로 적어 같은 만료가 늘 같은 줄 해시가 되게 한다.
--   풀린 뒤에 만료가 지난 행(released_at < expires_at)은 만료가 아니라 해제다. 만료 뒤에 풀린 행은 만료가 먼저 일어났다
CREATE OR REPLACE FUNCTION note_block_expired(ip inet, expires timestamptz)
RETURNS boolean
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
DECLARE
    b       blocklist%ROWTYPE;
    v_exp   text;
    v_actor text := coalesce(nullif(current_setting('opsloop.actor', true), ''), 'db:' || session_user);
    n       integer;
BEGIN
    IF ip IS NULL OR expires IS NULL THEN
        RETURN false;
    END IF;
    SELECT * INTO b FROM blocklist WHERE actor_ip = ip;
    IF NOT FOUND OR b.expires_at IS DISTINCT FROM expires OR b.expires_at > clock_timestamp()
       OR b.released_at < b.expires_at THEN
        RETURN false;
    END IF;
    v_exp := to_char(expires AT TIME ZONE 'UTC', 'YYYY-MM-DD"T"HH24:MI:SS.US"Z"');
    INSERT INTO events (line_hash, ts, eventid, src_ip, username, input, provenance, sensor)
    VALUES (encode(sha256(convert_to(concat_ws('|', 'audit', 'console.block.expired', host(ip), v_exp), 'UTF8')), 'hex'),
            clock_timestamp(), 'console.block.expired', inet_client_addr(), left(v_actor, 128),
            left(format('by=%s ip=%s incident=%s expires=%s', v_actor, host(ip), coalesce(b.incident_key, '-'), v_exp),
                 1024),
            'real', 'audit')
    ON CONFLICT (line_hash) DO NOTHING;
    GET DIAGNOSTICS n = ROW_COUNT;
    RETURN n > 0;
END;
$$;
REVOKE ALL ON FUNCTION note_block_expired(inet, timestamptz) FROM PUBLIC;

-- 집행 역할은 이 권한뿐이다. 콘솔은 금지 대역을 읽기만 한다(차단 요청 전에 거를 수 있게). 탐지 · 적재는 보지 못한다
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_enforcer') THEN
        EXECUTE format('GRANT CONNECT ON DATABASE %I TO opsloop_enforcer', current_database());
        GRANT USAGE ON SCHEMA public TO opsloop_enforcer;
        REVOKE ALL ON ALL TABLES IN SCHEMA public FROM opsloop_enforcer;
        REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM opsloop_enforcer;
        GRANT SELECT ON blocklist, block_exempt TO opsloop_enforcer;
        GRANT UPDATE (method, enforced_at, enforce_note) ON blocklist TO opsloop_enforcer;
        GRANT EXECUTE ON FUNCTION note_block_expired(inet, timestamptz) TO opsloop_enforcer;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_console') THEN
        GRANT SELECT ON block_exempt TO opsloop_console;
    END IF;
END
$$;
COMMIT;
