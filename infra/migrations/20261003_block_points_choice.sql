-- 차단 적용 지점 선택 (이슈 #77). schema.sql 의 '차단 적용 지점 선택 (이슈 #77)' 블록이 글자 그대로 들어 있으며(lock_timeout 한 줄만
--   다르다) 여러 번 적용해도 같다 (infra/test_block_points_choice_db.py 가 대조한다).
--   - blocklist.points · absorbed_blocks.points: 요청 지점('{gateway,fw}' · '{fw}' 두 값만, CHECK). 기존 행은 기본값 두 지점이다
--     (상수 기본값이라 표를 다시 쓰지 않고 감사도 남지 않는다)
--   - blocklist_points_change · trg_blocklist_points: 살아 있는 행의 지점 좁히기 거부(23514 blocklist_points_narrow), 넓히기는
--     console.block.points 로 남긴다
--   표 · 열 권한은 주지 않는다. 감사 detail 의 points= 는 20260927_block_enforce.sql 의 audit_blocklist 가 싣는다(열이 없으면 '-').
--   적용 순서: 이 파일만 먼저 적용한다. 20260927 은 여기서 다시 적용하지 않는다(집행기 설치기가 27 → 29 → 30 → 77 차례로 다시
--   적용한다). 콘솔 · triage 새 판(이 열을 쓴다)보다 먼저 적용한다. 옛 콘솔 · triage · 집행기는 이 열을 모르므로 먼저 적용해도 그대로
--   돈다(새 행은 기본값 두 지점).
--   잠금: 처음 적용할 때는 열 · 제약을 더하는 동안 blocklist · absorbed_blocks 를 잠깐 잠근다(읽기도 기다린다).
--   5초 안에 잠금을 얻지 못하면 실패하고 아무것도 바꾸지 않는다. 그때는 다시 돌린다(그동안 콘솔 요청이 최대 5초 늦는다).
--   다시 적용할 때는 열 · 제약이 있으면 표를 잠그지 않고, 트리거를 바꾸는 동안 blocklist 쓰기만 잠깐 기다린다.
--   다시 적용: 권한을 주지 않으므로 역할 블록 · 20260927 · 20260929 · 20260930 을 다시 적용한 뒤에 다시 적용하지 않아도 된다.
--   복원 뒤에는 다시 적용한다.
--   되돌리기: 하지 않는다(새 콘솔 · triage 가 이 열을 쓴다). 비상이면 트리거 · 제약만 지운다(열은 지우지 않는다):
--     DROP TRIGGER IF EXISTS trg_blocklist_points ON blocklist; ALTER TABLE blocklist DROP CONSTRAINT IF EXISTS blocklist_points_valid;
-- 적용 (Mac, 저장소 루트):
--   ssh -F ~/.ssh/config.opsloop data01 'sudo -n docker exec -i opsloop-db psql -U opsloop -d opsloop -v ON_ERROR_STOP=1 -q' \
--     < infra/migrations/20261003_block_points_choice.sql
-- 확인: infra/vmware/scripts/verify-db-roles.sh 의 '차단 적용 지점' 줄, SELECT points, count(*) FROM blocklist GROUP BY 1
BEGIN;
SET LOCAL lock_timeout = '5s';
-- 차단 적용 지점 선택 (이슈 #77)
--   차단 요청마다 적용 지점을 고른다. 내부 방화벽은 늘 막고 AWS 관문은 고른 요청만 막는다(관문 전용은 없다). 기본값은 콘솔 ·
--   triage 가 규칙으로 정한다(app/block_points.py). 집행기는 목록 문서의 entries(관문 목록)에 관문을 요청한 행을, points.fw(내부
--   방화벽 목록)에 모든 행을 싣는다(enforcer/block_enforcer.py).
--     blocklist.points  요청 지점. '{gateway,fw}' · '{fw}' 두 값만 받는다(정규 순서, CHECK blocklist_points_valid). 기존 행과 열을
--                  모르는 옛 문장(콘솔 · triage 옛 판)은 기본값 두 지점이라 #77 전 동작 그대로다. 상수 기본값이라 표를 다시 쓰지 않는다.
--     absorbed_blocks.points  흡수 후속 차단 약속의 지점. 같은 기본값 · CHECK(absorbed_blocks_points_valid)다.
--     blocklist_points_change · trg_blocklist_points  points 를 쓰는 갱신마다 돈다. 살아 있는 행(해제 전 · 만료 전)을 풀지 않고
--                  좁히면 거부한다(23514 blocklist_points_narrow). 좁히기는 감사 없는 부분 해제라서, 관리자의 '관문 빼기' 는 콘솔이
--                  한 트랜잭션에서 해제 뒤 다시 건다. 살아 있는 행을 넓히면 console.block.points(ip · from · to)로 남긴다. 해제 · 만료된
--                  행을 다시 거는 것은 어느 값이든 받는다(기록은 audit_blocklist 의 rearmed · extended 줄 points=). SECURITY DEFINER 다
--                  (audit_blocklist 와 같다).
--   enforcement(#51 블록)의 상태에 removing 을 더한다: 목록에서 빠진 행(해제 · 만료 · 제외)이나 요청했다가 뺀 지점(관리자 관문 빼기)을
--   그 지점이 뺐다고 확인하기 전이다. 확인한 지점 키는 지우고 모두 지워지면 NULL 이다. 그 밖에 요청하지 않은 지점은 키가 없고, 목록 행의
--   요청 지점에는 removing 이 없다.
--   권한은 새로 주지 않는다: 콘솔(triage 포함)은 표 INSERT · UPDATE 로 쓰고, 집행 역할은 표 SELECT 로 읽기만 한다(열 UPDATE 목록에
--   points 가 없다). 탐지 역할은 차단 목록을 보지 못하고 백업은 pg_read_all_data 로 읽는다.
--   infra/migrations/20261003_block_points_choice.sql 이 이 블록과 같다(lock_timeout 한 줄만 다르다. infra/test_block_points_choice_db.py
--   가 대조한다). 여러 번 적용해도 결과가 같고, 역할 블록 · 20260927 · 20260929 · 20260930 을 다시 적용한 뒤 다시 적용하지 않아도
--   된다(권한을 주지 않는다). 콘솔 · triage 새 판보다 먼저, 복원 뒤에도 적용한다.
-- 열 · 제약은 없을 때만 더한다. ALTER TABLE 은 IF NOT EXISTS 여도 ACCESS EXCLUSIVE 부터 잡으므로, 이미 있으면 표를 잠그지 않아
-- 다시 적용이 읽는 트랜잭션(백업 pg_dump · 콘솔 조회)을 기다리지 않는다
DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_attribute
                    WHERE attrelid = 'blocklist'::regclass AND attname = 'points' AND NOT attisdropped) THEN
        ALTER TABLE blocklist ADD COLUMN points text[] NOT NULL DEFAULT '{gateway,fw}';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_attribute
                    WHERE attrelid = 'absorbed_blocks'::regclass AND attname = 'points' AND NOT attisdropped) THEN
        ALTER TABLE absorbed_blocks ADD COLUMN points text[] NOT NULL DEFAULT '{gateway,fw}';
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'blocklist'::regclass AND conname = 'blocklist_points_valid') THEN
        ALTER TABLE blocklist ADD CONSTRAINT blocklist_points_valid
            CHECK (points IN ('{gateway,fw}'::text[], '{fw}'::text[]));
    END IF;
    IF NOT EXISTS (SELECT 1 FROM pg_constraint
                    WHERE conrelid = 'absorbed_blocks'::regclass AND conname = 'absorbed_blocks_points_valid') THEN
        ALTER TABLE absorbed_blocks ADD CONSTRAINT absorbed_blocks_points_valid
            CHECK (points IN ('{gateway,fw}'::text[], '{fw}'::text[]));
    END IF;
END
$$;
CREATE OR REPLACE FUNCTION blocklist_points_change() RETURNS trigger
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public, pg_temp
AS $$
BEGIN
    IF OLD.released_at IS NOT NULL OR OLD.expires_at <= now() THEN
        RETURN NULL;                             -- 해제 · 만료된 행을 다시 거는 것은 어느 값이든 받는다
    END IF;
    IF NEW.released_at IS NULL AND NOT NEW.points @> OLD.points THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'blocklist_points_narrow',
            TABLE = 'blocklist', COLUMN = 'points',
            MESSAGE = format('살아 있는 차단의 적용 지점은 좁히지 못한다(해제 뒤 다시 건다): %s %s → %s', host(NEW.actor_ip),
                             array_to_string(OLD.points, ','), array_to_string(NEW.points, ','));
    END IF;
    IF NEW.released_at IS NULL AND (NEW.expires_at IS NULL OR NEW.expires_at > now())
       AND NEW.points IS DISTINCT FROM OLD.points THEN
        PERFORM audit_event('console.block.points',
                            format('ip=%s from=%s to=%s', host(NEW.actor_ip), array_to_string(OLD.points, ','),
                                   array_to_string(NEW.points, ',')));
    END IF;
    RETURN NULL;
END;
$$;
-- 트리거 함수는 직접 부를 수 없지만 SECURITY DEFINER 이므로 PUBLIC 실행 권한도 거둔다 (audit_blocklist 와 같다)
REVOKE ALL ON FUNCTION blocklist_points_change() FROM PUBLIC;
CREATE OR REPLACE TRIGGER trg_blocklist_points
    AFTER UPDATE OF points ON blocklist
    FOR EACH ROW EXECUTE FUNCTION blocklist_points_change();
COMMIT;
