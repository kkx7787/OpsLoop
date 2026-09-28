-- 관제 대상 상태판 (이슈 #52). schema.sql 의 '관제 대상 상태판 (이슈 #52)' 블록이 글자 그대로 들어 있으며
--   여러 번 적용해도 같다 (infra/test_status_board_db.py 가 대조한다).
--   - sensor_heartbeats: 업로더 생존 신호(적재기가 쓴다) · 관문 · 내부 방화벽 차단 보고 신호(집행기가 쓴다)
--   - sensor_heartbeats_guard: 적재 역할은 업로더 행만, 집행 역할은 차단 보고 행만 넣고 바꾼다
--   - 권한: 적재 · 집행 역할은 SELECT · INSERT · UPDATE, 콘솔은 sensor_heartbeats · node_metrics 읽기
--   '차단 집행 지점 · 시험 출발지 (이슈 #51)' 블록 뒤에 적용한다. 역할 블록(schema.sql · 20260924_db_roles.sql)이나
--   20260927_block_enforce.sql 을 다시 적용하면 이 파일도 다시 적용한다(둘 다 역할의 표 권한을 먼저 거둔다).
--   역할 블록을 다시 적용했다면 20260925_cti.sql 도 다시 적용한다(콘솔의 CTI 읽기가 빠진다. 빠져도 상태판은 취약점 줄만 '정보 없음').
--   enforcer/install-enforcer.sh 는 #47 → #51 → 이 파일 순으로 적용한다.
--   앱 · 적재기 · 집행기보다 먼저 적용하지 않아도 된다(표 · 권한이 없으면 콘솔은 '미확인' 으로 답하고, 적재기 · 집행기는 기록만 건너뛴다).
-- 적용 (Mac, 저장소 루트):
--   ssh -F ~/.ssh/config.opsloop data01 'sudo -n docker exec -i opsloop-db psql -U opsloop -d opsloop -v ON_ERROR_STOP=1 -q' \
--     < infra/migrations/20260930_status_board.sql
-- 확인: infra/vmware/scripts/verify-db-roles.sh 의 '관제 대상 상태판' 줄
BEGIN;
-- 관제 대상 상태판 (이슈 #52)
--   대시보드의 관제 대상 카드가 읽는 생존 신호 표와 콘솔의 읽기 권한이다. 생존 신호가 있는 대상만 수집 상태를 정상 · 수신 없음으로
--   가르고, 로그 시각만 있는 대상은 '생존 상태 미확인' 으로 둔다(콘솔 API app/targets.py).
--     sensor_heartbeats  신호 하나에 한 줄. source 가 키다.
--                  uploader:<인스턴스 ID>  센서 업로더의 생존 신호(hb). 적재기(puller/record_heartbeats.py)가 적재 회차마다 쓴다
--                  block:gateway · block:fw  관문 · 내부 방화벽 동기화의 차단 보고. 집행기(enforcer/block_enforcer.py)가 1분마다 쓴다
--                  seen_at 은 신호 자체의 시각이고 checked_at 은 기록한 쪽이 마지막으로 읽어 본 시각이다. 둘을 나눠 '신호가 끊김' 과
--                  '기록하는 쪽이 멈춤' 을 가른다. 못 읽은 회차는 seen_at 을 지우지 않고 checked_at · problem 만 바꾼다.
--                  오래됨은 problem 이 아니라 시각으로 판단한다.
--     sensor_heartbeats_guard  두 역할의 표 권한이 같으므로 행 종류는 트리거로 가른다. kind='uploader' 행은 적재 역할,
--                  kind='block_report' 행은 집행 역할만 넣고 바꾼다(UPDATE 는 바뀌기 전 행의 kind 도 본다). 슈퍼유저(스키마 적용 ·
--                  복원)는 막지 않는다. 키 모양(uploader:<host> · block:<role>)과 역할 · 호스트 모양도 함께 본다.
--                  장악된 적재기가 방화벽 보고를, 장악된 집행기가 업로더 신호를 꾸미지 못한다.
--                  지우는 역할은 없다. OPSLOOP_HOSTS 에서 뺀 호스트의 줄은 소유자가 지운다(infra/vmware/README.md '생존 신호 표').
--     콘솔       sensor_heartbeats · node_metrics 를 읽기만 한다(대상 카드의 생존 신호 · 자원 지표 한 줄).
--   infra/migrations/20260930_status_board.sql 이 이 블록과 같다(infra/test_status_board_db.py 가 대조한다). 역할 블록
--   (20260924_db_roles.sql)이나 20260927_block_enforce.sql 을 다시 적용하면 이 블록도 다시 적용한다(둘 다 역할의 표 권한을 먼저 거둔다).
--   여러 번 적용해도 결과가 같다. 앱보다 먼저 적용하지 않아도 된다(콘솔 API 는 표 · 권한이 없으면 '미확인' 으로 답하고,
--   적재기 · 집행기는 표 · 권한이 없으면 기록만 건너뛴다).
CREATE TABLE IF NOT EXISTS sensor_heartbeats (
    source     text        PRIMARY KEY,           -- 'uploader:<인스턴스 ID>' · 'block:gateway' · 'block:fw'
    kind       text        NOT NULL CHECK (kind IN ('uploader', 'block_report')),
    role       text        NOT NULL CHECK (role IN ('sensor', 'gateway', 'fw')),
    host       text        NOT NULL,              -- 인스턴스 ID(i-…) 또는 fw-<이름>
    seen_at    timestamptz,                       -- 신호 자체의 시각: 업로더 hb 의 S3 LastModified · 차단 보고의 at(검증한 값)
    checked_at timestamptz NOT NULL,              -- 기록한 쪽(적재기 · 집행기)이 마지막으로 읽어 본 시각
    problem    text                               -- 읽기 문제(없음 · 형식이 틀림 · 일시 오류 …). 정상이면 NULL
);
CREATE OR REPLACE FUNCTION sensor_heartbeats_guard() RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = public, pg_temp
AS $$
DECLARE
    -- 이 세션이 쓸 수 있는 행 종류. 적재 · 집행 역할이 아니면 NULL 이라 어느 행도 쓰지 못한다
    v_kind text := CASE session_user::text WHEN 'opsloop_ingest' THEN 'uploader'
                                           WHEN 'opsloop_enforcer' THEN 'block_report' END;
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = session_user AND rolsuper) THEN
        RETURN NEW;
    END IF;
    IF NEW.kind IS DISTINCT FROM v_kind THEN
        RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege', TABLE = 'sensor_heartbeats', COLUMN = 'kind',
            MESSAGE = format('생존 신호(%s)는 그 신호를 기록하는 쪽만 쓴다 (업로더 신호: 적재기 · 차단 보고: 집행기)', NEW.kind);
    END IF;
    IF TG_OP = 'UPDATE' THEN
        IF OLD.kind IS DISTINCT FROM v_kind THEN
            RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege', TABLE = 'sensor_heartbeats', COLUMN = 'kind',
                MESSAGE = format('생존 신호(%s)는 그 신호를 기록하는 쪽만 바꾼다 (업로더 신호: 적재기 · 차단 보고: 집행기)', OLD.kind);
        END IF;
    END IF;
    IF NOT ((NEW.kind = 'uploader' AND NEW.role IN ('sensor', 'gateway') AND NEW.host ~ '^i-[0-9a-f]{8,17}$'
             AND NEW.source = 'uploader:' || NEW.host)
         OR (NEW.kind = 'block_report' AND NEW.role IN ('gateway', 'fw') AND NEW.host ~ '^(i-[0-9a-f]{8,17}|fw-[a-z0-9-]{1,40})$'
             AND NEW.source = 'block:' || NEW.role)) THEN
        RAISE EXCEPTION USING ERRCODE = 'check_violation', CONSTRAINT = 'sensor_heartbeats_source', TABLE = 'sensor_heartbeats',
            MESSAGE = format('생존 신호 키 · 역할 · 호스트가 맞지 않다: %s', left(NEW.source, 80));
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION sensor_heartbeats_guard() FROM PUBLIC;
CREATE OR REPLACE TRIGGER sensor_heartbeats_guard
    BEFORE INSERT OR UPDATE ON sensor_heartbeats
    FOR EACH ROW EXECUTE FUNCTION sensor_heartbeats_guard();

-- 적재 · 집행 역할은 자기 신호를 넣고 고친다(ON CONFLICT DO UPDATE 가 기존 값을 읽으므로 SELECT 도 준다). 지우지는 못한다.
-- 콘솔은 생존 신호와 노드 지표를 읽기만 한다. 역할 블록 · #47 블록이 표 권한을 먼저 거두므로 그것을 다시 적용하면 이 블록도 다시 적용한다
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_ingest') THEN
        GRANT SELECT, INSERT, UPDATE ON sensor_heartbeats TO opsloop_ingest;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_enforcer') THEN
        GRANT SELECT, INSERT, UPDATE ON sensor_heartbeats TO opsloop_enforcer;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_console') THEN
        GRANT SELECT ON sensor_heartbeats, node_metrics TO opsloop_console;
    END IF;
END
$$;
COMMIT;
