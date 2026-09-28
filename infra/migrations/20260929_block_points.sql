-- 차단 집행 지점 · 시험 출발지 (이슈 #51). schema.sql 의 '차단 집행 지점 · 시험 출발지 (이슈 #51)' 블록이 글자 그대로 들어 있으며
--   여러 번 적용해도 같다 (infra/test_block_points_db.py 가 대조한다).
--   - blocklist.enforcement (jsonb): 집행 지점(관문 · 내부 방화벽)별 결과. 집행기만 쓴다(트리거 blocklist_enforcement_guard)
--   - test_ranges: 시험 출발지 대역과 초기값(문서용 대역 셋)
--   - is_test_source(inet): 시험 출발지 판단(SECURITY DEFINER · PUBLIC 실행). 콘솔 · 대시보드 집계가 부른다
--   - rule_quality: 시험 출발지의 사건을 뺀 정의로 교체(열 그대로)
--   '차단 집행 (이슈 #47)' 블록 뒤에 적용한다. 역할 블록(schema.sql · 20260924_db_roles.sql)이나 20260927_block_enforce.sql 을
--   다시 적용하면 이 파일도 다시 적용한다(둘 다 집행 · 콘솔 역할의 표 권한을 먼저 거둔다). enforcer/install-enforcer.sh 는 둘을 차례로 적용한다.
--   앱보다 먼저 적용해도 된다(콘솔은 enforcement 가 없으면 지점별 표를 그리지 않는다). 집행기(OPSLOOP_FW_ID)보다 먼저 적용해야 한다.
-- 적용 (Mac, 저장소 루트):
--   ssh -F ~/.ssh/config.opsloop data01 'sudo -n docker exec -i opsloop-db psql -U opsloop -d opsloop -v ON_ERROR_STOP=1 -q' \
--     < infra/migrations/20260929_block_points.sql
-- 확인: infra/vmware/scripts/verify-db-roles.sh 의 '집행 지점' 줄
BEGIN;
-- 차단 집행 지점 · 시험 출발지 (이슈 #51)
--   집행 지점이 관문 하나에서 둘(AWS 관문 · 온프레미스 내부 방화벽)이 된다. 관문의 확인 세 열(method · enforced_at · enforce_note)과
--   그 감사(console.block.enforced · unenforced)는 그대로 두고, 지점별 결과는 enforcement(jsonb)에 둔다.
--     enforcement  {"gateway": {...}, "fw": {...}}. 지점마다 state(pending 보고 전 · confirmed 그 지점이 적용한 목록에 이 행이 있음 ·
--                  failed 그 지점이 거부 · stale 보고 없음 또는 5분 넘게 미반영) · since(그 상태가 된 시각 ISO) · mode(nft · fail2ban) · note.
--                  집행기(enforcer/block_enforcer.py)만 쓴다. 상태가 바뀔 때만 쓰고 감사 트리거는 이 열을 보지 않는다.
--                  목록에서 빠진 행(해제 · 만료 · 제외)은 NULL 로 비운다.
--     blocklist_enforcement_guard  콘솔 역할은 해제 · 연장 때문에 blocklist 표 전체 UPDATE 권한이 있어 열 권한으로는 막히지 않는다.
--                  그래서 트리거로 막는다: enforcement 를 넣거나 바꾸는 것은 집행 역할과 슈퍼유저(스키마 적용 · 복원)뿐이다.
--                  장악된 콘솔이 내부 방화벽 '적용 확인' 을 꾸미지 못한다.
--     test_ranges  시험 출발지 대역(표 정의는 rule_quality 뷰 앞). 초기값은 문서용 대역 셋이다. 지운 줄은 다시 적용하면 되살아난다.
--     is_test_source(inet)  시험 출발지인가(SECURITY DEFINER). 콘솔 · 대시보드 · 규칙 화면은 표를 직접 읽지 않고 이 함수를 부른다.
--                  함수 실행은 PUBLIC 기본값이라 역할 블록을 다시 적용해도 집계가 멈추지 않는다.
--     rule_quality 시험 출발지의 사건을 뺀 정의로 다시 만든다(열은 그대로). 위(차단 목록 앞)의 정의와 글자가 같다.
--   infra/migrations/20260929_block_points.sql 이 이 블록과 같다(infra/test_block_points_db.py 가 대조한다). 역할 블록이 모든 표의
--   권한을 먼저 거두므로 권한은 여기서 다시 준다. '차단 집행 (이슈 #47)' 블록 뒤에 있어야 하고, 역할 블록을 다시 적용하면 이 블록도 다시 적용한다.
ALTER TABLE blocklist ADD COLUMN IF NOT EXISTS enforcement jsonb;
CREATE TABLE IF NOT EXISTS test_ranges (
    cidr       inet        PRIMARY KEY,
    note       text        NOT NULL,
    created_at timestamptz DEFAULT now()
);
CREATE OR REPLACE FUNCTION is_test_source(ip inet) RETURNS boolean
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = public, pg_temp
AS $$ SELECT EXISTS (SELECT 1 FROM test_ranges t WHERE ip <<= t.cidr) $$;
CREATE OR REPLACE FUNCTION blocklist_enforcement_guard() RETURNS trigger
LANGUAGE plpgsql
SET search_path = public, pg_temp
AS $$
BEGIN
    IF (TG_OP = 'INSERT' AND NEW.enforcement IS NOT NULL)
       OR (TG_OP = 'UPDATE' AND NEW.enforcement IS DISTINCT FROM OLD.enforcement) THEN
        IF session_user::text <> 'opsloop_enforcer'
           AND NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = session_user AND rolsuper) THEN
            RAISE EXCEPTION USING ERRCODE = 'insufficient_privilege', TABLE = 'blocklist', COLUMN = 'enforcement',
                MESSAGE = '집행 지점별 결과(blocklist.enforcement)는 집행기만 쓴다';
        END IF;
    END IF;
    RETURN NEW;
END;
$$;
REVOKE ALL ON FUNCTION blocklist_enforcement_guard() FROM PUBLIC;
CREATE OR REPLACE TRIGGER blocklist_enforcement_guard
    BEFORE INSERT OR UPDATE OF enforcement ON blocklist
    FOR EACH ROW EXECUTE FUNCTION blocklist_enforcement_guard();
INSERT INTO test_ranges (cidr, note) VALUES
    ('192.0.2.0/24',    '문서용 · 동기화 자가 시험 주소'),
    ('198.51.100.0/24', '문서용 · 차단 집행 끝-끝 시험 주소'),
    ('203.0.113.0/24',  '문서용 · 외부 역할 세그먼트 (시연용 공격자 VM)')
ON CONFLICT (cidr) DO NOTHING;
CREATE OR REPLACE VIEW rule_quality AS
SELECT
    i.rule_id,
    i.rule_version,
    count(*)                                                        AS incidents,
    count(v.id)                                                     AS judged,
    count(*) FILTER (WHERE v.verdict = 'threat')                    AS threats,
    count(*) FILTER (WHERE v.verdict = 'non_actionable')            AS non_actionable,
    count(*) FILTER (WHERE v.verdict = 'false_positive')            AS false_positives,
    -- 미결은 판정이 아니므로 분모에서 뺀다. 양성 정탐은 정확한 탐지이므로
    -- 분모에는 남기고 분자에서만 뺀다. 둘을 같이 취급하면 규칙의 정확도가
    -- 실제와 달라진다.
    round(100.0 * count(*) FILTER (WHERE v.verdict = 'false_positive')
          / NULLIF(count(v.id) FILTER (WHERE v.verdict <> 'undetermined'), 0), 1)
                                                                    AS false_positive_rate,
    round(100.0 * count(*) FILTER (WHERE v.verdict IN ('non_actionable', 'false_positive',
                                                       'benign_positive'))
          / NULLIF(count(v.id) FILTER (WHERE v.verdict <> 'undetermined'), 0), 1)
                                                                    AS non_action_rate,
    -- 새 열은 뒤에 붙인다. 뷰는 기존 열의 이름과 순서를 바꾸면 교체되지 않는다.
    count(*) FILTER (WHERE v.verdict = 'benign_positive')           AS benign_positives,
    count(*) FILTER (WHERE v.verdict = 'undetermined')              AS undetermined,
    count(v.id) FILTER (WHERE v.verdict <> 'undetermined')          AS judged_effective
FROM incidents i
LEFT JOIN LATERAL (
    SELECT id, verdict FROM verdicts WHERE incident_key = i.incident_key
    ORDER BY created_at DESC, id DESC LIMIT 1
) v ON true
-- 시험 출발지(test_ranges · 이슈 #51)의 사건은 뺀다. 시연을 되풀이해도 규칙 품질이 바뀌지 않게 한다.
-- 표 · 함수가 이 뷰보다 먼저 있어야 하므로 정의가 위(차단 목록 앞)에 있다
WHERE NOT is_test_source(i.actor_ip)
GROUP BY i.rule_id, i.rule_version;

-- 집행 역할은 지점별 결과 열을 더 쓴다. 콘솔은 시험 대역 목록을 읽기만 한다(집계는 is_test_source 로 한다).
-- #47 마이그레이션(20260927_block_enforce.sql)이 집행 역할의 표 권한을 먼저 모두 거두므로, 그것을 다시 적용하면 이 블록도 다시 적용한다
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_enforcer') THEN
        GRANT UPDATE (enforcement) ON blocklist TO opsloop_enforcer;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_console') THEN
        GRANT SELECT ON test_ranges TO opsloop_console;
    END IF;
END
$$;
COMMIT;
