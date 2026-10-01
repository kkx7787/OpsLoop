"""기간 보고서 (이슈 #58). GET /api/reports/period?period=24h|7d|14d|30d&sections=<이름>&sections=…

인쇄 · PDF 로 남기는 보고서의 본문이다. 기간은 출력 시각에서 거꾸로 잰다. until = 출력 시각(as_of), since = until - 기간이고
경계는 [since, until) 이다(사건 목록 · 규칙 화면의 기간 조건과 같다). 날짜 묶음은 한국 시각(AT TIME ZONE 'Asia/Seoul')이다.
DB 는 UTC 로 돌아 ::date 로 자르면 UTC 날짜가 된다(UTC 15:00 에 KST 날짜가 바뀐다).
반복 읽기 · 읽기 전용 트랜잭션 하나에서 모든 구역을 읽는다(대시보드 summary 와 같다). 구역마다 기준(basis)과 설명(notes)을 낸다.
  period  기간 안에 생긴 것만 센다   as_of  출력 시각의 상태다(이력이 없다)   mixed  둘이 섞였다(어느 값이 어느 쪽인지 notes 에 적는다)

구역
  overview  사건(심각도 · 발생원) · 판정 · 지금 잔량 · 목표 초과 · 판정 대기 · 판정 소요 · KST 날짜별 · 상위 출발지
  rules     규칙별 판정(operations.py /api/rules/quality 와 같은 계산) · 흡수 · 억제 · 기간 중 규칙 버전
  blocks    차단 · 해제 조치 · 새 차단 요청의 요청자 종류 · 차단 감사 이벤트 수 · 관문 반영 지연 · 지금 차단 상태
  targets   대상별 수집 · 대응(상태판 targets_view 에서 추림) · 센서별 이벤트 · 탐지 실행 공백 · web-01 자원 최대
  cti       자산별 취약점 · 주목 CVE(출력 시점) · 기간 중 KEV 등재 가운데 우리 자산에 걸린 것 · 신선도
  ops       감사 이벤트 수 · 로그인 실패 · 알림 발송(관리자만)
표 · 권한이 없는 구역은 오류가 아니라 {"available": false, "reason"} 이다(cti.TABLES_SQL 과 같은 선검사). 한 질의라도 실패하면
트랜잭션 전체가 멈추므로 예외로 가르지 않는다.

PDF 는 시스템 밖으로 나간다. 감사 기록은 종류별 수만 싣고 행위자 · detail 원문은 싣지 않는다. 알림은 채널 주소를 싣지 않는다.
이벤트 집계는 실제(provenance='real') 이벤트만 센다. 시험 출발지(is_test_source)는 규칙 화면처럼 합계에서 빼고 수를 따로 밝힌다.
"""
from datetime import timedelta
from typing import Literal

from fastapi import APIRouter, Query, Request

import cti
import targets
from access import require_role
from block_points import BLOCK_STATES_SQL
from dashboard import dashboard_metrics

router = APIRouter()

TZ = "Asia/Seoul"
STATEMENT_TIMEOUT = "5s"
PERIODS = {"24h": timedelta(hours=24), "7d": timedelta(days=7), "14d": timedelta(days=14), "30d": timedelta(days=30)}
PERIOD = Literal["24h", "7d", "14d", "30d"]
# 구역 이름. 이 순서로 낸다(요청 순서와 무관하다)
SECTIONS = ("overview", "rules", "blocks", "targets", "cti", "ops")
SECTION = Literal["overview", "rules", "blocks", "targets", "cti", "ops"]
ADMIN_ONLY = ("ops",)       # 감사 · 알림 발송 조회(/api/audit · /api/notify/deliveries)와 같이 관리자만
SEVERITIES = ("critical", "high", "medium", "low")
VERDICTS = ("threat", "non_actionable", "false_positive", "benign_positive", "undetermined")
# 발생원: 규칙 번호 앞자리(R0xx 허니팟 · R1xx 웹 · 관제 대상 · R2xx 감사 · 자체 감시 · R3xx 수집 기반)
ORIGINS = ("R0xx", "R1xx", "R2xx", "R3xx", "other")
# 차단 감사 이벤트(schema.sql audit_blocklist · note_block_expired · blocklist_points_change). 없는 종류도 0 으로 낸다
BLOCK_EVENTS = ("console.block.created", "console.block.rearmed", "console.block.extended", "console.block.shortened",
                "console.block.points", "console.block.released", "console.block.expired", "console.block.enforced",
                "console.block.unenforced")
REQUESTER_KINDS = ("console", "triage", "system", "unknown")

# 구역이 읽는 표. 모두 있고 콘솔 역할이 읽을 수 있어야 그 구역을 낸다. 역할 블록만 다시 적용하면 뒤쪽 블록의 권한이 빠지므로
#   구역마다 먼저 본다. nodes 는 콘솔에 열 권한만 있어(has_table_privilege 가 거짓이다) 넣지 않는다. 상태판(targets_view)은
#   생존 신호 · 자원 지표 · nodes(열 권한으로 본다, 등록 노드 카드) · CTI · 금지 대역을 스스로 가른다. 흡수 기록 · 주목 CVE ·
#   알림 발송은 없으면 그 부분만 null 이다
TABLES = {
    "overview": ["incidents", "verdicts"],
    "rules": ["incidents", "verdicts", "rule_versions"],
    "blocks": ["actions", "blocklist", "audit_log"],
    "targets": ["events", "incidents", "verdicts", "rule_versions", "detector_runs", "blocklist"],
    "cti": cti.CTI_TABLES,
    "ops": ["audit_log", "events"],
}

# 읽을 수 없는 표(없거나 SELECT 권한이 없다). 표가 없으면 권한 함수가 오류를 내므로 CASE 로 먼저 가른다(cti.TABLES_SQL 과 같은 꼴)
MISSING_SQL = ("SELECT coalesce(array_agg(t ORDER BY t), '{}') FROM unnest($1::text[]) AS t"
               " WHERE CASE WHEN to_regclass(t) IS NULL THEN true ELSE NOT has_table_privilege(t, 'SELECT') END")

# 사건 수. 발생 시각(first_ts) 기준이라 사건 목록 · 규칙 구역의 기간 조건과 같다. $1 since · $2 until
INCIDENTS_SQL = """
    SELECT is_test_source(actor_ip) AS test, severity,
           coalesce('R' || substring(rule_id from '^R([0-3])[0-9]{2}(?:[^0-9]|$)') || 'xx', 'other') AS origin,
           count(*) AS n
    FROM incidents WHERE first_ts >= $1 AND first_ts < $2
    GROUP BY 1, 2, 3"""

# 기간 안에 기록된 판정(재판정 포함)
VERDICTS_SQL = """
    SELECT is_test_source(i.actor_ip) AS test, v.verdict, count(*) AS n
    FROM verdicts v JOIN incidents i USING (incident_key)
    WHERE v.created_at >= $1 AND v.created_at < $2
    GROUP BY 1, 2"""

# 지금 최신 판정이 판단 유보인 사건(판정 없음은 dashboard_metrics 가 센다)
UNDETERMINED_SQL = """
    SELECT count(*) FROM (SELECT DISTINCT ON (incident_key) verdict FROM verdicts
                          ORDER BY incident_key, created_at DESC, id DESC) v
    WHERE v.verdict = 'undetermined'"""

# 판정 대기: 기간 안에 만들어진(created_at) 사건의 생성 → 첫 판정(기간 끝 전)까지 초. 운영 부담 지표(docs/2026-09-28)의 정의다
WAIT_SQL = """
    WITH q AS (
        SELECT CASE WHEN f.first_at IS NOT NULL      -- greatest 는 NULL 을 건너뛰어 0 이 되므로 판정 없음을 먼저 가른다
                    THEN greatest(0, extract(epoch FROM (f.first_at - i.created_at)))::float8 END AS wait
        FROM incidents i
        CROSS JOIN LATERAL (SELECT min(v.created_at) AS first_at FROM verdicts v
                            WHERE v.incident_key = i.incident_key AND v.created_at < $2) f
        WHERE i.created_at >= $1 AND i.created_at < $2 AND NOT is_test_source(i.actor_ip))
    SELECT count(*) AS incidents, count(wait) AS judged,
           percentile_cont(0.5) WITHIN GROUP (ORDER BY wait) AS p50,
           percentile_cont(0.9) WITHIN GROUP (ORDER BY wait) AS p90
    FROM q"""

# 판정 소요: 콘솔 판정 화면이 잰 초(verdicts.decision_seconds). triage · 일괄 판정은 값이 없다
DECISION_SQL = """
    SELECT count(*) AS n,
           percentile_cont(0.5) WITHIN GROUP (ORDER BY v.decision_seconds) AS p50,
           percentile_cont(0.9) WITHIN GROUP (ORDER BY v.decision_seconds) AS p90
    FROM verdicts v JOIN incidents i USING (incident_key)
    WHERE v.created_at >= $1 AND v.created_at < $2 AND v.decision_seconds IS NOT NULL
      AND NOT is_test_source(i.actor_ip)"""

# KST 날짜별 만들어진 사건(created_at) · 기록된 판정. 사건 · 판정이 없는 날도 0 으로 낸다. 끝은 [since, until) 라 until 직전의 날짜다
DAILY_SQL = f"""
    WITH days AS (
        SELECT generate_series(($1::timestamptz AT TIME ZONE '{TZ}')::date,
                               (($2::timestamptz - interval '1 microsecond') AT TIME ZONE '{TZ}')::date,
                               interval '1 day')::date AS date),
    rows AS (
        SELECT (i.created_at AT TIME ZONE '{TZ}')::date AS date, 1 AS created, 0 AS judged FROM incidents i
        WHERE i.created_at >= $1 AND i.created_at < $2 AND NOT is_test_source(i.actor_ip)
        UNION ALL
        SELECT (v.created_at AT TIME ZONE '{TZ}')::date, 0, 1 FROM verdicts v JOIN incidents i USING (incident_key)
        WHERE v.created_at >= $1 AND v.created_at < $2 AND NOT is_test_source(i.actor_ip))
    SELECT days.date, coalesce(sum(r.created), 0) AS created, coalesce(sum(r.judged), 0) AS judged
    FROM days LEFT JOIN rows r USING (date)
    GROUP BY days.date ORDER BY days.date"""

# 상위 출발지 5곳과 전체 출발지 수(시험 대역 제외). 최고 심각도는 글자 max 가 아니라 순위로 고른다(main.py 사건 목록 정렬과 같다)
TOP_SOURCES_SQL = """
    SELECT host(actor_ip) AS ip, count(*) AS incidents,
           (ARRAY['critical', 'high', 'medium', 'low'])[1 + min(CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                                                                 WHEN 'medium' THEN 2 ELSE 3 END)] AS severity,
           max(last_ts) AS last_ts, count(*) OVER () AS sources
    FROM incidents
    WHERE first_ts >= $1 AND first_ts < $2 AND actor_ip IS NOT NULL AND NOT is_test_source(actor_ip)
    GROUP BY actor_ip ORDER BY incidents DESC, actor_ip LIMIT 5"""

# 규칙별 판정. operations.py quality() 의 details 질의와 글자가 같다(test_reports_db 가 두 결과를 견준다)
QUALITY_SQL = """
            WITH latest AS (
                SELECT DISTINCT ON (incident_key) incident_key, verdict FROM verdicts
                ORDER BY incident_key, created_at DESC, id DESC
            )
            SELECT i.rule_id, i.rule_version, count(*) AS incidents, count(v.verdict) AS judged,
                count(*) FILTER (WHERE v.verdict='threat') AS threats,
                count(*) FILTER (WHERE v.verdict='non_actionable') AS non_actionable,
                count(*) FILTER (WHERE v.verdict='false_positive') AS false_positives,
                count(*) FILTER (WHERE v.verdict='benign_positive') AS benign_positives,
                count(*) FILTER (WHERE v.verdict='undetermined') AS undetermined,
                count(v.verdict) FILTER (WHERE v.verdict<>'undetermined') AS judged_effective,
                round(100.0*count(*) FILTER (WHERE v.verdict='false_positive') /
                      nullif(count(v.verdict) FILTER (WHERE v.verdict<>'undetermined'),0),1) AS false_positive_rate,
                round(100.0*count(*) FILTER (WHERE v.verdict IN ('non_actionable','false_positive','benign_positive')) /
                      nullif(count(v.verdict) FILTER (WHERE v.verdict<>'undetermined'),0),1) AS non_action_rate
            FROM incidents i LEFT JOIN latest v USING (incident_key)
            WHERE ($1::timestamptz IS NULL OR i.first_ts >= $1) AND ($2::timestamptz IS NULL OR i.first_ts < $2)
              AND NOT is_test_source(i.actor_ip)   -- 시험 출발지 제외 (이슈 #51)
            GROUP BY i.rule_id,i.rule_version ORDER BY i.rule_id,i.rule_version
        """

# 기간 안에 기록된(recorded_at) 흡수 · 억제. 탐지기가 판정 없는 사건을 지우며 남긴 것이라 사건 수에는 없다
ABSORBED_SQL = """
    SELECT rule_id, rule_version, count(*) FILTER (WHERE kind = 'absorbed') AS absorbed,
           count(*) FILTER (WHERE kind = 'suppressed') AS suppressed
    FROM incident_absorbed
    WHERE recorded_at >= $1 AND recorded_at < $2 AND NOT is_test_source(actor_ip)
    GROUP BY rule_id, rule_version ORDER BY rule_id, rule_version"""

# 기간 안에 만든 규칙 버전. 정의 본문은 싣지 않고 규칙 id 만(id 가 없는 항목은 뺀다)
VERSIONS_SQL = """
    SELECT rule_version, reason, created_at,
           ARRAY(SELECT r ->> 'id' FROM jsonb_array_elements(CASE WHEN jsonb_typeof(definition -> 'rules') = 'array'
                                                                  THEN definition -> 'rules' ELSE '[]'::jsonb END) r
                 WHERE jsonb_typeof(r) = 'object' AND r ->> 'id' IS NOT NULL) AS rules
    FROM rule_versions WHERE created_at >= $1 AND created_at < $2
    ORDER BY created_at, rule_version"""

ACTIONS_SQL = """
    SELECT action, count(*) AS n FROM actions
    WHERE action IN ('block_ip', 'unblock_ip') AND created_at >= $1 AND created_at < $2
    GROUP BY action"""

# 기간 안의 새 차단 요청(r)과 집행 확인(a 의 enforced). 감사 detail(schema.sql audit_blocklist)에서 주소 · 요청자 · 만료 전 값 ·
#   요청 지점 · 관문 적용 시각만 꺼낸다(값은 싣지 않는다). 새 요청은 created · rearmed 와, 만료가 지난 행을 다시 건 extended(만료 전
#   값 from 이 기록 시각보다 앞선다)다. 살아 있는 차단의 만료 연장은 새 요청이 아니다. extended 에는 요청자가 없다.
#   요청 지점(points=gateway,fw · fw · 열이 없던 DB 의 '-', 이슈 #77)이 없는 옛 감사는 두 지점 요청이다. 집행 확인의 쪽지(note=)가
#   ' · 기존 차단 유지'(kept) · ' · 연속성 확인 불가'(uncertain)로 끝나면 앞 확인을 비운 적 없이 다시 확인한 것이다. 관문 차단이 이어진
#   것을 보고로 확인했는가로 가른다(집행기 NOTE_KEPT · NOTE_UNCERTAIN, 이슈 #77 결정 2 · 3).
#   시각 글자는 pg_input_is_valid 로 먼저 가른다(캐스트 오류가 트랜잭션 전체를 멈춘다). next 는 같은 주소의 다음 요청,
#   n 은 같은 주소 안의 요청 순번이다((ip, n) 이 요청 하나. 같은 시각 요청도 가른다)
REQUESTS_CTE = """
    WITH a AS (
        SELECT ts, eventid,
               substring(detail from '(?:^|[[:space:]])ip=([^[:space:]]+)') AS ip,
               substring(detail from '(?:^|[[:space:]])requested_by=([^[:space:]]+)') AS who,
               substring(detail from '(?:^|[[:space:]])from=([^=]+) to=') AS was,
               substring(detail from '(?:^|[[:space:]])points=([^[:space:]]+)') AS points,
               substring(detail from '(?:^|[[:space:]])at=([^=]+) note=') AS at,
               detail ~ ' note=관문 반영 · [^=]* · 기존 차단 유지$' AS kept,
               detail ~ ' note=관문 반영 · [^=]* · 연속성 확인 불가$' AS uncertain
        FROM audit_log
        WHERE eventid IN ('console.block.created', 'console.block.rearmed', 'console.block.extended',
                          'console.block.enforced')
          AND ts >= $1 AND ts < $2),
    r AS (
        SELECT ts, ip, who, points, lead(ts) OVER w AS next, row_number() OVER w AS n FROM a
        WHERE eventid IN ('console.block.created', 'console.block.rearmed')
           OR (eventid = 'console.block.extended'
               AND CASE WHEN pg_input_is_valid(was, 'timestamptz') THEN was::timestamptz END <= ts)
        WINDOW w AS (PARTITION BY ip ORDER BY ts))"""

# 새 차단 요청의 요청자 종류. 요청자는 감사 detail 의 requested_by 다(콘솔: 사용자 이름 · triage:<판정자> · system:…).
#   조치 기록(actions.operator)은 triage 도 접두 없는 판정자 이름이라 종류를 가를 수 없다. 값은 싣지 않고 종류만 센다
REQUESTERS_SQL = REQUESTS_CTE + """
    SELECT CASE WHEN who LIKE 'triage:%' THEN 'triage' WHEN who LIKE 'system:%' THEN 'system'
                WHEN who IS NULL OR who = '-' THEN 'unknown' ELSE 'console' END AS kind, count(*) AS n
    FROM r GROUP BY 1"""

# 감사 이벤트 종류별 수. $3 종류 LIKE(차단: 'console.block.%' · 운영 기록: 전부)
AUDIT_SQL = """
    SELECT eventid, count(*) AS n FROM audit_log
    WHERE ts >= $1 AND ts < $2 AND eventid LIKE $3
    GROUP BY eventid ORDER BY eventid"""

# 관문 반영 지연(관문을 요청한 새 차단 요청 → 관문 반영). 내부 방화벽만 요청한 요청은 관문에 넘기지 않아 빼고(다음 요청 판단에는
#   넣는다), 지점이 없는 옛 요청 · '-' 는 두 지점이다. 살아 있는 차단의 넓히기(console.block.points)는 새 요청이 아니라 넣지 않는다
#   (그 뒤의 관문 확인은 짝이 없다. 기준 설명에 적는다). 요청마다 같은 주소의 다음 요청 전 · 기간 끝 전의 첫 집행 확인(enforced)과 짝짓고,
#   그 확인의 관문 적용 시각(at=, 차단 목록의 enforced_at 과 같은 값. 읽지 못하면 확인 기록 시각)에서 요청 시각을 뺀다.
#   짝이 기존 차단 유지(kept) · 연속성 확인 불가(uncertain)면 관문이 이 주소를 뺐다는 오류 없는 보고 없이 다시 건 요청이라 새 반영이
#   아니다. maintained · uncertain 으로 따로 세고 지연(enforced · 평균 · 중앙값 · 최대)에서 뺀다(이슈 #77 결정 2 · 3). 관문이 뺀 뒤 다시
#   건 요청은 unenforced 뒤의 새 확인과 짝지어 지연에 든다.
#   차단 목록으로 재지 않는다. 집행기가 해제 · 만료된 행의 enforced_at 을 비우고(enforcer/block_enforcer.py) 다시 걸면
#   created_at 을 덮어, 기간이 차단 수명(24시간)보다 길면 지난 요청의 집행이 사라진다.
#   확인(e)을 주소로 한 번 조인하고(해시 · 병합 조인) 요청마다 첫 확인을 DISTINCT ON 으로 고른다. 요청마다 a 를 다시 훑으면
#   (LATERAL) 요청 수의 제곱이라 수천 건에서 5초 상한에 걸린다. 짝 없는 요청(LEFT JOIN 의 NULL)은 지연도 NULL 이다
#   (greatest 는 NULL 을 무시해 0 이 된다)
ENFORCE_SQL = REQUESTS_CTE + """,
    e AS (
        SELECT ts, ip, CASE WHEN pg_input_is_valid(at, 'timestamptz') THEN at::timestamptz ELSE ts END AS at, kept, uncertain
        FROM a WHERE eventid = 'console.block.enforced'),
    f AS (
        SELECT DISTINCT ON (r.ip, r.n) coalesce(e.kept, false) AS kept, coalesce(e.uncertain, false) AS uncertain,
               CASE WHEN e.ts IS NOT NULL AND NOT e.kept AND NOT e.uncertain
                    THEN greatest(0, extract(epoch FROM (e.at - r.ts)))::float8 END AS delay
        FROM r LEFT JOIN e ON e.ip = r.ip AND e.ts >= r.ts AND (r.next IS NULL OR e.ts < r.next)
        WHERE r.points IS NULL OR r.points = '-' OR 'gateway' = ANY(string_to_array(r.points, ','))
        ORDER BY r.ip, r.n, e.ts)
    SELECT count(*) AS created, count(f.delay) AS enforced, count(*) FILTER (WHERE f.kept) AS maintained,
           count(*) FILTER (WHERE f.uncertain) AS uncertain, avg(f.delay) AS mean,
           percentile_cont(0.5) WITHIN GROUP (ORDER BY f.delay) AS p50, max(f.delay) AS max
    FROM f"""

# 살아 있는 차단 요청의 종합 상태는 main 과 같은 상수(block_points.BLOCK_STATES_SQL, 이슈 #77)를 불러 쓴다. $1 기준 시각
ENFORCE_EXCLUDED = targets.ENFORCE_EXCLUDED
ENFORCE_MISMATCH = "관문 불일치"

SENSOR_EVENTS_SQL = """
    SELECT sensor, count(*) AS n FROM events
    WHERE provenance = 'real' AND ts >= $1 AND ts < $2
    GROUP BY sensor ORDER BY sensor"""


def gap_sql(times: str) -> str:
    """기간 안 시각들(times 의 at 열) 사이의 가장 긴 공백(초). 기간 시작 · 끝도 넣어 처음 · 끝에서 멈춘 것도 잡는다.
    한 번도 없으면 기간 전체다. $1 since · $2 until"""
    return f"""(SELECT max(extract(epoch FROM (g.at - g.prev))) FROM (
               SELECT t.at, lag(t.at) OVER (ORDER BY t.at) AS prev
               FROM (SELECT at FROM {times} UNION ALL SELECT $1::timestamptz UNION ALL SELECT $2::timestamptz) t) g)"""


RUNS_SQL = f"""
    WITH r AS (SELECT started_at AS at FROM detector_runs WHERE started_at >= $1 AND started_at < $2)
    SELECT (SELECT count(*) FROM r) AS runs, {gap_sql('r')} AS max_gap"""

# web-01 1분 지표의 기간 최대값과 지표 공백. $3 노드 id
WEB_METRICS_SQL = f"""
    WITH m AS (SELECT ts AS at, cpu_pct, mem_used_pct, disk_root_pct FROM node_metrics
               WHERE node_id = $3 AND ts >= $1 AND ts < $2)
    SELECT count(*) AS samples, max(cpu_pct) AS cpu_pct, max(mem_used_pct) AS mem_used_pct,
           max(disk_root_pct) AS disk_root_pct, {gap_sql('m')} AS max_gap
    FROM m"""

# 기간 중 KEV 에 오른 항목(등재일은 날짜라 KST 날짜로 기간과 견준다)과 그 CVE 가 걸린 자산
KEV_ADDED_SQL = f"""
    SELECT k.cve_id, k.name, k.date_added,
           coalesce(array_agg(DISTINCT av.asset_id ORDER BY av.asset_id) FILTER (WHERE av.asset_id IS NOT NULL),
                    '{{}}') AS assets
    FROM cti_kev k LEFT JOIN asset_vulnerabilities av ON av.cve_id = k.cve_id
    WHERE k.date_added BETWEEN ($1::timestamptz AT TIME ZONE '{TZ}')::date
                           AND (($2::timestamptz - interval '1 microsecond') AT TIME ZONE '{TZ}')::date
    GROUP BY k.cve_id, k.name, k.date_added ORDER BY k.date_added DESC, k.cve_id"""

LOGIN_FAILED_SQL = """
    SELECT count(*) FROM events
    WHERE sensor = 'console' AND eventid = 'console.login.failed' AND provenance = 'real' AND ts >= $1 AND ts < $2"""

# 알림 발송. 시험 발송(event='test')은 뺀다. 지연은 보낸 것의 넣은 시각 → 보낸 시각
NOTIFY_SQL = """
    SELECT event, status, count(*) AS n FROM notify_deliveries
    WHERE event <> 'test' AND created_at >= $1 AND created_at < $2
    GROUP BY event, status ORDER BY event, status"""
NOTIFY_DELAY_SQL = """
    SELECT percentile_cont(0.5) WITHIN GROUP (ORDER BY extract(epoch FROM (sent_at - created_at)))
    FROM notify_deliveries
    WHERE event <> 'test' AND created_at >= $1 AND created_at < $2 AND status = 'sent' AND sent_at IS NOT NULL"""


# ----------------------------------------------------------------------
#  순수 함수 (DB 없이 시험한다)
# ----------------------------------------------------------------------

def window(as_of, period: str):
    """(since, until). until 은 출력 시각이다."""
    return as_of - PERIODS[period], as_of


def chosen(request: Request, sections) -> list[str]:
    """낼 구역(SECTIONS 순서). 없으면 역할이 볼 수 있는 전부다. 관리자가 아닌데 운영 기록을 달라면 DB 에 닿기 전에 403 이다."""
    user = require_role(request, "viewer", "operator", "admin")
    if sections and any(name in ADMIN_ONLY for name in sections):
        require_role(request, "admin")
    wanted = set(sections) if sections else {name for name in SECTIONS
                                             if name not in ADMIN_ONLY or user["r"] == "admin"}
    return [name for name in SECTIONS if name in wanted]


def num(value, digits=1):
    """초 · 백분율. numeric(Decimal) · 실수를 소수 digits 자리 실수로 낸다(없으면 None)."""
    return round(float(value), digits) if value is not None else None


def unavailable(missing: list) -> dict:
    return {"available": False, "reason": "표가 없거나 읽기 권한이 없음: " + " · ".join(missing)}


# ----------------------------------------------------------------------
#  구역 (부른 쪽이 반복 읽기 트랜잭션을 연다. 시험은 기준 시각을 넘겨 경계를 본다)
# ----------------------------------------------------------------------

async def overview(c, since, until, as_of) -> dict:
    incidents = {"total": 0, "by_severity": dict.fromkeys(SEVERITIES, 0), "by_origin": dict.fromkeys(ORIGINS, 0),
                 "test_source": 0}
    for r in await c.fetch(INCIDENTS_SQL, since, until):
        if r["test"]:
            incidents["test_source"] += r["n"]
            continue
        incidents["total"] += r["n"]
        incidents["by_severity"][r["severity"]] = incidents["by_severity"].get(r["severity"], 0) + r["n"]
        incidents["by_origin"][r["origin"]] += r["n"]
    verdicts = {"total": 0, "by_verdict": dict.fromkeys(VERDICTS, 0), "test_source": 0}
    for r in await c.fetch(VERDICTS_SQL, since, until):
        if r["test"]:
            verdicts["test_source"] += r["n"]
            continue
        verdicts["total"] += r["n"]
        verdicts["by_verdict"][r["verdict"]] = verdicts["by_verdict"].get(r["verdict"], 0) + r["n"]
    pending = (await dashboard_metrics(c, as_of))["pending"]
    wait = await c.fetchrow(WAIT_SQL, since, until)
    decision = await c.fetchrow(DECISION_SQL, since, until)
    top = await c.fetch(TOP_SOURCES_SQL, since, until)
    return {
        "basis": "mixed",
        "notes": ["사건 수 · 상위 출발지: 발생 시각이 기간 안인 사건",
                  "판정 수 · 날짜별 판정: 기간 안에 기록된 판정(재판정 포함)",
                  "시험 출발지(시험 대역): 사건 · 판정 수는 따로 세고 다른 값에서는 뺀다. 잔량 · 목표 초과에만 넣는다",
                  "흡수 · 억제로 지워진 알림은 사건 수에 없다",
                  "판정 대기: 기간 안에 만들어진 사건 대상. 기간 끝까지 판정된 사건만 백분위에 넣는다",
                  "판정 소요: 콘솔에서 한 판정만. triage · 일괄 판정은 값이 없어 빠진다",
                  "잔량 · 목표 초과: 출력 시각 기준. 목표 시간은 발생 시각부터 잰다",
                  "날짜별: 한국 시각(KST) 날짜, 사건은 만들어진 시각 기준. 첫날 · 마지막 날은 기간에 든 시간만 센다"],
        "incidents": incidents,
        "verdicts": verdicts,
        "backlog": {"unjudged": pending["total"], "undetermined": await c.fetchval(UNDETERMINED_SQL),
                    "overdue": pending["overdue"], "warning": pending["warning"],
                    "oldest_seconds": num(pending["oldest_seconds"])},
        "wait": {"incidents": wait["incidents"], "judged": wait["judged"],
                 "p50_seconds": num(wait["p50"]), "p90_seconds": num(wait["p90"])},
        "decision": {"n": decision["n"], "p50_seconds": num(decision["p50"]), "p90_seconds": num(decision["p90"])},
        "daily": [{"date": r["date"].isoformat(), "created": int(r["created"]), "judged": int(r["judged"])}
                  for r in await c.fetch(DAILY_SQL, since, until)],
        "top_sources": {"items": [{"ip": r["ip"], "incidents": r["incidents"], "severity": r["severity"],
                                   "last_ts": cti.iso(r["last_ts"])} for r in top],
                        "total": top[0]["sources"] if top else 0},
    }


async def rules(c, since, until, as_of) -> dict:
    rows = [{k: num(v) if k.endswith("_rate") else v for k, v in dict(r).items()}
            for r in await c.fetch(QUALITY_SQL, since, until)]
    notes = ["규칙별 판정: 발생 시각이 기간 안인 사건의 출력 시각 기준 최신 판정. 판정을 고치면 다시 뽑은 값이 달라진다",
             "시험 출발지의 사건 · 흡수는 뺀다",
             "흡수 · 억제: 기간 안에 기록된 흡수 기록. 사건 수에는 없다"]
    absorbed = None
    # 표를 읽을 수 없으면 absorbed 가 null 이고, 화면 · 인쇄물은 그 null 을 보고 빠졌다는 문장을 한 번 찍는다(notes 에 되풀이하지 않는다)
    if not await c.fetchval(MISSING_SQL, ["incident_absorbed"]):
        by_rule = [dict(r) for r in await c.fetch(ABSORBED_SQL, since, until)]
        absorbed = {"absorbed": sum(r["absorbed"] for r in by_rule), "suppressed": sum(r["suppressed"] for r in by_rule),
                    "rules": by_rule}
    versions = [{"rule_version": r["rule_version"], "reason": r["reason"], "created_at": cti.iso(r["created_at"]),
                 "rules": list(r["rules"])} for r in await c.fetch(VERSIONS_SQL, since, until)]
    return {"basis": "period", "notes": notes, "rows": rows, "absorbed": absorbed, "versions": versions}


async def blocks(c, since, until, as_of) -> dict:
    actions = dict.fromkeys(("block_ip", "unblock_ip"), 0) | {
        r["action"]: r["n"] for r in await c.fetch(ACTIONS_SQL, since, until)}
    requests = dict.fromkeys(REQUESTER_KINDS, 0) | {r["kind"]: r["n"] for r in await c.fetch(REQUESTERS_SQL, since, until)}
    counts = {r["eventid"]: r["n"] for r in await c.fetch(AUDIT_SQL, since, until, "console.block.%")}
    audit = [{"eventid": e, "count": counts.pop(e, 0)} for e in BLOCK_EVENTS] + \
            [{"eventid": e, "count": n} for e, n in counts.items()]
    enforce = await c.fetchrow(ENFORCE_SQL, since, until)
    states = await c.fetchrow(BLOCK_STATES_SQL, as_of)
    return {
        "basis": "mixed",
        "notes": ["조치: 기간 안에 기록된 차단 · 해제 조치(사건 조치 기록)",
                  "새 차단 요청: 기간 안의 차단 요청 · 재요청과 만료 뒤 다시 건 차단. 만료 뒤 다시 건 차단은 요청자가 남지 않아 "
                  "미기록으로 센다. 살아 있는 차단의 연장은 새 요청이 아니다",
                  "감사 이벤트: 기간 안의 차단 감사 기록 종류별 수(행위자 · 내용은 싣지 않는다). '차단 연장'은 살아 있는 차단의 연장과 "
                  "만료 뒤 다시 건 차단을 함께 센다",
                  "관문 반영 지연(관문 요청만): 관문을 요청한 새 차단 요청부터 첫 집행 확인이 적은 관문 적용 시각까지(같은 주소의 "
                  "다음 요청 전). 해제 · 만료된 차단도 넣고, 기간 끝까지 확인되지 않은 요청은 집행 확인 수에서 빠진다. 내부 방화벽만 "
                  "요청한 차단과, 살아 있는 차단에 관문을 더한 것(차단 지점 넓힘)은 넣지 않는다. 해제 · 만료 뒤 관문이 그 주소를 "
                  "뺐다는 오류 없는 보고 없이 다시 건 차단은 새 반영이 아니다. 관문 보고가 오류 없이 이어졌으면 '기존 차단 유지', "
                  "보고 누락 · 덮임 · 오류가 있거나 다시 걸기 전에 만료가 지났으면 '연속성 확인 불가' 로 따로 세고 둘 다 지연(확인 수 · "
                  "평균 · 중앙값 · 최대)에서 뺀다",
                  "차단 상태: 출력 시각 기준. 요청한 지점이 모두 확인해야 적용이다",
                  "시험 출발지의 차단(차단 시연)도 함께 센다"],
        "actions": actions,
        "requests": {"total": sum(requests.values()), **requests},
        "audit": audit,
        "enforcement": {"created": enforce["created"], "enforced": enforce["enforced"], "maintained": enforce["maintained"],
                        "uncertain": enforce["uncertain"], "mean_seconds": num(enforce["mean"]),
                        "p50_seconds": num(enforce["p50"]), "max_seconds": num(enforce["max"])},
        "states": dict(states),
    }


async def targets_section(c, since, until, as_of) -> dict:
    view = await targets.targets_view(c, as_of)
    rows = [{"id": x["id"], "label": x["label"],
             "collection": {"state": x["collection"]["state"], "reason": x["collection"]["reason"]},
             "response": {k: x["response"][k] for k in ("point_label", "applied", "failed", "unverified", "unrequested",
                                                        "removing", "exempt", "stalled")}}
            for x in view["targets"]]
    runs = await c.fetchrow(RUNS_SQL, since, until)
    notes = ["대상별 수집 · 대응: 출력 시각의 상태판 값(생존 신호 이력이 없다)",
             "센서별 이벤트: 기간 안의 실제 이벤트",
             "탐지 실행 · 지표 공백: 기간 시작 · 기록 시각들 · 기간 끝 사이의 가장 긴 간격"]
    web = None
    if view["metrics_available"]:
        m = await c.fetchrow(WEB_METRICS_SQL, since, until, targets.WEB_NODE)
        web = {"samples": m["samples"], "cpu_pct": num(m["cpu_pct"]), "mem_used_pct": num(m["mem_used_pct"]),
               "disk_root_pct": num(m["disk_root_pct"]), "max_gap_seconds": num(m["max_gap"])}
        notes.append("web-01 자원: 기간 안 1분 지표의 최대값")
    return {
        "basis": "mixed", "notes": notes, "targets": rows,
        "sensors": [{"sensor": r["sensor"], "events": r["n"]} for r in await c.fetch(SENSOR_EVENTS_SQL, since, until)],
        "detector": {"runs": runs["runs"], "max_gap_seconds": num(runs["max_gap"])},
        "web": web,
    }


async def watch_summary(c, as_of) -> dict:
    """주목 CVE 대조를 요약 값별로 센다. cti.watch_list 와 같은 계산이다."""
    watch = await c.fetch(cti.WATCH_SQL)
    affected = {r["cve_id"]: cti.loads(r["affected"]) for r in watch}
    wanted = sorted({key.rpartition("/")[2] for a in affected.values() if isinstance(a, dict) for key in a} - {""})
    assets = [{**dict(r), "os": cti.loads(r["os"]), "kernel": cti.loads(r["kernel"]), "packages": cti.loads(r["packages"]),
               "probe_errors": cti.loads(r["probe_errors"])}
              for r in await c.fetch(cti.WATCH_ASSETS_SQL, wanted)]
    ecosystems = sorted({e for e in (cti.ubuntu_ecosystem(a["os"]) for a in assets) if e})
    items = sorted((cti.watch_item(r, affected[r["cve_id"]] if r["detailed"] else None, assets, ecosystems, as_of)
                    for r in watch), key=cti.watch_sort_key)
    summaries = [i["summary"] for i in items]
    return {"total": len(items), **{s: summaries.count(s) for s in (cti.AFFECTED, cti.UNKNOWN, cti.NOT_AFFECTED)},
            "affected_cves": [i["cve_id"] for i in items if i["summary"] == cti.AFFECTED]}


async def cti_section(c, since, until, as_of) -> dict:
    snapshots = await c.fetch(cti.SNAPSHOTS_SQL)
    assets = await c.fetch(cti.ASSETS_SQL, None)
    notes = ["자산별 취약점 · 주목 CVE: 출력 시각의 대조 결과(이력이 없다)",
             "KEV 등재: 등재일(날짜)이 기간의 KST 날짜 안인 항목. 우리 자산에 걸린 것만 자산을 적는다",
             "신선도: 출처별 마지막 성공 수집과 자산 조사 시각"]
    watch = None
    if not await c.fetchval(MISSING_SQL, ["cti_watch"]):
        watch = await watch_summary(c, as_of)
    kev = await c.fetch(KEV_ADDED_SQL, since, until)
    return {
        "basis": "mixed", "notes": notes,
        "assets": [{"asset_id": r["asset_id"], "role": r["role"], "vuln_total": r["vuln_total"], "vuln_kev": r["vuln_kev"],
                    "vuln_fix_available": r["vuln_fix_available"], "vuln_reboot_pending": r["vuln_reboot_pending"],
                    "collected_at": cti.iso(r["collected_at"]), "stale": cti.is_stale(r["collected_at"], as_of)}
                   for r in assets],
        "watch": watch,
        "kev_added": {"total": len(kev),
                      "ours": [{"cve_id": r["cve_id"], "name": r["name"], "date_added": cti.iso(r["date_added"]),
                                "assets": list(r["assets"])} for r in kev if r["assets"]]},
        "freshness": cti.freshness(snapshots, assets, as_of),
    }


async def ops(c, since, until, as_of) -> dict:
    notes = ["감사 이벤트: 기간 안의 감사 기록 종류별 수(행위자 · 내용은 싣지 않는다)"]
    notify = None
    if not await c.fetchval(MISSING_SQL, ["notify_deliveries"]):
        rows = [{"event": r["event"], "status": r["status"], "count": r["n"]}
                for r in await c.fetch(NOTIFY_SQL, since, until)]
        notify = {"total": sum(r["count"] for r in rows), "failed": sum(r["count"] for r in rows if r["status"] == "failed"),
                  "p50_seconds": num(await c.fetchval(NOTIFY_DELAY_SQL, since, until)), "rows": rows}
        notes.append("알림 발송: 기간 안에 넣은 발송(시험 발송 제외). 지연은 넣은 시각 → 보낸 시각")
    return {
        "basis": "period", "notes": notes,
        "audit": [{"eventid": r["eventid"], "count": r["n"]} for r in await c.fetch(AUDIT_SQL, since, until, "%")],
        "login_failed": await c.fetchval(LOGIN_FAILED_SQL, since, until),
        "notify": notify,
    }


BUILDERS = {"overview": overview, "rules": rules, "blocks": blocks, "targets": targets_section, "cti": cti_section,
            "ops": ops}


async def build(c, as_of, period: str, names: list[str], username: str) -> dict:
    """보고서 본문. names 는 chosen() 이 고른 구역이다."""
    since, until = window(as_of, period)
    sections = {}
    for name in names:
        missing = await c.fetchval(MISSING_SQL, TABLES[name])
        sections[name] = unavailable(missing) if missing else \
            {"available": True, **await BUILDERS[name](c, since, until, as_of)}
    return {"as_of": cti.iso(as_of), "since": cti.iso(since), "until": cti.iso(until), "period": period, "tz": TZ,
            "generated_by": username, "sections": sections}


@router.get("/api/reports/period")
async def period_report(request: Request, period: PERIOD, sections: list[SECTION] | None = Query(None)):
    names = chosen(request, sections)
    async with request.app.state.pool.acquire() as c, c.transaction(isolation="repeatable_read", readonly=True):
        await c.execute(f"SET LOCAL statement_timeout = '{STATEMENT_TIMEOUT}'")
        as_of = await c.fetchval("SELECT now()")
        return await build(c, as_of, period, names, request.state.user["u"])
