"""관제 대상별 상태판 (이슈 #52 · #64 · #72 · #82 · #83 · #84). GET /api/dashboard/targets · GET /api/dashboard/monitor(관제 이상)

고정 카드 네 장(허니팟 센서 · web-01 · 관제 콘솔 · 데이터 노드) 뒤에 등록 노드 카드(nodes 에서 폐기되지 않고 고정 대상과 겹치지
않는 노드, node_id 순)를 붙여 수집 · 보안 · 시스템 · 대응 · 취약점을 대상별로 모은다. 등록 노드 카드는 web-01 카드와 같은 모양이다.
반복 읽기 · 읽기 전용 트랜잭션 하나에서 읽는다(대시보드 summary 와 같다). 표 · 권한이 없는 것은 오류가 아니라
선검사(to_regclass + has_table_privilege, 열 권한만 있는 nodes 는 has_column_privilege)로 갈라 '미확인' 으로 답한다.
한 질의라도 실패하면 트랜잭션 전체가 멈추므로 예외로 가르지 않는다.
사건의 관련 장비(목록 · 상세 · 먼저 처리할 사건)도 여기서 계산한다. 조회할 때마다 기존 근거로 계산하고 저장하지 않는다.

정직한 표기
  - 수집: 생존 신호가 있는 대상만 신호 시각으로 정상 · 수신 없음을 가른다. 로그 시각만으로 정상 · 장애를 정하지 않는다.
    신호는 정상인데 로그가 없으면 '요청 없음'(quiet)이다. 콘솔은 생존 신호가 없어 생존을 확정하지 않고, 이 조회에 응답했다는
    사실('응답 중', responding)과 DB 연결(콘솔 역할 세션 가운데 콘솔 이름표 연결의 있음 · 없음)만 적는다(이슈 #76). DB 연결은
    응답 · HAProxy 분배를 보장하지 않는다.
  - 대응: 그 지점(관문 · 내부 방화벽)이 적용을 확인한 것만 적용이다. 지점이 없는 대상은 수를 내지 않는다(null).
    0 이 '막지 못했다' 로 읽히지 않게 화면이 문구를 고른다. 지점별 수는 그 지점을 요청한 행만 세고, 요청하지 않은 행은
    미요청(unrequested), 요청했다가 빼서 그 지점이 뺐다고 확인하기 전인 행은 빠짐 확인 전(removing)으로 따로 센다(이슈 #77).
    미확인은 정상 반영 시간(5분) 안의 확인 전(checking)과 그 밖(delayed: 5분 넘은 확인 전 · 지점 불일치)으로 나눈다(이슈 #84).
  - 사건 → 대상 매핑은 순수 함수(resolve_links)다. 붙인 곳마다 근거(확인 · 규칙 범위 · 대체 추정)를 단다. 한 사건이 여러 대상에
    붙을 수 있어 카드 합은 전체와 다르다. 카드 수 · 장비 필터는 대체 추정을 뺀 곳(shown)으로 센다. 어느 대상에도 붙이지 못한 사건은
    숨기지 않고 unmapped(화면 '장비 미확인')로 센다.
  - 등록 노드의 발생원(events.sensor = nodes.sensor)은 그 노드 카드로 잇는다. 노드 에이전트 이벤트(sshd. · nginx.)는 고정 web-01 과
    등록 노드가 함께 내므로 등록 노드가 있으면 실제 이벤트의 발생원으로 어느 노드의 사건인지 고른다. 등록 노드가 없으면 지금처럼
    web-01 이고, 등록 노드가 있는데 고르지 못하면 대체 추정(장비 미확인)이다.
  - 관제 이상: 카드가 이상 · 확인 불가로 보이는 수집 · 탐지 · 집행 상태는 띠에도 항목이 있다(카드와 같은 판정 함수를 쓴다).
    1분 다리 탐지는 돌아야 할 버전(BRIDGE_VERSIONS)과 24시간 안 실행을 대조해, 하루 넘게 멈춘 버전도 멈춤으로 남는다.
  - 미결: 최신 판정이 사람이 남긴 판단 유보인 사건을 미판정과 따로 센다(대시보드 · 사건 목록 undetermined 필터와 같은 식).
  - 앞선 시각(미래) 줄: 기준 시각 + 5분 넘게 앞선 로그는 마지막 로그 · 웹 로그 적재 판정에 넣지 않는다(장비 로그 목록과 같은 기준).
"""
import json
from datetime import datetime, timedelta

from fastapi import APIRouter, Request

import cti
from absorbed import block_nets
from block_points import removing_sql, unrequested_sql
from dashboard import HUMAN_UNDETERMINED, PENDING_ROWS

router = APIRouter()

WINDOW_SECONDS = 3600          # 카드의 '최근 1시간'
LATEST_HOURS = 24              # 최근 중요 탐지 · 매핑 대상 사건의 창
HEARTBEAT_STALE = 900          # 업로더 생존 신호 · 탐지 실행 · 집행 지점 보고가 이보다 오래되면 끊긴 것이다(15분).
                               #   업로더 신호는 적재기가 확인한 시각 기준으로 잰다(pull.py 의 HB_STALE 과 같은 기준)
CHECKER_STALE = 1800           # 적재기 확인 중단. checked_at 은 풀러 회차가 시작한 시각이고 기록은 받기 뒤라, 회차 간격 5분 +
                               #   받기 최장 10분(RUN_SECONDS) + 적재 · 탐지 여유를 넘겨야 멈춘 것이다(30분)
BLOCK_CHECKER_STALE = 600      # 집행기 확인 중단. 집행기는 1분마다 돈다. 10분 넘게 확인이 없으면 지점 적용 확인을 믿지 않는다
APPLY_WAIT = 300               # 집행 지점 반영을 기다리는 정상 시간(5분). 확인 전이 이보다 오래면 확인 지연이다. 집행기 point_state 의
                               #   '5분 넘게 반영되지 않음'(enforcer/block_enforcer.py STALE)과 같은 기준이다(test_targets 가 맞춰 본다)
# 요청 지점 결과의 상태. 집행기 POINT_STATES 와 같다(test_targets 가 맞춰 본다). 빠짐 확인 전(removing)은 요청 지점이 이어받지 않는다
POINT_STATES = ("pending", "confirmed", "failed", "stale")
NODE_SILENT = 600              # 노드 수신 끊김(operations.py /api/nodes 의 10분과 같다)
METRICS_STALE = 600            # 자원 지표 최신 행이 이보다 오래되면 오래됨(10분)
PARSE_LAG = 600                # 도착한 웹 로그 줄(receipt)보다 마지막 nginx. 이벤트가 이보다 앞서면 적재되지 않은 것이다(10분)
REPORT_PROBLEM_GRACE = 300     # 집행 지점 보고의 읽기 문제는 마지막으로 읽은 보고가 이보다 오래됐을 때만 이상이다(5분, 한두 회차 일시 오류는 넘긴다)
ACTIVE_RECEPTIONS = ("normal", "silent")   # 활성 노드의 수신. 등록 대기(waiting) · 폐기(revoked)는 의도한 상태라 관제 이상이 아니다
HIGH_SEVERITIES = ("critical", "high")
# 앞선 시각(미래) 줄 상한: 기준 시각 + 5분. 장비 로그 목록(node_logs.LINES_SQL)과 같은 기준이다(test_targets 가 맞춰 본다).
#   마지막 로그(LOGS_SQL) · 웹 로그 적재 판정(PARSE_SQL) · 요약 최근 원문 수집(main.EVENTS_SQL)이 쓴다
FUTURE_LIMIT = "interval '5 minutes'"

# 허니팟 쪽 이름(이슈 #78). 위치(AWS) 대신 역할로 부른다. 내부 id(aws-sensor · cowrie · gateway)와 주소 인자는 그대로다(저장된
#   링크 · 보고서 호환). 문장 안의 짧은 이름 '관문' 과 집행기 쪽지 말머리(ENFORCE_MISMATCH '관문 불일치')는 그대로 둔다
SENSOR_NAME = "허니팟 센서"
COWRIE_NAME = "SSH 허니팟(Cowrie)"
GATEWAY_NAME = "허니팟 관문"
# (id, 이름, 역할). 순서가 카드 순서다
TARGETS = [
    ("aws-sensor", SENSOR_NAME, f"{COWRIE_NAME} · 웹 디코이 · {GATEWAY_NAME} (AWS DMZ)"),
    ("web-01", "web-01", "실서비스 웹 서버 (온프레미스)"),
    ("console", "관제 콘솔", "콘솔 A · B (HAProxy 뒤)"),
    ("data-node", "데이터 노드", "DB · 적재 · 탐지 · 집행 (온프레미스)"),
]
# 발생원(events.sensor · evidence.sensors · 규칙 params.sensors) → 대상
SENSOR_TARGET = {"cowrie": "aws-sensor", "decoy": "aws-sensor", "gateway": "aws-sensor", "web-01": "web-01",
                 "console": "console", "audit": "console", "collector": "data-node", "puller": "data-node"}
# 이벤트 이름 접두 → 발생원. 규칙의 eventids · eventid · eventid_like 로 발생원 후보를 고른다
EVENT_PREFIXES = {"cowrie.": "cowrie", "decoy.": "decoy", "gateway.": "gateway", "sshd.": "web-01",
                  "nginx.": "web-01", "console.": "console"}
# 발생원 조건 없이 세션 · 기준선을 보는 규칙은 허니팟(Cowrie) 규칙이다
COWRIE_TYPES = frozenset({"session_compound", "baseline_deviation", "key_plant"})
# 발생원 조건이 없는 세션 규칙(v3 R002)은 sessions 표 전체를 본다. 그 표에는 Cowrie 세션과 디코이 세션(parse_decoy)이 함께 있어
#   대상은 허니팟 센서지만 나눔은 사건의 세션(evidence.sessions)으로 고른다
SESSION_TYPES = frozenset({"session_compound"})
SESSION_SOURCES = ("cowrie", "decoy")
# 허니팟 센서 카드의 발생원 나눔
AWS_PARTS = [("cowrie", COWRIE_NAME), ("decoy", "웹 디코이"), ("gateway", GATEWAY_NAME)]
PART_KEYS = frozenset(key for key, _ in AWS_PARTS)
# 업로더 생존 신호(role) → (신호 이름, 여럿일 때 부르는 이름). 센서 신호는 허니팟 센서 카드의 수집 판정이다
UPLOADERS = {"sensor": ("업로더 생존 신호", "센서"), "gateway": ("관문 기록 신호", "관문")}
# 대상별 로그(events.sensor, 이름). 데이터 노드는 로그가 아니라 탐지 실행이 신호다
LOGS = {"aws-sensor": [("cowrie", COWRIE_NAME), ("decoy", "웹 디코이"), ("gateway", f"{GATEWAY_NAME} 기록")],
        "web-01": [("web-01", "web-01 로그")], "console": [("console", "마지막 로그인 기록")], "data-node": []}
# 수집 상태 ok · quiet 를 가르는 로그(관문 기록은 요청이 아니라 관문 자체의 기록이라 넣지 않는다)
ACTIVE_LOGS = {"aws-sensor": ("cowrie", "decoy"), "web-01": ("web-01",)}
# 집행 지점(차단을 실제로 적용하는 곳)과 그 이름. 콘솔 · 데이터 노드 앞에는 차단 결과를 모으는 지점이 없다
POINTS = {"aws-sensor": ("gateway", GATEWAY_NAME), "web-01": ("fw", "내부 방화벽")}
POINT_LABELS = dict(POINTS.values())       # {지점: 이름}. 관문 먼저
# 대상별 자산(asset_inventory.asset_id)
TARGET_ASSETS = {"aws-sensor": ["honeypot-dmz", "gateway"], "web-01": ["web-01"],
                 "console": ["console-a", "console-b"], "data-node": ["data-01"]}
WEB_NODE = "web-01"
# 노드 에이전트(parser/parse_agent.py: auth · nginx)가 내는 이벤트 이름 접두. 고정 web-01 과 등록 노드가 함께 낸다
NODE_PREFIXES = ("sshd.", "nginx.")
NODE_ROLE = "등록 노드"        # 등록 노드 카드의 역할 설명
PARSE_WARNING = "웹 로그 도착 · 적재 없음(형식 밖 · 선언 밖)"     # 웹 로그 적재 없음(parse_gap)의 카드 경고 표지

# 집행기가 enforce_note 에 쓰는 '집행 제외' · '관문 불일치' 말머리. main.ENFORCE_EXCLUDED · ENFORCE_MISMATCH 와 같다
#   (test_targets 가 맞춰 본다). main 을 불러오면 순환이라 여기 둔다
ENFORCE_EXCLUDED = "집행 제외"
ENFORCE_MISMATCH = "관문 불일치"

# 사건 → 장비 연결의 근거. 확인: 사건 자체(대상 열 · 근거 발생원 · 탐지와 같은 범위의 이벤트)가 가리킴. 규칙 범위: 규칙이 한 장비만
#   봄. 대체 추정: 고르지 못해 규칙상 그럴 법한 곳으로 둔 것(카드 수 · 장비 필터 · 배지에 쓰지 않는다)
CONFIRMED, RULE_SCOPE, FALLBACK = "confirmed", "rule_scope", "fallback"
QUEUE_SIZE = 8                 # 먼저 처리할 사건(앞 · 뒤 합계)
UNCONFIRMED = "_unconfirmed"   # 목록 device 예약값(장비 미확인). 노드 id 형식(operations.EnrollmentIn.node_id) 밖이다
# 사건 근거에서 발생원 · 세션만 꺼낸다(목록 · 상태판 · 먼저 처리할 사건이 같은 값으로 장비를 계산한다)
EVIDENCE_COLUMNS = """CASE WHEN jsonb_typeof(i.evidence -> 'sensors') = 'array' THEN i.evidence -> 'sensors' END AS sensors,
           CASE WHEN jsonb_typeof(i.evidence -> 'sessions') = 'array' THEN i.evidence -> 'sessions' END AS sessions"""
# 장비 표기의 로그 종류. 이벤트 이름 접두 · 발생원 → 사람이 읽는 이름
PREFIX_KIND = {"sshd.": "SSH 인증", "nginx.": "웹 접근", "cowrie.": "SSH 세션", "decoy.": "웹 요청",
               "gateway.": "관문 기록", "console.": "콘솔 기록"}
SOURCE_KIND = {"cowrie": "SSH 세션", "decoy": "웹 요청", "gateway": "관문 기록", "console": "콘솔 기록",
               "audit": "감사 기록", "collector": "수집 관문", "puller": "원장 가져오기"}
# 장비 무리. 보호 대상(web-01 · 등록 노드) → 관측 센서 → 관제 시스템 순서로 늘어놓는다
GROUP_ORDER = {"protected": 0, "sensor": 1, "monitor": 2}
MONITOR_IDS = ("console", "data-node")
DEVICE_RANK = {WEB_NODE: "", **{tid: str(i) for i, tid in enumerate(MONITOR_IDS)}}   # 무리 안 순서(나머지는 id 순)
PART_ORDER = {None: 0, **{key: i + 1 for i, (key, _) in enumerate(AWS_PARTS)}}

# 표가 있고 이 역할이 읽을 수 있는가. 표가 없으면 권한 함수가 오류를 내므로 먼저 본다(absorbed.EXEMPT_READABLE_SQL 과 같은 꼴)
HEARTBEATS_READABLE_SQL = ("SELECT CASE WHEN to_regclass('sensor_heartbeats') IS NULL THEN false"
                           " ELSE has_table_privilege('sensor_heartbeats', 'SELECT') END")
METRICS_READABLE_SQL = ("SELECT CASE WHEN to_regclass('node_metrics') IS NULL THEN false"
                        " ELSE has_table_privilege('node_metrics', 'SELECT') END")

# nodes 를 읽을 수 있는가. 콘솔에는 열 권한만 있어(has_table_privilege 는 거짓이다) 읽는 열마다 본다. 표가 없으면
#   to_regclass 가 NULL 이라 행이 없어 거짓이고, 없는 열은 권한 함수에 넘기지 않는다(이름으로 넘기면 오류다). $1 읽는 열
_NODES_READABLE = """
    SELECT count(*) = cardinality({p}::text[]) FROM pg_attribute a
    WHERE a.attrelid = to_regclass('nodes') AND a.attname = ANY({p}::text[]) AND NOT a.attisdropped
      AND has_column_privilege(a.attrelid, a.attnum, 'SELECT')"""
NODES_READABLE_SQL = _NODES_READABLE.format(p="$1")
NODE_COLUMNS = ["node_id", "hostname", "sensor", "status", "registered_at", "last_seen_at", "last_loaded_at"]
# 고정 web-01 수신(NODE_SQL)이 읽는 열. 카드 열(hostname · sensor)만 모자라면 web-01 은 전처럼 읽는다
WEB_NODE_COLUMNS = ["node_id", "status", "registered_at", "last_seen_at", "last_loaded_at"]
# 웹 로그 적재 판정(PARSE_SQL)이 읽는 열. 콘솔 역할의 열 권한에 있다(장비 로그 node_logs 도 읽는다)
PARSE_COLUMNS = ["node_id", "logs", "receipt"]
# 관제 이상(monitor_view)이 읽을 수 있는 표 · 열을 한 질의로 본다. 칸마다 위 선검사와 같다. $1 카드 열 · $2 web-01 열 · $3 웹 로그 적재 열
MONITOR_READABLE_SQL = (f"SELECT ({HEARTBEATS_READABLE_SQL}) AS heartbeats, ({METRICS_READABLE_SQL}) AS metrics, "
                        + ", ".join(f"({_NODES_READABLE.format(p=f'${n}')}) AS {name}"
                                    for n, name in ((1, "cards"), (2, "web"), (3, "parse"))))

HEARTBEATS_SQL = "SELECT source, kind, role, host, seen_at, checked_at, problem FROM sensor_heartbeats ORDER BY source"

# 관제 콘솔의 DB 연결(이슈 #76). (DB 이름표 application_name, 이름, 없을 때 붙이는 말). 이름표는 compose OPSLOOP_WORKER 이고
#   (live.db_settings) 화면 api/live.ts consoleLabel 과 같은 이름이다. B 는 평소 꺼 두는 예비라 없음이 평상시다
CONSOLES = (("opsloop-console-a", "콘솔 A", None), ("opsloop-console-b", "콘솔 B", "평소 꺼 두는 예비"))
DB_LINKS_HEAD = "DB 연결 확인"             # 카드 수집 줄 머리. 보고서는 reports.REPORT_DB_LINKS_HEAD
DB_LINKS_UNKNOWN = "DB 연결 확인 불가"     # pg_stat_activity 를 읽지 못함
# pg_stat_activity 를 읽을 수 있는가. 뷰 안 함수는 호출자 권한으로 돈다. 기본은 PUBLIC 이지만 질의가 실패하면 트랜잭션 전체가
#   멈추므로 위 선검사들처럼 먼저 본다
CONSOLE_LINKS_READABLE_SQL = ("SELECT has_table_privilege('pg_catalog.pg_stat_activity', 'SELECT')"
                              " AND has_function_privilege('pg_catalog.pg_stat_get_activity(integer)', 'EXECUTE')")
# 콘솔 이름마다 이 DB 에 그 이름표로 붙은 콘솔 역할(usename = current_user, 콘솔은 opsloop_console 로 직접 로그인한다) 연결이
#   있는가. 수는 보지 않는다(풀 유휴 정리로 오르내린다). 다른 역할이 같은 이름표를 써도 세지 않는다. 다른 역할 세션은 역할 · 이름표까지만
#   보인다. 조회마다 새 트랜잭션이라 그 순간의 목록이다. $1 콘솔 이름표들(CONSOLES 순서)
CONSOLE_LINKS_SQL = """
    SELECT u.n AS name,
           EXISTS (SELECT 1 FROM pg_catalog.pg_stat_activity a
                   WHERE a.datname = current_database() AND a.usename = current_user AND a.application_name = u.n) AS present
    FROM unnest($1::text[]) WITH ORDINALITY AS u(n, i) ORDER BY u.i"""

# 매핑 대상 사건: 최근 1시간에 시작했거나, 24시간 안에 이어졌거나, 판정 기록이 없는 것(창 안, in_window). 창 밖이어도 최신 판정이
#   사람의 미결(dashboard.HUMAN_UNDETERMINED)이면 읽는다. 창 밖 미결은 미결 수에만 세고 카드 rows(최근 중요 탐지 · 대응 금지 대역 수)에는
#   넣지 않는다(tally). 판정 여부 · 값은 최신 판정 한 행(lv)으로 낸다. 근거는 발생원(sensors)만 꺼낸다.
#   시험 출발지를 빼지 않는다(대시보드 미판정 수와 같게). $1 기준 시각 · $2 창(초) · $3 최근 시간(시)
#   사건마다 최신 판정을 붙이면(LATERAL) 사건이 많을 때 느리다. 최신 판정(lv)은 판정 기록을 볼 사건(jc: 시각 창 안이거나 사람 미결
#   판정이 한 번이라도 있는 사건)만 한 번에 구하고(DISTINCT ON), 판정 없음은 옛 식(NOT EXISTS)으로 거른다. jc 밖 사건은 lv 가 비어도
#   창 밖 · 판정 있음이라 WHERE 에서 빠지므로, 읽는 행의 lv 는 늘 최신 판정이다(verdicts.verdict 는 NOT NULL 이라 lv.verdict IS NULL 은
#   판정 없음). 미결 뒤 재판정된 사건은 jc 에 들어도 WHERE 에서 빠진다
_WINDOW_TS = """(i.first_ts >= $1::timestamptz - make_interval(secs => $2)
            OR i.last_ts >= $1::timestamptz - make_interval(hours => $3))"""
_IN_WINDOW = f"({_WINDOW_TS} OR lv.verdict IS NULL)"
INCIDENTS_SQL = f"""
    WITH jc AS (
        SELECT i.incident_key FROM incidents i WHERE {_WINDOW_TS}
        UNION
        SELECT v.incident_key FROM verdicts v WHERE v.verdict = 'undetermined' AND {HUMAN_UNDETERMINED.format(v="v")}),
    latest AS (
        SELECT DISTINCT ON (v.incident_key) v.incident_key, v.verdict, v.operator
        FROM verdicts v JOIN jc ON jc.incident_key = v.incident_key
        ORDER BY v.incident_key, v.created_at DESC, v.id DESC)
    SELECT i.incident_key, i.rule_id, i.rule_version, i.rule_name, i.severity, host(i.actor_ip) AS actor_ip, i.target,
           i.first_ts, i.last_ts,
           {EVIDENCE_COLUMNS},
           lv.verdict IS NOT NULL AS judged, lv.verdict,
           {HUMAN_UNDETERMINED.format(v="lv")} AS undetermined,
           {_IN_WINDOW} AS in_window
    FROM incidents i
    LEFT JOIN latest lv ON lv.incident_key = i.incident_key
    WHERE {_WINDOW_TS}
       OR {HUMAN_UNDETERMINED.format(v="lv")}
       OR NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.incident_key = i.incident_key)
    ORDER BY i.incident_key"""

# 규칙 정의에서 발생원을 가르는 값만 꺼낸다(서명 목록 같은 큰 값은 가져오지 않는다). 규칙 버전 정의는 고칠 수 없으니
#   rules 가 배열이 아니거나 항목이 객체가 아니어도 질의가 실패하지 않게 거른다
RULES_SQL = """
    SELECT rv.rule_version, r ->> 'id' AS rule_id, r ->> 'type' AS type,
           r #> '{params,sensors}' AS sensors, r #> '{params,eventids}' AS eventids,
           r #> '{params,eventid}' AS eventid, r #> '{params,eventid_like}' AS eventid_like,
           r #> '{params,http_status}' AS http_status, r #> '{params,exclude_url_patterns}' AS exclude_url_patterns,
           r #> '{params,window_seconds}' AS window_seconds, r #> '{params,threshold}' AS threshold
    FROM rule_versions rv
    CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(rv.definition -> 'rules') = 'array'
                                                 THEN rv.definition -> 'rules' ELSE '[]'::jsonb END) r
    WHERE rv.rule_version = ANY($1::text[]) AND jsonb_typeof(r) = 'object'"""

# 발생원이 섞인 규칙(R101 w2 · R102 · R104 …)의 사건만 실제 이벤트로 발생원을 고른다. 사건마다 묻지 않고 한 번에 묻는다.
#   탐지가 센 이벤트와 같은 범위를 본다(detect.signals_actor_rate):
#   - 출발지 빈도 규칙(w · th 가 있음)은 첫 시각 · 끝 시각이 든 고정 창 전체를 보고, 창 안 이벤트 수가 임계치 이상인 창만 센다
#     (끝 시각은 마지막 창의 첫 행이라 그 창의 나머지를 놓치면 안 된다. 임계치에 못 미친 사이 창은 사건에 들지 않았다)
#   - 응답 코드(st) · 제외 경로(ex, 탐지처럼 ^(?: … )$ 로 감싼 것)도 같게 건다
#   - 그 밖(event_match 등)은 첫 시각 ~ 끝 시각의 이벤트다
#   $1 [{k 사건 키, ip 출발지, f 첫 시각, l 끝 시각, ids 이벤트 이름들, lk 이벤트 이름 LIKE, ss 발생원 조건,
#        st 응답 코드들, ex 제외 경로 정규식들, w 창(초), th 임계치}]
#   이벤트 이름 조건이 둘 다 없으면 이름으로 거르지 않는다. 출발지 색인(idx_events_src_ip)으로 읽는다
JOIN_SQL = """
    SELECT q.k AS incident_key, e.sensor
    FROM jsonb_to_recordset($1::jsonb) AS q(k text, ip inet, f timestamptz, l timestamptz, ids text[], lk text, ss text[],
                                            st int[], ex text[], w int, th int)
    CROSS JOIN LATERAL (
        SELECT DISTINCT b.sensor FROM (
            SELECT ev.sensor, count(*) OVER (PARTITION BY floor(extract(epoch FROM ev.ts) / q.w)) AS n
            FROM events ev
            WHERE ev.src_ip = q.ip AND ev.provenance = 'real'
              AND ((q.w IS NULL AND ev.ts BETWEEN q.f AND q.l)
                   OR (q.w IS NOT NULL
                       AND ev.ts >= to_timestamp(floor(extract(epoch FROM q.f) / q.w) * q.w)
                       AND ev.ts < to_timestamp((floor(extract(epoch FROM q.l) / q.w) + 1) * q.w)))
              AND ((q.ids IS NULL AND q.lk IS NULL) OR ev.eventid = ANY(q.ids) OR ev.eventid LIKE q.lk)
              AND (q.ss IS NULL OR ev.sensor = ANY(q.ss))
              AND (q.st IS NULL OR ev.http_status = ANY(q.st))
              AND (q.ex IS NULL OR ev.url IS NULL OR NOT (ev.url ~ ANY(q.ex)))) b
        WHERE q.th IS NULL OR b.n >= q.th) e
    ORDER BY q.k, e.sensor"""

# 발생원 조건 없는 세션 규칙(v3 R002)의 사건: 근거의 세션으로 Cowrie · 디코이를 고른다. 세션 색인(idx_events_session)으로 읽는다.
#   $1 [{k 사건 키, s 세션들}]
SESSION_JOIN_SQL = """
    SELECT q.k AS incident_key, e.sensor
    FROM jsonb_to_recordset($1::jsonb) AS q(k text, s text[])
    CROSS JOIN LATERAL (
        SELECT DISTINCT ev.sensor FROM events ev
        WHERE ev.session = ANY(q.s) AND ev.sensor = ANY($2::text[]) AND ev.provenance = 'real') e
    ORDER BY q.k, e.sensor"""

# 발생원별 마지막 로그. 앞선 시각 줄(FUTURE_LIMIT 넘게)은 빼고 고른다(미래 줄 하나가 수집 '정상' 을 붙잡지 않게).
#   (sensor, ts) 색인(idx_events_sensor_ts)으로 발생원마다 한 번 내려간다. $1 발생원들 · $2 기준 시각
LOGS_SQL = f"""
    SELECT s AS sensor, (SELECT max(e.ts) FROM events e WHERE e.sensor = s AND e.provenance = 'real'
                         AND e.ts <= $2::timestamptz + {FUTURE_LIMIT}) AS last_at
    FROM unnest($1::text[]) AS s"""

# 노드 수신 판정. operations.py /api/nodes 의 CASE 와 같은 규칙이다(now() 대신 기준 시각 {at})
RECEPTION_SQL = """CASE WHEN n.status='revoked' THEN 'revoked' WHEN n.status='pending' THEN 'waiting'
                WHEN coalesce(n.last_seen_at,n.registered_at) < {at}::timestamptz-interval '10 minutes' THEN 'silent'
                WHEN n.last_seen_at IS NULL THEN 'waiting' ELSE 'normal' END"""

# 고정 web-01 의 수신. $1 노드 id · $2 기준 시각
NODE_SQL = f"""
    SELECT n.status, n.last_seen_at, n.last_loaded_at,
           {RECEPTION_SQL.format(at="$2")} AS reception
    FROM nodes n WHERE n.node_id = $1"""

# 등록 노드 전체와 수신(node_id 순). 카드로 붙일 노드는 node_targets 가 고른다(nodes 는 작은 표다). $1 기준 시각
NODES_SQL = f"""
    SELECT n.node_id, n.hostname, n.sensor, n.status, n.last_seen_at, n.last_loaded_at,
           {RECEPTION_SQL.format(at="$1")} AS reception
    FROM nodes n ORDER BY n.node_id"""

DETECTOR_SQL = "SELECT max(started_at) FROM detector_runs"

# 탐지 경로별 마지막 실행(24시간 안만 읽는다. 색인이 started_at 하나다). 규칙 id 가 모두 R0xx 인 버전은 허니팟 탐지(5분 풀러)이고
#   나머지는 노드 · 관제 탐지(1분 다리)다. 규칙 정의가 없거나 모양이 틀리면 허니팟으로 보지 않는다. 하루 넘게 멈춘 1분 다리 버전은
#   창에 없어 돌아야 할 버전(BRIDGE_VERSIONS)과 대조해 찾는다(bridge_rows). $1 기준 시각
DETECT_PATHS_SQL = """
    SELECT d.rule_version, max(d.started_at) AS last_at,
           coalesce((SELECT bool_and(r ->> 'id' ~ '^R0[0-9]{2}([^0-9]|$)') FROM rule_versions rv
                     CROSS JOIN LATERAL jsonb_array_elements(CASE WHEN jsonb_typeof(rv.definition -> 'rules') = 'array'
                                                                  THEN rv.definition -> 'rules' ELSE '[]'::jsonb END) r
                     WHERE rv.rule_version = d.rule_version AND jsonb_typeof(r) = 'object'), false) AS honeypot
    FROM detector_runs d WHERE d.started_at >= $1::timestamptz - interval '24 hours'
    GROUP BY d.rule_version ORDER BY d.rule_version"""
# (키, 이름). 5분 풀러는 규칙 파일 하나만 돌아 경로 최댓값으로, 1분 다리는 규칙 파일마다 따로 돌아 버전마다 가른다
DETECT_PATHS = (("honeypot", "허니팟 탐지(5분)"), ("bridge", "노드 · 관제 탐지(1분)"))
# 1분 다리가 돌려야 할 규칙 버전(collector/pull_loki.py RULESETS 의 파일마다 rule_version, test_targets 가 대조한다). 콘솔 컨테이너에는
#   app/ 만 들어가 그 파일을 읽을 수 없어 여기 둔다. data01 의 RULESETS 를 바꾸면 콘솔도 같은 커밋으로 배포한다
BRIDGE_VERSIONS = ("s1", "w2", "a1", "i2", "c1", "sg1")

# 노드별 최신 자원 지표 한 행. (node_id, ts) 색인(idx_node_metrics_node_ts)으로 노드마다 한 번 내려간다. $1 노드 id 들
METRICS_SQL = """
    SELECT n AS node_id, m.ts, m.cpu_pct, m.mem_used_pct, m.disk_root_pct, m.load1
    FROM unnest($1::text[]) AS n
    CROSS JOIN LATERAL (SELECT ts, cpu_pct, mem_used_pct, disk_root_pct, load1 FROM node_metrics
                        WHERE node_id = n ORDER BY ts DESC LIMIT 1) m"""

# 웹 로그 적재 판정(parse_gap)의 재료: 노드의 선언 로그 · 받은 줄 기록과 그 발생원의 마지막 nginx. 이벤트. 받은 줄이 1시간 안일 때만
#   보고 그보다 10분 넘게 앞선 이벤트는 없는 것과 같아 창($4, 1시간 10분) 안만 읽는다((sensor, ts) 색인). 적재됐는지만 보므로
#   시험 출발지 줄(provenance fixture: 첫 수신 탐침 · 운영자 회선)도 적재된 것이다. 앞선 시각 줄(FUTURE_LIMIT 넘게)은 빼서
#   미래 줄 하나가 적재 없음 경고를 가리지 않게 한다.
#   $1 노드 id 들 · $2 발생원들(같은 순서) · $3 기준 시각 · $4 창(초)
PARSE_SQL = f"""
    SELECT q.node_id, n.logs, n.receipt,
           (SELECT max(e.ts) FROM events e
            WHERE e.sensor = q.sensor AND e.eventid LIKE 'nginx.%'
              AND e.ts >= $3::timestamptz - make_interval(secs => $4)
              AND e.ts <= $3::timestamptz + {FUTURE_LIMIT}) AS nginx_at
    FROM unnest($1::text[], $2::text[]) AS q(node_id, sensor) JOIN nodes n ON n.node_id = q.node_id
    ORDER BY q.node_id"""

def _since(p: str) -> str:
    """그 지점 결과가 지금 상태가 된 시각(enforcement.<지점>.since). 기록이 없거나, 요청 지점 상태(POINT_STATES)가 아니거나(관문을 뺀 뒤
    다시 요청한 행에 남은 removing. 집행기가 이어받지 않는다), 시각 글자가 아니면 요청 시각(created_at. 콘솔 · triage 가 다시 걸거나
    넓힐 때 now() 로 둔다)이다. 시각 글자는 pg_input_is_valid 로 먼저 가른다(캐스트 오류가 트랜잭션 전체를 멈춘다)."""
    since = f"enforcement -> '{p}' ->> 'since'"
    states = ", ".join(f"'{s}'" for s in POINT_STATES)
    return (f"coalesce(CASE WHEN enforcement -> '{p}' ->> 'state' IN ({states}) AND pg_input_is_valid({since}, 'timestamptz') "
            f"THEN ({since})::timestamptz END, created_at)")


def _checking(p: str) -> str:
    """그 지점이 확인 전(pending · 기록 없음)이고 정상 반영 시간(APPLY_WAIT) 안이다. 시각을 모르면 안이 아니다(NULL 이 아니라 거짓)."""
    return (f"coalesce(enforcement -> '{p}' ->> 'state', '') NOT IN ('confirmed', 'failed', 'stale') "
            f"AND coalesce({_since(p)} > $1::timestamptz - make_interval(secs => {APPLY_WAIT}), false)")


# 살아 있는 차단(해제 · 만료 안 됨, 만료 없는 옛 차단 · 집행 제외 아님)을 지점별로 적용 확인 · 실패 · 미확인으로 나눈다.
#   지점마다 그 지점을 요청한 행(blocklist.points, 이슈 #77)만 세고, 요청하지 않은 행은 미요청(unrequested), 그 가운데 그 지점에
#   기록이 남은 행(관리자 관문 빼기 뒤 관문이 뺐다고 확인하기 전)은 빠짐 확인 전(removing)으로 따로 센다(block_points.removing_sql).
#   실패는 그 지점이 거부했다고 보고한 것(failed)이다. 모르는 것이 아니라 알려진 미적용이라 미확인과 가른다.
#   미확인은 그 밖(pending · stale · 기록 없음)이고, 그 가운데 지점 불일치(stale: 적용 수 부족 · 5분 넘게 미반영)는 따로도 센다.
#   미확인은 확인 중(checking)과 확인 지연(delayed)으로도 나눈다(합이 미확인, 이슈 #84 결정 6). 확인 중은 확인 전(pending · 기록 없음)이고
#   그 상태가 된 시각(_since)이 정상 반영 시간(APPLY_WAIT) 안인 것, 확인 지연은 그 밖(그 시간을 넘긴 확인 전 · 지점 불일치)이다.
#   만료 없음 · 집행 제외는 종합 상태(block_points.STATE_CASE)의 excluded 와 같은 정의다. mismatch 는 관문을 요청한 행의 관문 불일치
#   쪽지다(관제 이상 gateway_mismatch). $1 기준 시각
BLOCKS_SQL = "SELECT " + ", ".join(
    f"count(*) FILTER (WHERE '{p}' = ANY(points) AND enforcement -> '{p}' ->> 'state' = 'confirmed') AS {p}_applied, "
    f"count(*) FILTER (WHERE '{p}' = ANY(points) AND enforcement -> '{p}' ->> 'state' = 'failed') AS {p}_failed, "
    f"count(*) FILTER (WHERE '{p}' = ANY(points) "
    f"AND coalesce(enforcement -> '{p}' ->> 'state', '') NOT IN ('confirmed', 'failed')) AS {p}_unverified, "
    f"count(*) FILTER (WHERE '{p}' = ANY(points) AND enforcement -> '{p}' ->> 'state' = 'stale') AS {p}_stale, "
    f"count(*) FILTER (WHERE '{p}' = ANY(points) AND {_checking(p)}) AS {p}_checking, "
    f"count(*) FILTER (WHERE '{p}' = ANY(points) "
    f"AND coalesce(enforcement -> '{p}' ->> 'state', '') NOT IN ('confirmed', 'failed') AND NOT ({_checking(p)})) AS {p}_delayed, "
    f"count(*) FILTER (WHERE {unrequested_sql(p)}) AS {p}_unrequested, "
    f"count(*) FILTER (WHERE {removing_sql(p)}) AS {p}_removing"
    for p, _ in POINTS.values()) + f""",
    count(*) FILTER (WHERE 'gateway' = ANY(points) AND enforce_note LIKE '{ENFORCE_MISMATCH}%') AS mismatch
    FROM blocklist
    WHERE released_at IS NULL AND expires_at > $1
      AND (enforce_note IS NULL OR enforce_note NOT LIKE '{ENFORCE_EXCLUDED}%')"""

# 출발지 중 차단 금지 대역(absorbed.block_nets)에 드는 것. $1 주소들 · $2 대역들
EXEMPT_SQL = """
    SELECT DISTINCT host(ip) AS ip FROM unnest($1::text[]::inet[]) AS ip
    WHERE ip <<= ANY($2::text[]::inet[])"""


# ----------------------------------------------------------------------
#  순수 함수 (DB 없이 시험한다)
# ----------------------------------------------------------------------

def _strings(value) -> list[str]:
    """jsonb 값(글자로 온 것 포함) → 비지 않은 문자열 목록. 목록이 아니면 빈 목록."""
    value = cti.loads(value)
    return [v for v in value if isinstance(v, str) and v] if isinstance(value, list) else []


def _string(value) -> str | None:
    value = cti.loads(value)
    return value if isinstance(value, str) and value else None


def _ints(value) -> list[int]:
    value = cti.loads(value)
    return [v for v in value if isinstance(v, int) and not isinstance(v, bool)] if isinstance(value, list) else []


def _positive(value) -> int | None:
    value = cti.loads(value)
    return value if isinstance(value, int) and not isinstance(value, bool) and value > 0 else None


def rule_spec(row) -> dict:
    """규칙 정의 한 개(RULES_SQL 한 행) → {type, sensors, eventids, eventid_like, http_status, exclude, window, threshold}.
    eventid 는 eventids 에 합친다. sensors 가 없으면 None(발생원 조건 없음)이다.
    출발지 빈도 규칙(actor_rate)만 창 · 임계치 · 응답 코드 · 제외 경로를 쓴다(탐지와 같은 범위로 발생원을 고른다).
    제외 경로는 탐지처럼 ^(?: … )$ 로 감싼다. 규칙 정의(rule_versions)는 탐지가 형식을 본 뒤 들어간 것이다."""
    eventids = _strings(row["eventids"])
    one = _string(row["eventid"])
    if one and one not in eventids:
        eventids.append(one)
    rate = row["type"] == "actor_rate"
    window, threshold = _positive(row.get("window_seconds")), _positive(row.get("threshold"))
    return {"type": row["type"], "sensors": _strings(row["sensors"]) or None, "eventids": eventids,
            "eventid_like": _string(row["eventid_like"]),
            "http_status": (_ints(row.get("http_status")) or None) if rate else None,
            "exclude": ([f"^(?:{x})$" for x in _strings(row.get("exclude_url_patterns"))] or None) if rate else None,
            "window": window if rate and threshold else None, "threshold": threshold if rate and window else None}


def event_source(name: str) -> str | None:
    """이벤트 이름(또는 LIKE 식)의 접두로 고른 발생원."""
    for prefix, source in EVENT_PREFIXES.items():
        if name.startswith(prefix):
            return source
    return None


def candidate_sources(spec: dict, nodes=None) -> list[str]:
    """규칙의 발생원 후보: params.sensors ∪ 이벤트 이름 접두로 고른 발생원. 노드 에이전트 이벤트(sshd. · nginx.)는 web-01 과
    등록 노드의 발생원(nodes 의 키)이 모두 후보다."""
    found = list(spec.get("sensors") or [])
    for name in [*spec.get("eventids", []), *([spec["eventid_like"]] if spec.get("eventid_like") else [])]:
        source = event_source(name)
        more = [source] if source else []
        if name.startswith(NODE_PREFIXES):
            more += list(nodes or {})
        found += [s for s in more if s not in found]
    return found


def attach(sources, nodes=None) -> set[tuple[str, str | None]]:
    """발생원들 → {(대상, 허니팟 센서 발생원 나눔 또는 None)}. 고정 발생원(SENSOR_TARGET)이 먼저이고 그다음 등록 노드의
    발생원(nodes: {발생원: 노드 id})이다. 모르는 발생원은 버린다."""
    out = set()
    for source in sources:
        target = SENSOR_TARGET.get(source) or (nodes or {}).get(source)
        if target:
            out.add((target, source if source in PART_KEYS else None))
    return out


EVENTS, SESSIONS = "events", "sessions"   # resolve 의 둘째 값: 무엇으로 발생원을 더 고르는가(없으면 False)


def based(pairs, basis) -> dict:
    """{(대상, 나눔)} → {(대상, 나눔): 근거}."""
    return {pair: basis for pair in pairs}


def resolve_links(target, sensors, spec, nodes=None) -> tuple[dict, str | bool]:
    """사건 하나를 대상에 붙인다. (붙인 곳 {(대상, 나눔): 근거}, 더 고를 방법: False · EVENTS · SESSIONS).
    nodes 는 등록 노드 {발생원: 노드 id} 다(없으면 고정 대상만 본다).

    순서: (1) target 'node:<id>' → 등록 노드면 그 카드, 아니면 고정 발생원(web-01) (2) target 'user:…' → 콘솔
    (3) 근거의 발생원(evidence.sensors). 여기까지는 사건 자체가 가리켜 확인이다 (4) 규칙의 발생원 후보.
    후보의 대상이 하나면 그 대상(규칙 범위)이고, 대상이 둘 이상이면(발생원이 섞인 규칙) 이벤트로 고른다(붙인 곳 없음 · EVENTS).
    등록 노드 발생원이 더해져서 둘 이상이 됐을 뿐이면(고정 발생원만으로는 하나, n1 R101 의 sshd.) 고르지 못할 때 등록 노드 없이
    정한 값을 대체 추정으로 둔다(n1 R101 은 web-01 대체 추정 · EVENTS).
    대상은 하나인데 허니팟 센서 발생원이 여럿이면 대상은 정하고(규칙 범위) 나눔만 이벤트로 고른다(EVENTS).
    (5) 후보가 없는 세션 규칙(v3 R002)은 허니팟 센서(규칙 범위)이고 나눔은 사건의 세션으로 고른다(SESSIONS).
    (6) 후보가 없는 기준선 · 키 심기 규칙은 Cowrie 대체 추정이다. 기준선(R005)은 Cowrie · 디코이 · 콘솔을 함께 센다
    (detector/detect.py BASELINE_SENSORS) (7) 그 밖은 붙이지 못한다.
    """
    if isinstance(target, str) and target.startswith("node:"):
        node_id = target[len("node:"):]
        return based({(node_id, None)} if node_id in (nodes or {}).values() else attach([node_id]), CONFIRMED), False
    if isinstance(target, str) and target.startswith("user:"):
        return {("console", None): CONFIRMED}, False
    evidence = _strings(sensors)
    if evidence:
        return based(attach(evidence, nodes), CONFIRMED), False
    if spec is None:
        return {}, False
    sources = candidate_sources(spec, nodes)
    if sources:
        pairs = attach(sources, nodes)
        targets = {t for t, _ in pairs}
        if len(targets) > 1:
            # 고르지 못하면 등록 노드 없이 정한 값을 대체 추정으로 둔다(고정 발생원만으로도 섞였으면 붙인 곳 없음)
            return (based(resolve_links(target, sensors, spec)[0], FALLBACK) if nodes else {}), EVENTS
        if len({p for _, p in pairs if p}) > 1:
            return based({(t, None) for t in targets}, RULE_SCOPE), EVENTS
        return based(pairs, RULE_SCOPE), False
    if spec.get("type") in SESSION_TYPES:
        return {("aws-sensor", None): RULE_SCOPE}, SESSIONS
    if spec.get("type") in COWRIE_TYPES:
        return {("aws-sensor", "cowrie"): FALLBACK}, False
    return {}, False


def resolve(target, sensors, spec, nodes=None) -> tuple[set, str | bool]:
    """근거 없이 붙인 곳만(옛 모양). resolve_links 와 같은 판정이다."""
    links, need = resolve_links(target, sensors, spec, nodes)
    return set(links), need


def _without_bare(pairs: set) -> set:
    """같은 대상에 나눔 있는 짝이 있으면 (대상, None) 을 뺀다."""
    parted = {t for t, p in pairs if p}
    return {(t, p) for t, p in pairs if p or t not in parted}


def legacy_pairs(links: dict) -> set:
    """옛 attach_incidents 결과 모양. 세션으로 고르지 못한 R002 는 전처럼 Cowrie 다."""
    return _without_bare(set(links))


def shown(links: dict) -> set:
    """카드 수 · 장비 필터 · 배지에 쓰는 짝: 대체 추정을 뺀 것."""
    return _without_bare({pair for pair, basis in links.items() if basis != FALLBACK})


def shown_targets(links: dict) -> set[str]:
    return {t for t, _ in shown(links)}


def device_group(target_id: str, cards) -> str:
    """보호 대상(web-01 · 등록 노드 카드) · 관측 센서(aws-sensor) · 관제 시스템(콘솔 · 데이터 노드)."""
    if target_id == "aws-sensor":
        return "sensor"
    return "monitor" if target_id in MONITOR_IDS else "protected"


def log_kinds(target_id: str, part: str | None, spec: dict | None, cards) -> list[str]:
    """이 장비에서 규칙이 본 로그 종류. 처음으로 비지 않는 단계에서 멈춘다: 규칙 정의 없음 → 없음, 노드 무응답 → 지표 수신,
    규칙 발생원 → 이벤트 이름 접두 → 나눔 → 세션 규칙. 중복은 빼고 처음 나온 순서다."""
    if spec is None:
        return []
    if spec.get("type") == "node_silence":
        return ["지표 수신"]
    group = device_group(target_id, cards)

    def mine(source: str) -> bool:
        return SENSOR_TARGET.get(source) == target_id and (part is None or source == part)

    def unique(kinds):
        return list(dict.fromkeys(k for k in kinds if k))

    kinds = unique(SOURCE_KIND.get(s) for s in spec.get("sensors") or [] if mine(s))
    if kinds:
        return kinds
    names = [*spec.get("eventids", []), *([spec["eventid_like"]] if spec.get("eventid_like") else [])]
    kinds = unique(kind for name in names for prefix, kind in PREFIX_KIND.items()
                   if name.startswith(prefix) and (mine(EVENT_PREFIXES[prefix])
                                                   or (prefix in NODE_PREFIXES and group == "protected")))
    if kinds:
        return kinds
    if part:
        return [SOURCE_KIND[part]]
    return ["세션 기록"] if spec.get("type") in SESSION_TYPES else []


def device_label(target_id: str, part: str | None, cards) -> str:
    """허니팟 센서는 나눔 이름(나눔 없으면 '허니팟 센서'), 고정 대상은 이름, 등록 노드는 카드 이름(hostname, 비신뢰)."""
    if target_id == "aws-sensor" and part:
        return dict(AWS_PARTS)[part]
    fixed = {tid: label for tid, label, _ in TARGETS}
    if target_id in fixed:
        return fixed[target_id]
    return next((card["label"] for card in cards if card["id"] == target_id), target_id)


def device_sort_key(device: dict):
    """보호 대상(web-01 → 노드 id 순) → 관측 센서(나눔 없음 → Cowrie → 디코이 → 관문) → 관제 시스템(콘솔 → 데이터 노드)."""
    return (GROUP_ORDER[device["group"]], DEVICE_RANK.get(device["id"], device["id"]),
            PART_ORDER.get(device["part"], len(PART_ORDER)))


def devices_of(links: dict, spec: dict | None, cards) -> dict:
    """사건 하나의 관련 장비. devices 는 확인 · 규칙 범위(shown), device_fallback 은 대체 추정(화면 ⓘ 에만 쓴다).
    device_state: 확인이 하나라도 있으면 confirmed, 장비가 있으면 rule_scope, 없으면 unconfirmed(장비 미확인)."""
    def one(pair, basis):
        tid, part = pair
        return {"id": tid, "part": part, "label": device_label(tid, part, cards), "group": device_group(tid, cards),
                "logs": log_kinds(tid, part, spec, cards), "basis": basis}
    devices = sorted((one(pair, links[pair]) for pair in shown(links)), key=device_sort_key)
    fallback = sorted((one(pair, basis) for pair, basis in links.items() if basis == FALLBACK), key=device_sort_key)
    state = ("confirmed" if any(d["basis"] == CONFIRMED for d in devices) else "rule_scope") if devices else "unconfirmed"
    return {"devices": devices, "device_state": state, "device_fallback": fallback}


def device_options(cards) -> list[dict]:
    """목록 장비 필터의 선택지. 행과 관계없이 늘 싣는다: web-01 → 등록 노드(node_id 순) → 허니팟 센서 → 콘솔 → 데이터 노드."""
    fixed = {tid: label for tid, label, _ in TARGETS}
    ids = [WEB_NODE, *(card["id"] for card in cards), "aws-sensor", *MONITOR_IDS]
    labels = fixed | {card["id"]: card["label"] for card in cards}
    return [{"id": tid, "label": labels[tid], "group": device_group(tid, cards)} for tid in ids]


def device_matches(device: str, links: dict) -> bool:
    """목록 device 조건. 장비 미확인은 shown 이 빈 사건이다(카드 unmapped 와 같다)."""
    targets = shown_targets(links)
    return not targets if device == UNCONFIRMED else device in targets


def lane_of(links: dict) -> str:
    """먼저 처리할 사건의 묶음. 장비 미확인 · 보호 대상 · 관제 시스템이 하나라도 있으면 앞, 허니팟 센서뿐이면 뒤(허니팟 · 디코이).
    규칙 번호로 가르지 않는다."""
    return "back" if shown_targets(links) == {"aws-sensor"} else "front"


def queue_of(rows: list, links: dict, specs: dict, cards, size=QUEUE_SIZE) -> dict:
    """먼저 처리할 사건. rows 는 PENDING_ROWS(미판정 전체). 앞 묶음 먼저, 각 묶음 안은 오래된 순(첫 시각 · 키), 합계 size 건."""
    entries = []
    for row in rows:
        link = links.get(row["incident_key"]) or {}
        lane = lane_of(link)
        entries.append(((lane != "front", row["first_ts"], row["incident_key"]), {
            "incident_key": row["incident_key"], "rule_id": row["rule_id"], "rule_name": row["rule_name"],
            "severity": row["severity"], "actor_ip": row["actor_ip"], "target": row["target"],
            "first_ts": cti.iso(row["first_ts"]), "pending_seconds": float(row["pending_seconds"]),
            "target_seconds": row["target_seconds"], "overdue": bool(row["overdue"]), "lane": lane,
            **devices_of(link, specs.get((row["rule_version"], row["rule_id"])), cards)}))
    items = [item for _, item in sorted(entries, key=lambda e: e[0])]
    return {"total": len(items), "front": sum(x["lane"] == "front" for x in items),
            "back": sum(x["lane"] == "back" for x in items),
            "unconfirmed": sum(x["device_state"] == "unconfirmed" for x in items),
            "overdue": sum(x["overdue"] for x in items), "items": items[:size]}


def join_item(incident: dict, spec: dict) -> dict:
    """JOIN_SQL 에 넘길 사건 한 개."""
    return {"k": incident["incident_key"], "ip": incident["actor_ip"], "f": cti.iso(incident["first_ts"]),
            "l": cti.iso(incident["last_ts"]), "ids": spec["eventids"] or None, "lk": spec["eventid_like"],
            "ss": spec["sensors"], "st": spec.get("http_status"), "ex": spec.get("exclude"),
            "w": spec.get("window"), "th": spec.get("threshold")}


def session_item(incident: dict) -> dict | None:
    """SESSION_JOIN_SQL 에 넘길 사건 한 개. 근거에 세션이 없으면 None."""
    sessions = _strings(incident.get("sessions"))
    return {"k": incident["incident_key"], "s": sessions} if sessions else None


def ago(as_of, at) -> str:
    """사람이 읽는 경과(방금 · n분 전 · n시간 전 · n일 전). 앞선 시각(시계 차)은 방금이다."""
    seconds = max(0.0, (as_of - at).total_seconds())
    if seconds < 60:
        return "방금"
    minutes = int(seconds // 60)
    if minutes < 120:
        return f"{minutes}분 전"
    hours = minutes // 60
    return f"{hours}시간 전" if hours < 48 else f"{hours // 24}일 전"


def older(as_of, at, seconds) -> bool:
    """at 이 as_of 보다 seconds 넘게 앞선다(없으면 참)."""
    return at is None or as_of - at > timedelta(seconds=seconds)


def logs_of(target_id: str, last: dict) -> list[dict]:
    return [{"key": key, "label": label, "last_at": cti.iso(last.get(key))} for key, label in LOGS[target_id]]


def active(target_id: str, last: dict, as_of) -> bool:
    """최근 1시간 안에 요청 로그가 있는가."""
    return any(not older(as_of, last.get(key), WINDOW_SECONDS) for key in ACTIVE_LOGS.get(target_id, ()))


def signal_of(label: str, stale_after: int, seen=None, checked=None, problem=None) -> dict:
    return {"label": label, "seen_at": cti.iso(seen), "checked_at": cti.iso(checked),
            "stale_after_seconds": stale_after, "problem": problem}


def collection(state, reason, signal, logs, extra=()) -> dict:
    return {"state": state, "reason": reason, "signal": signal, "logs": logs, "extra": list(extra)}


def uploader_signal(as_of, available: bool, heartbeats: list, role: str = "sensor") -> tuple:
    """업로더 생존 신호(role=sensor · gateway) 판정 (state, reason, row). 허니팟 센서 카드와 관제 이상(sensor · gateway_uploader)이 같이 쓴다.

    seen_at 은 풀러가 회차를 시작하며 읽은 hb 의 S3 시각, checked_at 은 그 회차가 시작한 시각이고, 기록은 받기가 끝난 뒤다.
    그래서 신호가 끊겼는지는 확인 시점 기준(checked_at - seen_at > 15분, pull.py 의 HB_STALE 과 같다)으로 재고, 적재기가 멈췄는지는
    지금 기준(as_of - checked_at > 30분)으로 따로 잰다. 받기가 길어 기록이 늦었을 뿐인 신호를 '수신 없음' 으로 그리지 않는다.
    적재기가 더는 확인하지 않는 행(떼어 둔 호스트의 남은 행)은 고르지 않는다. 모든 행이 그렇다면 적재기 확인이 멈춘 것이다(미확인).
    여럿이면 확인 시점에 가장 늦었던 신호로 가른다.
    state 는 unknown(표 · 행 없음 · 적재기 확인 중단) · no_signal 이고, 신호가 새로우면 None(reason 은 신호 · 확인 시각 머리 글)이다.
    row 는 고른 행이다(표 · 행이 없으면 None)."""
    label, noun = UPLOADERS[role]
    rows = [r for r in heartbeats if r["kind"] == "uploader" and r["role"] == role]
    if not available or not rows:
        return "unknown", "생존 신호 미기록" + ("" if available else " · 생존 신호 표를 읽을 수 없음"), None
    live = [r for r in rows if not older(as_of, r["checked_at"], CHECKER_STALE)]
    if not live:
        row = max(rows, key=lambda r: r["checked_at"])
        return "unknown", f"적재기 확인 중단 · 마지막 확인 {ago(as_of, row['checked_at'])}", row

    def lag(r):
        return (r["checked_at"] - r["seen_at"]).total_seconds() if r["seen_at"] is not None else float("inf")
    row = max(live, key=lambda r: (lag(r), r["host"]))
    many = f"({noun} {len(live)}대 중 가장 늦은 것)" if len(live) > 1 else ""
    if row["seen_at"] is None:
        return "no_signal", f"{label} 없음{many}" + (f" · {row['problem']}" if row["problem"] else ""), row
    head = f"{label} {ago(as_of, row['seen_at'])}{many} · 적재기 확인 {ago(as_of, row['checked_at'])}"
    if lag(row) > HEARTBEAT_STALE:
        return "no_signal", f"{head} · 확인 때 이미 15분 넘게 새 신호 없음", row
    return None, head, row


def gateway_note(as_of, available: bool, heartbeats: list) -> str:
    """센서 카드 까닭 끝에 붙이는 관문 업로더(role=gateway) 신호 시각. 적재기가 확인 중인 관문 행이 없으면(관문 업로더가 없는 구성 ·
    떼어 둔 호스트의 남은 행뿐) 붙이지 않는다."""
    state, _, row = uploader_signal(as_of, available, heartbeats, "gateway")
    if row is None or state == "unknown":
        return ""
    return f" · 관문 기록 신호 {ago(as_of, row['seen_at'])}" if row["seen_at"] is not None else " · 관문 기록 신호 없음"


def sensor_signal(as_of, available: bool, heartbeats: list) -> tuple:
    """관제 이상 sensor 의 (state, reason, row). 판정은 uploader_signal 이고 까닭은 카드처럼 관문 기록 신호 시각을 붙인다
    (수신 없음 · 미확인일 때 카드 까닭과 같은 글이다)."""
    state, reason, row = uploader_signal(as_of, available, heartbeats)
    return state, reason + gateway_note(as_of, available, heartbeats), row


def sensor_collection(as_of, available: bool, heartbeats: list, last: dict) -> dict:
    """허니팟 센서. 업로더 생존 신호(role=sensor, uploader_signal)로 가르고, 신호가 새로우면 Cowrie · 웹 디코이 로그로 정상 · 요청 없음을
    가른다. 까닭 끝에 관문 기록 신호 시각(gateway_note)을 붙인다(state 는 센서 판정 그대로다)."""
    state, reason, row = uploader_signal(as_of, available, heartbeats)
    signal = signal_of(UPLOADERS["sensor"][0], HEARTBEAT_STALE,
                       *((row["seen_at"], row["checked_at"], row["problem"]) if row else ()))
    if state is None:
        state, reason = (("ok", f"{reason} · 최근 1시간 로그 있음") if active("aws-sensor", last, as_of)
                         else ("quiet", f"{reason} · 최근 1시간 요청 없음"))
    return collection(state, reason + gateway_note(as_of, available, heartbeats), signal, logs_of("aws-sensor", last))


def receipt_at(receipt, job: str):
    """nodes.receipt 의 job 마지막 줄 시각(last_line_at). 사전이 아니거나 글자가 아니거나 ISO 시각이 아니면(시간대가 없는 것 포함)
    None 이다. 장비 로그(node_logs.receipt_times)도 쓴다."""
    try:
        rec = cti.loads(receipt)
    except ValueError:
        return None
    cur = rec.get(job) if isinstance(rec, dict) else None
    value = cur.get("last_line_at") if isinstance(cur, dict) else None
    if not isinstance(value, str):
        return None
    try:
        at = datetime.fromisoformat(value)
    except ValueError:
        return None
    return at if at.tzinfo is not None else None


def parse_gap(as_of, node, nginx_at):
    """웹 로그 적재 없음: nginx 를 선언한 노드(nodes.logs)에 1시간 안 도착한 줄(receipt.nginx.last_line_at)이 있는데 그 발생원의
    마지막 nginx. 이벤트가 없거나 그 도착보다 10분 넘게 앞서면 그 도착 시각, 아니면 None. 줄이 모두 형식 밖 · 선언 밖으로 버려지는
    경우다. 시험 출발지(fixture)로 적재된 줄도 적재다. auth 는 보지 않는다(sshd 외 줄은 늘 버려진다). 조용한 서버(도착도 없음)는
    경고가 아니다. node 는 PARSE_SQL 행이다."""
    if node is None or "nginx" not in (node["logs"] or []):
        return None
    at = receipt_at(node["receipt"], "nginx")
    if at is None or older(as_of, at, WINDOW_SECONDS):
        return None
    return at if older(at, nginx_at, PARSE_LAG) else None


def node_collection(as_of, node, last: dict, sources=None, readable=True, gap=None) -> dict:
    """web-01 · 등록 노드. 노드 수신 판정(operations.py 와 같은 규칙)으로 가른다. 정상이면 그 노드 로그로 정상 · 요청 없음을 가른다.
    sources 는 등록 노드 로그 [(발생원, 이름)](모두 요청 로그)이고 없으면 고정 web-01 이다. nodes 를 읽을 수 없으면(readable 거짓)
    등록 기록이 없는 것이 아니라 모르는 것이다. gap 은 웹 로그 적재 없음(parse_gap)의 마지막 도착이다. 있으면 state 는 그대로 두고
    경고 표지(warnings)를 단다(관제 이상 parse:<노드> 와 같은 판정)."""
    if sources is None:
        logs, keys = logs_of(WEB_NODE, last), ACTIVE_LOGS[WEB_NODE]
    else:
        logs = [{"key": key, "label": label, "last_at": cti.iso(last.get(key))} for key, label in sources]
        keys = [key for key, _ in sources]
    seen = node["last_seen_at"] if node else None
    signal = signal_of("노드 수신", NODE_SILENT, seen)
    extra = [{"label": "마지막 적재", "at": cti.iso(node["last_loaded_at"]) if node else None, "note": None}]
    warnings = [{"key": "parse", "label": PARSE_WARNING, "at": cti.iso(gap)}] if gap is not None else []

    def done(state, reason):
        return collection(state, reason, signal, logs, extra) | {"warnings": warnings}
    if not readable:
        return done("unknown", "노드 표를 읽을 수 없음")
    if node is None:
        return done("unknown", "노드 등록 기록 없음")
    reception = node["reception"]
    if reception == "revoked":
        return done("unknown", "노드 폐기됨")
    if reception == "waiting":
        return done("unknown", "노드 등록 대기 · 수신 전")
    if reception == "silent":
        return done("no_signal", f"노드 수신 {ago(as_of, seen)} · 10분 넘게 끊김" if seen
                    else "노드 수신 기록 없음 · 등록 뒤 10분 넘게 수신 없음")
    head = f"노드 수신 {ago(as_of, seen)}"
    if any(not older(as_of, last.get(key), WINDOW_SECONDS) for key in keys):
        return done("ok", f"{head} · 최근 1시간 로그 있음")
    return done("quiet", f"{head} · 최근 1시간 요청 없음")


def db_links_of(rows) -> list[dict]:
    """CONSOLE_LINKS_SQL 행 → [{name, label, present, note}](CONSOLES 순서). note 는 없을 때 붙이는 말이다(없으면 null)."""
    present = {r["name"]: bool(r["present"]) for r in rows}
    return [{"name": name, "label": label, "present": present.get(name, False), "note": note}
            for name, label, note in CONSOLES]


def db_links_reason(links, head=DB_LINKS_HEAD, unknown=DB_LINKS_UNKNOWN) -> str:
    """콘솔 DB 연결 글: '<head>: 콘솔 A 있음 · 콘솔 B 없음(평소 꺼 두는 예비)'. 읽지 못했으면(links None) unknown 이다.
    확인한 있음 · 없음만 적고 대기 · 정상 · 생존으로 꾸미지 않는다. 보고서는 머리를 '출력 시각의 DB 연결' 로 바꿔 부른다."""
    if links is None:
        return unknown
    return f"{head}: " + " · ".join(f"{x['label']} {'있음' if x['present'] else '없음'}"
                                     + (f"({x['note']})" if not x["present"] and x["note"] else "") for x in links)


def console_collection(last: dict, links=None) -> dict:
    """관제 콘솔(이슈 #76). 생존 신호가 없어 생존을 확정하지 않는다. 이 조회에 응답했다는 사실로 '응답 중'(responding)이고 까닭은
    DB 연결 확인(db_links_reason)이다. links 는 db_links_of 결과이고 읽지 못하면 None('확인 불가')이다. DB 연결은 콘솔 프로세스가
    DB 에 붙어 있다는 뜻일 뿐 응답 · HAProxy 분배를 보장하지 않는다(멈춘 프로세스도 세션은 남는다). 응답한 콘솔은 화면이 실시간
    연결(hello)로 보인다. 관제 이상 띠에는 싣지 않는다(B 는 평소 꺼 두고, A 없음은 B 가 응답 중인 상황이라 콘솔 장애 알림 몫이다)."""
    return collection("responding", db_links_reason(links), None, logs_of("console", last)) | {"db_links": links}


def checkers(as_of, available: bool, heartbeats: list) -> list[dict]:
    """적재기 · 집행기가 마지막으로 확인한 시각(종류별 최신) [{key, label, at, note, stopped}].
    note 는 없음 · '기록 없음' · '생존 신호 표를 읽을 수 없음' · '멈춤'(적재기 30분 · 집행기 10분 넘게 확인 없음),
    stopped 는 멈췄을 때의 까닭 글이다."""
    out = []
    for key, label, kind, limit in (("loader", "적재기 확인", "uploader", CHECKER_STALE),
                                    ("enforcer", "집행기 확인", "block_report", BLOCK_CHECKER_STALE)):
        times = [r["checked_at"] for r in heartbeats if r["kind"] == kind]
        at = max(times) if times else None
        note = None if times else ("기록 없음" if available else "생존 신호 표를 읽을 수 없음")
        stopped = None
        if times and older(as_of, at, limit):
            note, stopped = "멈춤", f"{label} 중단 · 마지막 {ago(as_of, at)}"
        out.append({"key": key, "label": label, "at": at, "note": note, "stopped": stopped})
    return out


def reports_of(heartbeats: list) -> dict:
    """{지점: 차단 보고 신호 행(block:<지점>)}."""
    return {r["source"][len("block:"):]: r for r in heartbeats
            if r["kind"] == "block_report" and r["source"].startswith("block:")}


def data_collection(as_of, started, available: bool, heartbeats: list, paths=()) -> dict:
    """데이터 노드. 마지막 탐지 실행이 신호다. 적재기 · 집행기가 마지막으로 확인한 시각을 곁들인다.
    stopped 는 화면 '주의' 에 쓰는 구조 값이다(state 는 늘리지 않는다). 적재기는 확인 중단, 집행기는 지점 하나라도 확인이 없거나
    멈춘 것이다(관제 이상 enforcer:* 와 같은 판정). 생존 신호 표를 읽을 수 없으면 둘은 비어 있다. 탐지(detect)는 마지막 실행은
    15분 안인데 탐지 경로(detect_paths) 하나가 멈춘 것이다(관제 이상 detect:* 와 같은 판정). 까닭 끝에 멈춘 경로를 붙인다."""
    signal = signal_of("마지막 탐지 실행", HEARTBEAT_STALE, started)
    checks = checkers(as_of, available, heartbeats)
    extra = [{"label": x["label"], "at": cti.iso(x["at"]), "note": x["note"]} for x in checks]
    late = [p for p in paths if p["stale"]] if not older(as_of, started, HEARTBEAT_STALE) else []
    tail = "".join(f" · {p['label']} 멈춤 · {p['reason']}" for p in late) \
        + "".join(f" · {x['stopped']}" for x in checks if x["stopped"])
    stopped = ["loader"] if any(x["stopped"] for x in checks if x["key"] == "loader") else []
    reports = reports_of(heartbeats)
    if available and any(point_counts(p, None, reports.get(p), as_of, available)["stalled"] for p in POINT_LABELS):
        stopped.append("enforcer")
    if late:
        stopped.append("detect")

    def done(state, reason):
        return collection(state, reason + tail, signal, [], extra) | {"stopped": stopped}
    if started is None:
        return done("unknown", "탐지 실행 기록 없음")
    head = f"마지막 탐지 실행 {ago(as_of, started)}"
    if older(as_of, started, HEARTBEAT_STALE):
        return done("no_signal", f"{head} · 15분 넘게 실행 없음")
    return done("ok", head)


def system_block(target_id: str, readable: bool, row, as_of, registered: bool = False) -> dict:
    """자원 지표. 고정 대상은 web-01 만 모은다. 읽을 수 없음 · 행 없음 · 오래됨을 가른다.
    등록 노드(registered)는 지표를 보내는 노드만이다. 행이 없으면 '없음' 이 아니라 미수집이다."""
    if target_id != WEB_NODE and not registered:
        return {"state": "not_collected", "metrics": None}
    if not readable:
        return {"state": "no_privilege", "metrics": None}
    if row is None:
        return {"state": "not_collected" if registered else "no_data", "metrics": None}

    def num(value, digits=1):
        return round(float(value), digits) if value is not None else None
    metrics = {"ts": cti.iso(row["ts"]), "cpu_pct": num(row["cpu_pct"]), "mem_used_pct": num(row["mem_used_pct"]),
               "disk_root_pct": num(row["disk_root_pct"]), "load1": num(row["load1"], 2)}
    return {"state": "stale" if older(as_of, row["ts"], METRICS_STALE) else "ok", "metrics": metrics}


def point_counts(point: str, blocks, report, as_of, heartbeats_available) -> dict:
    """한 지점의 적용 확인 · 실패 · 미확인 수와 미확인 가운데 지점 불일치(stale) 수(BLOCKS_SQL 한 행, 없으면 0).
    카드 대응 · 요약(blocks_by_point) · 관제 이상이 같이 쓴다. 수는 그 지점을 요청한 행만이고, 요청하지 않은 행은 unrequested,
    그 가운데 빠짐 확인 전은 removing 이다(이슈 #77. 요청 사실이라 아래 합치기에 넣지 않는다).
    미확인은 확인 중(checking: 정상 반영 시간 5분 안의 확인 전)과 확인 지연(delayed: 5분 넘은 확인 전 · 지점 불일치)으로도 나눈다
    (checking + delayed = unverified, 이슈 #84 결정 6).

    지점 결과(enforcement)를 내리는 쪽은 집행기뿐이다. 집행기가 멈추면 옛 '적용 확인' 이 그대로 남으므로, 그 지점의 집행기
    확인(block:<지점>.checked_at)이 없거나 10분 넘게 멈췄으면 적용 · 실패 · 불일치를 믿지 않고 모두 미확인으로 합친다. 생존 신호 표를
    읽을 수 없으면(마이그레이션 전 · 권한 빠짐) 멈춤을 판정할 수 없으니 같게 합친다. 까닭은 stalled 에 적는다. unreadable 은 표를 읽을
    수 없어 합친 것이다(집행기가 멈춘 것이 아니라 모르는 것이라 화면이 '확인 불가' 로 가른다)."""
    applied = int(blocks[f"{point}_applied"]) if blocks else 0
    failed = int(blocks[f"{point}_failed"]) if blocks else 0
    unverified = int(blocks[f"{point}_unverified"]) if blocks else 0
    stale = int(blocks[f"{point}_stale"]) if blocks else 0
    checking = int(blocks[f"{point}_checking"]) if blocks else 0
    delayed = int(blocks[f"{point}_delayed"]) if blocks else 0
    unrequested = int(blocks[f"{point}_unrequested"]) if blocks else 0
    removing = int(blocks[f"{point}_removing"]) if blocks else 0
    stalled = None
    if not heartbeats_available:
        stalled = "집행 보고를 읽을 수 없음 · 적용 여부 확인 불가"
    elif as_of is not None:
        if report is None:
            stalled = "집행기 확인 기록 없음"
        elif older(as_of, report["checked_at"], BLOCK_CHECKER_STALE):
            stalled = f"집행기 확인 중단 · 마지막 확인 {ago(as_of, report['checked_at'])}"
    if stalled:
        # 멈춘 지점은 확인 중 · 지연도 가르지 않는다(화면은 그 지점 경고 하나로 보인다)
        applied, failed, unverified, stale, checking, delayed = 0, 0, applied + failed + unverified, 0, 0, 0
    return {"point": point, "label": POINT_LABELS[point], "applied": applied, "failed": failed, "unverified": unverified,
            "stale": stale, "checking": checking, "delayed": delayed, "unrequested": unrequested, "removing": removing,
            "stalled": stalled, "unreadable": not heartbeats_available}


COUNT_KEYS = ("applied", "failed", "unverified", "stale", "checking", "delayed", "unrequested", "removing")


def response_block(target_id: str, blocks, exempt: int, reports: dict, as_of=None, heartbeats_available=False) -> dict:
    """대응. 지점이 있는 대상만 적용 확인 · 실패 · 미확인 수와 그 가운데 지점 불일치 · 확인 중 · 확인 지연 수, 그 지점 미요청 수
    (unrequested) · 빠짐 확인 전 수(removing)(point_counts)를 낸다. 지점이 없으면 수 대신 null 이다(0 이 아니다).
    reports 는 {지점: 차단 보고 신호 행}(없으면 빈 사전). report_issue 는 관제 이상 띠 report:<지점> 과 같은 판정(report_reason)의
    글이다(이슈 #84 결정 1. 접힌 줄 '보고 문제' 배지). 집행기가 멈췄거나(stalled, 띠는 enforcer:<지점>) 이상이 없으면 null 이다."""
    point, label = POINTS.get(target_id, (None, None))
    if point is None:
        return {"point": None, "point_label": None, **{k: None for k in COUNT_KEYS}, "exempt": exempt, "report": None,
                "report_issue": None, "stalled": None, "unreadable": None}
    report = reports.get(point)
    counts = point_counts(point, blocks, report, as_of, heartbeats_available)
    issue = None if counts["stalled"] or report is None or as_of is None else report_reason(report, as_of)
    return {"point": point, "point_label": label, **{k: counts[k] for k in COUNT_KEYS}, "exempt": exempt,
            "report": {"seen_at": cti.iso(report["seen_at"]), "checked_at": cti.iso(report["checked_at"]),
                       "problem": report["problem"]} if report else None,
            "report_issue": issue, "stalled": counts["stalled"], "unreadable": counts["unreadable"]}


VULN_COUNTS = ("vuln_total", "vuln_kev", "vuln_fix_available", "vuln_reboot_pending", "vuln_fix_unknown")


def vulns_block(target_id: str, available: bool, assets: dict, as_of) -> dict:
    """취약점. 자산 표에 없는 자산은 수 0 · 오래됨 · missing 이다(없다고 '취약점 0' 으로 읽히지 않게).
    수는 전체 · KEV · 수정판 있음 · 재부팅 대기 · 수정 여부 미확인(asset_vulnerabilities.fix_state)이다.
    대조 상태: check_failed 는 마지막 대조가 실패(check_error 있음), check_stale 은 마지막 대조가 48시간 넘음(조사 오래됨 stale 과
    같은 기준 cti.is_stale)이다. 대조 전(checked_at 없음)은 오래됨이 아니다. 둘 다 수를 바꾸지 않고, 오류 글은 싣지 않는다(자산 화면).
    등록 노드(TARGET_ASSETS 에 없는 대상)는 같은 이름(asset_id = node_id)의 자산이 있을 때만 잇고, 없으면 빈 목록(연결된 자산 없음)이다."""
    if not available:
        return {"available": False, "assets": []}
    ids = TARGET_ASSETS.get(target_id)
    if ids is None:
        ids = [target_id] if target_id in assets else []
    out = []
    for asset_id in ids:
        row = assets.get(asset_id)
        if row is None:
            out.append({"asset_id": asset_id, **{k: 0 for k in VULN_COUNTS}, "collected_at": None,
                        "checked_at": None, "stale": True, "missing": True, "check_failed": False, "check_stale": False})
            continue
        out.append({"asset_id": asset_id, **{k: int(row[k]) for k in VULN_COUNTS},
                    "collected_at": cti.iso(row["collected_at"]), "checked_at": cti.iso(row["checked_at"]),
                    "stale": cti.is_stale(row["collected_at"], as_of), "missing": False,
                    "check_failed": bool(row.get("check_error")),
                    "check_stale": row["checked_at"] is not None and cti.is_stale(row["checked_at"], as_of)})
    return {"available": True, "assets": out}


def bridge_rows(rows: list) -> list:
    """1분 다리 판정 행(DETECT_PATHS_SQL 모양, 버전 순): 돌아야 할 버전(BRIDGE_VERSIONS)마다 24시간 안 행, 없으면 last_at 이 None 인
    행이다. 기대 밖 버전(은퇴한 w1 · 떼어 낸 n1 등)의 기록은 보지 않는다. 24시간 안 다리 행이 하나도 없으면 빈 목록이다."""
    seen = {r["rule_version"]: r for r in rows if not r["honeypot"]}
    if not seen:
        return []
    return [seen.get(v) or {"rule_version": v, "last_at": None, "honeypot": False} for v in sorted(BRIDGE_VERSIONS)]


def late_reason(late: list, as_of) -> str:
    """멈춘 1분 다리 버전들의 글: '<버전들> 마지막 실행 n분 전'(그 가운데 가장 늦은 실행) · '<버전들> 24시간 넘게 실행 없음'."""
    ran = [r for r in late if r["last_at"] is not None]
    gone = [r["rule_version"] for r in late if r["last_at"] is None]
    parts = [" · ".join(r["rule_version"] for r in ran) + f" 마지막 실행 {ago(as_of, max(r['last_at'] for r in ran))}"] \
        if ran else []
    return " · ".join(parts + ([" · ".join(gone) + " 24시간 넘게 실행 없음"] if gone else []))


def detect_paths(rows: list, as_of) -> list[dict]:
    """탐지 경로별 마지막 실행(DETECT_PATHS_SQL 행). 허니팟(5분 풀러)은 규칙 파일 하나만 돌아 경로 최댓값으로 가르고 옛 버전은
    경보하지 않는다. 노드 · 관제(1분 다리)는 규칙 파일마다 따로 돌아, 돌아야 할 버전(bridge_rows) 하나라도 15분 넘게 멈추거나
    24시간 안 기록이 없으면 멈춤이다. 24시간 안에 그 경로 행이 없으면 멈춤이다. reason 은 멈췄을 때 관제 이상 항목에 쓰는 글이다
    (아니면 null)."""
    out = []
    for key, label in DETECT_PATHS:
        mine = [r for r in rows if r["honeypot"]] if key == "honeypot" else bridge_rows(rows)
        versions = [{"rule_version": r["rule_version"], "last_at": cti.iso(r["last_at"]),
                     "stale": older(as_of, r["last_at"], HEARTBEAT_STALE)} for r in mine]
        last = max((r["last_at"] for r in mine if r["last_at"] is not None), default=None)
        late = [r for r in mine if older(as_of, r["last_at"], HEARTBEAT_STALE)]
        stale = older(as_of, last, HEARTBEAT_STALE) if key == "honeypot" else (not mine or bool(late))
        reason = None
        if stale and not mine:
            reason = "24시간 안 실행 기록 없음"
        elif stale and key == "honeypot":
            reason = f"마지막 실행 {ago(as_of, last)}"
        elif stale:
            reason = late_reason(late, as_of)
        out.append({"key": key, "label": label, "last_at": cti.iso(last), "stale": stale, "reason": reason,
                    "versions": versions})
    return out


def report_reason(report, as_of) -> str | None:
    """집행 지점 보고(block:<지점> 행)가 15분 넘게 오래됐거나, 읽기 문제(problem, 비신뢰 글)가 5분 넘게 이어지면(못 읽은 회차는
    집행기가 옛 seen_at 을 두므로 마지막으로 읽은 보고가 5분 넘게 오래됨) 그 글, 아니면 None. 한두 회차 일시 오류는 넘긴다."""
    seen = report["seen_at"]
    lasting = report["problem"] and older(as_of, seen, REPORT_PROBLEM_GRACE)
    if not (older(as_of, seen, HEARTBEAT_STALE) or lasting):
        return None
    parts = [f"마지막 보고 {ago(as_of, seen)}" if seen is not None else "받은 보고 없음"]
    if report["problem"]:
        parts.append(report["problem"])
    return " · ".join(parts)


def device_checks(as_of, cards, gaps: dict, metrics: dict, metrics_available: bool, web=None) -> list[dict]:
    """관제 이상이 보는 보호 대상(web-01 · 등록 노드 카드) [{id, label, gap, metrics_at}]. gap 은 웹 로그 적재 없음의 마지막 도착
    (parse_gaps), metrics_at 은 자원 지표가 오래됐을 때 그 마지막 시각이다. 카드와 같은 판정(parse_gap · system_block)이다.
    등록 대기 · 폐기(재등록 중 포함)인 장비의 옛 지표는 싣지 않는다(의도한 상태). web 은 web-01 의 nodes 행이다(없으면 None)."""
    fixed = {tid: label for tid, label, _ in TARGETS}
    out = []
    for tid, label, registered, node in [(WEB_NODE, fixed[WEB_NODE], False, web),
                                         *((card["id"], card["label"], True, card["node"]) for card in cards)]:
        row = metrics.get(tid)
        stale = system_block(tid, metrics_available, row, as_of, registered)["state"] == "stale" \
            and (node is None or node["reception"] in ACTIVE_RECEPTIONS)
        out.append({"id": tid, "label": label, "gap": gaps.get(tid), "metrics_at": row["ts"] if stale else None})
    return out


def monitor_items(checks, points: dict, mismatch: int, node_rows, nodes_readable, paths, heartbeats_available, *,
                  as_of=None, sensor=None, gateway=None, reports=None, cards_readable=True, web_expected=False,
                  devices=()) -> list[dict]:
    """관제 이상 띠 · 사이드바 항목. 이상(alert) · 모름(unknown)만 이 순서로 싣는다: 생존 신호 표 → 적재기 → 집행기(지점별) →
    센서 수신 → 관문 기록 수신 → 탐지 경로 → 적용 실패(지점별) → 지점 불일치(지점별) → 관문 불일치 → 지점 보고(지점별) →
    확인 지연(지점별, 5분 넘은 확인 전. 이슈 #84) → 노드 수신 → 노드별 웹 로그 적재 → 노드별 자원 지표. 카드가 이상 · 확인 불가로
    보이는 수집 · 탐지 · 집행 상태는 카드와 같은 판정으로 여기에도 싣고, 같은 현상은 한 항목만 싣는다(표를 읽을 수 없거나 적재기가
    멈추면 센서의 모름, 관문 불일치가 있으면 관문 지점 불일치, 집행기가 멈추면 그 지점 보고, 그 지점 보고가 있으면 그 지점 확인 지연,
    수신이 끊긴 노드의 자원 지표는 뺀다).
    생존 신호 표를 읽을 수 없으면 적재기 · 집행기 · 지점 보고는 판정하지 않는다. 노드 수신은 활성(수신 정상 · 끊김) 노드가 한 대라도
    끊기면 이상이다(등록 대기 · 폐기는 활성이 아니다). cards_readable 이 거짓이면 web-01 행만 읽은 것이다(등록 노드 열 모름).
    web_expected 면 nodes 에 web-01 행이 없을 때(고정 카드 '노드 등록 기록 없음') 모름이다.
    sensor 는 sensor_signal, gateway 는 uploader_signal 결과다. 관문 기록은 수신 없음만 싣는다(행이 없으면 관문 업로더가 없는 구성,
    적재기가 확인하지 않는 행뿐이면 떼어 둔 호스트의 남은 행이다). reports 는 {지점: 보고 행}, devices 는 device_checks 다.
    넘기지 않은 것은 보지 않는다."""
    items = []

    def add(key, level, label, reason=None, at=None, count=None):
        items.append({"key": key, "level": level, "label": label, "reason": reason, "at": at, "count": count})

    if not heartbeats_available:
        add("heartbeats", "unknown", "생존 신호", "생존 신호 표를 읽을 수 없음")
    else:
        loader = next(x for x in checks if x["key"] == "loader")
        if loader["stopped"]:
            add("loader", "alert", "적재기", loader["stopped"], cti.iso(loader["at"]))
        elif loader["at"] is None:
            add("loader", "unknown", "적재기", "적재기 확인 기록 없음")
        for point, counts in points.items():
            if counts["stalled"]:
                add(f"enforcer:{point}", "alert", f"{counts['label']} 집행기", counts["stalled"])
    covered = any(x["key"] in ("heartbeats", "loader") for x in items)
    for key, label, signal in (("sensor", f"{SENSOR_NAME} 수신", sensor), ("gateway_uploader", f"{GATEWAY_NAME} 기록 수신", gateway)):
        state, reason, row = signal or (None, None, None)
        if state == "no_signal":
            add(key, "alert", label, reason, cti.iso(row["seen_at"]))
        elif state == "unknown" and not covered and key == "sensor":
            add(key, "unknown", label, reason)
    for path in paths:
        if path["stale"]:
            add(f"detect:{path['key']}", "alert", path["label"], path["reason"], path["last_at"])
    for point, counts in points.items():
        if counts["failed"] > 0:
            add(f"block_failed:{point}", "alert", f"{counts['label']} 적용 실패", count=counts["failed"])
    for point, counts in points.items():
        if counts["stale"] > 0 and not (point == "gateway" and mismatch > 0):
            add(f"point_stale:{point}", "alert", f"{counts['label']} 불일치", count=counts["stale"])
    if mismatch > 0:
        add("gateway_mismatch", "alert", ENFORCE_MISMATCH, count=mismatch)
    if heartbeats_available and reports is not None:
        for point, counts in points.items():
            report = reports.get(point)
            if counts["stalled"]:
                continue                                  # 집행기 항목(enforcer:<지점>)이 있다
            if report is None:
                add(f"report:{point}", "unknown", f"{counts['label']} 보고", "보고 기록 없음")
            elif (reason := report_reason(report, as_of)) is not None:
                add(f"report:{point}", "alert", f"{counts['label']} 보고", reason, cti.iso(report["seen_at"]))
    # 확인 지연 가운데 지점 불일치(위 항목)를 뺀 5분 넘은 확인 전. 집행기가 보고를 판정하지 못한 회차(보류)에는 직전 대기와 그 시각이
    #   남아 카드 '적용 확인 지연' 만 뜬다. 그 지점 보고 항목이 있으면 같은 현상이라 싣지 않는다(집행기가 멈춘 지점은 0 이다)
    shown = {x["key"] for x in items}
    for point, counts in points.items():
        late = counts["delayed"] - counts["stale"]
        if late > 0 and f"report:{point}" not in shown:
            add(f"point_delayed:{point}", "alert", f"{counts['label']} 적용 확인 지연", count=late)
    silent = []
    if not nodes_readable:
        add("nodes", "unknown", "노드 수신", "노드 표를 읽을 수 없음")
    else:
        active = [r for r in node_rows if r["reception"] in ACTIVE_RECEPTIONS]
        # 확인한 사실만 적는다(서버 장애인지 에이전트 · 망 · 적재 문제인지는 아직 가르지 못한다). 여러 대면 대수로 묶고 상세는 /nodes
        silent = sorted((r for r in active if r["reception"] == "silent"), key=lambda r: r["node_id"])
        if len(silent) == 1:
            seen = silent[0]["last_seen_at"]
            add("nodes_silent", "alert", "노드 수신", f"{silent[0]['node_id']} 수신 끊김 · "
                + (f"마지막 수신 {ago(as_of, seen)}" if seen is not None else "수신 기록 없음"), cti.iso(seen), count=1)
        elif silent:
            add("nodes_silent", "alert", "노드 수신", f"노드 {len(silent)}대 수신 끊김", count=len(silent))
        unread = (["등록 노드 열을 읽을 수 없음"] if not cards_readable else []) \
            + ([f"{WEB_NODE} 등록 기록 없음"] if web_expected and all(r["node_id"] != WEB_NODE for r in node_rows) else [])
        if unread:
            add("nodes", "unknown", "노드 수신", " · ".join(unread))
    for device in devices:
        if device["gap"] is not None:
            add(f"parse:{device['id']}", "alert", f"{device['label']} 웹 로그 적재",
                f"로그는 도착하는데 적재되지 않음 · 마지막 도착 {ago(as_of, device['gap'])}", cti.iso(device["gap"]))
    for device in devices:
        if device["metrics_at"] is not None and device["id"] not in {r["node_id"] for r in silent}:
            add(f"metrics:{device['id']}", "alert", f"{device['label']} 자원 지표",
                f"마지막 지표 {ago(as_of, device['metrics_at'])}", cti.iso(device["metrics_at"]))
    return items


def latest_of(incidents: list, as_of) -> dict | None:
    """최근 중요 탐지 한 줄: 24시간 안 critical · high 중 last_ts 최신, 없으면 24시간 안 아무 사건 최신.
    verdict 는 최신 판정 값(없으면 None)이다. 판정됨(judged)이어도 undetermined 면 화면이 '미결' 로 보인다."""
    recent = [i for i in incidents if not older(as_of, i["last_ts"], LATEST_HOURS * 3600)]
    if not recent:
        return None
    pool = [i for i in recent if i["severity"] in HIGH_SEVERITIES] or recent
    best = min(pool, key=lambda i: (-i["last_ts"].timestamp(), i["incident_key"]))
    return {"incident_key": best["incident_key"], "rule_id": best["rule_id"], "rule_name": best["rule_name"],
            "severity": best["severity"], "actor_ip": best["actor_ip"], "target": best["target"],
            "last_ts": cti.iso(best["last_ts"]), "judged": bool(best["judged"]), "verdict": best.get("verdict")}


def tally(incidents: list, attached: dict, as_of, extra=()) -> tuple[dict, dict]:
    """대상별 보안 집계와 붙이지 못한 사건 수. attached 는 {사건 키: {(대상, 나눔)}}. 대상별 rows 는 붙은 사건이다.
    extra 는 등록 노드 카드 id 다. undetermined 는 최신 판정이 사람의 미결인 사건 수다. 창 밖(in_window 거짓) 행은 미결이어서
    읽은 것이다. 미결 수에만 세고 rows(최근 중요 탐지 · 대응 금지 대역 수)에는 넣지 않는다(그 수가 미결 확장으로 바뀌지 않게).
    행에 두 칸이 없으면 창 안 · 미결 아님이다."""
    since = as_of - timedelta(seconds=WINDOW_SECONDS)
    per = {tid: {"incidents_1h": 0, "high_1h": 0, "pending": 0, "undetermined": 0, "rows": [],
                 "parts": {key: {"incidents_1h": 0, "pending": 0} for key, _ in AWS_PARTS}}
           for tid in [*(tid for tid, _, _ in TARGETS), *extra]}
    unmapped = {"incidents_1h": 0, "pending": 0, "undetermined": 0}
    for inc in incidents:
        pairs = attached.get(inc["incident_key"]) or set()
        fresh, pending = inc["first_ts"] >= since, not inc["judged"]
        undetermined, in_window = bool(inc.get("undetermined")), inc.get("in_window", True)
        if not pairs:
            unmapped["incidents_1h"] += fresh
            unmapped["pending"] += pending
            unmapped["undetermined"] += undetermined
            continue
        for tid in sorted({t for t, _ in pairs}):
            slot = per[tid]
            slot["incidents_1h"] += fresh
            slot["high_1h"] += fresh and inc["severity"] in HIGH_SEVERITIES
            slot["pending"] += pending
            slot["undetermined"] += undetermined
            if in_window:
                slot["rows"].append(inc)
        for part in sorted({p for _, p in pairs if p}):
            per["aws-sensor"]["parts"][part]["incidents_1h"] += fresh
            per["aws-sensor"]["parts"][part]["pending"] += pending
    return per, unmapped


def node_targets(rows) -> list[dict]:
    """등록 노드 행(NODES_SQL) → 카드로 붙일 노드 [{id, label, sensor, node}](node_id 순).
    폐기된 노드 · 고정 대상과 id 가 겹치는 노드(web-01 은 고정 카드다) · 발생원이 고정 발생원이나 앞 노드와 겹치는 노드는 뺀다
    (그 발생원의 로그 · 사건은 이미 다른 카드 것이라 두 카드에 나뉘면 안 된다). 발생원은 nodes.sensor, 없으면 node_id 다
    (적재는 node_id 를 events.sensor 로 쓰고 등록은 sensor 를 node_id 로 넣는다). 이름은 hostname, 없으면 node_id 다."""
    fixed = {tid for tid, _, _ in TARGETS}
    out, taken = [], set(SENSOR_TARGET)
    for row in sorted(rows, key=lambda r: r["node_id"]):
        sensor = row["sensor"] or row["node_id"]
        if row["status"] == "revoked" or row["node_id"] in fixed or sensor in taken:
            continue
        taken.add(sensor)
        out.append({"id": row["node_id"], "label": row["hostname"] or row["node_id"], "sensor": sensor, "node": row})
    return out


def node_sources(cards) -> dict[str, str]:
    """등록 노드 카드 → {발생원: 노드 id}(resolve · attach 의 nodes)."""
    return {card["sensor"]: card["id"] for card in cards}


def security_block(target_id: str, slot: dict, as_of) -> dict:
    parts = [{"key": key, "label": label, **slot["parts"][key]} for key, label in AWS_PARTS] \
        if target_id == "aws-sensor" else []
    return {"incidents_1h": slot["incidents_1h"], "high_1h": slot["high_1h"], "pending": slot["pending"],
            "undetermined": slot["undetermined"], "parts": parts, "latest": latest_of(slot["rows"], as_of)}


# ----------------------------------------------------------------------
#  조회
# ----------------------------------------------------------------------

async def read_nodes(c, as_of) -> tuple[bool, list[dict]]:
    """(web-01 수신(NODE_SQL)을 읽을 수 있는가, 카드로 붙일 등록 노드). 표가 없거나 열 권한이 모자라면 등록 노드 카드는 없다
    (고정 네 대상만). 카드 열(hostname · sensor)만 모자라면 web-01 수신은 전처럼 읽는다(카드 때문에 web-01 값이 바뀌지 않게)."""
    if await c.fetchval(NODES_READABLE_SQL, NODE_COLUMNS):
        return True, node_targets(await c.fetch(NODES_SQL, as_of))
    return bool(await c.fetchval(NODES_READABLE_SQL, WEB_NODE_COLUMNS)), []


async def link_incidents(c, incidents: list, nodes=None) -> tuple[dict, dict]:
    """({사건 키: {(대상, 나눔): 근거}}, {(규칙 버전, 규칙 id): 규칙 정의}). 규칙 정의는 쓰인 버전만 한 번에 읽고, 발생원이 섞인
    규칙의 사건만 이벤트로 고른다. 이벤트 · 세션으로 찾은 발생원은 확인이다. nodes 는 등록 노드 {발생원: 노드 id} 다.
    incidents 행은 incident_key · rule_id · rule_version · actor_ip · target · first_ts · last_ts · sensors · sessions 를 쓴다."""
    versions = sorted({v for v in (i["rule_version"] for i in incidents) if v})
    specs = {}
    for row in (await c.fetch(RULES_SQL, versions) if versions else []):
        specs.setdefault((row["rule_version"], row["rule_id"]), rule_spec(row))
    links, joins, by_session, fallback = {}, [], [], {}
    for inc in incidents:
        spec = specs.get((inc["rule_version"], inc["rule_id"]))
        found, need = resolve_links(inc["target"], inc["sensors"], spec, nodes)
        links[inc["incident_key"]] = found
        if need == EVENTS and inc["actor_ip"]:
            joins.append(join_item(inc, spec))
            fallback[inc["incident_key"]] = found
        elif need == SESSIONS:
            # 세션으로 고르지 못하면(근거에 세션 없음 · 이벤트 없음) 허니팟 센서(규칙 범위)이고 나눔은 Cowrie 대체 추정이다
            links[inc["incident_key"]] = fallback[inc["incident_key"]] = {("aws-sensor", None): RULE_SCOPE,
                                                                          ("aws-sensor", "cowrie"): FALLBACK}
            item = session_item(inc)
            if item:
                by_session.append(item)
    found_sources: dict[str, list] = {}
    if joins:
        for row in await c.fetch(JOIN_SQL, json.dumps(joins)):
            found_sources.setdefault(row["incident_key"], []).append(row["sensor"])
    if by_session:
        for row in await c.fetch(SESSION_JOIN_SQL, json.dumps(by_session), list(SESSION_SOURCES)):
            found_sources.setdefault(row["incident_key"], []).append(row["sensor"])
    for key, sensors in found_sources.items():
        # 이벤트가 모르는 발생원뿐이면 앞서 정한 것(대상만 · Cowrie · 없음)을 근거째 둔다
        links[key] = based(attach(sensors, nodes), CONFIRMED) or fallback[key]
    return links, specs


async def parse_gaps(c, as_of, cards) -> dict:
    """{장비 id: 웹 로그 적재 없음의 마지막 도착(parse_gap)}. web-01(발생원 web-01)과 등록 노드 카드(카드 발생원)를 한 질의로 본다.
    부른 쪽이 PARSE_COLUMNS 를 읽을 수 있는지 먼저 본다."""
    devices = [(WEB_NODE, WEB_NODE), *((card["id"], card["sensor"]) for card in cards)]
    rows = await c.fetch(PARSE_SQL, [d for d, _ in devices], [s for _, s in devices], as_of, WINDOW_SECONDS + PARSE_LAG)
    gaps = {r["node_id"]: parse_gap(as_of, r, r["nginx_at"]) for r in rows}
    return {key: at for key, at in gaps.items() if at is not None}


async def attach_incidents(c, incidents: list, nodes=None) -> dict:
    """{사건 키: {(대상, 나눔)}}(옛 모양, legacy_pairs). 계산은 link_incidents 와 같다."""
    links, _ = await link_incidents(c, incidents, nodes)
    return {key: legacy_pairs(value) for key, value in links.items()}


async def incident_devices(c, rows: list, as_of) -> tuple[dict, list]:
    """사건 행들의 관련 장비 ({사건 키: devices_of 결과}, 등록 노드 카드). 행이 없으면 카드만 읽고 매핑 질의를 하지 않는다.
    rows 는 link_incidents 와 같은 열(EVIDENCE_COLUMNS 포함)을 가진다."""
    _, cards = await read_nodes(c, as_of)
    if not rows:
        return {}, cards
    links, specs = await link_incidents(c, rows, node_sources(cards))
    return {r["incident_key"]: devices_of(links[r["incident_key"]], specs.get((r["rule_version"], r["rule_id"])), cards)
            for r in rows}, cards


async def targets_view(c, as_of, queue: bool = False) -> dict:
    """상태판 본문. 부른 쪽이 반복 읽기 트랜잭션을 연다(시험은 기준 시각을 넘겨 경계를 본다).
    queue 면 먼저 처리할 사건(미판정 전체를 같은 매핑으로 앞 · 뒤로 가름)을 더한다. 보고서는 queue 없이 부른다."""
    heartbeats_available = bool(await c.fetchval(HEARTBEATS_READABLE_SQL))
    metrics_available = bool(await c.fetchval(METRICS_READABLE_SQL))
    heartbeats = [dict(r) for r in await c.fetch(HEARTBEATS_SQL)] if heartbeats_available else []
    # 등록 노드 카드. nodes 를 읽을 수 없으면 고정 네 대상만이고, web-01 이 읽는 열까지 없으면 web-01 수신도 모른다
    nodes_readable, cards = await read_nodes(c, as_of)
    nodes = node_sources(cards)

    incidents = [dict(r) for r in await c.fetch(INCIDENTS_SQL, as_of, WINDOW_SECONDS, LATEST_HOURS)]
    links, specs = await link_incidents(c, incidents, nodes)
    # 카드 수는 대체 추정을 뺀 곳으로 센다(목록 장비 필터와 같은 기준). 대응의 금지 대역 수(exempt)도 같은 사건으로 센다
    per, unmapped = tally(incidents, {key: shown(value) for key, value in links.items()}, as_of,
                          [card["id"] for card in cards])

    logs = {card["id"]: [(card["sensor"], f"{card['label']} 로그")] for card in cards}
    sensors = sorted({key for rows in [*LOGS.values(), *logs.values()] for key, _ in rows})
    last = {r["sensor"]: r["last_at"] for r in await c.fetch(LOGS_SQL, sensors, as_of)}
    node = await c.fetchrow(NODE_SQL, WEB_NODE, as_of) if nodes_readable else None
    started = await c.fetchval(DETECTOR_SQL)
    paths = detect_paths(await c.fetch(DETECT_PATHS_SQL, as_of), as_of)
    metrics = {r["node_id"]: r for r in await c.fetch(METRICS_SQL, [WEB_NODE, *(card["id"] for card in cards)])} \
        if metrics_available else {}
    # 웹 로그 적재 없음(parse_gap). nodes 의 선언 로그 · 받은 줄 기록 열을 읽을 수 있을 때만 판정한다
    gaps = await parse_gaps(c, as_of, cards) \
        if nodes_readable and await c.fetchval(NODES_READABLE_SQL, PARSE_COLUMNS) else {}
    blocks = await c.fetchrow(BLOCKS_SQL, as_of)
    reports = reports_of(heartbeats)
    # 콘솔 DB 연결(이슈 #76). pg_stat_activity 를 읽을 수 없으면 확인 불가(None)다
    db_links = db_links_of(await c.fetch(CONSOLE_LINKS_SQL, [name for name, _, _ in CONSOLES])) \
        if await c.fetchval(CONSOLE_LINKS_READABLE_SQL) else None

    # 차단 금지 대역에 드는 출발지(대상별로 서로 다른 주소 수)
    ips = sorted({i["actor_ip"] for slot in per.values() for i in slot["rows"] if i["actor_ip"]})
    exempt_ips = {r["ip"] for r in await c.fetch(EXEMPT_SQL, ips, await block_nets(c))} if ips else set()

    # 표가 있고 콘솔 역할이 모두 읽을 수 있어야 한다(cti.TABLES_SQL 이 권한까지 본다). 역할 블록만 다시 적용해 CTI 권한이 빠져도
    #   취약점 구역만 '정보 없음' 이 되고 나머지 구역은 그대로 나온다
    cti_available = bool(await c.fetchval(cti.TABLES_SQL, cti.CTI_TABLES))
    assets = {r["asset_id"]: r for r in await c.fetch(cti.ASSETS_SQL, None)} if cti_available else {}

    collections = {
        "aws-sensor": sensor_collection(as_of, heartbeats_available, heartbeats, last),
        "web-01": node_collection(as_of, node, last, readable=nodes_readable, gap=gaps.get(WEB_NODE)),
        "console": console_collection(last, db_links),
        "data-node": data_collection(as_of, started, heartbeats_available, heartbeats, paths),
        **{card["id"]: node_collection(as_of, card["node"], last, logs[card["id"]], gap=gaps.get(card["id"]))
           for card in cards},
    }
    targets = []
    # 고정 대상 뒤에 등록 노드. kind 는 화면이 순서 · 아이콘을 가르는 값이다
    for tid, label, role, kind in [*((tid, label, role, "fixed") for tid, label, role in TARGETS),
                                   *((card["id"], card["label"], NODE_ROLE, "node") for card in cards)]:
        exempt = len({i["actor_ip"] for i in per[tid]["rows"] if i["actor_ip"] in exempt_ips})
        targets.append({
            "id": tid, "kind": kind, "label": label, "role": role,
            "collection": collections[tid],
            "security": security_block(tid, per[tid], as_of),
            "system": system_block(tid, metrics_available, metrics.get(tid), as_of, kind == "node"),
            "response": response_block(tid, blocks, exempt, reports, as_of, heartbeats_available),
            "vulns": vulns_block(tid, cti_available, assets, as_of),
        })
    body = {"as_of": cti.iso(as_of), "window_seconds": WINDOW_SECONDS,
            "heartbeats_available": heartbeats_available, "metrics_available": metrics_available,
            "targets": targets, "unmapped": unmapped}
    if queue:
        body["queue"] = queue_of([dict(r) for r in await c.fetch(PENDING_ROWS, as_of)], links, specs, cards)
    return body


async def monitor_view(c, as_of) -> dict:
    """관제 이상(띠 · 사이드바). 적재기 · 집행기 확인, 센서 · 관문 기록 수신, 탐지 경로, 지점별 적용 실패 · 불일치 · 보고 · 확인 지연,
    활성 노드 수신, 보호 대상별 웹 로그 적재 · 자원 지표를 본다. 읽을 수 있는 표 · 열을 한 질의로 보고(MONITOR_READABLE_SQL) 표마다
    한 번씩 읽어 질의는 8개 이하(now 포함)다.
    nodes 는 카드 열까지 읽을 수 있으면 전부(web-01 포함), web-01 이 읽는 열만 되면 web-01 한 행(등록 노드 열 모름)이고, 둘 다 안
    되면 모른다."""
    readable = await c.fetchrow(MONITOR_READABLE_SQL, NODE_COLUMNS, WEB_NODE_COLUMNS, PARSE_COLUMNS)
    can = dict(readable) if readable else {}
    heartbeats_available, metrics_available = bool(can.get("heartbeats")), bool(can.get("metrics"))
    heartbeats = [dict(r) for r in await c.fetch(HEARTBEATS_SQL)] if heartbeats_available else []
    cards = []
    if can.get("cards"):
        node_rows = list(await c.fetch(NODES_SQL, as_of))
        cards = node_targets(node_rows)
    elif can.get("web"):
        row = await c.fetchrow(NODE_SQL, WEB_NODE, as_of)
        node_rows = [{"node_id": WEB_NODE, **dict(row)}] if row else []
    else:
        node_rows = []
    nodes_readable = bool(can.get("cards") or can.get("web"))
    web = next((r for r in node_rows if r["node_id"] == WEB_NODE), None)
    blocks = await c.fetchrow(BLOCKS_SQL, as_of)
    paths = detect_paths(await c.fetch(DETECT_PATHS_SQL, as_of), as_of)
    metrics = {r["node_id"]: r for r in await c.fetch(METRICS_SQL, [WEB_NODE, *(card["id"] for card in cards)])} \
        if metrics_available else {}
    gaps = await parse_gaps(c, as_of, cards) if nodes_readable and can.get("parse") else {}
    reports = reports_of(heartbeats)
    points = {p: point_counts(p, blocks, reports.get(p), as_of, heartbeats_available) for p in POINT_LABELS}
    items = monitor_items(checkers(as_of, heartbeats_available, heartbeats), points,
                          int(blocks["mismatch"]) if blocks else 0, node_rows, nodes_readable, paths,
                          heartbeats_available, as_of=as_of,
                          sensor=sensor_signal(as_of, heartbeats_available, heartbeats),
                          gateway=uploader_signal(as_of, heartbeats_available, heartbeats, "gateway"),
                          reports=reports, cards_readable=bool(can.get("cards")), web_expected=True,
                          devices=device_checks(as_of, cards, gaps, metrics, metrics_available, web))
    return {"as_of": cti.iso(as_of), "items": items, "detect_paths": paths}


@router.get("/api/dashboard/targets")
async def dashboard_targets(request: Request):
    """관제 대상별 상태판. 읽기 조회라 역할 검사 없이 세션 미들웨어만 둔다."""
    async with request.app.state.pool.acquire() as c, c.transaction(isolation="repeatable_read", readonly=True):
        as_of = await c.fetchval("SELECT now()")
        return await targets_view(c, as_of, queue=True)


@router.get("/api/dashboard/monitor")
async def dashboard_monitor(request: Request):
    """관제 이상. 띠와 사이드바가 같은 조회를 쓴다. 읽기 조회라 역할 검사 없이 세션 미들웨어만 둔다."""
    async with request.app.state.pool.acquire() as c, c.transaction(isolation="repeatable_read", readonly=True):
        as_of = await c.fetchval("SELECT now()")
        return await monitor_view(c, as_of)
