"""복원 훈련 SQL (이슈 #45). drill.py 가 불러 쓴다. 표준 라이브러리만 쓴다.

훈련 DB 에 보내는 SQL 은 모두 drill_sql() 로 감싼다. 맨 앞에 cluster_name 확인 DO 블록이 붙고 psql 은 첫 오류에서 멈춘다.
  훈련 컨테이너는 -c cluster_name=opsloop-drill 로 뜬다. 운영 cluster_name 은 빈 값이다.
  그래서 호스트 · 컨테이너 이름을 잘못 적어 운영 DB 에 닿아도 첫 문장에서 멈추고 아무것도 바꾸지 않는다.
운영 DB 에 보내는 SQL 은 모두 prod_sql() 로 감싼다. 먼저 쓰기 문장이 없는지 보고(assert_read_only),
  맨 앞에 읽기 전용 확인 DO 블록이 붙는다. 접속은 opsloop_backup(pg_read_all_data · 쓰기 권한 없음)에
  default_transaction_read_only=on 을 건 세션이다(drill.py PROD_PSQL).
출력은 psql -qAt 한 열이다. 줄마다 '<꼬리표>|값|값…' 꼴로 만들어 drill.py 가 꼬리표로 읽는다.
"""
import re

DRILL_CLUSTER = "opsloop-drill"
# 시각 · 실수를 양쪽에서 같은 글자로 찍는다(지문 대조). SET 은 쓰기가 아니라 읽기 전용 세션에서도 된다
SESSION = ("SET TimeZone = 'UTC';\nSET DateStyle = 'ISO, YMD';\nSET IntervalStyle = 'postgres';\n"
           "SET extra_float_digits = 1;")
GUARD = ("DO $drill$ BEGIN IF current_setting('cluster_name') IS DISTINCT FROM '" + DRILL_CLUSTER + "' THEN "
         "RAISE EXCEPTION '훈련 DB 가 아니다 (cluster_name=%)', current_setting('cluster_name'); END IF; END $drill$;")
DRILL_HEAD = "\\set ON_ERROR_STOP on\n" + GUARD + "\n" + SESSION + "\n"
PROD_GUARD = ("DO $ro$ BEGIN IF current_setting('transaction_read_only') <> 'on' THEN "
              "RAISE EXCEPTION '운영 조회가 읽기 전용이 아니다'; END IF; "
              "IF current_setting('cluster_name') = '" + DRILL_CLUSTER + "' THEN "
              "RAISE EXCEPTION '운영 조회가 훈련 DB 로 갔다'; END IF; END $ro$;")
PROD_HEAD = "\\set ON_ERROR_STOP on\n" + PROD_GUARD + "\n" + SESSION + "\n"

IDENT = re.compile(r"^[a-z_][a-z0-9_]{0,62}$")
# 덤프의 26개 표 (infra/schema.sql · infra/notify.sql · 이슈 #47 block_exempt · 이슈 #51 test_ranges ·
# 이슈 #52 sensor_heartbeats). 복원 뒤 건수 대조는 덤프 목차의 표 이름으로 한다
TABLES = ("events", "sessions", "rule_versions", "incidents", "actions", "verdicts", "blocklist", "nodes",
          "console_users", "node_enrollments", "node_metrics", "detector_runs", "incident_absorbed",
          "absorbed_blocks", "notify_channels", "notify_deliveries", "cti_snapshots", "cti_kev", "cti_cve",
          "cti_osv", "cti_watch", "asset_inventory", "asset_vulnerabilities", "block_exempt", "test_ranges",
          "sensor_heartbeats")
# 계약의 구조 수치 (참고). 합격은 운영 카탈로그(사전 점검 때 읽음)와 같은지로 본다.
# 이슈 #47 뒤: 표 +1(block_exempt) · 트리거 +1(blocklist_guard) · 함수 +2(blocklist_guard · note_block_expired)
# 이슈 #51 뒤: 표 +1(test_ranges) · 트리거 +1(blocklist_enforcement_guard) · 함수 +2(is_test_source · blocklist_enforcement_guard).
#   FK · 뷰(rule_quality 는 교체) · 시퀀스(test_ranges 기본 키는 inet)는 그대로다
# 이슈 #52 뒤: 표 +1(sensor_heartbeats) · 트리거 +1 · 함수 +1(sensor_heartbeats_guard). FK · 뷰 · 시퀀스(기본 키는 text)는 그대로다
# 이슈 #59 뒤: 트리거 +2(console_users_stamp · trg_audit_console_users) · 함수 +3(console_users_stamp · console_account_set ·
#   audit_console_users). 표(console_users 에 열만 더한다) · FK · 뷰(audit_log 는 교체) · 시퀀스는 그대로다
EXPECT = {"tables": 26, "fk": 15, "triggers": 9, "functions": 15, "views": 3}
S3_SENSORS = ("cowrie", "decoy", "gateway")      # opsloop-ingest SENSORS. 나머지 센서는 관제 대상 로그(Loki · 관문 · 관리 원장)
DB_ONLY_SENSORS = ("audit", "console")           # DB 에만 있는 이벤트. 원장에서 다시 만들 수 없다


class SqlError(Exception):
    """운영에 보내려던 SQL 에 쓰기로 보이는 것이 있다."""


def drill_sql(body: str) -> str:
    return DRILL_HEAD + body.strip() + "\n"


# ── 읽기 전용 검사 ───────────────────────────────────────────────────────
_LITERALS = re.compile(r"'(?:[^']|'')*'|\$([A-Za-z_]*)\$.*?\$\1\$|--[^\n]*|/\*.*?\*/", re.S)
_WRITE = re.compile(
    r"\b(INSERT|UPDATE|DELETE|MERGE|TRUNCATE|DROP|ALTER|CREATE|GRANT|REVOKE|COPY|CALL|VACUUM|ANALYZE|REINDEX|"
    r"CLUSTER|LOCK|NOTIFY|LISTEN|UNLISTEN|REFRESH|SECURITY|COMMENT|IMPORT|DISCARD|PREPARE|EXECUTE|DO|BEGIN|"
    r"COMMIT|ROLLBACK|SAVEPOINT|RESET|SET|INTO|set_config|nextval|setval|pg_terminate_backend|pg_cancel_backend|"
    r"query_to_xml|pg_read_file|pg_read_binary_file|pg_ls_dir|dblink\w*|lo_\w+)\b", re.I)


def assert_read_only(body: str) -> None:
    """문장마다 SELECT · WITH 로 시작하고 쓰기 · 잠금 · 세션 바꾸기 낱말이 없어야 한다. 아니면 SqlError."""
    bare = _LITERALS.sub(" ", body)
    if "\\" in bare:
        raise SqlError("운영 SQL 에 psql 명령(\\)이 있다")
    for stmt in bare.split(";"):
        s = stmt.strip()
        if not s:
            continue
        if not re.match(r"^(SELECT|WITH)\b", s, re.I):
            raise SqlError("운영 SQL 은 SELECT · WITH 만 쓴다: %s" % s[:60])
        m = _WRITE.search(s)
        if m:
            raise SqlError("운영 SQL 에 '%s' 가 있다: %s" % (m.group(1), s[:60]))


def prod_sql(body: str) -> str:
    assert_read_only(body)
    return PROD_HEAD + body.strip() + "\n"


def lit(text) -> str:
    """문자열 상수. 작은따옴표를 겹친다."""
    return "'" + str(text).replace("'", "''") + "'"


def ts_lit(iso_or_placeholder) -> str:
    """시각 상수. drill.py 가 만든 ISO 문자열이거나 드라이런 자리표시(<T_b> 등)다."""
    return lit(iso_or_placeholder) + "::timestamptz"


def _ident(name: str) -> str:
    if not IDENT.match(name or ""):
        raise SqlError("이름이 이상하다: %r" % (name,))
    return name


# ── 건수 · 카탈로그 · 기준값 ─────────────────────────────────────────────
def q_counts(tables) -> str:
    parts = ["SELECT 'n|%s|' || (SELECT count(*) FROM %s)" % (_ident(t), _ident(t)) for t in tables]
    return "-- q:counts\n" + "\nUNION ALL ".join(parts) + ";"


Q_CATALOG = """-- q:catalog
SELECT 'c|tables|' || count(*) FROM pg_tables WHERE schemaname = 'public';
SELECT 'c|fk|' || count(*) FROM pg_constraint WHERE contype = 'f' AND connamespace = 'public'::regnamespace;
SELECT 'c|triggers|' || coalesce(string_agg(tgname || '=' || tgenabled::text, ',' ORDER BY tgname), '')
  FROM pg_trigger WHERE NOT tgisinternal;
SELECT 'c|functions|' || coalesce(string_agg(proname, ',' ORDER BY proname), '')
  FROM pg_proc WHERE pronamespace = 'public'::regnamespace;
SELECT 'c|views|' || coalesce(string_agg(viewname, ',' ORDER BY viewname), '') FROM pg_views WHERE schemaname = 'public';
SELECT 'c|sequences|' || count(*) FROM pg_class WHERE relkind = 'S' AND relnamespace = 'public'::regnamespace;
SELECT 'c|extensions|' || coalesce(string_agg(extname, ',' ORDER BY extname), '') FROM pg_extension;"""

# 운영에서도 0 이 아닌 값. 0 을 요구하지 않고 운영값과 대조한다
Q_BASELINE = """-- q:baseline
SELECT 'b|judged_not_resolved|' || count(*) FROM incidents i
  WHERE EXISTS (SELECT 1 FROM verdicts v WHERE v.incident_key = i.incident_key) AND i.status <> 'resolved';
SELECT 'b|verdict_operator_missing|' || count(*) FROM verdicts v
  WHERE v.operator IS NOT NULL AND NOT EXISTS (SELECT 1 FROM console_users u WHERE u.username = v.operator);
SELECT 'b|released_blocks|' || count(*) FROM blocklist WHERE released_at IS NOT NULL;
SELECT 'b|released_audit|' || count(*) FROM events WHERE sensor = 'audit' AND eventid = 'console.block.released';"""

# 운영 상태 (사전 점검 · 정리 뒤 확인). 알림 채널은 url 을 찍지 않고 지문만 낸다
Q_PROD_STATE = """-- q:prod_state
SELECT 'p|cluster_name|' || current_setting('cluster_name');
SELECT 'p|read_only|' || current_setting('transaction_read_only');
SELECT 'p|server_version|' || current_setting('server_version');
SELECT 'p|now|' || now();
SELECT 'p|verdicts_max|' || coalesce(max(created_at)::text, '-') FROM verdicts;
SELECT 'p|events_max|' || coalesce(max(ts)::text, '-') || '|' || count(*) FROM events;
SELECT 'p|runs_max|' || coalesce(max(started_at)::text, '-') FROM detector_runs;
SELECT 'p|channels|' || count(*) FILTER (WHERE enabled) || '|' || count(*) FROM notify_channels;
SELECT 'p|channels_sig|' || md5(coalesce(string_agg(ROW(id, enabled, md5(url))::text, ',' ORDER BY id), ''))
  FROM notify_channels;
SELECT 'p|fixture|' || count(*) FROM events WHERE provenance <> 'real';"""

Q_T0 = "-- q:t0\nSELECT 'p|now|' || now();"

# 복원 직후 훈련 DB 의 끝 시각. 재적재 · 판정 전에 떠 둔다 (T_b 하한 확인 · 판정 손실 계산)
Q_RESTORED = """-- q:restored
SELECT 'r|runs_max|' || coalesce(max(started_at)::text, '-') FROM detector_runs;
SELECT 'r|verdicts_max|' || coalesce(max(created_at)::text, '-') FROM verdicts;
SELECT 'r|verdicts_max_id|' || coalesce(max(id), 0) FROM verdicts;"""

# ── 무결성: 훈련 DB 에서 0 이어야 하는 것 ──────────────────────────────
ZERO = (
    ("verdict_orphan", "판정 → 사건 고아",
     "SELECT count(*) FROM verdicts v WHERE NOT EXISTS (SELECT 1 FROM incidents i WHERE i.incident_key = v.incident_key)"),
    ("action_orphan", "조치 → 사건 고아",
     "SELECT count(*) FROM actions a WHERE NOT EXISTS (SELECT 1 FROM incidents i WHERE i.incident_key = a.incident_key)"),
    ("block_orphan", "차단 → 사건 고아 (FK 없음)",
     "SELECT count(*) FROM blocklist b WHERE b.incident_key IS NOT NULL"
     " AND NOT EXISTS (SELECT 1 FROM incidents i WHERE i.incident_key = b.incident_key)"),
    ("incident_rule_version", "사건의 규칙 판 없음",
     "SELECT count(*) FROM incidents i WHERE NOT EXISTS (SELECT 1 FROM rule_versions r WHERE r.rule_version = i.rule_version)"),
    ("run_rule_version", "탐지 실행의 규칙 판 없음",
     "SELECT count(*) FROM detector_runs d"
     " WHERE NOT EXISTS (SELECT 1 FROM rule_versions r WHERE r.rule_version = d.rule_version)"),
    ("absorbed_links", "흡수 기록 (첫 사건 없음 · 흡수된 사건이 남음 · 경유 없음)",
     "SELECT count(*) FROM incident_absorbed a"
     " WHERE NOT EXISTS (SELECT 1 FROM incidents i WHERE i.incident_key = a.first_key)"
     " OR EXISTS (SELECT 1 FROM incidents i WHERE i.incident_key = a.member_key)"
     " OR (a.via_key IS NOT NULL AND NOT EXISTS (SELECT 1 FROM incident_absorbed b WHERE b.member_key = a.via_key)"
     " AND NOT EXISTS (SELECT 1 FROM incidents i WHERE i.incident_key = a.via_key))"),
    ("absorbed_rule_version", "흡수 기록의 규칙 판 없음",
     "SELECT count(*) FROM incident_absorbed a"
     " WHERE NOT EXISTS (SELECT 1 FROM rule_versions r WHERE r.rule_version = a.rule_version)"),
    ("absorbed_block_orphan", "흡수 차단 → 첫 사건 없음",
     "SELECT count(*) FROM absorbed_blocks ab WHERE NOT EXISTS (SELECT 1 FROM incidents i WHERE i.incident_key = ab.first_key)"),
    ("notify_subject", "알림 대상 사건 · 노드 없음",
     "SELECT count(*) FROM notify_deliveries d"
     " WHERE (d.event IN ('incident.created', 'pending.overdue')"
     " AND NOT EXISTS (SELECT 1 FROM incidents i WHERE i.incident_key = d.subject_key))"
     " OR (d.event = 'node.silent'"
     " AND NOT EXISTS (SELECT 1 FROM nodes n WHERE 'node:' || n.node_id = split_part(d.subject_key, '@', 1)))"),
    ("notify_channel_orphan", "알림 → 채널 고아",
     "SELECT count(*) FROM notify_deliveries d WHERE NOT EXISTS (SELECT 1 FROM notify_channels c WHERE c.id = d.channel_id)"),
    ("block_action_without_row", "block_ip 조치인데 차단 행 없음",
     "SELECT count(*) FROM actions a JOIN incidents i USING (incident_key)"
     " WHERE a.action = 'block_ip' AND i.actor_ip IS NOT NULL"
     " AND NOT EXISTS (SELECT 1 FROM blocklist b WHERE b.actor_ip = i.actor_ip)"),
    ("revoked_not_applied", "폐기 기록 뒤 폐기되지 않은 노드",
     "SELECT count(*) FROM nodes n CROSS JOIN LATERAL (SELECT eventid FROM events e"
     " WHERE e.sensor = 'collector' AND e.eventid LIKE 'collector.admin.%'"
     " AND split_part(e.input, ' ', 1) = 'node_id=' || n.node_id ORDER BY e.ts DESC LIMIT 1) l"
     " WHERE l.eventid = 'collector.admin.revoke' AND n.status <> 'revoked'"),
    ("enrollment_orphan", "등록 토큰 → 노드 고아",
     "SELECT count(*) FROM node_enrollments e WHERE NOT EXISTS (SELECT 1 FROM nodes n WHERE n.node_id = e.node_id)"),
    ("cti_kev", "KEV 스냅숏 종류 불일치",
     "SELECT count(*) FROM cti_kev k JOIN cti_snapshots s ON s.id = k.snapshot_id WHERE s.source <> 'kev' OR s.status <> 'ok'"),
    ("cti_osv", "OSV 스냅숏 종류 불일치",
     "SELECT count(*) FROM cti_osv o JOIN cti_snapshots s ON s.id = o.snapshot_id WHERE s.source <> 'osv' OR s.status <> 'ok'"),
    ("cti_cve", "EPSS · NVD 스냅숏 종류 불일치",
     "SELECT count(*) FROM cti_cve c LEFT JOIN cti_snapshots e ON e.id = c.epss_snapshot_id"
     " LEFT JOIN cti_snapshots n ON n.id = c.nvd_snapshot_id"
     " WHERE (c.epss_snapshot_id IS NOT NULL AND (e.source <> 'epss' OR e.status <> 'ok'))"
     " OR (c.nvd_snapshot_id IS NOT NULL AND (n.source <> 'nvd' OR n.status <> 'ok'))"),
    ("asset_snapshot", "자산 스냅숏 종류 불일치",
     "SELECT count(*) FROM asset_inventory a LEFT JOIN cti_snapshots s ON s.id = a.snapshot_id"
     " WHERE a.snapshot_id IS NOT NULL AND (s.source <> 'assets' OR s.status <> 'ok')"),
    ("fk_unvalidated", "검증 안 된 FK",
     "SELECT count(*) FROM pg_constraint WHERE contype = 'f' AND NOT convalidated"),
    ("triggers_disabled", "꺼진 트리거",
     "SELECT count(*) FROM pg_trigger WHERE NOT tgisinternal AND tgenabled <> 'O'"),
)


def q_zero() -> str:
    return "-- q:zero\n" + "\n".join("SELECT 'z|%s|' || (%s);" % (name, sql) for name, _desc, sql in ZERO)


# 시퀀스 마지막 값 ≥ 그 열의 최댓값 (훈련 DB 에서만. query_to_xml 로 표마다 max 를 구한다)
Q_SEQUENCES = """-- q:sequences
WITH owned AS (
  SELECT c.oid::regclass::text AS seq, t.oid::regclass::text AS tbl, a.attname AS col
  FROM pg_class c
  JOIN pg_depend d ON d.objid = c.oid AND d.classid = 'pg_class'::regclass
   AND d.refclassid = 'pg_class'::regclass AND d.deptype IN ('a', 'i')
  JOIN pg_class t ON t.oid = d.refobjid
  JOIN pg_attribute a ON a.attrelid = t.oid AND a.attnum = d.refobjsubid
  WHERE c.relkind = 'S' AND c.relnamespace = 'public'::regnamespace
), v AS (
  SELECT seq, pg_sequence_last_value(seq::regclass) AS last,
         (xpath('/row/m/text()', query_to_xml(format('SELECT max(%I) AS m FROM %s', col, tbl), false, true, '')))[1]::text AS mx
  FROM owned
)
SELECT 'q|' || seq || '|' || coalesce(last::text, '-') || '|' || coalesce(mx, '-') FROM v ORDER BY seq;"""

# 역할 속성 · 멤버십 (훈련 DB 에서만. pg_authid 는 슈퍼유저만 읽는다. 비밀번호는 있는지만 본다)
Q_ROLES_STATE = """-- q:roles_state
SELECT 'a|' || rolname || '|' || rolcanlogin::text || '|' || rolinherit::text || '|' || rolconnlimit || '|'
  || rolsuper::text || '|' || (rolpassword IS NOT NULL)::text
  FROM pg_authid WHERE rolname LIKE 'opsloop%' ORDER BY rolname;
SELECT 'g|' || r.rolname || '|' || m.rolname || '|' || am.inherit_option::text
  FROM pg_auth_members am JOIN pg_roles r ON r.oid = am.roleid JOIN pg_roles m ON m.oid = am.member
  WHERE m.rolname LIKE 'opsloop%' ORDER BY r.rolname, m.rolname;"""

Q_NOTIFY_OFF = """-- q:notify_off
UPDATE notify_channels SET enabled = false, url = 'https://notify.invalid/';
SELECT 'o|' || count(*) FILTER (WHERE enabled) || '|' || count(*) FILTER (WHERE url <> 'https://notify.invalid/')
  || '|' || count(*) FROM notify_channels;"""

Q_NOTIFY_STATE = """-- q:notify_state
SELECT 'o|' || count(*) FILTER (WHERE enabled) || '|' || count(*) FILTER (WHERE url <> 'https://notify.invalid/')
  || '|' || count(*) FROM notify_channels;"""

Q_CONSOLE_BASE = """-- q:console_base
SELECT 'v|' || count(*) || '|' || coalesce(max(id), 0) FROM verdicts;
SELECT 'u|' || incident_key || '|' || rule_id || '|' || severity FROM unjudged_incidents
  ORDER BY first_ts DESC LIMIT 3;"""


def q_console_after(base_id) -> str:
    return ("-- q:console_after\nSELECT 'w|' || v.id || '|' || v.incident_key || '|' || v.verdict || '|' || "
            "coalesce(v.operator, '-') || '|' || i.status FROM verdicts v JOIN incidents i USING (incident_key) "
            "WHERE v.id > %d ORDER BY v.id;" % int(base_id))


# ── 지문: 사람이 남긴 기록 (행마다 열쇠 · md5 · 시각) ──────────────────────
# (이름, 열쇠, 행 식, 시각 식, 표, 조건). 바뀌는 열(last_seen_at · receipt · last_login_at)은 뺀다.
# 비밀 열은 md5 로만 넣는다. 알림 채널 url 은 넣지 않는다(흐름 주소가 곧 비밀이다).
# 시각 식은 그 행이 마지막으로 생기거나 바뀐 때다. 운영에만 있는 행 · 바뀐 행을 T_f 앞뒤로 나눈다(RPO 손실)
FINGERPRINTS = (
    ("verdicts", "id::text",
     "ROW(id, incident_key, verdict, reason, observed_value, operator, proposed, created_at, decision_seconds)",
     "created_at", "verdicts", ""),
    ("actions", "id::text", "ROW(id, incident_key, action, operator, note, created_at)", "created_at", "actions", ""),
    ("blocklist", "actor_ip::text",
     "ROW(actor_ip, reason, incident_key, created_at, expires_at, released_at, released_by, requested_by, method,"
     " enforced_at, enforce_note)", "greatest(created_at, released_at, enforced_at)", "blocklist", ""),
    ("absorbed_blocks", "first_key",
     "ROW(first_key, expires_at, requested_by, created_at, released_at, released_by)",
     "greatest(created_at, released_at)", "absorbed_blocks", ""),
    ("nodes", "node_id", "ROW(node_id, hostname, role, sensor, status, addr, logs, registered_at, md5(token_hash))",
     "registered_at", "nodes", ""),
    ("node_enrollments", "id::text",
     "ROW(id, node_id, md5(token_hash), issued_by, issued_at, expires_at, used_at, used_from, canceled_at)",
     "greatest(issued_at, used_at, canceled_at)", "node_enrollments", ""),
    # 역할 · 활성 · 비밀번호가 바뀌면 updated_at 이 찍힌다(이슈 #59 도장 트리거). 로그인 시각은 뺀다
    ("console_users", "username", "ROW(username, role, created_at, disabled_at, md5(password_hash))",
     "greatest(created_at, updated_at)", "console_users", ""),
    ("notify_channels", "id::text",
     "ROW(id, name, kind, grade, events, min_severity, batch_seconds, template_header, template_item, enabled,"
     " created_by, created_at, updated_by, updated_at, enabled_at)", "greatest(created_at, updated_at, enabled_at)",
     "notify_channels", ""),
    ("notify_deliveries", "id::text", "ROW(id, channel_id, event, subject_key, status, attempts, created_at, sent_at)",
     "greatest(created_at, claimed_at, sent_at)", "notify_deliveries", ""),
    ("audit", "line_hash", "ROW(line_hash, ts, sensor, eventid, input, provenance)", "ts", "events",
     "WHERE sensor IN ('audit', 'console')"),
)
IMMUTABLE = ("verdicts", "actions", "audit")      # 추가만 되는 기록. 바뀐 행 · 사라진 행이 있으면 불합격


def q_fingerprint() -> str:
    lines = ["-- q:fingerprint"]
    for name, key, row, ts, table, where in FINGERPRINTS:
        lines.append(("SELECT 'f|%s|' || replace(%s, '|', '/') || '|' || md5(%s::text) || '|' || coalesce((%s)::text, '-')"
                      " FROM %s %s" % (name, key, row, ts, table, where)).rstrip() + ";")
    return "\n".join(lines)


def q_loss(tb, tf, runs_max) -> str:
    """운영(읽기 전용) 참고값. 로그인 시각(지문에서 뺀 열) · T_f 까지 마지막 판정 · 복원 DB 다음 탐지 실행."""
    TF = ts_lit(tf)
    return "\n".join((
        "-- q:loss",
        "SELECT 'l|console_logins|' || count(*) FILTER (WHERE last_login_at <= %s) || '|' || "
        "count(*) FILTER (WHERE last_login_at > %s) FROM console_users WHERE last_login_at > %s;"
        % (TF, TF, ts_lit(tb)),
        "SELECT 'm|verdicts_max_tf|' || coalesce(max(created_at)::text, '-') FROM verdicts WHERE created_at <= %s;" % TF,
        "SELECT 'm|runs_next|' || coalesce(min(started_at)::text, '-') FROM detector_runs WHERE started_at > %s;"
        % ts_lit(runs_max),
    ))


# ── 재생성 대조 (양쪽 같은 문장) ────────────────────────────────────────
def q_regen(lo, cut) -> str:
    LO, CUT = ts_lit(lo), ts_lit(cut)
    skip = ", ".join(lit(s) for s in DB_ONLY_SENSORS)
    return "\n".join((
        "-- q:regen",
        "SELECT 'e|' || sensor || '|' || count(*) || '|' || md5(coalesce(string_agg(line_hash, ',' ORDER BY line_hash), ''))"
        " FROM events WHERE provenance = 'real' AND sensor NOT IN (%s) AND ts >= %s AND ts < %s"
        " GROUP BY sensor ORDER BY sensor;" % (skip, LO, CUT),
        "SELECT 's|' || count(*) || '|' || md5(coalesce(string_agg(ROW(session, src_ip, protocol, sensor, first_ts, last_ts,"
        " duration_ms, login_attempts, login_success, command_count, downloads, provenance)::text, ',' ORDER BY session), ''))"
        " FROM sessions WHERE provenance = 'real' AND first_ts >= %s AND last_ts < %s;" % (LO, CUT),
        "SELECT 'm|' || node_id || '|' || count(*) || '|' || md5(coalesce(string_agg(line_hash, ',' ORDER BY line_hash), ''))"
        " FROM node_metrics WHERE ts >= %s AND ts < %s GROUP BY node_id ORDER BY node_id;" % (LO, CUT),
        "SELECT 'i|' || count(*) || '|' || md5(coalesce(string_agg(incident_key, ',' ORDER BY incident_key), ''))"
        " FROM incidents WHERE first_ts >= %s AND first_ts < %s;" % (LO, CUT),
        "SELECT 'x|fixture|' || count(*) FROM events WHERE provenance <> 'real' AND ts >= %s AND ts < %s;" % (LO, CUT),
    ))


def q_hashes(sensor, lo, cut) -> str:
    """대조가 어긋난 센서의 줄 해시와 시각 (차이 줄 찾기)."""
    if not re.match(r"^[A-Za-z0-9_.-]{1,64}$", sensor or ""):
        raise SqlError("센서 이름이 이상하다: %r" % (sensor,))
    return ("-- q:hashes\nSELECT 'h|' || line_hash || '|' || ts FROM events WHERE provenance = 'real' AND sensor = %s"
            " AND ts >= %s AND ts < %s ORDER BY line_hash;" % (lit(sensor), ts_lit(lo), ts_lit(cut)))


# ── 역할별 허용 · 거부 (verify-db-roles.sh 의 문장을 그대로 쓴다) ──────────
def q_role_checks(role, checks) -> str:
    """한 역할로 붙어 문장마다 BEGIN … ROLLBACK 하고 SQLSTATE 를 찍는다. 확인 블록 뒤에는 오류에서 멈추지 않는다.
    p(권한 식)는 소유자로 붙어 t · f 를 찍는다."""
    out = ["\\set ON_ERROR_STOP off", "-- q:role_checks %s" % _ident(role)]
    for c in checks:
        if c["kind"] == "p":
            out.append("SELECT 'P %d ' || CASE WHEN (%s) THEN 't' ELSE 'f' END;" % (c["idx"], c["stmt"]))
        else:
            out += ["BEGIN;", c["stmt"].rstrip().rstrip(";") + ";", "\\echo R %d :SQLSTATE" % c["idx"], "ROLLBACK;"]
    return "\n".join(out)
