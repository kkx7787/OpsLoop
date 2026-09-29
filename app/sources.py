"""출발지 분석 (이슈 #58). GET /api/sources · /api/sources/detail · /api/sources/fingerprints

행위자는 곧 출발지 주소(incidents.actor_ip)다. 사건을 출발지 단위로 모아 "누가 얼마나 오래 무엇을 노렸고 지금 막혀 있는가" 를
답하고, 같은 도구 지문(HASSH · SSH 클라이언트 버전 · 디코이 User-Agent)을 쓴 출발지를 묶어 본다. 표 · 권한은 바꾸지 않는다.

  - 읽기: 반복 읽기 · 읽기 전용 트랜잭션 하나에 문장 시간 상한 5초. 풀(최대 10)을 무거운 질의가 오래 붙잡지 않게 한다
  - 목록 대상은 사건이 있는 출발지다. 주소 없는 사건(target 만: user:… · node:…)과 흡수로 사건이 지워진 출발지는 빠진다
  - 최고 심각도는 글자 max 가 아니라 순위(critical 0 · high 1 · medium 2 · low 3)로 고른다. 판정은 사건마다 마지막 것 하나다
  - 이벤트는 실제(provenance='real') 이벤트만 센다. events 전체를 출발지로 묶지 않고 쪽에 나온 주소만 따로 묻는다
    (출발지 색인 idx_events_src_ip). 관문 로그로 이벤트가 크게 늘어도 목록 비용이 쪽 크기에 묶인다
  - 감사 기록(sensor='audit')은 어디서도 읽지 않는다. 그 src_ip 는 공격 출발지가 아니라 우리 DB 접속 주소이고, 종류별 수는
    관리자 전용(/api/audit · 보고서 ops 구역)이다. 콘솔 기록(sensor='console')은 사건 있는 주소에만 싣는다(콘솔 무차별 대입의
    근거). 사건 없는 주소는 콘솔 로그인만으로는 출발지가 아니다(404). 우리 사용자의 접속 주소 · 시각이 모든 역할에 드러나지 않게
  - 마지막 사건(last_ts, 사건 기준 · 정렬 기준)과 마지막 관측(last_seen, 이 주소 실제 이벤트의 마지막 시각)은 다르다.
    차단 뒤에도 관문을 두드리면 관측만 늘어난다
  - 지문은 전용 열이 없어 이벤트에서 꺼낸다(FINGERPRINTS, 운영 DB 에서 확인한 문구). 흔한 라이브러리끼리 겹치므로 같은 지문이
    같은 행위자라는 뜻은 아니다. UA · SSH 버전은 공격자가 넣은 글자라 512자로 자르기만 하고 화면이 비신뢰 글자로 그린다
  - 표 · 권한이 없으면(마이그레이션 전 · 역할 블록만 다시 적용한 DB) 그 값은 null 이다. 화면이 '확인 불가' 로 그린다
  - 차단 행은 사건 상세(main.get_incident 의 blocked)와 같은 모양이다. 감사 기록 기반 차단 이력은 싣지 않는다(/api/audit 는
    관리자 전용이라 모든 역할에 보이면 노출 범위가 바뀐다). 조치 이력은 이 주소 사건의 block_ip · unblock_ip 뿐이다
"""
import ipaddress
from typing import Literal, Optional

from fastapi import APIRouter, HTTPException, Query, Request

import cti
import targets
from absorbed import block_nets, exempt_of, has_exempt_table

router = APIRouter()

STATEMENT_TIMEOUT = "SET LOCAL statement_timeout = '5s'"
PAGE_MAX = 100              # 목록 · 지문 한 쪽 상한
DETAIL_INCIDENTS = 200      # 상세 사건 흐름(첫 시각 순). 수(incidents_total)는 전체를 센다
DETAIL_KINDS = 50           # 상세 이벤트 종류
DETAIL_FINGERPRINTS = 10    # 상세 지문 종류마다
DETAIL_ACTIONS = 50         # 상세 조치 이력(최근 순)
UNTRUSTED_MAX = 512         # 비신뢰 글자(UA · SSH 버전) 자르는 길이. 적재기가 UA 를 자르는 길이와 같다

SEVERITIES = ("critical", "high", "medium", "low")   # 순위 순. main.py 목록 정렬의 CASE 와 같다
SEVERITY_RANK = "CASE i.severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END"
VERDICTS = ("threat", "non_actionable", "false_positive", "benign_positive", "undetermined")
BLOCK_ACTIONS = ["block_ip", "unblock_ip"]
CHECKER_POINTS = ("gateway", "fw")                   # 집행기 확인 신호 block:<지점>
SORTS = Literal["recent", "incidents", "severity"]
FP_KINDS = Literal["hassh", "ssh_version", "user_agent"]

# 지문 종류 → (고르는 조건, 값). 빈 글자는 지문이 아니다(nullif). 묶을 때와 거를 때 같은 식을 쓰므로 잘린 값으로도 목록이 걸린다
#   hassh       Cowrie 'SSH client hassh fingerprint: <32자 16진>' (eventid 색인)
#   ssh_version Cowrie 'Remote SSH version: <문자열>' (eventid 색인)
#   user_agent  웹 디코이 요청의 UA 열((sensor, ts) 색인). 콘솔 로그인 UA 는 우리 쪽 사용자라 넣지 않는다
FINGERPRINTS = {
    "hassh": ("eventid = 'cowrie.client.kex'", "substring(message from 'fingerprint: ([0-9a-f]{32})')"),
    "ssh_version": ("eventid = 'cowrie.client.version'",
                    f"nullif(left(substring(message from '^Remote SSH version: (.*)$'), {UNTRUSTED_MAX}), '')"),
    "user_agent": ("sensor = 'decoy' AND user_agent IS NOT NULL", f"nullif(left(user_agent, {UNTRUSTED_MAX}), '')"),
}


# 이 화면이 읽는 이벤트: 실제 이벤트이고 감사 기록이 아니다. 감사 행의 src_ip 는 audit_event() 가 넣는 DB 접속 주소
#   (inet_client_addr())라 출발지가 아니다. 사건 없는 주소에서는 콘솔 기록(로그인 · 로그아웃, 우리 사용자의 접속)도 뺀다
REAL_EVENTS = "provenance = 'real' AND sensor <> 'audit'"
NO_INCIDENT_EVENTS = f"{REAL_EVENTS} AND sensor <> 'console'"


def fp_events(kind: str) -> str:
    """지문 이벤트(src_ip · ts · value). 실제 이벤트만이고 감사 기록은 뺀다."""
    where, value = FINGERPRINTS[kind]
    return f"SELECT src_ip, ts, {value} AS value FROM events WHERE {where} AND {REAL_EVENTS}"


# 출발지별 집계. 판정은 사건마다 마지막 것(operations.py 규칙 품질과 같은 고름), 시험 대역은 is_test_source(이슈 #51).
#   목록 · 상세 요약이 뒤에 SELECT … FROM s 를 붙여 쓴다
SOURCES_SQL = f"""
    WITH latest AS (
        SELECT DISTINCT ON (incident_key) incident_key, verdict FROM verdicts
        ORDER BY incident_key, created_at DESC, id DESC),
    src AS (
        SELECT i.actor_ip, count(*) AS incidents, count(*) FILTER (WHERE v.verdict IS NULL) AS unjudged,
               min({SEVERITY_RANK}) AS rank, array_agg(DISTINCT i.rule_id ORDER BY i.rule_id) AS rules,
               min(i.first_ts) AS first_ts, max(i.last_ts) AS last_ts,
               {", ".join(f"count(*) FILTER (WHERE v.verdict = '{x}') AS {x}" for x in VERDICTS)}
        FROM incidents i LEFT JOIN latest v USING (incident_key)
        WHERE i.actor_ip IS NOT NULL
        GROUP BY i.actor_ip),
    s AS (SELECT host(actor_ip) AS ip, *, is_test_source(actor_ip) AS test_source FROM src)"""

# 정렬. 같은 값이면 주소 순이라 쪽 사이 순서가 바뀌지 않는다
ORDERS = {"recent": "s.last_ts DESC, s.actor_ip",
          "incidents": "s.incidents DESC, s.actor_ip",
          "severity": "s.rank, s.last_ts DESC, s.actor_ip"}

# 쪽에 나온 주소들의 이벤트 발생원(노린 대상)과 마지막 관측. 사건 있는 주소라 콘솔 기록은 넣는다. $1 주소들
SENSORS_SQL = f"""
    SELECT host(src_ip) AS ip, array_agg(DISTINCT sensor ORDER BY sensor) AS sensors, max(ts) AS last_seen
    FROM events WHERE src_ip = ANY($1::text[]::inet[]) AND {REAL_EVENTS}
    GROUP BY src_ip"""

# 차단 행. 사건 상세(main.get_incident 의 blocked)와 같은 열이다. $1 주소들
BLOCKS_SQL = """
    SELECT host(actor_ip) AS ip, reason, method, created_at, expires_at, released_at, enforced_at, enforce_note,
           requested_by, enforcement
    FROM blocklist WHERE actor_ip = ANY($1::text[]::inet[])"""

# 사건 없는 주소가 출발지인가(이벤트가 있는가)와 그 마지막 관측. 콘솔 · 감사 기록만 있으면 없는 출발지다(404). $1 주소
HAS_EVENTS_SQL = f"SELECT EXISTS (SELECT 1 FROM events WHERE src_ip = $1::inet AND {NO_INCIDENT_EVENTS})"
LAST_SEEN_SQL = f"SELECT max(ts) FROM events WHERE src_ip = $1::inet AND {NO_INCIDENT_EVENTS}"

# 상세 사건 흐름. $1 주소 · $2 행 수
DETAIL_INCIDENTS_SQL = """
    WITH latest AS (
        SELECT DISTINCT ON (v.incident_key) v.incident_key, v.verdict
        FROM verdicts v JOIN incidents i ON i.incident_key = v.incident_key
        WHERE i.actor_ip = $1::inet
        ORDER BY v.incident_key, v.created_at DESC, v.id DESC)
    SELECT i.incident_key, i.rule_id, i.rule_version, i.rule_name, i.severity, i.status, i.first_ts, i.last_ts, i.target, l.verdict
    FROM incidents i LEFT JOIN latest l USING (incident_key)
    WHERE i.actor_ip = $1::inet
    ORDER BY i.first_ts, i.incident_key LIMIT $2"""

# 상세 이벤트 종류. 콘솔 기록은 사건 있는 주소만 싣는다. $1 주소 · $2 행 수 · $3 사건이 있는가
EVENT_KINDS_SQL = f"""
    SELECT sensor, eventid, count(*) AS count, min(ts) AS first_ts, max(ts) AS last_ts
    FROM events WHERE src_ip = $1::inet AND {REAL_EVENTS} AND ($3::boolean OR sensor <> 'console')
    GROUP BY sensor, eventid ORDER BY count DESC, sensor, eventid LIMIT $2"""

# 상세 조치 이력: 이 주소 사건의 차단 · 해제. 흡수 차단은 첫 사건(다른 주소)에 남으므로 여기 없다. $1 주소 · $2 조치 · $3 행 수
ACTIONS_SQL = """
    SELECT a.incident_key, a.action, a.operator, a.note, a.created_at
    FROM actions a JOIN incidents i ON i.incident_key = a.incident_key
    WHERE i.actor_ip = $1::inet AND a.action = ANY($2::text[])
    ORDER BY a.created_at DESC, a.id DESC LIMIT $3"""

ABSORBED_SQL = "SELECT count(*) FROM incident_absorbed WHERE actor_ip = $1::inet"


def fp_counts_sql(kind: str) -> str:
    """상세 지문: 이 주소가 쓴 값과 이벤트 수. $1 주소 · $2 행 수"""
    return f"""
    SELECT f.value, count(*) AS count FROM ({fp_events(kind)}) f
    WHERE f.src_ip = $1::inet AND f.value IS NOT NULL
    GROUP BY f.value ORDER BY count DESC, f.value LIMIT $2"""


def fp_groups_sql(kind: str) -> str:
    """지문 묶음. 사건 있는 출발지는 incidents.actor_ip 에 있는 주소다. 뒤에 SELECT … FROM g 를 붙여 쓴다"""
    return f"""
    WITH f AS ({fp_events(kind)}),
    g AS (
        SELECT f.value, count(DISTINCT f.src_ip) AS sources, count(*) AS connections,
               count(DISTINCT a.actor_ip) AS incident_sources, min(f.ts) AS first_ts, max(f.ts) AS last_ts
        FROM f LEFT JOIN (SELECT DISTINCT actor_ip FROM incidents WHERE actor_ip IS NOT NULL) a ON a.actor_ip = f.src_ip
        WHERE f.value IS NOT NULL
        GROUP BY f.value)"""


# ----------------------------------------------------------------------
#  순수 함수 (DB 없이 시험한다)
# ----------------------------------------------------------------------

def parse_ip(value: str, name: str = "ip") -> str:
    """주소 인자 → 정규화한 주소. 주소가 아니면 DB 에 닿기 전에 422 다(::inet 캐스팅 오류가 500 이 되지 않게).
    IPv6 영역 표기(fe80::1%eth0)는 파이썬은 받지만 PostgreSQL inet 이 받지 않아 함께 거른다."""
    try:
        ip = ipaddress.ip_address(value.strip())
    except ValueError:
        ip = None
    if ip is None or getattr(ip, "scope_id", None):
        raise HTTPException(422, f"{name} 는 IP 주소여야 합니다")
    return str(ip)


def targets_of(sensors, nodes=None) -> list[str]:
    """이벤트 발생원들 → 노린 대상 id(상태판 카드 순서: 고정 대상 뒤 등록 노드). 모르는 발생원은 버린다(targets.attach).
    nodes 는 등록 노드 {발생원: 노드 id}(targets.node_sources)다."""
    hit = {target for target, _ in targets.attach(sensors or [], nodes)}
    return [tid for tid, _, _ in targets.TARGETS if tid in hit] + [tid for tid in (nodes or {}).values() if tid in hit]


def block_of(row) -> dict | None:
    """차단 행 → 사건 상세 blocked 와 같은 모양. 시각은 UTC ISO, 지점별 결과(enforcement)는 객체로 푼다."""
    if row is None:
        return None
    return {"reason": row["reason"], "method": row["method"], "created_at": cti.iso(row["created_at"]),
            "expires_at": cti.iso(row["expires_at"]), "released_at": cti.iso(row["released_at"]),
            "enforced_at": cti.iso(row["enforced_at"]), "enforce_note": row["enforce_note"],
            "requested_by": row["requested_by"], "enforcement": cti.loads(row["enforcement"])}


def exempt_flag(in_nets: bool, readable: bool) -> bool | None:
    """차단 제외 대역에 드는가. 코드 상수(NO_BLOCK_NETS)나 block_exempt 대역에 들면 참이다. 들지 않을 때는 block_exempt 를
    읽을 수 있어야 거짓이고, 읽을 수 없으면 모른다(null). 표에만 있는 대역을 놓친 '거짓' 을 내지 않는다."""
    if in_nets:
        return True
    return False if readable else None


def source_item(row, seen, block, in_nets: bool, exempt_readable: bool, nodes=None) -> dict:
    """출발지 집계 한 행(SOURCES_SQL 의 s) → 목록 항목. seen 은 SENSORS_SQL 한 행(발생원 · 마지막 관측)이고 실제 이벤트가
    없으면 None 이다(노린 대상은 빈 목록, 마지막 관측은 null). nodes 는 등록 노드 {발생원: 노드 id} 다."""
    return {"ip": row["ip"], "incidents": row["incidents"], "unjudged": row["unjudged"],
            "severity": SEVERITIES[row["rank"]], "rules": list(row["rules"]),
            "targets": targets_of(seen["sensors"] if seen else None, nodes),
            "first_ts": cti.iso(row["first_ts"]), "last_ts": cti.iso(row["last_ts"]),
            "last_seen": cti.iso(seen["last_seen"] if seen else None),
            "verdicts": {v: row[v] for v in VERDICTS},
            "test_source": bool(row["test_source"]), "exempt": exempt_flag(in_nets, exempt_readable),
            "block": block_of(block)}


def checkers_of(readable: bool, heartbeats, as_of) -> dict:
    """집행기(관문 · 내부 방화벽) 확인이 멈췄는가. 멈췄으면 지점 결과(enforcement)의 적용 확인을 믿지 않는다
    (targets.response_block 과 같은 기준: 기록이 없거나 10분 넘게 확인이 없으면 멈춤). 생존 신호 표를 읽을 수 없으면 null."""
    if not readable:
        return {f"{p}_stale": None for p in CHECKER_POINTS}
    seen = {r["source"]: r["checked_at"] for r in heartbeats if r["kind"] == "block_report"}
    return {f"{p}_stale": targets.older(as_of, seen.get(f"block:{p}"), targets.BLOCK_CHECKER_STALE)
            for p in CHECKER_POINTS}


# ----------------------------------------------------------------------
#  조회
# ----------------------------------------------------------------------

async def checkers(c, as_of) -> dict:
    readable = bool(await c.fetchval(targets.HEARTBEATS_READABLE_SQL))
    return checkers_of(readable, await c.fetch(targets.HEARTBEATS_SQL) if readable else [], as_of)


async def source_items(c, rows, as_of) -> list[dict]:
    """집계 행들 → 목록 항목. 쪽에 나온 주소만 이벤트 발생원 · 마지막 관측 · 차단 행 · 차단 제외 대역을 따로 묻는다.
    노린 대상은 상태판과 같이 등록 노드 발생원도 그 노드로 본다(nodes 를 읽을 수 없으면 고정 대상만)."""
    ips = [r["ip"] for r in rows]
    if not ips:
        return []
    seen = {r["ip"]: r for r in await c.fetch(SENSORS_SQL, ips)}
    blocks = {r["ip"]: r for r in await c.fetch(BLOCKS_SQL, ips)}
    readable = await has_exempt_table(c)
    in_nets = {r["ip"] for r in await c.fetch(targets.EXEMPT_SQL, ips, await block_nets(c))}
    nodes = targets.node_sources((await targets.read_nodes(c, as_of))[1])
    return [source_item(r, seen.get(r["ip"]), blocks.get(r["ip"]), r["ip"] in in_nets, readable, nodes) for r in rows]


@router.get("/api/sources")
async def list_sources(request: Request,
                       q: Optional[str] = Query(None, pattern=r"^[0-9A-Fa-f:.]{1,45}$"),
                       sort: SORTS = "recent",
                       include_test: bool = False,
                       fp_kind: Optional[FP_KINDS] = None,
                       fp: Optional[str] = Query(None, min_length=1, max_length=UNTRUSTED_MAX),
                       limit: int = Query(50, ge=1, le=PAGE_MAX),
                       offset: int = Query(0, ge=0, le=cti.MAX_OFFSET)):
    """사건이 있는 출발지 목록. q 는 주소 앞부분, fp_kind · fp 는 그 지문을 쓴 출발지(이벤트 기준)로 좁힌다.
    시험 대역은 기본으로 뺀다(include_test=true 면 넣고 test_source 로 표시한다)."""
    if (fp_kind is None) != (fp is None):
        raise HTTPException(422, "지문 종류(fp_kind)와 값(fp)을 함께 지정해 주세요")
    if fp is not None and "\x00" in fp:
        # PostgreSQL 글자에는 NUL 이 없다. 그대로 넘기면 인코딩 오류가 500 이 된다
        raise HTTPException(422, "지문 값에 NUL 글자를 넣을 수 없습니다")

    where, params = [], []
    if not include_test:
        where.append("NOT s.test_source")
    if q:
        # host() 는 IPv6 를 소문자로 낸다. 패턴이 % · _ 를 막으므로 LIKE 특수 글자를 따로 풀지 않는다
        params.append(q.lower() + "%")
        where.append(f"s.ip LIKE ${len(params)}")
    if fp_kind:
        params.append(fp)
        where.append(f"s.actor_ip IN (SELECT f.src_ip FROM ({fp_events(fp_kind)}) f WHERE f.value = ${len(params)})")
    w = ("WHERE " + " AND ".join(where)) if where else ""

    async with request.app.state.pool.acquire() as c, c.transaction(isolation="repeatable_read", readonly=True):
        await c.execute(STATEMENT_TIMEOUT)
        as_of = await c.fetchval("SELECT now()")
        total = await c.fetchval(f"{SOURCES_SQL} SELECT count(*) FROM s {w}", *params)
        rows = await c.fetch(f"""{SOURCES_SQL}
            SELECT * FROM s {w}
            ORDER BY {ORDERS[sort]} LIMIT ${len(params) + 1} OFFSET ${len(params) + 2}""", *params, limit, offset)
        items = await source_items(c, rows, as_of)
        checks = await checkers(c, as_of)
    return {"as_of": cti.iso(as_of), "total": total, "limit": limit, "offset": offset, "checkers": checks,
            "items": items}


@router.get("/api/sources/detail")
async def source_detail(request: Request, ip: str = Query(..., max_length=64)):
    """출발지 하나. IPv6 에 ':' 가 있어 경로가 아니라 인자로 받는다. 사건도 실제 이벤트도 없으면 404 다.
    사건 없이 이벤트만 있는 출발지(지문 묶음에서 온 주소)는 요약이 null 이다. 콘솔 · 감사 기록만 있으면 이벤트가 없는 것이다.
    마지막 관측(last_seen)과 차단 제외(exempt_flag, 목록의 exempt 와 같은 판단)는 요약이 없어도 머리에 낸다."""
    addr = parse_ip(ip)
    async with request.app.state.pool.acquire() as c, c.transaction(isolation="repeatable_read", readonly=True):
        await c.execute(STATEMENT_TIMEOUT)
        as_of = await c.fetchval("SELECT now()")
        row = await c.fetchrow(f"{SOURCES_SQL} SELECT * FROM s WHERE s.actor_ip = $1::inet", addr)
        if row is None and not await c.fetchval(HAS_EVENTS_SQL, addr):
            raise HTTPException(404, "이 출발지의 사건이나 이벤트가 없습니다")
        summary = (await source_items(c, [row], as_of))[0] if row else None
        last_seen = summary["last_seen"] if summary else cti.iso(await c.fetchval(LAST_SEEN_SQL, addr))
        incidents = await c.fetch(DETAIL_INCIDENTS_SQL, addr, DETAIL_INCIDENTS)
        kinds = await c.fetch(EVENT_KINDS_SQL, addr, DETAIL_KINDS, row is not None)
        fingerprints = {kind: [{"value": r["value"], "count": r["count"]}
                               for r in await c.fetch(fp_counts_sql(kind), addr, DETAIL_FINGERPRINTS)]
                        for kind in FINGERPRINTS}
        actions = await c.fetch(ACTIONS_SQL, addr, BLOCK_ACTIONS, DETAIL_ACTIONS)
        block = await c.fetchrow(BLOCKS_SQL, [addr])
        exempt = await exempt_of(c, addr)
        # 차단 제외 여부. exempt(든 대역 객체)는 표를 못 읽을 때와 대역에 들지 않을 때가 모두 null 이라 가르지 못하고 코드 상수
        #   대역도 보지 않는다. 목록과 같이 상수 · 표 대역으로 보고 표를 못 읽으면 모른다(null)
        flag = summary["exempt"] if summary else exempt_flag(
            bool(await c.fetch(targets.EXEMPT_SQL, [addr], await block_nets(c))), await has_exempt_table(c))
        # 흡수 기록(규칙 v3)은 표가 없거나 읽을 수 없으면 모른다(null)
        absorbed = await c.fetchval(ABSORBED_SQL, addr) \
            if await c.fetchval(cti.TABLES_SQL, ["incident_absorbed"]) else None
        checks = await checkers(c, as_of)
    return {
        "as_of": cti.iso(as_of), "ip": addr, "summary": summary, "last_seen": last_seen, "checkers": checks,
        "incidents": [{**dict(r), "first_ts": cti.iso(r["first_ts"]), "last_ts": cti.iso(r["last_ts"])}
                      for r in incidents],
        "incidents_total": row["incidents"] if row else 0,
        "event_kinds": [{**dict(r), "first_ts": cti.iso(r["first_ts"]), "last_ts": cti.iso(r["last_ts"])}
                        for r in kinds],
        "fingerprints": fingerprints,
        "actions": [{**dict(r), "created_at": cti.iso(r["created_at"])} for r in actions],
        "block": block_of(block), "exempt": exempt, "exempt_flag": flag, "absorbed": absorbed,
    }


@router.get("/api/sources/fingerprints")
async def fingerprint_groups(request: Request, kind: FP_KINDS,
                             limit: int = Query(50, ge=1, le=PAGE_MAX),
                             offset: int = Query(0, ge=0, le=cti.MAX_OFFSET)):
    """도구 지문 묶음. 지문마다 쓴 출발지 수 · 연결(이벤트) 수 · 그 가운데 사건 있는 출발지 수. 출발지 많은 순."""
    groups = fp_groups_sql(kind)
    async with request.app.state.pool.acquire() as c, c.transaction(isolation="repeatable_read", readonly=True):
        await c.execute(STATEMENT_TIMEOUT)
        as_of = await c.fetchval("SELECT now()")
        total = await c.fetchval(f"{groups} SELECT count(*) FROM g")
        rows = await c.fetch(f"{groups} SELECT * FROM g ORDER BY sources DESC, value LIMIT $1 OFFSET $2",
                             limit, offset)
    return {"as_of": cti.iso(as_of), "kind": kind, "total": total, "limit": limit, "offset": offset,
            "items": [{**dict(r), "first_ts": cti.iso(r["first_ts"]), "last_ts": cti.iso(r["last_ts"])} for r in rows]}
