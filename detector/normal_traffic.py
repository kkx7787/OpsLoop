#!/usr/bin/env python3
"""
OpsLoop - 정상 트래픽 생성기 (WBS 3.7 · 이슈 #49)

사전에 정의한 정상 사용(detector/normal_traffic.json)을 실험 DB 사본의 events 에 넣는다.
정상 사용자가 없는 환경에서 오탐 분모를 만들기 위한 것이다. 정의된 정상 시나리오가 규칙에
걸리면 그것이 오탐이다(판정값 false_positive).

넣는 곳은 실험 DB(Mac 도커 · 127.0.0.1:55449)만이다. 운영 DB · 콘솔 · web-01 · 허니팟 · 디코이에는
아무것도 보내지 않는다. 그래서 --db-url 의 호스트가 127.0.0.1 이 아니면 종료 2 다. 포트도 55449 가
아니면 거부한다(시험용 임시 컨테이너는 --allow-port 로 연다). 셸의 DATABASE_URL 은 읽지 않는다.
--db-url 에 질의 문자열(?host= · ?hostaddr= · ?port= · ?service= …)이나 호스트 둘 이상(a,b)이 있으면 거부한다. libpq 는 그것으로
다른 주소에 붙기 때문이다. 같은 이유로 PGHOST · PGHOSTADDR · PGPORT · PGSERVICE · PGSERVICEFILE 환경변수는 지우고 붙는다(psycopg2 는
hostaddr=127.0.0.1 로 고정). 붙은 뒤에는 표식 아닌 이벤트의 max(ts) 가 DB 의 now() 로부터 30분 안이면 '지금도 이벤트가 들어오는
DB'(운영으로 보임)로 보고 종료 5 로 물러난다 — --allow-port 와 컨테이너 네트워크 공유로 주소 검사를 지나도 운영 DB 에는 쓰지 않는다.

행은 app/auth.py INSERT_EVENT · parser/parse_agent.py 와 같은 열로 넣는다.
  line_hash  sha256('normal49|<id>|<seq>|<ts>')
  message    '[정상 시나리오 <id>] …'            ← 표식. --rollback 은 이 머리 + (UA 머리 또는 username 머리) + sensor 로 지운다
  user_agent 'OpsLoop-Normal49/<id> …'           (HTTP 행)
  username   'normal49.…'                          (인증 행)
  provenance 'real'                                탐지기(detect.py)가 보도록. 실험 DB 라서 가능하다

시각은 구간 시작(--window-start, 기본 = 실험 DB max(events.ts) + 1시간)을 600초 경계로 올린 뒤 시나리오
오프셋을 더한 것이다. R101 · R102 가 10분 고정창(floor(epoch/600))으로 세므로 시나리오 하나가 창 하나에
들어가고, 시나리오 사이 1800초는 통합 창(1200초)보다 길어 같은 출발지 · 같은 규칙이라도 따로 뜬다.

트랜잭션 하나로 넣고, 넣기 전후의 사건 키 집합(incidents.incident_key 의 md5 집계)이 같은지 확인한다.
events 를 넣는 것만으로 incidents 가 변하면 안 된다. 다르면 되돌리고 종료 4 다.

사용
  python3 detector/normal_traffic.py --table                                    # 정의서에 붙이는 표 (DB 없음)
  python3 detector/normal_traffic.py --db-url $LAB                              # 계획만 (기본 --dry-run, 읽기 전용)
  python3 detector/normal_traffic.py --db-url $LAB --apply                      # 넣는다. JSON 한 줄을 stdout 에
  python3 detector/normal_traffic.py --db-url $LAB --apply --window-start 2026-09-27T09:00:00+00:00
  python3 detector/normal_traffic.py --db-url $LAB --rollback                   # 표식 행 삭제

종료 코드  0 정상 · 1 정의 오류 등 · 2 실험 DB 주소 아님 · 3 구간에 표식 아닌 이벤트가 있음 · 4 사건 키 집합이 변함
          · 5 지금도 이벤트가 들어오는 DB(운영으로 보임)
"""

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_SCENARIOS = os.path.join(HERE, "normal_traffic.json")
DEFAULT_RULES = os.path.join(HERE, "rules_w1.json")

LAB_HOST = "127.0.0.1"
LAB_PORT = 55449
EXIT_DB_URL, EXIT_WINDOW, EXIT_KEYS, EXIT_LIVE = 2, 3, 4, 5
LIVE_GRACE_SECONDS = 1800          # 표식 아닌 이벤트가 이 안에 있으면 지금도 이벤트가 들어오는 DB 다
# libpq · asyncpg 가 접속 주소를 정하는 데 쓰는 환경변수. --db-url 만 믿기 위해 붙기 전에 지운다
STEERING_ENV = ("PGHOST", "PGHOSTADDR", "PGPORT", "PGSERVICE", "PGSERVICEFILE", "PGSYSCONFDIR")

ID_RE = re.compile(r"^[A-Z][0-9]{2}$")
MARKER_SQL_RE = r"^\[정상 시나리오 [A-Z][0-9]{2}\] "      # PostgreSQL 정규식. --rollback · 구간 검사가 쓴다
MARKER_RE = re.compile(MARKER_SQL_RE)
TARGETS = ("console", "web-01")
VERDICTS = ("false_positive", "benign_positive")
# 발생원별로 넣을 수 있는 eventid. 콘솔은 app/main.py 가 log_event 로 남기는 것, web-01 은 parse_agent 가 만드는 것
EVENTIDS = {
    "console": ("console.login.success", "console.login.failed", "console.logout"),
    "web-01/sshd": ("sshd.login.success", "sshd.login.failed", "sshd.login.invalid_user"),
    "web-01/nginx": ("nginx.request",),
}
AUTH_EVENTIDS = ("console.login.success", "console.login.failed", "console.logout",
                 "sshd.login.success", "sshd.login.failed", "sshd.login.invalid_user")
HTTP_EVENTIDS = ("console.login.success", "console.login.failed", "console.logout", "nginx.request")
SRC_PORT_BASE = 40000
SSHD_PID_BASE = 49000

# app/auth.py INSERT_EVENT 와 같은 열 · 같은 순서. url · message 가 끝에 있다
COLUMNS = ("line_hash", "ts", "eventid", "session", "src_ip", "src_port", "dst_port", "protocol", "username",
           "provenance", "http_method", "http_status", "user_agent", "sensor", "url", "message")
FINGERPRINT_SQL = ("SELECT count(*), md5(coalesce(string_agg(incident_key, ',' ORDER BY incident_key), '')) "
                   "FROM incidents")
LIMITS = {"session": 128, "username": 256, "http_method": 16, "user_agent": 512, "url": 2048, "message": 512}


# ----------------------------------------------------------------------
#  정의 읽기 · 검사
# ----------------------------------------------------------------------

def load_scenarios(path=DEFAULT_SCENARIOS):
    with open(path, encoding="utf-8") as f:
        doc = json.load(f)
    validate(doc)
    return doc


def load_rules(path=DEFAULT_RULES):
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def _bad(msg):
    raise ValueError(f"normal_traffic.json: {msg}")


def validate(doc):
    """정의 파일의 모양을 검사한다. 어긋나면 ValueError."""
    for k in ("version", "marker", "timing", "sources", "candidates", "rules_watched", "verdict_rule", "scenarios"):
        if k not in doc:
            _bad(f"{k} 가 없다")
    slot = doc["timing"].get("slot_seconds")
    spacing = doc["timing"].get("scenario_spacing_seconds")
    if not (isinstance(slot, int) and slot > 0 and isinstance(spacing, int) and spacing >= slot):
        _bad("timing.slot_seconds · scenario_spacing_seconds 는 양의 정수이고 간격이 창 이상이어야 한다")
    cands = {k: v for k, v in doc["candidates"].items() if k != "comment"}
    if not cands or not all(isinstance(v, int) and v > 0 for v in cands.values()):
        _bad("candidates 는 이름 → 양의 정수 임계치다")
    rules = [k for k in doc["rules_watched"]]
    for name, s in doc["sources"].items():
        if name not in EVENTIDS:
            _bad(f"sources.{name}: 모르는 발생원")
        for k in ("src_ip", "dst_port", "protocol", "sensor"):
            if k not in s:
                _bad(f"sources.{name}: {k} 가 없다")
        if s["sensor"] not in TARGETS:
            _bad(f"sources.{name}: sensor 는 {TARGETS} 중 하나다")
    scenarios = doc["scenarios"]
    if not isinstance(scenarios, list) or not scenarios:
        _bad("scenarios 가 비었다")
    ids, prev_offset = set(), None
    uprefix = doc["marker"]["username_prefix"]
    for s in scenarios:
        sid = s.get("id")
        if not isinstance(sid, str) or not ID_RE.match(sid):
            _bad(f"id {sid!r}: 대문자 하나 + 숫자 둘이어야 한다")
        if sid in ids:
            _bad(f"{sid}: id 중복")
        ids.add(sid)
        for k in ("target", "source", "name", "offset_seconds", "events", "countable", "fires", "verdict_if_fired", "rationale"):
            if k not in s:
                _bad(f"{sid}: {k} 가 없다")
        if s["target"] not in TARGETS:
            _bad(f"{sid}: target 은 {TARGETS} 중 하나다")
        if s["source"] not in doc["sources"]:
            _bad(f"{sid}: source {s['source']} 가 sources 에 없다")
        if doc["sources"][s["source"]]["sensor"] != s["target"]:
            _bad(f"{sid}: source 의 sensor 와 target 이 다르다")
        off = s["offset_seconds"]
        if not isinstance(off, int) or off < 0 or off % slot:
            _bad(f"{sid}: offset_seconds 는 {slot} 의 배수여야 한다")
        if prev_offset is not None and off - prev_offset < spacing:
            _bad(f"{sid}: 앞 시나리오와 {spacing}초 이상 떨어져야 한다")
        prev_offset = off
        if not isinstance(s["events"], list) or not s["events"]:
            _bad(f"{sid}: events 가 비었다")
        for g in s["events"]:
            eid = g.get("eventid")
            if eid not in EVENTIDS[s["source"]]:
                _bad(f"{sid}: {eid} 는 {s['source']} 에 넣을 수 없는 eventid 다")
            if not (isinstance(g.get("count"), int) and g["count"] >= 1):
                _bad(f"{sid}: count 는 1 이상이다")
            if not (isinstance(g.get("interval_seconds"), int) and g["interval_seconds"] >= 0):
                _bad(f"{sid}: interval_seconds 는 0 이상이다")
            if "gap_before_seconds" in g and not (isinstance(g["gap_before_seconds"], int) and g["gap_before_seconds"] >= 0):
                _bad(f"{sid}: gap_before_seconds 는 0 이상이다")
            if eid in AUTH_EVENTIDS and not str(g.get("username", "")).startswith(uprefix):
                _bad(f"{sid}: 인증 행의 username 은 {uprefix!r} 로 시작해야 한다")
            if eid in HTTP_EVENTIDS:
                for k in ("url", "http_method", "http_status", "user_agent"):
                    if k not in g:
                        _bad(f"{sid}: HTTP 행에 {k} 가 없다")
                if not isinstance(g["http_status"], int):
                    _bad(f"{sid}: http_status 는 정수다")
            if not isinstance(g.get("message"), str) or not g["message"]:
                _bad(f"{sid}: message 가 없다")
        span = scenario_span(s)
        if span >= slot:
            _bad(f"{sid}: 시나리오가 {span}초로 한 창({slot}초)을 넘는다")
        if set(s["countable"]) != set(rules):
            _bad(f"{sid}: countable 의 규칙은 rules_watched 와 같아야 한다")
        if set(s["fires"]) != set(cands):
            _bad(f"{sid}: fires 의 후보는 candidates 와 같아야 한다")
        for c, lst in s["fires"].items():
            if not isinstance(lst, list) or any(r not in rules for r in lst):
                _bad(f"{sid}: fires.{c} 는 rules_watched 의 규칙 목록이다")
        if s["verdict_if_fired"] not in VERDICTS:
            _bad(f"{sid}: verdict_if_fired 는 {VERDICTS} 중 하나다")
    return True


def scenario_times(s):
    """시나리오 안 각 행의 상대 시각(초) 목록. 묶음 순서대로, 묶음 사이는 gap_before_seconds(기본 = 앞 묶음 간격 또는 10)."""
    out, t, prev_interval = [], 0, None
    for g in s["events"]:
        if out:
            t += g.get("gap_before_seconds", prev_interval if prev_interval else 10)
        for i in range(g["count"]):
            out.append((t, g, i))
            if i < g["count"] - 1:
                t += g["interval_seconds"]
        prev_interval = g["interval_seconds"]
    return out


def scenario_span(s):
    times = scenario_times(s)
    return times[-1][0] - times[0][0]


# ----------------------------------------------------------------------
#  규칙이 세는 것 · 기대 반응 (rules_w1.json 으로 계산해 정의와 대조)
# ----------------------------------------------------------------------

def _rule(rules, rid):
    for r in rules["rules"]:
        if r["id"] == rid:
            return r
    raise KeyError(rid)


def excluded_url(url, patterns):
    """detect.py signals_actor_rate 와 같은 뜻: url 전체가 패턴 중 하나에 맞으면 세지 않는다."""
    return url is not None and any(re.fullmatch(f"(?:{p})", url) for p in patterns)


def countable(s, rules):
    """시나리오의 행 가운데 R101 · R102 가 세는 수. rules_w1.json 의 eventids · http_status · exclude_url_patterns 를 그대로 쓴다."""
    r101, r102 = _rule(rules, "R101")["params"], _rule(rules, "R102")["params"]
    pats = r102.get("exclude_url_patterns", [])
    out = {"R101": 0, "R102": 0}
    for _, g, _ in scenario_times(s):
        if g["eventid"] in r101["eventids"]:
            out["R101"] += 1
        if g["eventid"] in r102["eventids"] and g.get("http_status") in r102.get("http_status", []) \
                and not excluded_url(g.get("url"), pats):
            out["R102"] += 1
    return out


def expected_fires(doc, s, rules):
    c = countable(s, rules)
    cands = {k: v for k, v in doc["candidates"].items() if k != "comment"}
    return {name: [r for r in ("R101", "R102") if c[r] >= th] for name, th in cands.items()}


def check_consistency(doc, rules):
    """정의에 적은 countable · fires 가 규칙 파일로 계산한 값과 다른 시나리오 목록. 비어 있어야 한다."""
    bad = []
    for s in doc["scenarios"]:
        c, f = countable(s, rules), expected_fires(doc, s, rules)
        if c != s["countable"] or {k: sorted(v) for k, v in f.items()} != {k: sorted(v) for k, v in s["fires"].items()}:
            bad.append((s["id"], c, f))
    return bad


# ----------------------------------------------------------------------
#  행 만들기
# ----------------------------------------------------------------------

def clip(v, n):
    if v is None:
        return None
    v = str(v).replace("\x00", "")
    return v if len(v) <= n else v[:n]


def align_slot(dt, slot):
    """dt 를 slot 초 경계로 올린다(이미 경계면 그대로). 고정창 계산이 epoch 기준이라 UTC 로 잰다."""
    epoch = int(dt.timestamp())
    up = -(-epoch // slot) * slot
    return datetime.fromtimestamp(up, tz=timezone.utc)


def parse_ts(text):
    dt = datetime.fromisoformat(text.replace("Z", "+00:00"))
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def line_hash(sid, seq, ts):
    return hashlib.sha256(f"normal49|{sid}|{seq}|{ts.isoformat()}".encode()).hexdigest()


def window_end(doc, window_start):
    last = max(s["offset_seconds"] for s in doc["scenarios"])
    return window_start + timedelta(seconds=last + doc["timing"]["scenario_spacing_seconds"])


def build_rows(doc, window_start):
    """모든 시나리오의 events 행. window_start 는 600초 경계에 있어야 한다(align_slot). 돌려주는 값: (행 목록, 시나리오 요약)."""
    slot = doc["timing"]["slot_seconds"]
    if int(window_start.timestamp()) % slot:
        raise ValueError(f"구간 시작이 {slot}초 경계에 있지 않다: {window_start.isoformat()}")
    mp, up = doc["marker"]["message_prefix"], doc["marker"]["user_agent_prefix"]
    rows, summary, seq = [], [], 0
    for s in doc["scenarios"]:
        src = doc["sources"][s["source"]]
        base = window_start + timedelta(seconds=s["offset_seconds"])
        first = last = None
        n = 0
        for t, g, i in scenario_times(s):
            seq += 1
            n += 1
            ts = base + timedelta(seconds=t)
            eid = g["eventid"]
            suffix = f" · {i + 1}/{g['count']}" if g["count"] > 1 else ""
            session = None
            if eid == "console.login.success":
                session = f"n49-{s['id']}-{seq:03d}"                        # 콘솔은 토큰 앞 17자를 남긴다. 그 길이 안이다
            elif eid.startswith("sshd."):
                session = f"{src['sensor']}/sshd/{SSHD_PID_BASE + seq}"      # parse_agent: <node>/sshd/<pid>
            row = {
                "line_hash": line_hash(s["id"], seq, ts),
                "ts": ts, "eventid": eid, "session": clip(session, LIMITS["session"]),
                "src_ip": src["src_ip"], "src_port": SRC_PORT_BASE + seq, "dst_port": src["dst_port"],
                "protocol": src["protocol"],
                "username": clip(g.get("username"), LIMITS["username"]),
                "provenance": doc["marker"]["provenance"],
                "http_method": clip(g.get("http_method"), LIMITS["http_method"]),
                "http_status": g.get("http_status"),
                "user_agent": clip(up.format(id=s["id"]) + g["user_agent"], LIMITS["user_agent"]) if "user_agent" in g else None,
                "sensor": src["sensor"],
                "url": clip(g.get("url"), LIMITS["url"]),
                "message": clip(mp.format(id=s["id"]) + g["message"] + suffix, LIMITS["message"]),
            }
            rows.append(row)
            first = first or ts
            last = ts
        summary.append({"id": s["id"], "rows": n, "first_ts": first, "last_ts": last,
                        "slot": int(first.timestamp()) // slot})
    return rows, summary


# ----------------------------------------------------------------------
#  표 (정의서에 붙인다)
# ----------------------------------------------------------------------

TARGET_LABEL = {"console": "콘솔", "web-01/sshd": "web-01 sshd", "web-01/nginx": "web-01 nginx"}
EVENT_LABEL = {
    "console.login.success": "로그인 성공", "console.login.failed": "로그인 실패", "console.logout": "로그아웃",
    "sshd.login.success": "SSH 성공", "sshd.login.failed": "SSH 실패", "sshd.login.invalid_user": "없는 계정",
}
CAND_LABEL = {"w2": "w2", "w2-c3": "c3", "w2-c8": "c8"}
TABLE_HEADER = ("id", "대상", "시나리오", "출발지", "횟수", "창", "기대 반응", "걸리면 판정값")


def counts_label(s, rules):
    pats = _rule(rules, "R102")["params"].get("exclude_url_patterns", [])
    order, acc = [], {}
    for g in s["events"]:
        eid = g["eventid"]
        if eid == "nginx.request":
            label = f"{g['http_status']}"
            if g["http_status"] == 404 and excluded_url(g.get("url"), pats):
                label += " 메타데이터"
        else:
            label = EVENT_LABEL[eid]
        if label not in acc:
            order.append(label)
            acc[label] = 0
        acc[label] += g["count"]
    return " · ".join(f"{k} {acc[k]}" for k in order)


def fires_label(doc, s):
    cands = [k for k in doc["candidates"] if k != "comment"]
    rules = sorted({r for lst in s["fires"].values() for r in lst})
    if not rules:
        c = s["countable"]
        return "안 뜸 (" + " · ".join(f"{k} {c[k]}" for k in c) + ")"
    parts = []
    for r in rules:
        parts.append(f"{r}: " + " · ".join(
            f"{CAND_LABEL.get(k, k)} {'뜸' if r in s['fires'][k] else '안 뜸'}" for k in cands))
    return " / ".join(parts)


def render_table(doc, rules):
    slot = doc["timing"]["slot_seconds"]
    lines = ["| " + " | ".join(TABLE_HEADER) + " |", "|" + "---|" * len(TABLE_HEADER)]
    for s in doc["scenarios"]:
        cells = (s["id"], TARGET_LABEL[s["source"]], s["name"], doc["sources"][s["source"]]["src_ip"],
                 counts_label(s, rules), f"{scenario_span(s)}초 ({slot // 60}분 창 1개)",
                 fires_label(doc, s), f"{s['verdict_if_fired']} (오탐)" if s["verdict_if_fired"] == "false_positive"
                 else f"{s['verdict_if_fired']} (양성 정탐)")
        if any("|" in str(c) for c in cells):
            raise ValueError(f"{s['id']}: 표 칸에 | 가 있다")
        lines.append("| " + " | ".join(str(c) for c in cells) + " |")
    return "\n".join(lines)


# ----------------------------------------------------------------------
#  DB
#  psycopg2(detect.py 와 같은 드라이버)가 있으면 그것을, 없으면 asyncpg(콘솔 app 이 쓰는 것)를 쓴다.
#  SQL 은 $1 · $2 자리표시자로 쓰고 psycopg2 에는 %s 로 바꿔 준다. 트랜잭션은 BEGIN … COMMIT/ROLLBACK 하나다.
# ----------------------------------------------------------------------

def check_db_url(url, allow_ports=()):
    """실험 DB 주소인지 본다. 호스트는 글자 그대로 127.0.0.1, 포트는 55449(또는 allow_ports). 질의 문자열 · 호스트 둘 이상은 거부.
    아니면 SystemExit(2)."""
    try:
        u = urlparse(url or "")
    except ValueError:
        u = None
    if u is None or u.scheme not in ("postgresql", "postgres") or not u.hostname:
        _refuse(f"--db-url 은 postgresql://…@127.0.0.1:{LAB_PORT}/… 꼴이어야 한다")
    if u.query or u.params or u.fragment:
        # libpq 는 ?host= · ?hostaddr= · ?port= · ?service= 로 netloc 과 다른 주소에 붙는다. 질의 문자열은 통째로 받지 않는다
        _refuse("--db-url 에 질의 문자열(?…)을 붙일 수 없다. libpq 가 그것으로 다른 주소에 붙는다")
    if "," in u.netloc:
        _refuse("--db-url 에 호스트를 둘 이상 적을 수 없다(a,b 는 첫 호스트가 죽으면 둘째로 붙는다)")
    if u.hostname != LAB_HOST:
        _refuse(f"실험 DB 호스트는 {LAB_HOST} 만 받는다 (받은 값 {u.hostname!r}). 운영 · 원격 DB 에는 넣지 않는다")
    try:
        port = u.port or 5432
    except ValueError:
        _refuse("--db-url 의 포트를 읽을 수 없다")
    if port != LAB_PORT and port not in set(allow_ports):
        _refuse(f"실험 DB 포트는 {LAB_PORT} 다 (받은 값 {port}). 임시 컨테이너면 --allow-port {port}")
    return u.hostname, port


def _refuse(msg):
    print(f"[normal49] 거부: {msg} (종료 {EXIT_DB_URL})", file=sys.stderr)
    sys.exit(EXIT_DB_URL)


def _die(msg, code=1):
    print(f"[normal49] {msg}", file=sys.stderr)
    sys.exit(code)


def _driver():
    """(이름, 모듈). 패키지 디렉터리만 남은 깨진 설치(속성 없는 이름공간 패키지)는 없는 것으로 본다."""
    for name in ("psycopg2", "asyncpg"):
        try:
            mod = __import__(name)
        except ImportError:
            continue
        if hasattr(mod, "connect"):
            return name, mod
    _die("psycopg2 도 asyncpg 도 없다. 실험 DB 에 붙을 드라이버가 필요하다 "
         "(venv 를 다시 만들거나, asyncpg 가 든 opsloop-api 이미지 안에서 돌린다 — 정의서 7절)")


class Session:
    """드라이버 두 개를 같은 모양으로 쓴다. fetch(sql, *params) → 튜플 목록, execute(sql, *params) → 영향 행 수."""

    def __init__(self, url, host=LAB_HOST, port=None):
        for k in STEERING_ENV:                     # PGHOSTADDR 등이 있으면 libpq 는 URL 과 다른 주소에 붙는다
            os.environ.pop(k, None)
        self.kind, mod = _driver()
        if self.kind == "psycopg2":
            # URL 과 함께 넘긴 인자가 이긴다(make_dsn). hostaddr 로 실제 접속 주소를 검사한 호스트로 고정한다
            kw = {"host": host, "hostaddr": host}
            if port:
                kw["port"] = port
            self.conn = mod.connect(url, **kw)
            self.cur = self.conn.cursor()
        else:
            import asyncio
            self.loop = asyncio.new_event_loop()
            self.conn = self.loop.run_until_complete(mod.connect(url, host=host, port=port))   # 인자가 DSN 을 이긴다
            self._run(self.conn.execute("BEGIN"))

    def _run(self, coro):
        return self.loop.run_until_complete(coro)

    @staticmethod
    def _pg(sql):
        return re.sub(r"\$[0-9]+", "%s", sql)

    def fetch(self, sql, *params):
        if self.kind == "psycopg2":
            self.cur.execute(self._pg(sql), params)
            return self.cur.fetchall()
        return [tuple(r) for r in self._run(self.conn.fetch(sql, *params))]

    def one(self, sql, *params):
        return self.fetch(sql, *params)[0]

    def execute(self, sql, *params):
        if self.kind == "psycopg2":
            self.cur.execute(self._pg(sql), params)
            return self.cur.rowcount
        status = self._run(self.conn.execute(sql, *params))          # 'INSERT 0 1' · 'DELETE 66'
        tail = status.rsplit(" ", 1)[-1]
        return int(tail) if tail.isdigit() else 0

    def read_only(self):
        self.execute("SET TRANSACTION READ ONLY")

    def commit(self):
        if self.kind == "psycopg2":
            self.conn.commit()
        else:
            self._run(self.conn.execute("COMMIT"))

    def rollback(self):
        if self.kind == "psycopg2":
            self.conn.rollback()
        else:
            self._run(self.conn.execute("ROLLBACK"))

    def close(self):
        if self.kind == "psycopg2":
            self.conn.close()
        else:
            self._run(self.conn.close())
            self.loop.close()


# 열 순서는 COLUMNS. src_ip 는 text 로 보내 서버가 inet 으로 바꾼다(두 드라이버가 같은 값을 보낸다)
INSERT_SQL = (
    "INSERT INTO events (" + ", ".join(COLUMNS) + ") VALUES ("
    + ", ".join(f"${i + 1}::text::inet" if c == "src_ip" else f"${i + 1}" for i, c in enumerate(COLUMNS))
    + ") ON CONFLICT (line_hash) DO NOTHING")


def fingerprint(db):
    n, h = db.one(FINGERPRINT_SQL)
    return {"count": n, "md5": h}


def foreign_rows_in_window(db, start, end):
    """구간 안에 표식이 아닌 이벤트가 있으면 그 수. 있으면 우리 구간이 실데이터를 덮는 것이라 넣지 않는다.
    message 가 NULL 인 행(콘솔 · 수집기 · 디코이에 흔하다)도 표식이 아니므로 센다(NULL ~ x 는 NULL 이라 따로 적는다)."""
    return db.one("SELECT count(*) FROM events WHERE ts >= $1 AND ts < $2 AND (message IS NULL OR NOT (message ~ $3))",
                  start, end, MARKER_SQL_RE)[0]


def check_not_live(db):
    """표식 아닌 이벤트의 max(ts) 가 DB 의 now() 로부터 LIVE_GRACE_SECONDS 안이면 지금도 이벤트가 들어오는 DB 다(운영).
    실험 DB 사본은 덤프 시각 뒤로 멈춰 있다. --allow-port 와 컨테이너 네트워크 공유로 주소 검사를 지나도 여기서 막는다(종료 5)."""
    now, mx = db.one("SELECT now(), max(ts) FROM events WHERE message IS NULL OR NOT (message ~ $1)", MARKER_SQL_RE)
    if mx is not None and (now - mx).total_seconds() < LIVE_GRACE_SECONDS:
        db.rollback()
        _die(f"표식 아닌 이벤트의 마지막 시각이 {int((now - mx).total_seconds())}초 전이다. 지금도 이벤트가 들어오는 DB(운영으로 보임)라 "
             f"손대지 않는다. 실험 DB 사본은 덤프 시각 뒤로 멈춰 있어야 한다", EXIT_LIVE)
    return mx


def ours_clause(doc):
    """--rollback 이 지우는 행의 조건과 인자. message 머리 + sensor + (UA 머리 또는 username 머리). 자리표시자 $1 ~ $4."""
    ua_like = doc["marker"]["user_agent_prefix"].split("{id}")[0] + "%"        # 'OpsLoop-Normal49/%'
    un_like = doc["marker"]["username_prefix"] + "%"                           # 'normal49.%'
    return ("message ~ $1 AND sensor = ANY($2) AND (user_agent LIKE $3 OR username LIKE $4)",
            (MARKER_SQL_RE, list(TARGETS), ua_like, un_like))


def default_window_start(db, doc):
    mx = db.one("SELECT max(ts) FROM events")[0]
    if mx is None:
        _die("events 가 비어 있어 기본 구간 시작을 정할 수 없다. --window-start 를 준다")
    return align_slot(mx.astimezone(timezone.utc) + timedelta(hours=1), doc["timing"]["slot_seconds"]), mx


def _json(obj):
    def default(v):
        if isinstance(v, datetime):
            return v.isoformat()
        raise TypeError(type(v))
    return json.dumps(obj, ensure_ascii=False, default=default)


def run_plan(db, doc, args, mode):
    """--dry-run · --apply. dry-run 은 읽기 전용 트랜잭션이다."""
    if mode == "dry-run":
        db.read_only()
    check_not_live(db)
    slot = doc["timing"]["slot_seconds"]
    requested = parse_ts(args.window_start) if args.window_start else None
    if requested is not None:
        start = align_slot(requested, slot)
        max_ts = db.one("SELECT max(ts) FROM events")[0]
    else:
        start, max_ts = default_window_start(db, doc)
    end = window_end(doc, start)
    rows, summary = build_rows(doc, start)
    before = fingerprint(db)
    events_before = db.one("SELECT count(*) FROM events")[0]
    foreign = foreign_rows_in_window(db, start, end)
    out = {
        "mode": mode, "driver": db.kind, "db": f"{args.host}:{args.port}",
        "scenarios_file": os.path.abspath(args.scenarios),
        "window_start_requested": requested, "window_start": start, "window_end": end,
        "window_seconds": int((end - start).total_seconds()), "slot_seconds": slot,
        "events_max_ts_before": max_ts, "events_before": events_before,
        "foreign_rows_in_window": foreign, "rows_planned": len(rows), "rows_inserted": 0,
        "scenarios": summary, "incident_keys_before": before,
    }
    if foreign:
        db.rollback()
        out["refused"] = f"구간 안에 표식이 아닌 이벤트 {foreign}건. 구간을 뒤로 옮긴다(--window-start)"
        print(_json(out))
        sys.exit(EXIT_WINDOW)
    if mode == "dry-run":
        db.rollback()
        print(_json(out))
        return 0
    inserted = 0
    for r in rows:
        inserted += db.execute(INSERT_SQL, *[r[c] for c in COLUMNS])
    after = fingerprint(db)
    marked = db.one("SELECT count(*) FROM events WHERE ts >= $1 AND ts < $2 AND message ~ $3", start, end, MARKER_SQL_RE)[0]
    events_after = db.one("SELECT count(*) FROM events")[0]
    out.update({"rows_inserted": inserted, "rows_marked_in_window": marked, "events_after": events_after,
                "incident_keys_after": after, "incident_keys_unchanged": after == before})
    if after != before:
        db.rollback()
        out["refused"] = "events 를 넣는 동안 사건 키 집합이 변했다. 되돌렸다"
        print(_json(out))
        sys.exit(EXIT_KEYS)
    db.commit()
    print(_json(out))
    return 0


def run_rollback(db, doc, args):
    check_not_live(db)
    before = fingerprint(db)
    where, prm = ours_clause(doc)
    n, lo, hi = db.one(f"SELECT count(*), min(ts), max(ts) FROM events WHERE {where}", *prm)
    incidents_in_window = 0
    if n:
        incidents_in_window = db.one("SELECT count(*) FROM incidents WHERE first_ts >= $1 AND first_ts <= $2", lo, hi)[0]
    deleted = db.execute(f"DELETE FROM events WHERE {where}", *prm)
    after = fingerprint(db)
    events_after = db.one("SELECT count(*) FROM events")[0]
    db.commit()
    print(_json({"mode": "rollback", "driver": db.kind, "db": f"{args.host}:{args.port}", "rows_deleted": deleted,
                 "deleted_ts_min": lo, "deleted_ts_max": hi, "events_after": events_after,
                 "incident_keys_before": before, "incident_keys_after": after,
                 "incidents_in_window": incidents_in_window,
                 "note": "incidents 는 지우지 않는다. 구간에서 뜬 사건은 리플레이 담당이 정리한다",
                 "deleted_where": "message 표식 + sensor(console · web-01) + (user_agent 머리 또는 username 머리)"}))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(description="OpsLoop 정상 트래픽 생성기 (실험 DB 전용)")
    ap.add_argument("--db-url", help=f"실험 DB. 127.0.0.1:{LAB_PORT} 만 받는다. 환경변수는 읽지 않는다")
    ap.add_argument("--scenarios", default=DEFAULT_SCENARIOS, help="시나리오 정의 JSON")
    ap.add_argument("--rules", default=DEFAULT_RULES, help="기대 반응을 대조할 규칙 파일 (R101 · R102)")
    ap.add_argument("--window-start", help="구간 시작 ISO 시각. 기본은 실험 DB max(events.ts) + 1시간. 600초 경계로 올린다")
    ap.add_argument("--allow-port", type=int, action="append", default=[], help="시험용 임시 컨테이너의 포트")
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--dry-run", action="store_true", help="계획만 (기본)")
    mode.add_argument("--apply", action="store_true", help="실험 DB 에 넣는다")
    mode.add_argument("--rollback", action="store_true", help="표식 행을 지운다")
    mode.add_argument("--table", action="store_true", help="정의서에 붙일 마크다운 표를 찍는다 (DB 없음)")
    args = ap.parse_args(argv)

    try:
        doc = load_scenarios(args.scenarios)
        rules = load_rules(args.rules)
        bad = check_consistency(doc, rules)
    except (OSError, ValueError, KeyError) as e:
        _die(f"정의 오류: {e}")
    if bad:
        _die("정의의 countable · fires 가 규칙 파일과 다르다: " + "; ".join(f"{i} 계산값 {c} {f}" for i, c, f in bad))

    if args.table:
        print(render_table(doc, rules))
        return 0

    if not args.db_url:
        _die("--db-url 이 필요하다 (환경변수 DATABASE_URL 은 읽지 않는다)", EXIT_DB_URL)
    if os.environ.get("DATABASE_URL"):
        print("[normal49] 주의: 셸에 DATABASE_URL 이 있다. 이 도구는 읽지 않지만 detect.py 는 읽는다. 비우는 것이 안전하다",
              file=sys.stderr)
    args.host, args.port = check_db_url(args.db_url, args.allow_port)

    db = Session(args.db_url, args.host, args.port)
    try:
        if args.rollback:
            return run_rollback(db, doc, args)
        return run_plan(db, doc, args, "apply" if args.apply else "dry-run")
    finally:
        db.close()


if __name__ == "__main__":
    sys.exit(main())
