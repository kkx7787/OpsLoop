#!/usr/bin/env python3
"""
OpsLoop - 웹 디코이 로그 파서 (WBS 3.2.3 / PostgreSQL)

decoy.json.YYYY-MM-DD 를 읽어 events 로 정규화한다. 구조는 Cowrie 파서와 같다.
로그 파일이 원장이고 DB 는 파생물이며, 재실행해도 중복이 쌓이지 않는다.

Cowrie 파서와 다른 점은 둘뿐이다.
  - 웹 계층 필드(요청 방식·상태코드·클라이언트 문자열)를 함께 넣는다.
  - 세션 재집계를 sensor 로 한정한다. 한 표에 두 종류의 로그가 있으므로
    범위를 나누지 않으면 한쪽 파서가 다른 쪽 세션을 0 으로 덮어쓴다.

사용
  set -a; . /etc/opsloop/collector.env; set +a
  python3 parser/parse_decoy.py                       적재 + 리포트
  python3 parser/parse_decoy.py --report --since 2026-09-19
"""

import argparse
import glob
import hashlib
import json
import os
import sys
from datetime import datetime, timezone

try:
    import psycopg2
    from psycopg2.extras import execute_batch
except ImportError:
    sys.exit("psycopg2 가 필요합니다:  sudo apt-get install -y python3-psycopg2")

DEFAULT_GLOB = "/opt/decoy/log/decoy.json*"
DEFAULT_EXCLUSIONS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exclusions.txt")
SENSOR = "decoy"

INSERT_EVENT = """
INSERT INTO events (line_hash, ts, eventid, session, src_ip, src_port, dst_port,
                    protocol, username, password, input, url, shasum,
                    provenance, message, http_method, http_status, user_agent, sensor)
VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
ON CONFLICT (line_hash) DO NOTHING
"""

# 세션 재집계. 판정과 규칙이 쓰는 값이므로 뜻을 웹 계층에 맞춰 옮긴다.
#   login_attempts : 로그인 시도 (성공·실패)
#   command_count  : 로그인 이후의 행위. 웹에서는 진단 입력과 화면 조회다.
#   downloads      : 도구 반입. 웹에서는 업로드 시도다.
REBUILD_SESSIONS = f"""
INSERT INTO sessions (session, src_ip, protocol, first_ts, last_ts,
                      login_attempts, login_success, command_count, downloads,
                      provenance, sensor)
SELECT
    session,
    max(src_ip),
    max(protocol),
    min(ts),
    max(ts),
    count(*) FILTER (WHERE eventid LIKE '%%.login.%%'),
    bool_or(eventid LIKE '%%.login.success'),
    count(*) FILTER (WHERE eventid LIKE '%%.action.%%'),
    count(*) FILTER (WHERE eventid LIKE '%%.action.upload'),
    max(provenance),
    '{SENSOR}'
FROM events
WHERE session IS NOT NULL AND sensor = '{SENSOR}'
GROUP BY session
ON CONFLICT (session) DO UPDATE SET
    src_ip         = EXCLUDED.src_ip,
    protocol       = EXCLUDED.protocol,
    first_ts       = EXCLUDED.first_ts,
    last_ts        = EXCLUDED.last_ts,
    login_attempts = EXCLUDED.login_attempts,
    login_success  = EXCLUDED.login_success,
    command_count  = EXCLUDED.command_count,
    downloads      = EXCLUDED.downloads,
    provenance     = EXCLUDED.provenance,
    sensor         = EXCLUDED.sensor
"""


def db_url(arg):
    url = arg or os.environ.get("DATABASE_URL")
    if not url:
        sys.exit("DATABASE_URL 이 없습니다. 환경변수나 --db-url 로 주세요.")
    return url


def load_exclusions(path):
    ips = set()
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    ips.add(line)
    return ips


def norm_ts(raw):
    if not raw:
        return None
    try:
        return datetime.fromisoformat(str(raw).replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, AttributeError):
        return None


def to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def clip(v, n):
    """긴 값을 자른다. 공격자가 보내는 문자열에는 길이 제한이 없다."""
    if v is None:
        return None
    v = str(v)
    return v if len(v) <= n else v[:n]


def parse_lines(files, exclusions):
    """파일을 읽어 적재할 행과 통계를 만든다. DB 에 의존하지 않는다."""
    rows, malformed = [], 0
    for path in files:
        try:
            fh = open(path, encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"  [건너뜀] {path}: {e}", file=sys.stderr)
            continue
        with fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    malformed += 1
                    continue
                eventid = ev.get("eventid")
                ts = norm_ts(ev.get("ts"))
                if not eventid or ts is None:
                    malformed += 1
                    continue
                src_ip = ev.get("src_ip")
                rows.append((
                    hashlib.sha1(line.encode("utf-8")).hexdigest(),
                    ts, eventid, ev.get("session"), src_ip,
                    to_int(ev.get("src_port")), to_int(ev.get("dst_port")),
                    ev.get("protocol"), clip(ev.get("username"), 256),
                    clip(ev.get("password"), 256), clip(ev.get("input"), 4096),
                    clip(ev.get("url"), 2048), ev.get("shasum"),
                    "fixture" if src_ip in exclusions else "real",
                    clip(ev.get("message"), 512),
                    clip(ev.get("http_method"), 16), to_int(ev.get("http_status")),
                    clip(ev.get("user_agent"), 512), ev.get("sensor") or SENSOR,
                ))
    return rows, malformed


def load(conn, files, exclusions):
    rows, malformed = parse_lines(files, exclusions)
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM events WHERE sensor = %s", (SENSOR,))
        before = cur.fetchone()[0]
        execute_batch(cur, INSERT_EVENT, rows, page_size=500)
        cur.execute("SELECT count(*) FROM events WHERE sensor = %s", (SENSOR,))
        after = cur.fetchone()[0]
        cur.execute(REBUILD_SESSIONS)
        cur.execute("SELECT count(*) FROM sessions WHERE sensor = %s", (SENSOR,))
        n_sessions = cur.fetchone()[0]
    conn.commit()
    inserted = after - before
    return inserted, len(rows) - inserted, malformed, n_sessions


def where_range(since, until, col):
    clauses = [f"sensor = '{SENSOR}'", "provenance = 'real'"]
    params = []
    if since:
        clauses.append(f"{col} >= %s"); params.append(since)
    if until:
        clauses.append(f"{col} < %s"); params.append(until)
    return " AND ".join(clauses), params


def report(conn, since, until):
    cur = conn.cursor()
    w, p = where_range(since, until, "ts")
    ws, ps = where_range(since, until, "first_ts")

    # psycopg2 는 %% 를 매개변수 자리표시자로 읽는다. LIKE 패턴의 % 는
    # %% 로 적어야 하며, 빠뜨리면 형식 지정자로 해석되어 질의가 터진다.
    def q(sql, params=()):
        cur.execute(sql, params)
        return cur.fetchall()

    span = q(f"SELECT min(ts), max(ts), count(*) FROM events WHERE {w}", p)[0]
    print("=" * 62)
    print(" OpsLoop  웹 디코이 수집 요약  (provenance = real)")
    print("=" * 62)
    if not span[2]:
        print(" 적재된 이벤트가 없습니다.")
        cur.close()
        return
    print(f" 기간   : {span[0]}  ~  {span[1]}")
    print(f" 이벤트 : {span[2]:,} 건")
    print(f" 세션   : {q(f'SELECT count(*) FROM sessions WHERE {ws}', ps)[0][0]:,} 건")
    print(f" 출발지 : {q(f'SELECT count(DISTINCT src_ip) FROM events WHERE {w}', p)[0][0]:,} 개 IP")

    fixture = q(f"SELECT count(*) FROM events WHERE sensor = '{SENSOR}' AND provenance = 'fixture'")[0][0]
    if fixture:
        print(f" (제외된 자체 테스트 이벤트 {fixture} 건)")

    def section(title, rows, width=46):
        print(f"\n-- {title} --")
        if not rows:
            print("   (없음)")
            return
        for name, cnt in rows:
            label = str(name) if name is not None else "(null)"
            if len(label) > width:
                label = label[: width - 1] + "…"
            print(f"   {cnt:>6,}  {label}")

    section("이벤트 유형", q(f"SELECT eventid, count(*) c FROM events WHERE {w} GROUP BY 1 ORDER BY c DESC LIMIT 12", p))
    section("요청 경로 TOP 15", q(f"SELECT url, count(*) c FROM events WHERE {w} AND eventid LIKE '%%.request' GROUP BY 1 ORDER BY c DESC LIMIT 15", p))
    section("상태코드", q(f"SELECT http_status, count(*) c FROM events WHERE {w} AND http_status IS NOT NULL GROUP BY 1 ORDER BY c DESC", p))
    section("클라이언트 문자열 TOP 10", q(f"SELECT user_agent, count(*) c FROM events WHERE {w} AND user_agent IS NOT NULL GROUP BY 1 ORDER BY c DESC LIMIT 10", p))
    section("출발지 TOP 10", q(f"SELECT src_ip, count(*) c FROM events WHERE {w} AND src_ip IS NOT NULL GROUP BY 1 ORDER BY c DESC LIMIT 10", p))
    section("시도된 계정 TOP 10", q(f"SELECT username, count(*) c FROM events WHERE {w} AND username IS NOT NULL GROUP BY 1 ORDER BY c DESC LIMIT 10", p))
    section("로그인 이후 행위", q(f"SELECT eventid, count(*) c FROM events WHERE {w} AND eventid LIKE '%%.action.%%' GROUP BY 1 ORDER BY c DESC", p))
    section("일자별 이벤트", q(f"SELECT to_char(ts, 'YYYY-MM-DD'), count(*) c FROM events WHERE {w} GROUP BY 1 ORDER BY 1", p))

    # 규칙 후보의 임계치는 관측 분포에서 나온다. 값을 먼저 정하고 분포를
    # 나중에 보면 근거가 "분포의 어디쯤"이라는 상대적인 것이 된다.
    print("\n-- 임계치 재료: 출발지별 15분 창 분포 --")
    for label, cond in [("로그인 실패 (R101)", "eventid LIKE '%%.login.failed'"),
                        ("404 응답 (R102)", "http_status = 404")]:
        rows = q(f"""
            WITH b AS (
                SELECT src_ip,
                       date_trunc('hour', ts)
                         + floor(extract(minute FROM ts) / 15) * interval '15 min' AS bucket,
                       count(*) AS c
                FROM events WHERE {w} AND {cond}
                GROUP BY 1, 2)
            SELECT count(*), max(c),
                   percentile_disc(0.5)  WITHIN GROUP (ORDER BY c),
                   percentile_disc(0.9)  WITHIN GROUP (ORDER BY c),
                   percentile_disc(0.95) WITHIN GROUP (ORDER BY c)
            FROM b""", p)
        n, mx, p50, p90, p95 = rows[0]
        if not n:
            print(f"   {label}: 관측 없음")
            continue
        print(f"   {label}: 창 {n}개 · 중앙 {p50} · p90 {p90} · p95 {p95} · 최대 {mx}")
    print()
    cur.close()


def main():
    ap = argparse.ArgumentParser(description="OpsLoop 웹 디코이 로그 파서 (PostgreSQL)")
    ap.add_argument("--logs", default=DEFAULT_GLOB)
    ap.add_argument("--db-url", dest="url", help="미지정 시 환경변수 DATABASE_URL 사용")
    ap.add_argument("--exclusions", default=DEFAULT_EXCLUSIONS)
    ap.add_argument("--load", action="store_true", help="로그를 읽어 적재")
    ap.add_argument("--report", action="store_true", help="요약 리포트 출력")
    ap.add_argument("--since")
    ap.add_argument("--until")
    args = ap.parse_args()

    if not args.load and not args.report:
        args.load = args.report = True

    conn = psycopg2.connect(db_url(args.url))

    if args.load:
        files = sorted(glob.glob(args.logs))
        if not files:
            sys.exit(f"로그 파일을 찾지 못했습니다: {args.logs}")
        exclusions = load_exclusions(args.exclusions)
        print(f"적재 대상 {len(files)}개 파일, 제외 IP {len(exclusions)}개")
        ins, dup, bad, nsess = load(conn, files, exclusions)
        print(f"  신규 {ins:,} / 중복 {dup:,} / 파싱실패 {bad:,}")
        print(f"  세션 {nsess:,} 건\n")

    if args.report:
        report(conn, args.since, args.until)

    conn.close()


if __name__ == "__main__":
    main()
