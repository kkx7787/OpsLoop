#!/usr/bin/env python3
"""
OpsLoop - Cowrie 로그 파서 (WBS 2.2 / PostgreSQL)

cowrie.json / cowrie.json.YYYY-MM-DD 를 읽어 PostgreSQL 로 정규화한다.

설계 원칙
  - 로그 파일이 원장이고 DB 는 파생물이다. DB 를 지워도 다시 만들 수 있다.
  - 시간 범위를 인자로 받는다. 코드에 기간을 박지 않는다.
  - provenance 로 실측(real)과 자체 테스트(fixture)를 분리한다.
  - 재실행해도 중복이 쌓이지 않는다 (원본 라인 해시 기준).

접속 정보는 환경변수 DATABASE_URL 또는 --db-url 로 준다.
  export DATABASE_URL='postgresql://opsloop:PASSWORD@10.0.0.5:5432/opsloop'

사용
  python3 parse_cowrie.py --load
  python3 parse_cowrie.py --report --since 2026-09-05 --until 2026-09-06
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

DEFAULT_GLOB = "/opt/cowrie/log/cowrie.json*"
DEFAULT_EXCLUSIONS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exclusions.txt")

INSERT_EVENT = """
INSERT INTO events (line_hash, ts, eventid, session, src_ip, src_port, dst_port,
                    protocol, username, password, input, url, shasum,
                    duration_ms, provenance, message)
VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
ON CONFLICT (line_hash) DO NOTHING
"""

REBUILD_SESSIONS = """
INSERT INTO sessions (session, src_ip, protocol, first_ts, last_ts, duration_ms,
                      login_attempts, login_success, command_count, downloads, provenance)
SELECT
    session,
    max(src_ip),
    max(protocol),
    min(ts),
    max(ts),
    max(duration_ms),
    count(*) FILTER (WHERE eventid IN ('cowrie.login.success', 'cowrie.login.failed')),
    bool_or(eventid = 'cowrie.login.success'),
    count(*) FILTER (WHERE eventid = 'cowrie.command.input'),
    count(*) FILTER (WHERE eventid LIKE 'cowrie.session.file_%%'),
    max(provenance)
FROM events
WHERE session IS NOT NULL
GROUP BY session
ON CONFLICT (session) DO UPDATE SET
    src_ip         = EXCLUDED.src_ip,
    protocol       = EXCLUDED.protocol,
    first_ts       = EXCLUDED.first_ts,
    last_ts        = EXCLUDED.last_ts,
    duration_ms    = EXCLUDED.duration_ms,
    login_attempts = EXCLUDED.login_attempts,
    login_success  = EXCLUDED.login_success,
    command_count  = EXCLUDED.command_count,
    downloads      = EXCLUDED.downloads,
    provenance     = EXCLUDED.provenance
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
        return datetime.fromisoformat(raw.replace("Z", "+00:00")).astimezone(timezone.utc)
    except (ValueError, AttributeError):
        return None


def to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def load(conn, files, exclusions):
    rows = []
    malformed = 0

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
                ts = norm_ts(ev.get("timestamp"))
                if not eventid or ts is None:
                    malformed += 1
                    continue
                src_ip = ev.get("src_ip")
                rows.append((
                    hashlib.sha1(line.encode("utf-8")).hexdigest(),
                    ts, eventid, ev.get("session"), src_ip,
                    to_int(ev.get("src_port")), to_int(ev.get("dst_port")),
                    ev.get("protocol"), ev.get("username"), ev.get("password"),
                    ev.get("input"), ev.get("url"), ev.get("shasum"),
                    to_int(ev.get("duration_ms")),
                    "fixture" if src_ip in exclusions else "real",
                    ev.get("message"),
                ))

    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM events")
        before = cur.fetchone()[0]
        execute_batch(cur, INSERT_EVENT, rows, page_size=500)
        cur.execute("SELECT count(*) FROM events")
        after = cur.fetchone()[0]
        cur.execute(REBUILD_SESSIONS)
        cur.execute("SELECT count(*) FROM sessions")
        n_sessions = cur.fetchone()[0]
    conn.commit()

    inserted = after - before
    return inserted, len(rows) - inserted, malformed, n_sessions


def where_range(since, until, col):
    clauses, params = ["provenance = 'real'"], []
    if since:
        clauses.append(f"{col} >= %s"); params.append(since)
    if until:
        clauses.append(f"{col} < %s"); params.append(until)
    return " AND ".join(clauses), params


def report(conn, since, until):
    cur = conn.cursor()
    w, p = where_range(since, until, "ts")
    ws, ps = where_range(since, until, "first_ts")

    def q(sql, params=()):
        cur.execute(sql, params)
        return cur.fetchall()

    span = q(f"SELECT min(ts), max(ts), count(*) FROM events WHERE {w}", p)[0]
    print("=" * 62)
    print(" OpsLoop  허니팟 수집 요약  (provenance = real)")
    print("=" * 62)
    print(f" 기간   : {span[0]}  ~  {span[1]}")
    print(f" 이벤트 : {span[2]:,} 건")

    n_sess = q(f"SELECT count(*) FROM sessions WHERE {ws}", ps)[0][0]
    n_ip = q(f"SELECT count(DISTINCT src_ip) FROM events WHERE {w}", p)[0][0]
    print(f" 세션   : {n_sess:,} 건")
    print(f" 출발지 : {n_ip:,} 개 IP")

    fixture = q("SELECT count(*) FROM events WHERE provenance = 'fixture'")[0][0]
    if fixture:
        print(f" (제외된 자체 테스트 이벤트 {fixture} 건)")

    def section(title, rows, width=34):
        print(f"\n-- {title} --")
        if not rows:
            print("   (없음)")
            return
        for name, cnt in rows:
            label = str(name) if name is not None else "(null)"
            if len(label) > width:
                label = label[: width - 1] + "…"
            print(f"   {cnt:>6,}  {label}")

    section("이벤트 유형",
            q(f"SELECT eventid, count(*) c FROM events WHERE {w} GROUP BY 1 ORDER BY c DESC LIMIT 12", p))
    section("공격 출발지 TOP 10",
            q(f"SELECT src_ip, count(*) c FROM events WHERE {w} AND src_ip IS NOT NULL GROUP BY 1 ORDER BY c DESC LIMIT 10", p))
    section("시도된 계정 TOP 10",
            q(f"SELECT username, count(*) c FROM events WHERE {w} AND username IS NOT NULL GROUP BY 1 ORDER BY c DESC LIMIT 10", p))
    section("시도된 비밀번호 TOP 10",
            q(f"SELECT password, count(*) c FROM events WHERE {w} AND password IS NOT NULL GROUP BY 1 ORDER BY c DESC LIMIT 10", p))
    section("침투 후 실행 명령 TOP 10",
            q(f"SELECT input, count(*) c FROM events WHERE {w} AND eventid = 'cowrie.command.input' GROUP BY 1 ORDER BY c DESC LIMIT 10", p), width=48)
    section("일자별 이벤트",
            q(f"SELECT to_char(ts, 'YYYY-MM-DD'), count(*) c FROM events WHERE {w} GROUP BY 1 ORDER BY 1", p))
    section("시간대별 이벤트 (UTC)",
            q(f"SELECT to_char(ts, 'HH24') || '시', count(*) c FROM events WHERE {w} GROUP BY 1 ORDER BY 1", p))

    ok, tot = q(f"SELECT count(*) FILTER (WHERE login_success), count(*) FROM sessions WHERE {ws}", ps)[0]
    if tot:
        print("\n-- 로그인 --")
        print(f"   성공 세션 {ok:,} / 전체 {tot:,}  ({100 * ok / tot:.1f}%)")
    deep = q(f"SELECT count(*) FROM sessions WHERE {ws} AND command_count > 0", ps)[0][0]
    print(f"   명령을 실행한 세션 {deep:,} 건\n")
    cur.close()


def main():
    ap = argparse.ArgumentParser(description="OpsLoop Cowrie 로그 파서 (PostgreSQL)")
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