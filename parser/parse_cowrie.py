#!/usr/bin/env python3
"""
OpsLoop - Cowrie 로그 파서 (WBS 2.2)

cowrie.json / cowrie.json.YYYY-MM-DD 를 읽어 SQLite로 정규화한다.
표준 라이브러리만 사용한다.

설계 원칙
  - 시간 범위를 인자로 받는다. 코드에 기간을 박지 않는다.
    (리플레이 평가 evaluate_rules(rule_version, start, end) 를 위한 전제)
  - provenance 로 실측(real)과 자체 테스트(fixture)를 분리한다.
  - 재실행해도 중복이 쌓이지 않는다 (raw 라인 해시 기준 UPSERT).

사용
  python3 parse_cowrie.py --load
  python3 parse_cowrie.py --report
  python3 parse_cowrie.py --report --since 2026-09-05 --until 2026-09-06
"""

import argparse
import glob
import hashlib
import json
import os
import sqlite3
import sys
from collections import Counter
from datetime import datetime, timezone

DEFAULT_GLOB = "/opt/cowrie/log/cowrie.json*"
DEFAULT_DB = os.path.expanduser("~/opsloop/data/opsloop.db")
DEFAULT_EXCLUSIONS = os.path.expanduser("~/opsloop/parser/exclusions.txt")

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
    line_hash   TEXT PRIMARY KEY,
    ts          TEXT NOT NULL,
    eventid     TEXT NOT NULL,
    session     TEXT,
    src_ip      TEXT,
    src_port    INTEGER,
    dst_port    INTEGER,
    protocol    TEXT,
    username    TEXT,
    password    TEXT,
    input       TEXT,
    url         TEXT,
    shasum      TEXT,
    duration_ms INTEGER,
    provenance  TEXT NOT NULL DEFAULT 'real',
    message     TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts      ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_eventid ON events(eventid);
CREATE INDEX IF NOT EXISTS idx_events_src_ip  ON events(src_ip);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session);

CREATE TABLE IF NOT EXISTS sessions (
    session        TEXT PRIMARY KEY,
    src_ip         TEXT,
    protocol       TEXT,
    first_ts       TEXT,
    last_ts        TEXT,
    duration_ms    INTEGER,
    login_attempts INTEGER DEFAULT 0,
    login_success  INTEGER DEFAULT 0,
    command_count  INTEGER DEFAULT 0,
    downloads      INTEGER DEFAULT 0,
    provenance     TEXT NOT NULL DEFAULT 'real'
);
CREATE INDEX IF NOT EXISTS idx_sessions_first_ts ON sessions(first_ts);
CREATE INDEX IF NOT EXISTS idx_sessions_src_ip   ON sessions(src_ip);
"""


def load_exclusions(path):
    """자체 테스트 접속 IP 목록. 없으면 빈 집합."""
    ips = set()
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                if line:
                    ips.add(line)
    return ips


def norm_ts(raw):
    """Cowrie 타임스탬프를 ISO8601(UTC)로 정규화. 실패하면 원문 유지."""
    if not raw:
        return None
    try:
        dt = datetime.fromisoformat(raw.replace("Z", "+00:00"))
        return dt.astimezone(timezone.utc).isoformat(timespec="microseconds")
    except ValueError:
        return raw


def to_int(v):
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def load(conn, files, exclusions):
    cur = conn.cursor()
    inserted = skipped = malformed = 0

    for path in files:
        try:
            fh = open(path, encoding="utf-8", errors="replace")
        except OSError as e:
            print(f"  [skip] {path}: {e}", file=sys.stderr)
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
                if not eventid or not ts:
                    malformed += 1
                    continue

                src_ip = ev.get("src_ip")
                prov = "fixture" if src_ip in exclusions else "real"
                h = hashlib.sha1(line.encode("utf-8")).hexdigest()

                cur.execute(
                    """INSERT OR IGNORE INTO events
                       (line_hash, ts, eventid, session, src_ip, src_port, dst_port,
                        protocol, username, password, input, url, shasum,
                        duration_ms, provenance, message)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (
                        h, ts, eventid, ev.get("session"), src_ip,
                        to_int(ev.get("src_port")), to_int(ev.get("dst_port")),
                        ev.get("protocol"), ev.get("username"), ev.get("password"),
                        ev.get("input"), ev.get("url"), ev.get("shasum"),
                        to_int(ev.get("duration_ms")), prov, ev.get("message"),
                    ),
                )
                if cur.rowcount:
                    inserted += 1
                else:
                    skipped += 1

    conn.commit()
    return inserted, skipped, malformed


def rebuild_sessions(conn):
    """events 에서 세션 단위 요약을 다시 만든다. 멱등하다."""
    cur = conn.cursor()
    cur.execute("DELETE FROM sessions")
    cur.execute(
        """
        INSERT INTO sessions
            (session, src_ip, protocol, first_ts, last_ts, duration_ms,
             login_attempts, login_success, command_count, downloads, provenance)
        SELECT
            session,
            MAX(src_ip),
            MAX(protocol),
            MIN(ts),
            MAX(ts),
            MAX(duration_ms),
            SUM(eventid IN ('cowrie.login.success','cowrie.login.failed')),
            MAX(eventid = 'cowrie.login.success'),
            SUM(eventid = 'cowrie.command.input'),
            SUM(eventid = 'cowrie.session.file_download'),
            MAX(provenance)
        FROM events
        WHERE session IS NOT NULL
        GROUP BY session
        """
    )
    conn.commit()
    return cur.rowcount


def where_range(since, until, col="ts"):
    clauses, params = ["provenance = 'real'"], []
    if since:
        clauses.append(f"{col} >= ?")
        params.append(since)
    if until:
        clauses.append(f"{col} < ?")
        params.append(until)
    return " AND ".join(clauses), params


def report(conn, since, until):
    cur = conn.cursor()
    w, p = where_range(since, until)
    ws, ps = where_range(since, until, col="first_ts")

    def q(sql, params=()):
        return cur.execute(sql, params).fetchall()

    span = q(f"SELECT MIN(ts), MAX(ts), COUNT(*) FROM events WHERE {w}", p)[0]
    print("=" * 62)
    print(" OpsLoop  허니팟 수집 요약  (provenance = real)")
    print("=" * 62)
    print(f" 기간   : {span[0]}  ~  {span[1]}")
    print(f" 이벤트 : {span[2]:,} 건")

    n_sess = q(f"SELECT COUNT(*) FROM sessions WHERE {ws}", ps)[0][0]
    n_ip = q(f"SELECT COUNT(DISTINCT src_ip) FROM events WHERE {w}", p)[0][0]
    print(f" 세션   : {n_sess:,} 건")
    print(f" 출발지 : {n_ip:,} 개 IP")

    fixture = cur.execute("SELECT COUNT(*) FROM events WHERE provenance='fixture'").fetchone()[0]
    if fixture:
        print(f" (제외된 자체 테스트 이벤트 {fixture} 건)")

    def section(title, rows, width=34):
        print(f"\n-- {title} --")
        if not rows:
            print("   (없음)")
            return
        for name, cnt in rows:
            label = (name if name is not None else "(null)")
            if len(label) > width:
                label = label[: width - 1] + "…"
            print(f"   {cnt:>6,}  {label}")

    section("이벤트 유형",
            q(f"SELECT eventid, COUNT(*) c FROM events WHERE {w} GROUP BY 1 ORDER BY c DESC LIMIT 12", p))
    section("공격 출발지 TOP 10",
            q(f"SELECT src_ip, COUNT(*) c FROM events WHERE {w} AND src_ip IS NOT NULL GROUP BY 1 ORDER BY c DESC LIMIT 10", p))
    section("시도된 계정 TOP 10",
            q(f"SELECT username, COUNT(*) c FROM events WHERE {w} AND username IS NOT NULL GROUP BY 1 ORDER BY c DESC LIMIT 10", p))
    section("시도된 비밀번호 TOP 10",
            q(f"SELECT password, COUNT(*) c FROM events WHERE {w} AND password IS NOT NULL GROUP BY 1 ORDER BY c DESC LIMIT 10", p))
    section("침투 후 실행 명령 TOP 10",
            q(f"SELECT input, COUNT(*) c FROM events WHERE {w} AND eventid='cowrie.command.input' GROUP BY 1 ORDER BY c DESC LIMIT 10", p), width=48)
    section("일자별 이벤트",
            q(f"SELECT substr(ts,1,10) d, COUNT(*) c FROM events WHERE {w} GROUP BY 1 ORDER BY 1", p))
    section("시간대별 이벤트 (UTC)",
            q(f"SELECT substr(ts,12,2) || '시', COUNT(*) c FROM events WHERE {w} GROUP BY 1 ORDER BY 1", p))

    ok, tot = q(f"SELECT SUM(login_success), COUNT(*) FROM sessions WHERE {ws}", ps)[0]
    if tot:
        print(f"\n-- 로그인 --")
        print(f"   성공 세션 {ok or 0:,} / 전체 {tot:,}  ({100*(ok or 0)/tot:.1f}%)")

    deep = q(f"SELECT COUNT(*) FROM sessions WHERE {ws} AND command_count > 0", ps)[0][0]
    print(f"   명령을 실행한 세션 {deep:,} 건")
    print()


def main():
    ap = argparse.ArgumentParser(description="OpsLoop Cowrie 로그 파서")
    ap.add_argument("--logs", default=DEFAULT_GLOB, help=f"로그 글롭 (기본 {DEFAULT_GLOB})")
    ap.add_argument("--db", default=DEFAULT_DB, help=f"SQLite 경로 (기본 {DEFAULT_DB})")
    ap.add_argument("--exclusions", default=DEFAULT_EXCLUSIONS, help="자체 테스트 IP 목록 파일")
    ap.add_argument("--load", action="store_true", help="로그를 읽어 DB에 적재")
    ap.add_argument("--report", action="store_true", help="요약 리포트 출력")
    ap.add_argument("--since", help="시작 시각 (예: 2026-09-05)")
    ap.add_argument("--until", help="종료 시각, 미포함 (예: 2026-09-07)")
    args = ap.parse_args()

    if not args.load and not args.report:
        args.load = args.report = True

    os.makedirs(os.path.dirname(os.path.abspath(args.db)), exist_ok=True)
    conn = sqlite3.connect(args.db)
    conn.executescript(SCHEMA)

    if args.load:
        files = sorted(glob.glob(args.logs))
        if not files:
            print(f"로그 파일을 찾지 못했습니다: {args.logs}", file=sys.stderr)
            sys.exit(1)
        exclusions = load_exclusions(args.exclusions)
        print(f"적재 대상 {len(files)}개 파일, 제외 IP {len(exclusions)}개")
        ins, dup, bad = load(conn, files, exclusions)
        n = rebuild_sessions(conn)
        print(f"  신규 {ins:,} / 중복 {dup:,} / 파싱실패 {bad:,}")
        print(f"  세션 재구성 {n:,} 건\n")

    if args.report:
        report(conn, args.since, args.until)

    conn.close()


if __name__ == "__main__":
    main()
