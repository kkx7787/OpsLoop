#!/usr/bin/env python3
"""
OpsLoop - 관문 방화벽 거부 기록 파서 (WBS 3.1 / 이슈 #15 / PostgreSQL)

gateway.log / gateway.log.YYYY-MM-DD 를 읽어 events 로 정규화한다. 구조는 디코이 파서와 같다.
로그 파일이 원장이고 DB 는 파생물이며, 재실행해도 중복이 쌓이지 않는다.

줄 모양 (rsyslog 가 커널 메시지 중 gw- 접두만 RFC3339 시각으로 쓴다. infra/aws/gateway/rsyslog-opsloop.conf)
  2026-09-22T01:02:03.123456+00:00 ip-10-0-1-10 kernel: gw-forward-drop IN=ens5 OUT=ens5 MAC=… SRC=203.0.113.7 \\
      DST=10.0.21.10 LEN=60 TOS=0x00 PREC=0x00 TTL=50 ID=1 DF PROTO=TCP SPT=54321 DPT=445 WINDOW=65535 RES=0x00 SYN URGP=0
  kernel: 뒤에 커널 가동 시각([ 1234.567890])이 붙어 있어도 된다 (rsyslog imklog 기본값).

접두 → eventid (방화벽 규칙 infra/aws/gateway/nftables.conf 의 log prefix 와 같이 바꾼다)
  gw-forward-drop  gateway.forward.drop   전달 거부 (인터넷 → DMZ 는 DNAT 된 22 · 23 · 8080 만 허용)
  gw-input-drop    gateway.input.drop     방화벽 자신으로의 유입 거부 (관리는 SSM 뿐이라 유입 포트가 없다)
  gw-egress        gateway.egress         DMZ → 인터넷 443 허용 기록 (이슈 #19 로 규칙이 없어져 새로 생기지 않는다. 옛 기록용)

디코이 파서와 다른 점
  - 줄이 JSON 이 아니라 커널 로그다. 시각 · 접두가 설계와 다른 줄(연도 없는 옛 syslog 형식 · 모르는 접두 ·
    잘려서 접두가 없는 줄)은 unmatched 로 세고 넘어간다. 접두 뒤가 잘린 줄은 있는 필드만으로 행을 만든다.
  - 세션이 없다. 세션 재집계를 하지 않는다.
  - 열 대응: src_ip=SRC · src_port=SPT · dst_port=DPT · protocol=PROTO(소문자) ·
    input='in=<IN> out=<OUT> dst=<DST>' · message=원문 512자. eventid 접두가 gateway. 라
    허니팟 규칙(cowrie.*)과 기준선(detector BASELINE_SENSORS)에 걸리지 않는다.
  - 출발지가 parser/exclusions.txt 에 있으면 provenance=fixture 다 (디코이와 같은 방식).

사용
  set -a; . /etc/opsloop/collector.env; set +a
  python3 parser/parse_gateway.py --load --files-from -       적재 실행기(opsloop-ingest)가 이렇게 부른다
  python3 parser/parse_gateway.py --report --since 2026-09-22
"""

import argparse
import glob
import hashlib
import ipaddress
import os
import re
import sys
from datetime import datetime, timedelta, timezone

try:
    import psycopg2
    from psycopg2.extras import execute_batch
except ImportError:
    sys.exit("psycopg2 가 필요합니다:  sudo apt-get install -y python3-psycopg2")

DEFAULT_GLOB = "/var/log/opsloop/gateway.log*"
DEFAULT_EXCLUSIONS = os.path.join(os.path.dirname(os.path.abspath(__file__)), "exclusions.txt")
SENSOR = "gateway"

# nft log prefix → eventid. 모르는 접두는 받지 않는다
EVENTIDS = {
    "gw-forward-drop": "gateway.forward.drop",
    "gw-input-drop": "gateway.input.drop",
    "gw-egress": "gateway.egress",
}

INSERT_EVENT = """
INSERT INTO events (line_hash, ts, eventid, session, src_ip, src_port, dst_port,
                    protocol, username, password, input, url, shasum,
                    provenance, message, http_method, http_status, user_agent, sensor)
VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
ON CONFLICT (line_hash) DO NOTHING
"""

INT4 = (-2**31, 2**31 - 1)
MAX_LINE = 4 * 1024 * 1024     # 이보다 긴 줄은 파싱하지 않는다 (메모리 보호. 정상 로그 한 줄은 수백 B 다)
BATCH = 5000   # 이만큼 모이면 DB 로 흘려보낸다. 큰 조각이 와도 메모리가 한없이 늘지 않는다

# fullmatch 로만 쓴다 ($ 는 끝 줄바꿈을 허용한다). 숫자는 [0-9] 로 쓴다 (\d 는 아랍-인도 숫자 등도 받는다)
TS_RE = re.compile(r"([0-9]{4})-([0-9]{2})-([0-9]{2})T([0-9]{2}):([0-9]{2}):([0-9]{2})(?:\.([0-9]{1,6}))?"
                   r"(Z|[+-][0-9]{2}:[0-9]{2})")
# "<RFC3339> <호스트> kernel: [<가동 시각>] <접두> <필드들>". 머리만 고정하고 필드는 있는 만큼 읽는다
HEAD_RE = re.compile(r"(\S+) (\S+) kernel: (?:\[ *[0-9]+\.[0-9]+\] )?(gw-[a-z-]+)(?: (.*))?")
# 커널 nft 기록의 KEY=VALUE. DF · SYN 처럼 값 없는 표시는 읽지 않는다
FIELD_RE = re.compile(r"(?:^| )([A-Z]+)=(\S*)")


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


def utc_ts(raw):
    """RFC3339 시각 → UTC. 연도 · 시간대가 없으면 비운다 (옛 syslog 형식 "Sep 22 01:02:03" 은 받지 않는다).

    fromisoformat 은 파이썬 판마다 받는 소수 자릿수가 달라 직접 푼다.
    """
    m = TS_RE.fullmatch(raw) if isinstance(raw, str) else None
    if not m:
        return None
    *parts, frac, off = m.groups()
    try:
        tz = timezone.utc
        if off != "Z":
            delta = timedelta(hours=int(off[1:3]), minutes=int(off[4:6]))
            tz = timezone(-delta if off[0] == "-" else delta)       # 24시간 이상이면 ValueError
        t = datetime(*map(int, parts), int((frac or "0").ljust(6, "0")), tzinfo=tz)
        return t.astimezone(timezone.utc)
    except (ValueError, OverflowError):      # 13월 · 60초 · 0001년에서 음의 시간대 등
        return None


def to_int(v):
    """정수 열(integer)에 들어갈 값. 커널 기록의 값은 ASCII 숫자뿐이다. 그 밖(빈 값 · 범위 밖)은 비운다."""
    if not isinstance(v, str) or not v.isascii() or not v.isdigit() or len(v) > 10:
        return None
    n = int(v)
    return n if INT4[0] <= n <= INT4[1] else None


def clip(v, n=None):
    """DB 에 넣을 글자 값. parse_decoy.clip 과 같은 규칙이다.

    - NUL(\\x00) 은 PostgreSQL 글자 열에 들어가지 못해 적재 전체가 실패한다. 지운다.
    - 짝 없는 서로게이트는 UTF-8 로 바꿀 수 없어 적재가 실패한다. 대체 문자로 바꾼다.
    - n 이 있으면 자른다.
    line_hash 는 원문 줄로 계산하므로 이 정리는 중복 판정에 영향이 없다.
    """
    if v is None:
        return None
    v = v.replace("\x00", "").encode("utf-8", "replace").decode("utf-8")
    return v if n is None or len(v) <= n else v[:n]


def ip_or_none(v):
    """inet 열에 들어갈 값. 주소가 아니면 비운다 (그대로 넘기면 적재 전체가 실패한다)."""
    if not isinstance(v, str):
        return None
    if "%" in v:                     # IPv6 영역 ID(fe80::1%eth0)는 inet 열이 받지 않는다
        return None
    try:
        ipaddress.ip_address(v)
    except ValueError:
        return None
    return v


def parse_line(line, exclusions):
    """앞뒤 공백을 뗀 한 줄 → events 행. 설계의 줄 모양이 아니면 None. DB 에 의존하지 않는다."""
    if len(line) > MAX_LINE:
        return None
    m = HEAD_RE.fullmatch(line)
    if not m:
        return None
    raw_ts, _host, prefix, rest = m.groups()
    ts, eventid = utc_ts(raw_ts), EVENTIDS.get(prefix)
    if ts is None or eventid is None:
        return None
    fields = {}
    for k, v in FIELD_RE.findall(rest or ""):
        fields.setdefault(k, v)          # 같은 키가 두 번 오면 앞 것
    src_ip = ip_or_none(fields.get("SRC"))
    proto = fields.get("PROTO")
    return (
        # 짝 없는 서로게이트가 섞여 와도 죽지 않게 surrogatepass 로 바꾼다. 정상 문자열에서는 encode("utf-8") 와 같은 바이트다
        hashlib.sha1(line.encode("utf-8", "surrogatepass")).hexdigest(),
        ts, eventid, None, src_ip,
        to_int(fields.get("SPT")), to_int(fields.get("DPT")),
        clip(proto.lower(), 32) if proto else None,
        None, None,
        clip(f"in={fields.get('IN', '')} out={fields.get('OUT', '')} dst={fields.get('DST', '')}", 256),
        None, None,
        "fixture" if src_ip in exclusions else "real",
        clip(line, 512),
        None, None, None, SENSOR,
    )


def parse_lines(files, exclusions, stats=None):
    """파일을 읽어 적재할 행을 하나씩 내준다. DB 에 의존하지 않는다.

    stats["unmatched"] 에 설계의 줄 모양이 아닌 줄 수를 센다. 한 파일 전체를 메모리에 올리지 않는다.
    """
    stats = stats if stats is not None else {}
    stats.setdefault("unmatched", 0)
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
                row = parse_line(line, exclusions)
                if row is None:
                    stats["unmatched"] += 1
                    continue
                yield row


def load(conn, files, exclusions):
    stats = {"unmatched": 0}
    total = 0
    with conn.cursor() as cur:
        cur.execute("SELECT count(*) FROM events WHERE sensor = %s", (SENSOR,))
        before = cur.fetchone()[0]
        batch = []
        for row in parse_lines(files, exclusions, stats):
            batch.append(row)
            if len(batch) >= BATCH:
                execute_batch(cur, INSERT_EVENT, batch, page_size=500)
                total += len(batch)
                batch = []
        if batch:
            execute_batch(cur, INSERT_EVENT, batch, page_size=500)
            total += len(batch)
        cur.execute("SELECT count(*) FROM events WHERE sensor = %s", (SENSOR,))
        after = cur.fetchone()[0]
    conn.commit()
    inserted = after - before
    return inserted, total - inserted, stats["unmatched"]


def reclassify(conn, exclusions):
    """이미 적재된 행의 출처를 제외 목록에 맞춰 다시 매긴다. 이 센서의 행만 건드린다 (parse_decoy 와 같다)."""
    with conn.cursor() as cur:
        if exclusions:
            cur.execute("""UPDATE events SET provenance = 'fixture'
                           WHERE sensor = %s AND provenance = 'real'
                             AND host(src_ip) = ANY(%s)""",
                        (SENSOR, list(exclusions)))
            to_fixture = cur.rowcount
            cur.execute("""UPDATE events SET provenance = 'real'
                           WHERE sensor = %s AND provenance = 'fixture'
                             AND NOT (host(src_ip) = ANY(%s))""",
                        (SENSOR, list(exclusions)))
        else:
            to_fixture = 0
            cur.execute("""UPDATE events SET provenance = 'real'
                           WHERE sensor = %s AND provenance = 'fixture'""", (SENSOR,))
        to_real = cur.rowcount
    conn.commit()
    return to_fixture, to_real


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

    def q(sql, params=()):
        cur.execute(sql, params)
        return cur.fetchall()

    span = q(f"SELECT min(ts), max(ts), count(*) FROM events WHERE {w}", p)[0]
    print("=" * 62)
    print(" OpsLoop  관문 방화벽 기록 요약  (provenance = real)")
    print("=" * 62)
    if not span[2]:
        print(" 적재된 이벤트가 없습니다.")
        cur.close()
        return
    print(f" 기간   : {span[0]}  ~  {span[1]}")
    print(f" 이벤트 : {span[2]:,} 건")
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

    section("이벤트 유형", q(f"SELECT eventid, count(*) c FROM events WHERE {w} GROUP BY 1 ORDER BY c DESC", p))
    section("전달 거부 목적지 포트 TOP 15", q(f"SELECT protocol || '/' || dst_port, count(*) c FROM events WHERE {w} "
                                          f"AND eventid = 'gateway.forward.drop' AND dst_port IS NOT NULL GROUP BY 1 ORDER BY c DESC LIMIT 15", p))
    section("유입 거부 목적지 포트 TOP 10", q(f"SELECT protocol || '/' || dst_port, count(*) c FROM events WHERE {w} "
                                          f"AND eventid = 'gateway.input.drop' AND dst_port IS NOT NULL GROUP BY 1 ORDER BY c DESC LIMIT 10", p))
    section("출발지 TOP 10", q(f"SELECT src_ip, count(*) c FROM events WHERE {w} AND src_ip IS NOT NULL GROUP BY 1 ORDER BY c DESC LIMIT 10", p))
    # DMZ 에서 밖으로 나간 443 은 허용하되 기록한다. 목적지가 SSM · S3 가 아니면 센서가 경유지로 쓰인 것이다
    section("DMZ 유출(443) 출발지 → 목적지 TOP 10", q(f"SELECT host(src_ip) || ' → ' || input, count(*) c FROM events WHERE {w} "
                                                   f"AND eventid = 'gateway.egress' GROUP BY 1 ORDER BY c DESC LIMIT 10", p), width=70)
    section("일자별 이벤트", q(f"SELECT to_char(ts, 'YYYY-MM-DD'), count(*) c FROM events WHERE {w} GROUP BY 1 ORDER BY 1", p))
    print()
    cur.close()


def read_file_list(src):
    fh = sys.stdin if src == "-" else open(src, encoding="utf-8")
    with fh:
        return [line.rstrip("\n") for line in fh if line.strip()]


def main():
    ap = argparse.ArgumentParser(description="OpsLoop 관문 방화벽 거부 기록 파서 (PostgreSQL)")
    ap.add_argument("--logs", default=DEFAULT_GLOB)
    ap.add_argument("--files-from", help="적재할 파일 목록 (한 줄에 하나, '-' 는 표준 입력). --logs 대신 쓴다")
    ap.add_argument("--db-url", dest="url", help="미지정 시 환경변수 DATABASE_URL 사용")
    ap.add_argument("--exclusions", default=DEFAULT_EXCLUSIONS)
    ap.add_argument("--load", action="store_true", help="로그를 읽어 적재")
    ap.add_argument("--report", action="store_true", help="요약 리포트 출력")
    ap.add_argument("--reclassify", action="store_true",
                    help="이미 적재된 행의 출처를 제외 목록에 맞춰 다시 매김")
    ap.add_argument("--since")
    ap.add_argument("--until")
    args = ap.parse_args()

    if not args.load and not args.report and not args.reclassify:
        args.load = args.report = True

    conn = psycopg2.connect(db_url(args.url))

    if args.reclassify:
        ex = load_exclusions(args.exclusions)
        fx, rl = reclassify(conn, ex)
        print(f"재분류: 실측 -> 제외 {fx:,} 건 · 제외 -> 실측 {rl:,} 건 "
              f"(제외 IP {len(ex)}개)\n")

    if args.load:
        files = read_file_list(args.files_from) if args.files_from else sorted(glob.glob(args.logs))
        if not files:
            sys.exit(f"로그 파일을 찾지 못했습니다: {args.files_from or args.logs}")
        exclusions = load_exclusions(args.exclusions)
        print(f"적재 대상 {len(files)}개 파일, 제외 IP {len(exclusions)}개")
        ins, dup, bad = load(conn, files, exclusions)
        print(f"  신규 {ins:,} / 중복 {dup:,} / 형식 불일치 {bad:,}\n")

    if args.report:
        report(conn, args.since, args.until)

    conn.close()


if __name__ == "__main__":
    main()
