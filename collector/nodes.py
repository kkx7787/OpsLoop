#!/usr/bin/env python3
"""관제 대상 노드 관리 CLI (이슈 #11 · WBS 3.4.3).

데이터 노드에서 root 로 돌린다. S-13 화면이 생기기 전까지 발급 · 폐기 · 첫 수신 확인은 이것으로 한다.
DB 에는 등록 토큰과 에이전트 키의 sha256 만 들어간다. 원문은 어디에도 저장하지 않는다.

명령
  issue <노드> --host H --addr A --logs nginx,auth,metrics [--ttl 3600]
      nodes 행을 만들거나 고치고(새 행은 pending) 1회용 등록 토큰을 발급한다.
      토큰은 표준 출력에 한 줄로만 낸다. 안내는 모두 표준 오류로 가므로 그대로 변수에 담을 수 있다.
        export OPSLOOP_ENROLL_TOKEN="$(ssh data01 sudo /opt/opsloop/app/collector/nodes.py issue web-01 ...)"
      같은 노드의 쓰지 않은 이전 토큰은 취소한다 (살아 있는 등록 토큰은 노드마다 하나).
      이미 있는 노드는 호스트 · 주소 · 로그만 고친다. 새 키가 등록되기 전까지 지금 키가 그대로 쓰인다.
  cancel <노드>
      쓰지 않은 등록 토큰을 모두 취소한다.
  revoke <노드>
      status 를 revoked 로 바꾼다. 키 해시는 남겨 관문이 거부 사유를 revoked 로 적게 한다.
      쓰지 않은 등록 토큰도 취소한다. 다시 쓰려면 새 키로 issue → 자기 등록을 다시 한다.
  list
      노드 목록. 키는 지문(sha256 앞 8자)만 보인다.
  check <노드> --nonce N [--wait 초] [--kick]
      node_first_receipt(노드, N) 를 5초마다 보고, 네 단계가 모두 통과하거나 --wait 가 지나면 끝난다.
      --kick 은 3단계를 통과한 뒤 opsloop-agents 를 한 번 당겨 탐지 실행(4단계)을 앞당긴다.

issue · cancel · revoke 는 관리 원장($OPSLOOP_ADMIN_DIR/admin-YYYY-MM-DD.jsonl, UTC 날짜)에 한 줄을 남긴다.
원장에 쓰지 못하면 DB 변경 · 토큰 출력은 그대로 하고 종료 코드 3 으로 알린다.
누가 했는지는 명령마다 issued_by(SUDO_USER 또는 USER)에 둔다 (다리의 parse_collector 가 username 으로 읽는다).
토큰과 해시는 쓰지 않는다. 원장에 쓰지 못해도 DB(node_enrollments)에 발급 기록이 있으므로 경고만 한다.
issue · revoke 뒤에는 관문에 HUP 을 보내 캐시를 바로 다시 읽게 한다 (실패해도 계속한다).

DB 잠금 순서는 nodes → node_enrollments 다. enroll_node() 도 같은 순서로 잠가 교착이 생기지 않는다.

종료 코드
  check   0 모두 통과 · 1~4 처음 통과하지 못한 단계 · 5 DB 접속 · 조회 실패
  그 밖   0 정상 · 1 실패 (노드 없음 · DB 오류)
  공통    64 인자 오류 (argparse 기본값 2 는 check 의 2단계와 겹치므로 쓰지 않는다)

환경변수
  DATABASE_URL     없으면 OPSLOOP_DB_ENV 파일에서 읽는다 (sudo 는 환경을 지우므로 보통 파일에서 온다)
  OPSLOOP_DB_ENV   KEY=VALUE 파일 (기본 /etc/opsloop/collector.env). 셸로 읽지 않는다
  OPSLOOP_ADMIN_DIR 관리 원장 폴더 (기본 /var/lib/opsloop/admin. 관문은 이 폴더에 쓸 수 없다)
"""
import argparse
import grp
import hashlib
import ipaddress
import json
import os
import pwd
import re
import secrets
import stat
import subprocess
import sys
import time
from datetime import datetime, timezone

try:
    import psycopg2
    DB_ERRORS = (psycopg2.Error,)
except ImportError:              # --help 와 시험은 psycopg2 없이도 돈다
    psycopg2 = None
    DB_ERRORS = ()

# 소유자 역할의 접속 정보. root 만 읽는다. collector.env 는 이제 적재 역할(opsloop_ingest)이라 발급 · 폐기를 못 한다 (이슈 #31)
DB_ENV = "/etc/opsloop/admin.env"
# 관리 원장은 관문 폴더가 아니라 root 만 쓰는 폴더에 둔다. 관문(네트워크에 노출된 프로세스)이 장악돼도
# 발급 · 취소 · 폐기 기록을 지우거나 가로채지 못한다. 다리(opsloop-pull 그룹)는 읽기만 한다
ADMIN_DIR = "/var/lib/opsloop/admin"
LEDGER_GROUP = "opsloop-pull"    # 다리(pull_loki.py)가 관리 원장을 읽는다
GATE_UNIT = "opsloop-gate"
AGENTS_UNIT = "opsloop-agents.service"

LOGS = ("nginx", "auth", "metrics")
# node_id 는 Loki 테넌트이자 events.sensor 값이다. 기존 발생원 이름을 쓰면
# 허니팟 집계 · 기준선 · 자기 탐지(R202)에 관제 대상 이벤트가 섞인다
NODE_RE = re.compile(r"[a-z0-9][a-z0-9-]{0,62}")
RESERVED = {"cowrie", "decoy", "gateway", "console", "collector", "puller"}   # gateway 는 관문 방화벽 거부 기록(#15)
HOST_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")
NONCE_RE = re.compile(r"[A-Za-z0-9._-]{1,128}")
TTL_MIN, TTL_MAX = 60, 86400
WAIT_MAX = 3600
POLL = 5

EXIT_LEDGER, EXIT_DB, EXIT_USAGE = 3, 5, 64

_JOURNAL = bool(os.environ.get("JOURNAL_STREAM"))
_CTRL = re.compile(r"[\x00-\x1f\x7f]")


class DBError(Exception):
    pass


def safe(v):
    """DB · 명령 출력에서 온 값을 로그에 쓸 때. 줄바꿈으로 가짜 로그 줄을 만들지 못하게 한다."""
    return _CTRL.sub(lambda m: f"\\x{ord(m.group()):02x}", str(v))[:300]


def log(msg, level=6):
    """안내는 모두 표준 오류로 낸다. 표준 출력은 issue 의 토큰 한 줄과 list · check 결과만 쓴다."""
    print(f"<{level}>{msg}" if _JOURNAL else msg, file=sys.stderr, flush=True)


def read_env(path):
    """KEY=VALUE 파일. 셸로 읽지 않는다 (값에 셸 문자가 있어도 실행되지 않는다)."""
    out = {}
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                out[k.strip()] = v.strip()
    return out


def database_url():
    url = os.environ.get("DATABASE_URL")
    if url:
        return url
    path = os.environ.get("OPSLOOP_DB_ENV", DB_ENV)
    try:
        return read_env(path).get("DATABASE_URL")
    except OSError as e:
        raise DBError(f"DB 접속 정보를 읽지 못했다: {path} ({e.strerror})")


def connect(autocommit=False):
    if psycopg2 is None:
        raise DBError("psycopg2 가 필요합니다:  sudo apt-get install -y python3-psycopg2")
    url = database_url()
    if not url:
        raise DBError("DATABASE_URL 이 없습니다 (환경변수나 OPSLOOP_DB_ENV 파일)")
    conn = psycopg2.connect(url, connect_timeout=10, application_name="opsloop-nodes")
    conn.autocommit = autocommit
    return conn


def sha256_hex(s):
    return hashlib.sha256(s.encode("utf-8")).hexdigest()


def new_token():
    return "olE_" + secrets.token_urlsafe(32)


def operator():
    """누가 했는지. sudo 로 돌리면 원래 사용자다."""
    name = os.environ.get("SUDO_USER") or os.environ.get("USER")
    if not name:
        try:
            name = pwd.getpwuid(os.getuid()).pw_name
        except KeyError:
            name = str(os.getuid())
    return re.sub(r"[^A-Za-z0-9._@-]", "?", name)[:64]


def utc_iso(dt):
    return dt.astimezone(timezone.utc).isoformat() if dt else None


def fmt_ts(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M:%SZ") if dt else "-"


# ----------------------------------------------------------------------
#  관리 원장 · systemd
# ----------------------------------------------------------------------

def ledger(event, fields, now=None):
    """관리 원장에 한 줄을 더한다. 쓰면 True.

    원장 폴더(root:opsloop-pull 2750)에는 root 만 쓴다. 그래도 링크는 따라가지 않고, FIFO 에 걸려 멈추지 않게
    O_NONBLOCK 으로 열며, 내가 만든 일반 파일에만 쓴다.
    """
    now = now or datetime.now(timezone.utc)
    rec = {"ts": now.isoformat(timespec="microseconds"), "eventid": f"collector.admin.{event}"}
    rec.update(fields)
    data = (json.dumps(rec, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    path = os.path.join(os.environ.get("OPSLOOP_ADMIN_DIR", ADMIN_DIR), f"admin-{now:%Y-%m-%d}.jsonl")
    try:
        fd = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC, 0o640)
    except OSError as e:
        log(f"관리 원장에 쓰지 못했다: {safe(path)} ({safe(e.strerror)})", 4)
        return False
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_uid != os.geteuid() or st.st_nlink != 1:
            log(f"관리 원장에 쓰지 않음: {safe(path)} 가 내가 만든 일반 파일이 아니다 (변조 의심)", 3)
            return False
        if os.geteuid() == 0:
            try:
                os.fchown(fd, 0, grp.getgrnam(LEDGER_GROUP).gr_gid)
            except KeyError:
                log(f"{LEDGER_GROUP} 그룹이 없어 관리 원장 그룹을 바꾸지 못했다", 4)
        os.fchmod(fd, 0o640)
        os.write(fd, data)          # 한 번에 쓴다 (O_APPEND 라 다른 줄과 섞이지 않는다)
        os.fsync(fd)
        return True
    except OSError as e:
        log(f"관리 원장에 쓰지 못했다: {safe(path)} ({safe(e.strerror)})", 4)
        return False
    finally:
        os.close(fd)


def systemctl(args):
    """systemctl 을 부른다. 성공하면 True. 실패는 경고만 한다."""
    try:
        r = subprocess.run(["systemctl", *args], capture_output=True, text=True, timeout=15)
    except (OSError, subprocess.TimeoutExpired) as e:
        log(f"systemctl {' '.join(args)} 실패: {safe(e)}", 4)
        return False
    if r.returncode != 0:
        log(f"systemctl {' '.join(args)} 실패 (종료 코드 {r.returncode}): {safe(r.stderr.strip())}", 4)
        return False
    return True


def hup_gate():
    if systemctl(["kill", "-s", "HUP", GATE_UNIT]):
        log("관문에 HUP 을 보냈다 (캐시를 바로 다시 읽는다)")
    else:
        log("관문에 HUP 을 보내지 못했다. 캐시는 15초 안에 저절로 갱신된다", 4)


# ----------------------------------------------------------------------
#  명령
# ----------------------------------------------------------------------

CANCEL_UNUSED = """UPDATE node_enrollments SET canceled_at = now()
                    WHERE node_id = %s AND used_at IS NULL AND canceled_at IS NULL"""


def cmd_issue(args):
    if sys.stdout.isatty() and not args.allow_tty:
        # 토큰이 화면 · 터미널 기록에 남는다. 변수로 받게 한다 (DB 도 바꾸지 않는다)
        log('표준 출력이 터미널이다. 토큰을 화면에 찍지 않는다. '
            'export OPSLOOP_ENROLL_TOKEN="$(ssh ... sudo nodes.py issue ...)" 처럼 받는다 (꼭 봐야 하면 --allow-tty)', 3)
        return EXIT_USAGE
    token = new_token()
    by = operator()
    conn = connect()
    try:
        cur = conn.cursor()
        # 새 행은 pending 이다. 활성화는 자기 등록(enroll_node)만 한다
        cur.execute("""INSERT INTO nodes (node_id, hostname, sensor, addr, logs, status)
                       VALUES (%s, %s, %s, %s, %s, 'pending')
                       ON CONFLICT (node_id) DO NOTHING
                       RETURNING status""",
                    (args.node, args.host, args.node, args.addr, args.logs))
        created = cur.fetchone() is not None
        if not created:
            cur.execute("SELECT status, host(addr) FROM nodes WHERE node_id = %s FOR UPDATE", (args.node,))
            status, old_addr = cur.fetchone()
            cur.execute("UPDATE nodes SET hostname = %s, addr = %s, logs = %s WHERE node_id = %s",
                        (args.host, args.addr, args.logs, args.node))
        cur.execute(CANCEL_UNUSED, (args.node,))
        canceled = cur.rowcount
        cur.execute("""INSERT INTO node_enrollments (node_id, token_hash, issued_by, expires_at)
                       VALUES (%s, %s, %s, now() + make_interval(secs => %s))
                       RETURNING expires_at""",
                    (args.node, sha256_hex(token), by, args.ttl))
        expires_at = cur.fetchone()[0]
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()

    if created:
        log(f"{args.node}: 새 노드 (pending). 등록 토큰은 {fmt_ts(expires_at)} 까지 한 번 쓸 수 있다")
    else:
        log(f"{args.node}: 기존 노드({status})를 고쳤다. 새 키가 등록되기 전까지 지금 키가 그대로 쓰인다. "
            f"토큰은 {fmt_ts(expires_at)} 까지")
        if old_addr and old_addr != args.addr:
            log(f"{args.node}: 주소가 바뀌었다 {safe(old_addr)} → {args.addr}. 관문은 새 주소에서 온 것만 받는다", 4)
    if canceled:
        log(f"{args.node}: 쓰지 않은 이전 등록 토큰 {canceled}개를 취소했다")
    wrote = ledger("issue", {"node_id": args.node, "issued_by": by, "expires_at": utc_iso(expires_at),
                             "host": args.host, "addr": args.addr, "logs": args.logs})
    sys.stdout.write(token + "\n")
    sys.stdout.flush()
    hup_gate()
    return 0 if wrote else EXIT_LEDGER


def cmd_cancel(args):
    conn = connect()
    try:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM nodes WHERE node_id = %s FOR UPDATE", (args.node,))
        if cur.fetchone() is None:
            conn.rollback()
            log(f"{args.node}: 노드 없음", 3)
            return 1
        cur.execute(CANCEL_UNUSED, (args.node,))
        n = cur.rowcount
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()
    wrote = ledger("cancel", {"node_id": args.node, "issued_by": operator(), "canceled": n})
    log(f"{args.node}: 쓰지 않은 등록 토큰 {n}개를 취소했다")
    return 0 if wrote else EXIT_LEDGER


def cmd_revoke(args):
    conn = connect()
    try:
        cur = conn.cursor()
        cur.execute("UPDATE nodes SET status = 'revoked' WHERE node_id = %s RETURNING agent_fp", (args.node,))
        row = cur.fetchone()
        if row is None:
            conn.rollback()
            log(f"{args.node}: 노드 없음", 3)
            return 1
        cur.execute(CANCEL_UNUSED, (args.node,))
        n = cur.rowcount
        conn.commit()
    except BaseException:
        conn.rollback()
        raise
    finally:
        conn.close()
    wrote = ledger("revoke", {"node_id": args.node, "issued_by": operator(), "status": "revoked",
                              "agent_fp": row[0], "canceled": n})
    log(f"{args.node}: 폐기했다 (키 {row[0] or '-'}). 쓰지 않은 등록 토큰 {n}개를 취소했다")
    hup_gate()
    return 0 if wrote else EXIT_LEDGER


def cmd_list(args):
    conn = connect(autocommit=True)
    try:
        cur = conn.cursor()
        cur.execute("""SELECT n.node_id, n.status, n.hostname, host(n.addr), array_to_string(n.logs, ','),
                              n.agent_fp, n.registered_at, n.last_seen_at,
                              (SELECT count(*) FROM node_enrollments e
                                WHERE e.node_id = n.node_id AND e.used_at IS NULL
                                  AND e.canceled_at IS NULL AND e.expires_at > now())
                         FROM nodes n ORDER BY n.node_id""")
        rows = cur.fetchall()
    finally:
        conn.close()
    print(f"{'노드':<16} {'상태':<8} {'호스트':<20} {'주소':<16} {'로그':<20} {'키':<9} "
          f"{'등록':<21} {'최근 수신':<21} 대기 토큰")
    for node, status, host, addr, logs, fp, reg, seen, pending in rows:
        print(f"{safe(node):<16} {safe(status):<8} {safe(host or '-'):<20} {safe(addr or '-'):<16} "
              f"{safe(logs or '-'):<20} {safe(fp or '-'):<9} {fmt_ts(reg):<21} {fmt_ts(seen):<21} {pending}")
    return 0


MARK = {True: "통과", False: "실패", None: "대기"}


def first_failed(rows):
    """처음 통과하지 못한 단계 번호. 모두 통과면 0."""
    if not rows:
        return 1
    for step, _name, ok, _detail in rows:
        if ok is not True:
            return step
    return 0


def receipt(conn, node, nonce):
    cur = conn.cursor()
    cur.execute("SELECT step, name, ok, detail FROM node_first_receipt(%s, %s) ORDER BY step", (node, nonce))
    return cur.fetchall()


def cmd_check(args):
    started = time.monotonic()
    deadline = started + args.wait
    conn, rows, err, kicked, last = None, None, None, False, None
    while True:
        try:
            if conn is None:
                conn = connect(autocommit=True)
            rows, err = receipt(conn, args.node, args.nonce), None
        except DB_ERRORS + (DBError,) as e:
            err = e
            if conn is not None:
                try:
                    conn.close()
                except DB_ERRORS:
                    pass
                conn = None
        elapsed = time.monotonic() - started
        if err is not None:
            state = f"DB 오류: {safe(err)}"
        else:
            code = first_failed(rows)
            state = " · ".join(f"{s} {MARK.get(ok, '대기')}" for s, _n, ok, _d in rows)
            if code:
                why = next((d for s, _n, _ok, d in rows if s == code), "결과 없음")
                state += f" — {code}단계: {safe(why)}"
        if state != last:
            log(f"[{elapsed:4.0f}초] {state}", 6 if err is None else 4)
            last = state
        if err is None:
            if code == 0:
                break
            ok3 = any(s == 3 and ok is True for s, _n, ok, _d in rows)
            if args.kick and not kicked and ok3:
                # 4단계는 첫 적재 뒤의 탐지 실행이 있어야 통과한다. 타이머(1분)를 기다리지 않고 당긴다
                kicked = True
                if systemctl(["start", "--no-block", AGENTS_UNIT]):
                    log(f"{AGENTS_UNIT} 를 당겼다")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        time.sleep(min(POLL, remaining))
    if conn is not None:
        conn.close()

    if rows is not None:
        for step, name, ok, detail in rows:
            print(f"{step} {name:<6} {MARK.get(ok, '대기')}  {safe(detail)}")
    if err is not None:
        log(f"첫 수신 확인을 끝내지 못했다: {safe(err)}", 3)
        return EXIT_DB
    return first_failed(rows)


# ----------------------------------------------------------------------
#  인자
# ----------------------------------------------------------------------

class Parser(argparse.ArgumentParser):
    def error(self, message):
        self.print_usage(sys.stderr)
        self.exit(EXIT_USAGE, f"{self.prog}: 인자 오류: {message}\n")


def arg_node(v):
    if not NODE_RE.fullmatch(v) or v in RESERVED:
        raise argparse.ArgumentTypeError(
            f"노드 이름 {v!r}: 소문자 · 숫자 · '-' 63자 이하, {', '.join(sorted(RESERVED))} 는 쓸 수 없다")
    return v


def arg_host(v):
    if not HOST_RE.fullmatch(v):
        raise argparse.ArgumentTypeError(f"호스트 이름 {v!r} 가 올바르지 않다")
    return v


def arg_addr(v):
    try:
        ip = ipaddress.ip_address(v)
    except ValueError:
        raise argparse.ArgumentTypeError(f"주소 {v!r}: 대역이 아니라 주소 하나여야 한다")
    if ip.is_unspecified or ip.is_multicast:
        raise argparse.ArgumentTypeError(f"주소 {v!r} 는 노드 주소가 될 수 없다")
    return str(ip)


def arg_logs(v):
    out = []
    for x in v.split(","):
        x = x.strip()
        if x not in LOGS:
            raise argparse.ArgumentTypeError(f"로그 {x!r}: {', '.join(LOGS)} 중에서 고른다")
        if x not in out:
            out.append(x)
    return out


def arg_int(lo, hi):
    def conv(v):
        try:
            n = int(v)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{v!r} 는 정수가 아니다")
        if not lo <= n <= hi:
            raise argparse.ArgumentTypeError(f"{n} 은 {lo}~{hi} 범위 밖이다")
        return n
    return conv


def arg_nonce(v):
    if not NONCE_RE.fullmatch(v):
        raise argparse.ArgumentTypeError("nonce 는 영문 · 숫자 · '._-' 128자 이하")
    return v


def build_parser():
    ap = Parser(prog="nodes.py", description="OpsLoop 관제 대상 노드 관리 (발급 · 취소 · 폐기 · 목록 · 첫 수신 확인)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("issue", help="등록 토큰 발급 (토큰은 표준 출력 한 줄)")
    p.add_argument("node", type=arg_node)
    p.add_argument("--host", required=True, type=arg_host, help="로그 줄에 찍히는 호스트 이름")
    p.add_argument("--addr", required=True, type=arg_addr, help="관문에 접속하는 출발지 주소")
    p.add_argument("--logs", required=True, type=arg_logs, help="보낼 로그 (쉼표). nginx,auth,metrics")
    p.add_argument("--ttl", type=arg_int(TTL_MIN, TTL_MAX), default=3600, help="토큰 수명 초 (기본 3600)")
    p.add_argument("--allow-tty", action="store_true", help="표준 출력이 터미널이어도 토큰을 찍는다 (화면에 남는다)")
    p.set_defaults(func=cmd_issue)

    p = sub.add_parser("cancel", help="쓰지 않은 등록 토큰 취소")
    p.add_argument("node", type=arg_node)
    p.set_defaults(func=cmd_cancel)

    p = sub.add_parser("revoke", help="노드 폐기")
    p.add_argument("node", type=arg_node)
    p.set_defaults(func=cmd_revoke)

    p = sub.add_parser("list", help="노드 목록")
    p.set_defaults(func=cmd_list)

    p = sub.add_parser("check", help="첫 수신 확인 (종료 코드 = 처음 실패한 단계)")
    p.add_argument("node", type=arg_node)
    p.add_argument("--nonce", required=True, type=arg_nonce, help="탐침 요청 경로에 넣은 값")
    p.add_argument("--wait", type=arg_int(0, WAIT_MAX), default=0, help="통과를 기다릴 초 (기본 0 = 한 번만 본다)")
    p.add_argument("--kick", action="store_true", help=f"3단계 통과 뒤 {AGENTS_UNIT} 를 한 번 당긴다")
    p.set_defaults(func=cmd_check)
    return ap


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        return args.func(args)
    except DB_ERRORS + (DBError,) as e:
        log(f"DB 오류: {safe(e)}", 3)
        return EXIT_DB if args.cmd == "check" else 1


if __name__ == "__main__":
    sys.exit(main())
