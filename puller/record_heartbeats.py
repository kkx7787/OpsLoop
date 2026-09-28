#!/usr/bin/env python3
"""업로더 생존 신호 기록 (이슈 #52). 풀러가 pull-state.json 에 남긴 호스트별 hb 결과를 DB sensor_heartbeats 표로 옮긴다.

opsloop-ingest 가 DB 접속 확인 뒤 · 적재 전에 적재 역할(opsloop_ingest) 접속 정보로 부른다. S3 키는 받지 않는다.
콘솔 대시보드의 AWS 센서 카드가 이 표를 읽어 업로더 생존 신호 시각을 보인다.

  읽기    $OPSLOOP_HOME/pull-state.json 의 heartbeats {호스트: {role, seen_at, checked_at, problem}} (puller/pull.py 가 회차마다 쓴다)
  쓰기    호스트마다 source='uploader:<호스트>' · kind='uploader' 한 줄을 넣거나 고친다 (한 트랜잭션).
          못 읽은 회차(seen_at 없음)는 옛 seen_at 을 지우지 않고 checked_at · problem 만 바꾼다.
          시각은 파일 값과 DB now() 중 이른 것이다. 상태 파일의 미래 시각으로 '방금 확인함' 을 만들지 못한다
  거르기  호스트는 i-<16진수 8~17자>, 역할은 sensor · gateway, 시각은 시간대가 있는 ISO 8601 만 받는다.
          맞지 않는 항목은 건너뛰고 한 줄 알린다. problem 은 제어 문자를 지우고 200자로 자른다

행 종류는 DB 트리거(sensor_heartbeats_guard)가 한 번 더 가른다. 적재 역할은 업로더 행만 넣고 바꿀 수 있다.
OPSLOOP_HOSTS 에서 뺀 호스트의 줄은 지우지 않는다(적재 역할에 DELETE 권한이 없다). 소유자가 지운다(infra/vmware/README.md).

종료 코드
  0  기록했거나 기록할 것이 없다. 표가 없거나(42P01) 권한이 없으면(42501) 한 줄 알리고 0 이다
     (마이그레이션 전이거나 역할 블록을 다시 적용한 뒤. 적재 · 탐지를 막지 않는다)
  1  그 밖의 DB 오류 · 상태 파일을 읽지 못함

환경변수
  DATABASE_URL   적재 역할 접속 (/etc/opsloop/collector.env)
  OPSLOOP_HOME   풀러 작업 폴더 (기본 /var/lib/opsloop)
"""
import json
import os
import re
import sys
from datetime import datetime

HOST_RE = re.compile(r"i-[0-9a-f]{8,17}")      # fullmatch 로만 쓴다 (pull.KEY_RE 의 host 와 같다)
ROLES = ("sensor", "gateway")
MAX_ITEMS = 200                                 # 한 번에 옮길 호스트 수의 상한 (OPSLOOP_HOSTS 는 몇 개다)
PROBLEM_MAX = 200
# pull-state.json 에는 받은 조각 목록도 들어 있다. 적재 서비스 메모리 상한(512M) 안에서 읽도록 이보다 크면 읽지 않는다(종료 1)
STATE_MAX = 64 * 1024 * 1024
SKIP_CODES = ("42P01", "42501")                 # 표 없음 · 권한 없음. 알리고 0 으로 끝난다
_CTRL = re.compile(r"[\x00-\x1f\x7f-\x9f]")

# 시각은 DB now() 보다 늦으면 now() 로 한다. least() 는 NULL 을 건너뛰므로 seen_at 은 CASE 로 감싼다.
# 못 읽은 회차는 옛 seen_at 을 둔다(같은 호스트일 때만. 키에 호스트가 들어 있어 업로더 행은 늘 같다)
UPSERT_SQL = """
INSERT INTO sensor_heartbeats AS h (source, kind, role, host, seen_at, checked_at, problem)
VALUES (%(source)s, 'uploader', %(role)s, %(host)s,
        CASE WHEN %(seen_at)s::timestamptz IS NOT NULL THEN least(%(seen_at)s::timestamptz, now()) END,
        least(%(checked_at)s::timestamptz, now()), %(problem)s)
ON CONFLICT (source) DO UPDATE SET
    kind = EXCLUDED.kind, role = EXCLUDED.role, host = EXCLUDED.host,
    seen_at = CASE WHEN h.host = EXCLUDED.host THEN coalesce(EXCLUDED.seen_at, h.seen_at) ELSE EXCLUDED.seen_at END,
    checked_at = EXCLUDED.checked_at, problem = EXCLUDED.problem"""

_JOURNAL = bool(os.environ.get("JOURNAL_STREAM"))


def log(msg, level=6):
    print(f"<{level}>{msg}" if _JOURNAL else msg, flush=True)


def clean(v, n=PROBLEM_MAX):
    """상태 파일 · DB 오류 문구를 로그 · 표에 넣을 때. 제어 문자를 '?' 로 바꾸고 자른다."""
    return _CTRL.sub("?", str(v))[:n]


def parse_ts(v):
    """시간대가 있는 ISO 8601 → datetime. 못 읽으면 None (시간대 없는 값도 받지 않는다)."""
    if not isinstance(v, str) or not 10 <= len(v) <= 40:
        return None
    try:
        dt = datetime.fromisoformat(v[:-1] + "+00:00" if v.endswith("Z") else v)
    except ValueError:
        return None
    return dt if dt.utcoffset() is not None else None


def rows_from_state(state):
    """상태 파일의 heartbeats → (넣을 행 목록, 건너뛴 항목 설명 목록)."""
    beats = state.get("heartbeats") if isinstance(state, dict) else None
    if not isinstance(beats, dict):
        return [], []
    rows, skipped = [], []
    for host in sorted(beats)[:MAX_ITEMS]:
        b, name = beats[host], clean(host, 40)
        if not HOST_RE.fullmatch(host):
            skipped.append(f"{name}: 호스트 모양")
            continue
        if not isinstance(b, dict) or b.get("role") not in ROLES:
            skipped.append(f"{name}: 역할")
            continue
        checked = parse_ts(b.get("checked_at"))
        seen = parse_ts(b.get("seen_at"))
        if checked is None or (b.get("seen_at") is not None and seen is None):
            skipped.append(f"{name}: 시각")
            continue
        problem = b.get("problem")
        if problem is not None and not isinstance(problem, str):
            skipped.append(f"{name}: 문제 글")
            continue
        rows.append({"source": f"uploader:{host}", "role": b["role"], "host": host, "seen_at": seen,
                     "checked_at": checked, "problem": clean(problem) if problem else None})
    if len(beats) > MAX_ITEMS:
        skipped.append(f"상한 {MAX_ITEMS}개를 넘은 {len(beats) - MAX_ITEMS}개")
    return rows, skipped


def record(cur, rows):
    """한 커서로 행을 넣거나 고친다(트랜잭션은 호출자가 맺고 끝낸다). 넣은 행 수를 돌려준다."""
    cur.execute("SET LOCAL statement_timeout = '30s'")
    cur.execute("SET LOCAL lock_timeout = '5s'")
    for r in rows:
        cur.execute(UPSERT_SQL, r)
    return len(rows)


def load_state(home):
    with open(os.path.join(home, "pull-state.json"), "rb") as f:
        body = f.read(STATE_MAX + 1)
    if len(body) > STATE_MAX:
        raise ValueError("상태 파일이 너무 크다")
    return json.loads(body)


def connect(url):
    import psycopg2
    return psycopg2.connect(url, connect_timeout=10, application_name="opsloop-heartbeats")


def main():
    home = os.environ.get("OPSLOOP_HOME", "/var/lib/opsloop")
    url = os.environ.get("DATABASE_URL")
    if not url:
        log("생존 신호 기록: DATABASE_URL 이 없다", 3)
        return 1
    try:
        state = load_state(home)
    except FileNotFoundError:
        log("생존 신호 기록: 상태 파일이 아직 없다 (풀러가 한 번도 돌지 않았다). 건너뛴다", 5)
        return 0
    except (OSError, ValueError, RecursionError) as e:
        log(f"생존 신호 기록: 상태 파일을 읽지 못했다 ({clean(type(e).__name__, 60)})", 3)
        return 1
    rows, skipped = rows_from_state(state)
    if skipped:
        log("생존 신호 기록: 건너뛴 항목 " + " · ".join(skipped[:10]), 4)
    if not rows:
        log("생존 신호 기록: 옮길 항목이 없다", 5)
        return 0
    try:
        conn = connect(url)
    except Exception as e:  # noqa: BLE001 - 접속 오류는 모두 1 (접속 문자열을 찍지 않는다)
        log(f"생존 신호 기록: DB 에 붙지 못했다 ({clean(type(e).__name__, 60)})", 3)
        return 1
    try:
        with conn, conn.cursor() as cur:
            n = record(cur, rows)
    except Exception as e:  # noqa: BLE001
        code = getattr(e, "pgcode", None)
        if code in SKIP_CODES:
            what = ("표가 없다 (infra/migrations/20260930_status_board.sql 적용 전)" if code == "42P01"
                    else "권한이 없다 (역할 블록을 다시 적용했다면 20260930_status_board.sql 도 다시 적용한다)")
            log(f"생존 신호 기록: {what}. 건너뛴다", 5)
            return 0
        log(f"생존 신호 기록 실패 ({code or clean(type(e).__name__, 60)}): {clean(e)}", 3)
        return 1
    finally:
        conn.close()
    log(f"생존 신호 {n}건을 기록했다")
    return 0


if __name__ == "__main__":
    sys.exit(main())
