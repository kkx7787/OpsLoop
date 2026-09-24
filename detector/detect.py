#!/usr/bin/env python3
"""
OpsLoop - 탐지 엔진 (WBS 2.3 / PostgreSQL)

정규화된 이벤트에 규칙을 적용해 인시던트를 만든다.

핵심 설계
  1. 시간 범위와 규칙 버전을 인자로 받는다. 기간을 코드에 박지 않아야
     같은 구간에 다른 규칙 버전을 재적용(리플레이)할 수 있다.
  2. 신호(signal)와 인시던트(incident)를 분리한다.
     신호는 규칙에 걸린 개별 사건, 인시던트는 사람이 볼 단위로 묶은 것.
     알림 피로는 이 통합 단계에서 줄인다.
  3. 멱등하다. 같은 (규칙, 버전, 대상, 시작시각)이면 다시 만들지 않는다.
  4. 규칙 정의를 rule_versions 에 남긴다. 임계치를 왜 바꿨는지가 남아야
     "조치가 탐지를 개선했다"를 나중에 증명할 수 있다.
  5. 규칙은 params.sensors 로 발생원을 한정한다. 실행마다 detector_runs 에 한 행을
     남겨 "적재 뒤에 탐지가 돌았는가"를 DB 가 답한다.
  6. IP 가 아닌 대상(사람 user:<이름> · 노드 node:<id>)은 신호의 detail._target 에 담아
     incidents.target 에 넣고 actor_ip 는 비운다. 콘솔은 actor_ip 가 있을 때만 차단 목록에
     넣으므로 이런 인시던트로는 콘솔 · 인프라 주소를 막을 수 없다.
  7. 같은 페이로드 흡수(params.absorb_same_payload, v3). 출발지가 달라도 같은 페이로드(파일 해시 · 심은 키 지문)를
     첫 사건에서 window_hours 안에 다시 가져온 인시던트는 첫 사건에 묶어 지운다. 지운 인시던트는 같은 문장에서
     incident_absorbed 표에 첫 사건 키와 함께 넣는다(출발지 · 첫 시각 · 세션 · 키, 상한 없음). 차단 근거는 이 표다.
     첫 사건의 근거(evidence.absorbed)에는 요약을 남기는데, 판정되면 굳으므로 판정 뒤의 흡수는 표에만 붙는다.
     옵션이 없는 규칙은 신호 · 적재 행 · 문장이 전과 같다. v3 는 infra/migrations/20260925_v3_absorbed.sql 이 필요하다.

사용
  export DATABASE_URL='postgresql://opsloop:PASSWORD@호스트:5432/opsloop'
  python3 detect.py --run
  python3 detect.py --run --since 2026-09-05 --until 2026-09-06
  python3 detect.py --run --rules rules_v2.json
  python3 detect.py --run --rules rules_v3.json
  python3 detect.py --run --rules rules_self.json --quiet     요약 표 없이
  python3 detect.py --list
  python3 detect.py --compare v1 v2
  python3 detect.py --quality
"""

import argparse
import base64
import binascii
import hashlib
import json
import os
import re
import statistics
import sys
from datetime import datetime, timedelta, timezone

try:
    import psycopg2
    from psycopg2.extras import execute_batch
except ImportError:
    sys.exit("psycopg2 가 필요합니다:  sudo apt-get install -y python3-psycopg2")

DEFAULT_RULES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "rules.json")

# session_threshold 규칙이 참조할 수 있는 컬럼. SQL 조립 전에 검사한다.
ALLOWED_SESSION_FIELDS = {
    "login_attempts", "command_count", "downloads", "duration_ms",
}
ALLOWED_OPS = {">=", ">", "=", "<=", "<"}

# 발생원을 정하지 않은 기준선 이탈이 보는 범위. 관제 대상(web-01 등)과 수집 관문의
# 이벤트가 섞이면 v1 · v2 기준선의 평균과 편차가 허니팟 트래픽이 아닌 것으로 흔들린다.
BASELINE_SENSORS = ["cowrie", "decoy", "console"]


def db_url(arg):
    url = arg or os.environ.get("DATABASE_URL")
    if not url:
        sys.exit("DATABASE_URL 이 없습니다. 환경변수나 --db-url 로 주세요.")
    return url


def range_clause(since, until, col, sensors=None):
    c, p = ["provenance = 'real'"], []
    if since:
        c.append(f"{col} >= %s"); p.append(since)
    if until:
        c.append(f"{col} < %s"); p.append(until)
    if sensors:
        c.append("sensor = ANY(%s)"); p.append(sensors)
    return " AND ".join(c), p


def rule_sensors(rule, default=None):
    """params.sensors 를 돌려준다. 없으면 default. 비었거나 문자열 목록이 아니면 규칙 오류다."""
    s = rule["params"].get("sensors", default)
    if s is not None and not (isinstance(s, list) and s and all(isinstance(x, str) and x for x in s)):
        raise ValueError(f"{rule['id']}: sensors 는 비어 있지 않은 문자열 목록이어야 합니다")
    return s


# ----------------------------------------------------------------------
#  규칙별 신호 수집
#  각 함수는 (ts, actor_ip, session, detail) 튜플 목록을 돌려준다
#  params.sensors 가 있으면 그 발생원(events · sessions 의 sensor)만 본다
#  detail 의 제어 필드(CONTROL_FIELDS)는 run() 이 읽고 evidence 에 넣기 전에 뺀다
#    _target  IP 가 아닌 대상. 묶음 · 키 · incidents.target 에 쓴다
#    _end     신호가 끝난 시각. last_ts 를 그 시각까지 늘린다 (노드 수신이 돌아온 시각)
#    _payload 같은 페이로드 흡수가 보는 페이로드 식별자 목록 (파일 해시 · 심은 키 지문). 비어 있으면 페이로드 없는
#             신호다. 그런 신호가 든 인시던트는 흡수되지 않는다 (absorb_same_payload)
# ----------------------------------------------------------------------

CONTROL_FIELDS = ("_target", "_end", "_payload")


def signals_session_threshold(cur, rule, since, until):
    p = rule["params"]
    if p["field"] not in ALLOWED_SESSION_FIELDS:
        raise ValueError(f"{rule['id']}: 허용되지 않은 필드 {p['field']}")
    if p["op"] not in ALLOWED_OPS:
        raise ValueError(f"{rule['id']}: 허용되지 않은 연산자 {p['op']}")
    w, prm = range_clause(since, until, "first_ts", rule_sensors(rule))
    cur.execute(
        f"SELECT first_ts, src_ip, session, {p['field']} "
        f"FROM sessions WHERE {w} AND {p['field']} {p['op']} %s",
        prm + [p["value"]])
    return [(ts, ip, s, {p["field"]: v}) for ts, ip, s, v in cur.fetchall()]


def signals_session_compound(cur, rule, since, until):
    """세션 지표의 논리식으로 거른다.

    v2 에서 조건 하나가 붙었다. 명령을 실행했다는 것과 무언가를 했다는 것은
    다르다. 관측된 봇 상당수가 로그인 후 `echo` 한 줄만 찍고 끊는다.
    자격증명이 먹히는지 확인하는 행위이지 침해 후 행위가 아니다.
    noop_command_patterns 에 걸리지 않는 명령이 하나라도 있어야 신호가 된다.
    """
    p = rule["params"]
    w, prm = range_clause(since, until, "first_ts", rule_sensors(rule))
    cond, extra = f"({p['expr']})", []
    noop = p.get("noop_command_patterns")
    if noop:
        cond += (" AND EXISTS (SELECT 1 FROM events e WHERE e.session = sessions.session"
                 " AND e.eventid = 'cowrie.command.input' AND e.input IS NOT NULL"
                 " AND e.input !~* ALL(%s))")
        extra.append(noop)
    cur.execute(
        f"SELECT first_ts, src_ip, session, login_attempts, command_count "
        f"FROM sessions WHERE {w} AND {cond}", prm + extra)
    return [(ts, ip, s, {"login_attempts": la, "command_count": cc})
            for ts, ip, s, la, cc in cur.fetchall()]


def signals_event_match(cur, rule, since, until):
    """이벤트 하나로 성립하는 규칙.

    v2 에서 제외 목록이 붙었다. 파일 이동 이벤트가 있다는 것과 악성코드가
    들어왔다는 것은 다르다. 빈 파일(0바이트)의 해시가 반복 관측되었고,
    이것을 critical 로 올리는 것은 규칙이 겨냥한 현상이 아니다.

    v3 에서 두 가지가 붙었다. 둘 다 없으면 문장 · 인자 · 신호가 전과 한 글자도 같다.
      exclude_pubkey_redir  같은 세션의 명령에 적힌 SSH 공개키 한 줄을 셸 리다이렉트로 저장한 것을 뺀다. cowrie 는
                            리다이렉트 내용을 file_download('Saved redir contents', url 없음)로 남기고 해시는 그 내용의
                            SHA-256 이다. 두 조건이 모두 맞아야 뺀다.
                              - 해시가 같은 세션 명령에 적힌 키 줄(뒤 줄바꿈 있음 · 없음, 주석 있음 · 없음)의 SHA-256 과 같다.
                                같은 세션의 다른 리다이렉트 저장은 남는다. 주석에 빈칸이 있는 등 줄을 다시 만들지 못하면
                                빼지 않는다(덜 빼는 쪽으로 틀린다)
                              - 같은 세션에 같은 규칙 파일의 key_plant 규칙(R006)이 잡는 쓰기 명령이 있다(_key_write,
                                prepare_rule 이 넣는다). 키 줄을 /tmp 에 저장했다가 R006 이 모르는 방법으로 옮기면 R006 이
                                뜨지 않으므로 그 저장은 여기 남는다. 두 규칙이 함께 놓치지 않게 제외를 R006 의 탐지에 묶는다
      absorb_same_payload   신호마다 파일 해시를 _payload 로 넘긴다. run() 의 같은 페이로드 흡수가 쓴다
    """
    p = rule["params"]
    w, prm = range_clause(since, until, "ts", rule_sensors(rule))
    if "eventid" in p:
        cond, extra = "eventid = %s", [p["eventid"]]
    else:
        cond, extra = "eventid LIKE %s", [p["eventid_like"]]
    for pref in p.get("exclude_shasum_prefixes", []):
        cond += " AND (shasum IS NULL OR shasum NOT LIKE %s)"
        extra.append(pref + "%")
    pubkey = p.get("exclude_pubkey_redir", False)
    if not isinstance(pubkey, bool):
        raise ValueError(f"{rule['id']}: exclude_pubkey_redir 는 true · false 여야 합니다")
    if pubkey:
        kw = p.get("_key_write")
        if not kw:
            raise ValueError(f"{rule['id']}: exclude_pubkey_redir 는 같은 규칙 파일에 켜진 key_plant 규칙이 하나 있어야 합니다")
        cond += PUBKEY_REDIR_SQL
        extra += [SSH_KEY_RE, kw["eventid"], kw["patterns"]]
    absorb = absorb_conf(rule) is not None
    cols = "ts, src_ip, session, eventid, coalesce(shasum, url, input, message)" + (", shasum" if absorb else "")
    cur.execute(f"SELECT {cols} FROM events WHERE {w} AND {cond}", prm + extra)
    if not absorb:
        return [(ts, ip, s, {"eventid": ev, "detail": d}) for ts, ip, s, ev, d in cur.fetchall()]
    return [(ts, ip, s, {"eventid": ev, "detail": d, "_payload": [sh] if sh else []})
            for ts, ip, s, ev, d, sh in cur.fetchall()]


# SSH 공개키 한 개 (종류, base64 본체, 빈칸 뒤 주석 한 토막). PostgreSQL ARE 와 파이썬 re 가 같은 뜻으로 읽는다.
# 주석이 없으면 셋째 묶음은 NULL(None)이다
SSH_KEY_RE = (r"(ssh-(?:rsa|dss|ed25519)|ecdsa-sha2-nistp(?:256|384|521)|sk-(?:ssh-ed25519|ecdsa-sha2-nistp256)@openssh\.com)"
              r"\s+([A-Za-z0-9+/]{16,}={0,3})(?: +([^\s\"';&|<>]+))?")
_SSH_KEY = re.compile(SSH_KEY_RE)

# exclude_pubkey_redir. 리다이렉트 저장(url 없음 · 'Saved redir contents')의 해시가 같은 세션 명령 입력에 적힌
# 키 줄의 SHA-256 과 같고, 같은 세션에 key_plant 규칙의 쓰기 명령(eventid · write_patterns)이 있으면 뺀다.
# 줄은 '종류 본체' 와 '종류 본체 주석' 두 가지, 끝은 줄바꿈 있음(echo) · 없음(printf) 두 가지다.
# 인자는 키 정규식, key_plant 의 eventid, write_patterns 순서다. 탐지 역할의 events 읽기 권한으로 된다
PUBKEY_REDIR_SQL = (
    " AND NOT EXISTS (SELECT 1 FROM events c"
    " CROSS JOIN LATERAL regexp_matches(c.input, %s, 'g') AS m"
    " CROSS JOIN LATERAL (VALUES (m[1] || ' ' || m[2]), (m[1] || ' ' || m[2] || ' ' || m[3])) AS k(line)"
    " CROSS JOIN (VALUES (E'\\n'), ('')) AS n(nl)"
    " WHERE events.url IS NULL AND events.message LIKE 'Saved redir contents%%'"
    " AND c.session = events.session AND c.eventid = 'cowrie.command.input'"
    " AND encode(sha256(convert_to(k.line || n.nl, 'UTF8')), 'hex') = events.shasum"
    " AND EXISTS (SELECT 1 FROM events w WHERE w.session = events.session AND w.provenance = 'real'"
    " AND w.eventid = %s AND w.input ~ ANY(%s)))")


def key_fingerprint(blob):
    """OpenSSH 와 같은 꼴의 키 지문(SHA256:…, ssh-keygen -l 과 같은 값). base64 가 깨졌으면 None."""
    try:
        raw = base64.b64decode(blob, validate=True)
    except (binascii.Error, ValueError):
        return None
    return "SHA256:" + base64.b64encode(hashlib.sha256(raw).digest()).decode().rstrip("=")


def signals_key_plant(cur, rule, since, until):
    """SSH 키 심기 (v3 R006). 명령 입력 가운데 authorized_keys 에 쓰는 것.

    판정 기준(2026-09-25)은 키 심기를 파일 투하와 같은 위협으로 본다. 허니팟 기록에는 파일 이동이 아니라 명령
    입력으로 남으므로 이벤트 종류가 아니라 쓰기 대상을 본다. params.write_patterns(PostgreSQL 정규식 목록) 가운데
    하나에 맞는 입력이 신호다. 대상은 이름이 authorized_keys(2) 인 파일이다(따옴표로 끊긴 경로 포함, .bak 같은 다른
    이름은 아니다). v3 는 리다이렉트 · tee · cp/mv/install 의 마지막 인자 · dd of= 를 본다. cowrie 는 같은 리다이렉트의
    내용을 file_download('Saved redir contents')로도 남겨 v2 R003 이 그것을 '파일 투하'로 잡았다. v3 R003 은 그
    세션에 여기 맞는 쓰기가 있을 때만 그 저장을 뺀다(exclude_pubkey_redir).

    명령에 적힌 공개키마다 OpenSSH 꼴 지문을 key_fps 로 남기고 같은 페이로드 흡수의 식별자(_payload)로 쓴다.
    주석(mdrfckr 등)은 지문에 들어가지 않으므로 주석만 바꿔 같은 키를 심어도 같은 페이로드다. 키가 적혀 있지 않은
    쓰기(cat 파일 >> authorized_keys, 비우기 등)도 신호다. key_fps 가 비고, 인시던트 근거에 payloadless_signals 로
    세며, 그런 신호가 든 인시던트는 흡수되지 않는다(다른 키일 수 있다).
    """
    p = rule["params"]
    pats = p.get("write_patterns")
    if not (isinstance(pats, list) and pats and all(isinstance(x, str) and x for x in pats)):
        raise ValueError(f"{rule['id']}: write_patterns 는 비어 있지 않은 정규식 목록이어야 합니다")
    w, prm = range_clause(since, until, "ts", rule_sensors(rule))
    cur.execute(f"SELECT ts, src_ip, session, input FROM events WHERE {w} AND eventid = %s AND input ~ ANY(%s)",
                prm + [p["eventid"], pats])
    out = []
    for ts, ip, s, text in cur.fetchall():
        fps = []
        for m in _SSH_KEY.finditer(text):
            fp = key_fingerprint(m.group(2))
            if fp and fp not in fps:
                fps.append(fp)
        out.append((ts, ip, s, {"eventid": p["eventid"], "detail": text, "key_fps": fps, "_payload": list(fps)}))
    return out


def signals_baseline_deviation(cur, rule, since, until):
    """시간당 이벤트 수가 평균 + kσ 를 넘는 구간을 신호로 만든다.

    학습 모델이 아니라 기술 통계다. 관측 구간의 평균과 표준편차로 임계선을
    정한다. 규칙에 없는 새 패턴을 잡기 위한 보완 장치.
    sensors 가 없으면 허니팟 · 콘솔(BASELINE_SENSORS)만 센다.
    params.baseline_days 가 있으면(v3) signals_baseline_trailing 으로 간다. 없으면 아래가 전과 같다.
    """
    p = rule["params"]
    if "baseline_days" in p:
        return signals_baseline_trailing(cur, rule, since, until)
    w, prm = range_clause(since, until, "ts", rule_sensors(rule, BASELINE_SENSORS))

    # v2: 이미 다른 규칙이 잡은 행위자를 기준선에서 뺀다.
    #
    # 이 규칙은 "규칙에 없는 새 패턴"을 잡으라고 넣었는데, v1 에서 잡은 두 건이
    # 모두 기존 규칙이 이미 잡은 IP 하나의 폭주였다. 전체 이벤트로 기준선을
    # 계산하면 한 행위자의 활동이 기준선을 흔들고, 그 흔들림을 자기가 다시
    # 잡는다. 새 패턴이 아니라 기존 규칙의 그림자를 잡는 것이다.
    #
    # 같은 실행 안에서 앞선 규칙들이 만든 인시던트를 본다. 그래서 이 규칙은
    # 규칙 목록의 마지막에 있어야 한다.
    excl = []
    if p.get("exclude_alerted_actors"):
        cur.execute(
            "SELECT DISTINCT host(actor_ip) FROM incidents "
            "WHERE rule_version = %s AND rule_id <> %s AND actor_ip IS NOT NULL",
            (p["_version"], rule["id"]))
        excl = [r[0] for r in cur.fetchall()]

    cond = w
    if excl:
        cond += " AND (src_ip IS NULL OR host(src_ip) <> ALL(%s))"
        prm = prm + [excl]

    cur.execute(
        f"SELECT date_trunc('hour', ts) h, count(*) FROM events WHERE {cond} GROUP BY 1 ORDER BY 1",
        prm)
    rows = cur.fetchall()
    if len(rows) < p.get("min_buckets", 24):
        return []
    counts = [c for _, c in rows]
    mean, sd = statistics.mean(counts), statistics.pstdev(counts)
    if sd == 0:
        return []
    limit = mean + p["sigma"] * sd
    return [(h, None, None,
             {"bucket": h.isoformat(), "count": c, "mean": round(mean, 1),
              "sigma": round(sd, 1), "limit": round(limit, 1),
              "excluded_actors": len(excl)})
            for h, c in rows if c > limit]


def signals_baseline_trailing(cur, rule, since, until):
    """기준선 이탈의 v3 꼴 (params.baseline_days). 시간 칸 h 의 답을 h 까지의 사실로만 정한다.

    v2 는 실행 범위 전체의 평균 · 표준편차로 임계선을 정했다. 같은 칸이라도 뒤에 데이터가 쌓이면 임계선이 움직여,
    회차마다 전 기간을 다시 도는 운영과 나중에 한 번에 돌린 리플레이가 다른 답을 냈다. 제외 행위자도 실행 시점의
    인시던트 전부라 그 칸 뒤에 알림이 난 행위자까지 소급해 뺐다. v3 는 다음으로 바꾼다.
      - 기준선: [h - baseline_days일, h) 의 시간 칸. v2 처럼 (제외 뒤) 이벤트가 있는 칸만 센다
      - 제외 행위자(exclude_alerted_actors): 같은 버전 다른 규칙의 인시던트 가운데 첫 시각이 h 가 끝나기 전
        (h + 1시간 미만)인 출발지. 기준선 칸과 h 모두에서 그 출발지의 이벤트를 뺀다. 표에 남은 인시던트와 함께
        흡수 · 흡수로 가린 억제로 지운 인시던트(incident_absorbed)도 센다. 전 기간 실행은 지울 사건을 다시 만들어
        지우기 전에 이 규칙이 보지만, 구간 실행(--since)은 앞 구간이 지운 사건을 다시 만들지 않기 때문이다
      - 칸은 끝나고 settle_seconds 가 지난 뒤에만 본다(기준 시각은 until 과 지금 중 이른 쪽). R001 은 15분 창이
        차야, R002 는 세션이 끝나야 인시던트가 되므로 칸이 끝나자마자 보면 그 칸에서 알림이 날 행위자가 아직 제외
        목록에 없다. 한 번 뜬 인시던트는 다음 회차에 신호가 사라져도 지워지지 않으므로 기다렸다가 본다
      - since 가 있으면 기준선을 위해 since - baseline_days일부터 읽고, h + 1시간 + settle >= since 인 칸부터 낸다.
        앞 구간(until = since)이 기다림이 덜 차 보지 못한 끝 칸을 이번 구간이 본다. 같은 칸을 두 번 보면 키가 같다
    칸 최소 수(min_buckets) · sigma · 표준편차 0 이면 신호 없음은 v2 와 같다. 신호에는 기준선 칸 수와, 반올림 전
    평균 · 표준편차로 잰 z 를 더 남긴다. 근거의 mean · sigma 는 한 자리로 반올림돼 그것으로 다시 재면 임계선 근처에서
    어긋난다(9/11 19시 실제 6.90 · 반올림 값 6.95). run() 은 z 가 있으면 그것으로 observed_sigma_max 를 쓴다.
    """
    p = rule["params"]
    days, settle = p["baseline_days"], p.get("settle_seconds", 0)
    if not (isinstance(days, int) and not isinstance(days, bool) and days > 0):
        raise ValueError(f"{rule['id']}: baseline_days 는 양의 정수여야 합니다")
    if not (isinstance(settle, int) and not isinstance(settle, bool) and settle >= 0):
        raise ValueError(f"{rule['id']}: settle_seconds 는 0 이상의 정수여야 합니다")
    c, prm = ["provenance = 'real'"], []
    if since:
        c.append("ts >= %s::timestamptz - make_interval(days => %s)"); prm += [since, days]
    if until:
        c.append("ts < %s"); prm.append(until)
    c.append("sensor = ANY(%s)"); prm.append(rule_sensors(rule, BASELINE_SENSORS))
    w = " AND ".join(c)
    cur.execute("SELECT %s::timestamptz, least(%s::timestamptz, now())", [since, until])
    lo, ref = cur.fetchone()
    cur.execute(f"SELECT date_trunc('hour', ts) h, count(*) FROM events WHERE {w} GROUP BY 1 ORDER BY 1", prm)
    total = cur.fetchall()
    alerted, per = {}, {}
    if p.get("exclude_alerted_actors"):
        cur.execute(ALERTED_SQL, (p["_version"], rule["id"]) * 2)
        alerted = dict(cur.fetchall())
    if alerted:
        # 알림이 난 출발지의 칸별 건수. 칸마다 그 칸을 볼 때의 제외 목록만큼 뺀다
        cur.execute(f"SELECT date_trunc('hour', ts), host(src_ip), count(*) FROM events WHERE {w} "
                    f"AND host(src_ip) = ANY(%s) GROUP BY 1, 2", prm + [sorted(alerted)])
        for h, ip, n in cur.fetchall():
            per.setdefault(h, []).append((alerted[ip], n))
    counts = dict(total)
    hours = [h for h, _ in total]
    hour, span, wait = timedelta(hours=1), timedelta(days=days), timedelta(seconds=settle)
    out, start = [], 0
    for i, h in enumerate(hours):
        if (lo is not None and h + hour + wait < lo) or h + hour + wait > ref:
            continue
        cut = h + hour

        def left(b):
            return counts[b] - sum(n for a, n in per.get(b, ()) if a < cut)
        while start < i and hours[start] < h - span:
            start += 1
        base = [x for x in (left(b) for b in hours[start:i]) if x > 0]
        n = left(h)
        if len(base) < p.get("min_buckets", 24) or n <= 0:
            continue
        mean, sd = statistics.mean(base), statistics.pstdev(base)
        if sd == 0:
            continue
        limit = mean + p["sigma"] * sd
        if n > limit:
            out.append((h, None, None,
                        {"bucket": h.isoformat(), "count": n, "mean": round(mean, 1), "sigma": round(sd, 1),
                         "limit": round(limit, 1), "excluded_actors": sum(1 for a in alerted.values() if a < cut),
                         "baseline_hours": len(base), "z": round((n - mean) / sd, 2)}))
    return out


# 기준선 이탈 v3 의 제외 행위자. 출발지별 가장 이른 첫 시각을, 표에 남은 인시던트와 지운 인시던트의 기록에서 함께 본다
ALERTED_SQL = ("SELECT ip, min(t) FROM ("
               "SELECT host(actor_ip) AS ip, first_ts AS t FROM incidents "
               "WHERE rule_version = %s AND rule_id <> %s AND actor_ip IS NOT NULL "
               "UNION ALL SELECT host(actor_ip), first_ts FROM incident_absorbed "
               "WHERE rule_version = %s AND rule_id <> %s AND actor_ip IS NOT NULL) AS x GROUP BY 1")


def signals_actor_rate(cur, rule, since, until):
    """동일 출발지의 이벤트 누적 빈도를 본다.

    관측 결과 봇은 한 세션에 로그인 1회만 시도하고 끊는다. 무차별 대입이
    세션 안이 아니라 세션들 사이에 퍼져 있어, 세션 단위 임계치로는 잡히지 않는다.
    그래서 IP 단위로 고정 시간창을 잘라 누적 횟수를 센다.

    params.http_status(정수 목록)가 있으면 그 응답 코드의 요청만 센다 (w1 R102 404 반복).
    자리는 eventid 조건 바로 뒤다. 없으면 문장과 인자가 전과 한 글자도 같다.
    params.exclude_url_patterns(PostgreSQL 정규식 목록)가 있으면 url 이 그중 하나에 맞는 행은 세지 않는다 (w2 R102:
    robots.txt · favicon 같은 사이트 메타데이터 조회). url 이 없는 행은 센다. 패턴은 읽기 쉽게 ^ 로 시작해 $ 로 끝나게
    쓰고, 엔진이 다시 ^(?: … )$ 로 감싸 넘긴다. 맨 바깥의 | 가 한쪽 끝을 풀어도 url 전체가 맞아야 빠진다. 그래서
    /robots.txt.php · /x/robots.txt · 질의 문자열이 붙은 요청은 그대로 센다. 자리는 http_status 조건 뒤다.
    없으면 문장과 인자가 전과 같다.
    """
    p = rule["params"]
    window = p["window_seconds"]
    w, prm = range_clause(since, until, "ts", rule_sensors(rule))
    status, extra = "", []
    if "http_status" in p:
        codes = p["http_status"]
        if not (isinstance(codes, list) and codes
                and all(isinstance(c, int) and not isinstance(c, bool) for c in codes)):
            raise ValueError(f"{rule['id']}: http_status 는 비어 있지 않은 정수 목록이어야 합니다")
        status, extra = " AND http_status = ANY(%s)", [codes]
    if "exclude_url_patterns" in p:
        pats = p["exclude_url_patterns"]
        if not (isinstance(pats, list) and pats
                and all(isinstance(x, str) and len(x) > 2 and x[0] == "^" and x[-1] == "$" for x in pats)):
            raise ValueError(f"{rule['id']}: exclude_url_patterns 는 ^ 로 시작해 $ 로 끝나는 "
                             "정규식의 비어 있지 않은 목록이어야 합니다")
        status += " AND (url IS NULL OR NOT (url ~ ANY(%s)))"
        extra = extra + [[f"^(?:{x})$" for x in pats]]
    # 행을 모두 올리지 않고 DB 에서 (출발지, 시간창) 별로 센다. 매분 도는 규칙(w1)이 전체 기간을 다시 봐도
    # 메모리는 신호 수만큼만 쓴다. 창 번호는 예전 계산(초 단위 시각 ÷ 창, 내림)과 같고, 신호의 시각 · 세션은
    # 그 창에서 가장 이른 행의 것이다
    cur.execute(
        f"SELECT min(ts), src_ip, (array_agg(session ORDER BY ts))[1], count(*) FROM events "
        f"WHERE {w} AND eventid = ANY(%s) AND src_ip IS NOT NULL{status} "
        f"GROUP BY src_ip, floor(extract(epoch FROM ts) / %s) "
        f"HAVING count(*) >= %s ORDER BY src_ip, min(ts)",
        prm + [p["eventids"]] + extra + [window, p["threshold"]])
    return [(ts, ip, sess, {"count": n, "window_seconds": window, "threshold": p["threshold"]})
            for ts, ip, sess, n in cur.fetchall()]


def signals_operator_rate(cur, rule, since, until):
    """한 사람(username)이 앞 window_seconds 초 안에 같은 관리 행위를 몇 번 했는가 (a1 R201 차단 대량 해제).

    출발지로 묶지 않는다. 감사 이벤트(sensor=audit)의 출발지는 DB 에 붙은 콘솔 VM 이다. 출발지로 묶으면
    콘솔 주소가 차단 대상이 되고, HAProxy 가 A · B 에 번갈아 보내 한 사람의 행위가 둘로 갈린다.
    창은 행마다 뒤로 센다(미끄럼 창). 고정 창은 경계에서 2+2 로 갈려 임계치를 피할 수 있다.
    신호의 시각은 임계치에 닿은 행의 시각이라, 이벤트가 늦게 끼어들지 않는 한 다시 돌려도 키가 같다.
    대상은 detail._target(user:<행위자>)이고 actor_ip 는 비운다. items 는 창 안 행위의 입력과 DB 접속 출발지다.
    items 는 DB 에서 최근 20건(ROWS 창)만 모아 창 밖 것을 거른다. 창 전체를 모으면 대량 해제 N건에 N² 로 커진다.
    """
    p = rule["params"]
    window = p["window_seconds"]
    w, prm = range_clause(since, until, "ts", rule_sensors(rule))
    cur.execute(
        f"SELECT ts, username, n, item_ts, items FROM ("
        f"SELECT ts, username, count(*) OVER win AS n, array_agg(ts) OVER last20 AS item_ts, "
        f"array_agg(concat_ws(' ', coalesce(input, '-'), 'db_client=' || host(src_ip))) OVER last20 AS items "
        f"FROM events WHERE {w} AND eventid = ANY(%s) AND username IS NOT NULL "
        f"WINDOW win AS (PARTITION BY username ORDER BY ts "
        f"RANGE BETWEEN make_interval(secs => %s) PRECEDING AND CURRENT ROW), "
        f"last20 AS (PARTITION BY username ORDER BY ts ROWS BETWEEN 19 PRECEDING AND CURRENT ROW)"
        f") AS x WHERE n >= %s ORDER BY username, ts",
        prm + [p["eventids"], window, p["threshold"]])
    out = []
    for ts, who, n, item_ts, items in cur.fetchall():
        lo = ts - timedelta(seconds=window)
        keep = [it for t, it in zip(item_ts, items) if t >= lo]
        out.append((ts, None, None, {"_target": f"user:{who}", "count": n, "window_seconds": window,
                                     "threshold": p["threshold"], "items": keep[-20:]}))
    return out


def signals_node_silence(cur, rule, since, until):
    """지표를 올리던 노드의 수신이 threshold_seconds 넘게 끊긴 구간 (R301, i1 · i2).

    대상은 활성 노드 가운데 지표(metrics)를 선언한 노드이고, 마지막 등록(registered_at) 뒤에 받은 지표만 본다.
    폐기 뒤 재등록하면 폐기 기간이 공백으로 소급되지 않는다. 노드가 지표를 만든 시각(ts)이 아니라 다리가 받아
    넣은 시각(node_metrics.loaded_at)을 본다. 에이전트가 밀린 줄을 나중에 한꺼번에 보내면 ts 에는 공백이
    없지만 그동안 관제는 아무것도 받지 못했다. 노드별 적재 시각 사이 [마지막 수신, 다음 수신)이 공백이고,
    다음 수신이 아직 없으면 기준 시각(until 과 지금 중 이른 쪽)까지로 잰다.

    관제 쪽이 함께 멈춘 공백은 버린다. 맥 절전처럼 data-01 도 멈췄으면 노드가 아니라 관제가 멈춘 것이다.
    공백 안에서 탐지가 돈 분(detector_runs.started_at 을 분으로 자른 DISTINCT)이
    threshold_seconds / 60 × alive_ratio 이상일 때만 신호다.

    신호의 시각은 공백 시작(마지막 수신)이라 진행 중에 낸 키와 복구 뒤에 다시 돌린 키가 같다.
    복구 시각은 _end 로 넘겨 last_ts 에 남긴다. node_metrics 에는 provenance 가 없어 range_clause 를 쓰지
    않고, since · until 은 공백 시작 시각에만 건다. 적재 시각 계열은 전 기간으로 본다.

    params.split_on_gate_reject 가 true 면(i2) 위를 통과한 공백을 같은 노드의 관문 거부 시각으로 쪼갠다.
    관문이 그 노드의 밀어넣기를 거부했다는 것은 노드가 그 시각에 보냈다는 증거다. 조각마다 위와 같은 잣대
    (임계치를 넘는가 · 그 조각에서 관제가 산 분이 기준 이상인가)를 대고, 둘 다 맞는 조각이 없으면 신호를
    내지 않는다. 거부가 없으면 조각은 공백 하나뿐이라 결과가 i1 과 같다. 거부로 치는 줄은 GATE_SPLIT_SQL 참고.
    신호 시각은 여전히 공백 시작이라, 거부가 이어지다 멈춘 뒤 노드가 계속 조용하면 같은 키로 뜬다.
    내는 신호에는 거부 건수(gate_refusals)와 가장 긴 조각(longest_uncovered_seconds)을 더 남긴다.

    거부 줄은 인증 뒤에 남으니 그 노드가 보낸 것은 맞지만, 노드가 스스로 만들 수도 있다. 침해된 노드가
    잘못된 형식이나 예약을 채우는 요청을 10분 안쪽마다 보내면 Loki 에는 아무것도 들어가지 않는데 공백이
    쪼개진다. 그래서 두 가지로 막는다.
      - 사유를 eventid 별로 인정한다(params.gate_reject_reasons = {eventid: [사유, …]}). 지금 관문이 남기는
        형식 거부(throttled 415)와 끊김(client_gone)은 노드가 헤더 · 연결만으로 만들 수 있어 넣지 않는다.
      - 공백 전체가 params.split_max_gap_seconds 를 넘으면 조각과 상관없이 낸다. 인정한 사유(busy 등)를
        노드가 만들어도 그 길이까지만 가릴 수 있다. 이때 근거에 split_capped 를 남긴다.

    i2 는 규칙 버전이 달라 인시던트 키(R301|i2|…)가 i1(R301|i1|…)과 다르다. i1 로 뜬 인시던트와 판정은
    i1 키로 그대로 남고, i2 로 처음 돌면 쪼개도 남는 과거 공백이 i2 키로 새로 뜬다. 판정할 건이 하나씩
    더 생기고 알림 트리거(AFTER INSERT)도 그만큼 울린다. 허니팟 v1 → v2 와 같은 방식이다.
    """
    p = rule["params"]
    threshold, ratio = p["threshold_seconds"], p["alive_ratio"]
    if not (isinstance(threshold, int) and not isinstance(threshold, bool) and threshold > 0):
        raise ValueError(f"{rule['id']}: threshold_seconds 는 양의 정수여야 합니다")
    if not (isinstance(ratio, (int, float)) and not isinstance(ratio, bool) and 0 <= ratio <= 1):
        raise ValueError(f"{rule['id']}: alive_ratio 는 0 이상 1 이하의 수여야 합니다")
    split = p.get("split_on_gate_reject", False)
    if not isinstance(split, bool):
        raise ValueError(f"{rule['id']}: split_on_gate_reject 는 true · false 여야 합니다")
    if split:
        if "gate_reject_eventids" in p:
            # 예전 꼴(eventid 목록 × 사유 목록)은 모든 조합을 인정했다. 조용히 무시하지 않고 멈춘다
            raise ValueError(f"{rule['id']}: gate_reject_eventids 는 없어졌습니다. gate_reject_reasons 에 eventid 별로 적습니다")
        by_eid, cap = p.get("gate_reject_reasons"), p.get("split_max_gap_seconds")
        # 사유는 원장 줄의 input 앞머리(reason=…)에서 [a-z_]+ 로 뽑는다. 그 꼴이 아니면 영영 맞지 않는다
        if not (isinstance(by_eid, dict) and by_eid and all(
                isinstance(k, str) and k and isinstance(v, list) and v and
                all(isinstance(x, str) and GATE_REASON_RE.fullmatch(x) for x in v) for k, v in by_eid.items())):
            raise ValueError(f"{rule['id']}: gate_reject_reasons 는 {{eventid: [사유([a-z_]+), …]}} 꼴이어야 합니다")
        if not (isinstance(cap, int) and not isinstance(cap, bool) and cap > threshold):
            raise ValueError(f"{rule['id']}: split_max_gap_seconds 는 threshold_seconds 보다 큰 정수여야 합니다")
        # (eventid, 사유) 쌍을 나란한 두 배열로 넘긴다. SQL 이 unnest 로 다시 짝짓는다
        pair_eids = [k for k, v in by_eid.items() for _ in v]
        pair_reasons = [x for v in by_eid.values() for x in v]
    rng, extra = "", []
    if since:
        rng += " AND g.gap_start >= %s"; extra.append(since)
    if until:
        rng += " AND g.gap_start < %s"; extra.append(until)
    cur.execute(
        "WITH r AS (SELECT least(%s::timestamptz, now()) AS ref), "
        "l AS (SELECT DISTINCT m.node_id, m.loaded_at FROM node_metrics m "
        "JOIN nodes n ON n.node_id = m.node_id "
        "WHERE n.status = 'active' AND 'metrics' = ANY(n.logs) AND m.loaded_at >= n.registered_at), "
        "g AS (SELECT node_id, loaded_at AS gap_start, "
        "lead(loaded_at) OVER (PARTITION BY node_id ORDER BY loaded_at) AS gap_end FROM l), "
        "s AS (SELECT g.node_id, g.gap_start, g.gap_end, coalesce(g.gap_end, r.ref) AS gap_stop "
        "FROM g, r WHERE coalesce(g.gap_end, r.ref) - g.gap_start > make_interval(secs => %s)"
        f"{rng}) "
        "SELECT s.node_id, s.gap_start, s.gap_end, "
        "(SELECT count(DISTINCT date_trunc('minute', d.started_at)) FROM detector_runs d "
        "WHERE d.started_at >= s.gap_start AND d.started_at < s.gap_stop) "
        "FROM s ORDER BY s.node_id, s.gap_start",
        [until, threshold] + extra)
    # 1500초 × 0.28 이 7.000000000000001분이 되어 7분을 떨어뜨리지 않게 자리를 줄여 비교한다
    need = round(threshold / 60 * ratio, 6)
    gaps = [(node, start, end, alive) for node, start, end, alive in cur.fetchall() if alive >= need]
    out = []
    for node, start, end, alive in gaps:
        detail = {"_target": f"node:{node}", "_end": end, "last_receipt": start.isoformat(),
                  "alive_minutes": alive, "threshold_seconds": threshold, "ongoing": end is None}
        if split:
            # 위를 통과한 공백(신호 후보)마다 한 번 돈다. 다리는 전 기간을 다시 돌므로 지난 공백도 회차마다 다시 보지만,
            # 거부 줄은 (sensor, ts) 색인으로 그 공백 구간만 읽는다
            cur.execute(GATE_SPLIT_SQL, [start, end, until, node, GATE_PUSH_PATH, pair_eids, pair_reasons, threshold])
            pieces = cur.fetchall()
            # 조각은 공백 [lo, hi) 를 빈틈없이 덮으므로 길이의 합이 공백 전체다
            capped = sum(float(x) for x, _, _ in pieces) > cap
            if pieces and not capped and not any(a is not None and a >= need for _, _, a in pieces):
                continue
            detail["gate_refusals"] = pieces[0][1] if pieces else 0
            detail["longest_uncovered_seconds"] = round(max((float(x) for x, _, _ in pieces), default=0.0), 1)
            if capped:
                detail["split_capped"] = True
        out.append((start, None, None, detail))
    return out


# R301 i2 가 공백을 쪼개는 관문 거부 줄. 관문 원장(collector/gate.py) → 다리(parse_collector)가 넣은 행이다.
#   sensor = collector, 밀어넣기 경로(GATE_PUSH_PATH)
#   username = 그 노드 id. 관문이 키로 노드를 알아낸 거부에만 붙는다(모르는 키 · 키 없음은 비어 있다)
#   출발지 = 그 노드의 등록 주소(nodes.addr). 다른 곳에서 그 노드의 키를 쓴 거부(addr_mismatch)는 빠진다
#   등록(registered_at) 뒤. 공백이 등록 뒤의 적재에서 시작하므로 겹치지만, 재등록 전 기록이 끼지 않게 적어 둔다
#   (eventid, 사유) 쌍이 params.gate_reject_reasons 에 있는 것. 사유는 input 앞머리 reason=… 이다.
#   같은 사유라도 eventid 에 따라 인정 여부가 다르다(옛 관문의 415 거부는 인정, 지금 관문의 415 제한은 아님)
# 공백 [lo, hi) 의 hi 는 주 질의의 gap_stop 과 같다(끝났으면 다음 적재, 진행 중이면 until 과 지금 중 이른 쪽).
# now() 는 트랜잭션 시작 시각이라 주 질의와 같은 값이다. 조각은 [lo, 거부1), [거부1, 거부2) … [거부n, hi) 이고
# 행마다 (조각 길이 초, 거부 건수, 임계치를 넘는 조각만 그 안에서 탐지가 돈 분 · 아니면 NULL) 를 돌려준다.
# 탐지 역할이 nodes.addr 를 읽어야 한다 (infra/schema.sql 역할 블록).
GATE_PUSH_PATH = "/loki/api/v1/push"
GATE_REASON_RE = re.compile(r"[a-z_]+")
GATE_SPLIT_SQL = (
    "WITH w AS (SELECT %s::timestamptz AS lo, coalesce(%s::timestamptz, least(%s::timestamptz, now())) AS hi), "
    "x AS (SELECT e.ts FROM events e JOIN nodes n ON n.node_id = %s CROSS JOIN w "
    "WHERE e.provenance = 'real' AND e.sensor = 'collector' AND e.url = %s "
    "AND e.username = n.node_id AND host(e.src_ip) = host(n.addr) AND e.ts >= n.registered_at "
    "AND e.ts > w.lo AND e.ts < w.hi AND (e.eventid, substring(e.input from '^reason=([a-z_]+) ')) IN "
    "(SELECT k.eid, k.reason FROM unnest(%s::text[], %s::text[]) AS k(eid, reason))), "
    "p AS (SELECT lo AS ts FROM w UNION ALL SELECT ts FROM x UNION ALL SELECT hi FROM w), "
    "c AS (SELECT ts AS a, lead(ts) OVER (ORDER BY ts) AS b FROM p) "
    "SELECT extract(epoch FROM c.b - c.a), (SELECT count(*) FROM x), "
    "CASE WHEN c.b - c.a > make_interval(secs => %s) THEN "
    "(SELECT count(DISTINCT date_trunc('minute', d.started_at)) FROM detector_runs d "
    "WHERE d.started_at >= c.a AND d.started_at < c.b) END "
    "FROM c WHERE c.b IS NOT NULL ORDER BY c.a")


COLLECTORS = {
    "session_threshold": signals_session_threshold,
    "actor_rate": signals_actor_rate,
    "session_compound": signals_session_compound,
    "event_match": signals_event_match,
    "baseline_deviation": signals_baseline_deviation,
    "operator_rate": signals_operator_rate,
    "node_silence": signals_node_silence,
    "key_plant": signals_key_plant,
}


# ----------------------------------------------------------------------
#  인시던트 통합
# ----------------------------------------------------------------------

def aggregate(signals, gap_seconds):
    """동일 대상(IP, _target)의 신호를 시간 간격으로 묶는다. [((ip, target), items)] 를 돌려준다.

    간격이 gap_seconds 이내로 이어지면 같은 인시던트로 본다.
    한 IP 가 사흘 내내 두드려도 끊김 없이 이어지면 인시던트 하나다.
    _target 이 없는 신호는 (ip, None) 으로 묶여 묶음과 순서가 IP 로만 묶던 때와 같다.
    """
    by_key = {}
    for ts, ip, sess, detail in signals:
        target = detail.get("_target") if isinstance(detail, dict) else None
        by_key.setdefault((ip, target), []).append((ts, sess, detail))

    groups = []
    for key, items in by_key.items():
        items.sort(key=lambda x: x[0])
        cur_group = [items[0]]
        for prev, nxt in zip(items, items[1:]):
            if (nxt[0] - prev[0]).total_seconds() <= gap_seconds:
                cur_group.append(nxt)
            else:
                groups.append((key, cur_group))
                cur_group = [nxt]
        groups.append((key, cur_group))
    return groups


def strip_control(detail):
    """evidence 에 넣을 detail. 제어 필드가 없으면 받은 것을 그대로 돌려준다."""
    if isinstance(detail, dict) and any(k in detail for k in CONTROL_FIELDS):
        return {k: v for k, v in detail.items() if k not in CONTROL_FIELDS}
    return detail


SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}

# 인시던트 적재. 열 목록과 VALUES 는 대상 열이 생기기 전 문장을 글자 그대로 옮긴 것이다(허니팟 v1 · v2 가 쓴다).
# _target 이 있는 행만 INSERT_TARGET 으로 target 열을 함께 넣는다.
#
# 충돌 처리만 DO NOTHING 에서 DO UPDATE 로 바꿨다. 글자 그대로 옮긴 것은 target 열을 더할 때 허니팟
# v1 · v2 의 적재 결과가 바뀌지 않음을 보이기 위해서였다. 이번에는 결과를 바꾸는 것이 목적이다.
#   - 1분 다리는 전 기간을 다시 돌므로 이어지는 사건은 회차마다 같은 키로 다시 나온다. DO NOTHING 은
#     그 사건의 last_ts · signal_count · session_count · evidence 를 처음 적재한 값으로 굳혔다
#     (운영 v1 에서 30건이 그랬다).
#   - 빈 표에 한 번 돌린 결과는 전과 같다. 열 · VALUES 는 그대로이고 충돌이 없으면 갱신 절은 돌지 않는다.
#     시험은 충돌 절 앞까지가 옛 문장과 글자가 같은지를 본다.
#   - 끝 시각 · 건수는 줄지 않는다(GREATEST). --until 을 앞당겨 다시 돌려도 커진 값을 되돌리지 않는다.
#     evidence 도 이번 회차의 끝 시각 · 건수가 둘 다 기존 이상일 때만 바꾼다(EVIDENCE_IF_GROWN). 부분 재적용이
#     근거(sessions · observed_count_max)만 잘린 구간 값으로 줄여 건수 · 끝 시각과 어긋나게 하지 않는다.
#     triage 는 observed_count_max 를 관측값으로 판정에 남긴다.
#   - 판정된 사건은 고치지 않는다. 판정자가 본 근거가 판정 기록과 함께 남아야 한다. 아래 WHERE 는 문장
#     시작 때의 스냅샷으로 판정을 보므로, 잠금을 기다리는 사이 커밋된 판정은 놓친다. 그 경우는 DB 트리거
#     (infra/schema.sql trg_incidents_keep_judged)가 새 스냅샷으로 다시 보고 갱신을 건너뛴다.
#   - 값이 그대로면 고치지 않는다. 회차마다 모든 미판정 행을 새로 쓰지 않게 한다.
#   - 알림 트리거(infra/notify.sql)는 AFTER INSERT 라 갱신에는 울리지 않는다. created_at 도 그대로라
#     실행 기록의 새 인시던트 수와 알림 발송기(created_at 기준)도 갱신을 새 사건으로 세지 않는다.
#   - 충돌한 행은 WHERE 가 거짓이어도 이 트랜잭션이 끝날 때까지 잠긴다. 그동안 콘솔의 상태 변경
#     (판정 · 확인)은 탐지 한 회차가 끝나기를 기다린다. 같은 회차의 억제 삭제는 사람이 손대는 중인 행을
#     건너뛰어(suppress 참고) 콘솔과 서로 기다리지 않는다.
# 탐지 역할(opsloop_detector)에는 이 네 열의 UPDATE 권한만 준다 (infra/schema.sql 역할 블록).
EVIDENCE_IF_GROWN = ("CASE WHEN EXCLUDED.last_ts >= incidents.last_ts "
                     "AND EXCLUDED.signal_count >= incidents.signal_count "
                     "THEN EXCLUDED.evidence ELSE incidents.evidence END")
ON_CONFLICT_GROW = f"""
            ON CONFLICT (incident_key) DO UPDATE
            SET last_ts       = GREATEST(incidents.last_ts, EXCLUDED.last_ts),
                signal_count  = GREATEST(incidents.signal_count, EXCLUDED.signal_count),
                session_count = GREATEST(incidents.session_count, EXCLUDED.session_count),
                evidence      = {EVIDENCE_IF_GROWN}
            WHERE NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.incident_key = incidents.incident_key)
              AND (incidents.last_ts, incidents.signal_count, incidents.session_count, incidents.evidence)
                  IS DISTINCT FROM (GREATEST(incidents.last_ts, EXCLUDED.last_ts),
                                    GREATEST(incidents.signal_count, EXCLUDED.signal_count),
                                    GREATEST(incidents.session_count, EXCLUDED.session_count),
                                    {EVIDENCE_IF_GROWN})"""

INSERT_BASE = """
            INSERT INTO incidents (incident_key, rule_id, rule_version, rule_name, severity,
                                   actor_ip, first_ts, last_ts, signal_count, session_count,
                                   evidence)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)""" + ON_CONFLICT_GROW

INSERT_TARGET = """
            INSERT INTO incidents (incident_key, rule_id, rule_version, rule_name, severity,
                                   actor_ip, first_ts, last_ts, signal_count, session_count,
                                   evidence, target)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s)""" + ON_CONFLICT_GROW


def absorb_conf(rule):
    """params.absorb_same_payload 를 (창 시간, 첫 사건 근거에 보일 출발지 · 흡수 항목 최대 수)로. 없으면 None.

    max_sources 는 근거(evidence.absorbed)의 길이만 자른다. 지운 인시던트는 상한 없이 incident_absorbed 에 남는다.
    """
    conf = rule.get("params", {}).get("absorb_same_payload")
    if conf is None:
        return None
    hours, cap = (conf.get("window_hours"), conf.get("max_sources", 50)) if isinstance(conf, dict) else (None, None)
    if not (isinstance(hours, (int, float)) and not isinstance(hours, bool) and hours > 0
            and isinstance(cap, int) and not isinstance(cap, bool) and cap > 0):
        raise ValueError(f"{rule['id']}: absorb_same_payload 는 {{window_hours: 양수, max_sources: 양의 정수}} 꼴이어야 합니다")
    return hours, cap


def prepare_rule(rules_doc, rule):
    """run() 이 신호 함수에 넘기는 제어 인자를 params 에 넣는다. 규칙 파일(rule_versions)에는 들어가지 않는다.

    _version    규칙 버전 (기준선 이탈이 같은 버전 인시던트를 본다)
    _key_write  exclude_pubkey_redir 가 켜진 규칙에만. 같은 규칙 파일의 켜진 key_plant 규칙(R006)의 eventid ·
                write_patterns 다. R003 은 R006 이 잡는 쓰기가 같은 세션에 있을 때만 키 줄 저장을 뺀다. 그런 규칙이
                없거나 둘 이상이면 규칙 오류다(무엇에 묶을지 모른다)
    """
    params = rule.setdefault("params", {})
    params["_version"] = rules_doc["rule_version"]
    if params.get("exclude_pubkey_redir") is True:
        plants = [r for r in rules_doc["rules"] if r.get("type") == "key_plant" and r.get("enabled", True)]
        if len(plants) != 1:
            raise ValueError(f"{rule['id']}: exclude_pubkey_redir 는 같은 규칙 파일에 켜진 key_plant 규칙이 하나 있어야 합니다")
        params["_key_write"] = {"eventid": plants[0]["params"]["eventid"],
                                "patterns": plants[0]["params"]["write_patterns"]}
    return rule


def absorb_same_payload(groups, hours, cap):
    """같은 페이로드를 첫 사건에서 hours 시간 안에 다시 가져온 인시던트를 첫 사건에 묶는다 (v3 R003 · R006).

    판정 기준(2026-09-25 §6): 출발지가 달라도 같은 페이로드를 첫 사건의 투하 시각에서 24시간 안에 다시 투하한
    사건은 첫 사건의 중복이다. 한 캠페인이 출발지만 바꿔 돌리는 것이라 두 번째 알림부터는 새로 알려주는 것이 없다.
    다만 그 출발지들은 차단 근거로 남아야 한다.

    groups 는 한 규칙의 [(키, 출발지, 첫 시각, {페이로드: 그 인시던트에서 처음 본 시각}, 근거 dict, 세션 목록,
    페이로드 없는 신호 수)] 이다. 페이로드마다 시각순으로 보며, 닻(첫 사건)이 없거나 닻에서 창을 넘었으면 그 인시던트가
    새 닻이 된다. 창은 닻에서 재고 미끄러지지 않는다(24시간이 지난 투하는 새 첫 사건). 인시던트의 페이로드가 모두 다른
    인시던트의 창 안이면 흡수되고, 하나라도 닻이면 남는다. 흡수한 첫 사건은 창에 든 닻 가운데 가장 이른 것이다.
    페이로드가 없는 인시던트는 묶지도 묶이지도 않는다.

    페이로드가 없는 신호(해시 없는 다운로드 실패의 URL, 키가 적히지 않은 authorized_keys 쓰기)가 하나라도 든 인시던트는
    흡수되지 않는다. 그 신호가 이미 본 페이로드와 같은지 알 수 없어, 지우면 새 URL · 새 키가 어디에도 남지 않는다.
    가진 페이로드의 닻은 될 수 있다. 그 페이로드를 처음 가져온 사건이므로, 닻에서 빼면 뒤의 반복이 새 첫 사건이 된다.

    근거는 제자리에서 고친다. 첫 사건에는 absorbed = {창, 흡수 건수, 다른 출발지 총수, 앞에서부터 cap 개까지의 출발지,
    앞에서부터 cap 건까지의 흡수 항목(키 · 출발지 · 첫 시각 · 세션)}, 흡수된 사건에는 duplicate_of = 첫 사건 키를 넣는다.
    이 근거는 판정자가 보는 요약이다. 판정되면 굳고(ON_CONFLICT_GROW · trg_incidents_keep_judged) cap 에서 잘린다.
    차단 근거의 전부는 remove_incidents 가 지우는 문장에서 incident_absorbed 에 넣는 행이다. {흡수된 키: 첫 사건 키} 를 돌려준다.
    """
    window = timedelta(hours=hours)
    anchor, anchors, cover = {}, set(), {}
    for ts, key, pid in sorted((ts, g[0], pid) for g in groups for pid, ts in g[3].items()):
        a = anchor.get(pid)
        if a is None or ts - a[0] > window:
            anchor[pid] = (ts, key)
            anchors.add(key)
        else:
            cover.setdefault(key, []).append(a)
    by_key = {g[0]: g for g in groups}
    victims = {g[0]: min(cover[g[0]])[1] for g in groups if g[3] and not g[6] and g[0] not in anchors}
    for first in sorted(set(victims.values())):
        fip, fev = by_key[first][1], by_key[first][4]
        taken = sorted((by_key[v][2], v) for v, f in victims.items() if f == first)
        sources, items = [], []
        for ts, v in taken:
            ip = by_key[v][1]
            if ip is not None and ip != fip and ip not in sources:
                sources.append(ip)
            items.append({"key": v, "actor_ip": ip, "first_ts": ts.isoformat(), "sessions": by_key[v][5][:10]})
        fev["absorbed"] = {"window_hours": hours, "incidents": len(taken), "sources_total": len(sources),
                           "sources": sources[:cap], "items": items[:cap]}
    for v, first in victims.items():
        by_key[v][4]["duplicate_of"] = first
    return victims


def suppress(cur, rules_doc, staged):
    """더 높은 심각도 알림에 흡수되는 인시던트를 지운다.

    판정 결과 R001 의 비조치율이 100% 였다. 관측값은 임계치의 5배까지
    올라갔는데도 전부 "무시 가능"이었고, 이유는 모두 같았다. 같은 행위자에
    대해 같은 시간대에 더 심각한 알림이 이미 떠 있었다.

    임계치를 올려서 해결되는 문제가 아니다. 관측값 전 구간이 비위협이므로
    임계치를 올리면 규칙이 아무것도 잡지 않게 될 뿐이다. 문제는 값이 아니라
    같은 사건을 여러 규칙이 각자 보고한다는 데 있다.

    그래서 값이 아니라 구조를 바꾼다. 규칙은 그대로 두고, 인시던트를 만드는
    단계에서 상위 심각도 알림에 흡수시킨다. 규칙을 지우지 않는 이유는 분명하다.
    상위 알림이 없을 때는 이 규칙이 유일한 탐지이기 때문이다.
    허니팟은 대부분의 비밀번호를 통과시켜 무차별 대입이 거의 항상 로그인
    성공으로 이어지지만, 실제 서버에서는 실패만 반복하는 쪽이 다수다.
    """
    counts, victims = plan_suppression(rules_doc, staged)
    remove_incidents(cur, victims)
    return counts


def plan_suppression(rules_doc, staged, by=None):
    """suppress 가 지울 인시던트를 고른다. ({규칙: 건수}, [키]) 를 돌려주고 DB 는 건드리지 않는다.

    by 에 dict 를 주면 지울 인시던트마다 그것을 가린(같은 출발지 · 겹치는 구간 · 더 높은 심각도) 인시던트 키를 모두
    넣는다(run() 이 가린 것이 흡수된 인시던트뿐인지 본다). 고르는 결과는 by 와 상관없이 같다.
    """
    conf = rules_doc["suppression"]
    if not conf.get("absorb_by_higher_severity"):
        return {}, []
    gap = conf.get("window_seconds", 900)

    flat = [(rule["id"], r) for rule, rows, _, _ in staged for r in rows]
    victims, counts = [], {}

    for rid, r in flat:
        rank, ip, first_ts, last_ts = SEVERITY_RANK[r[4]], r[5], r[6], r[7]
        if ip is None:
            continue
        hit = []
        for orid, o in flat:
            if o[0] == r[0] or o[5] != ip:
                continue
            if SEVERITY_RANK[o[4]] < rank and \
               (o[6] - last_ts).total_seconds() <= gap and \
               (first_ts - o[7]).total_seconds() <= gap:
                hit.append(o[0])
                if by is None:
                    break
        if hit:
            victims.append(r[0])
            counts[rid] = counts.get(rid, 0) + 1
            if by is not None:
                by[r[0]] = hit
    return counts, victims


def remove_incidents(cur, victims, absorbed=(), via=()):
    """억제된 인시던트(victims)와 같은 페이로드로 흡수된 인시던트(absorbed)를 지운다. {규칙: 흡수로 지운 건수} 를 돌려준다.

    absorbed 는 [{victim, first_key, sessions, payloads}] 이다. via 는 가린 것이 흡수된 인시던트뿐인 억제 대상
    [{member, via, rule_id, rule_version, actor_ip, first_ts, last_ts, signal_count, sessions}] 이다.

    사람이 손댄 인시던트는 지우지 않는다. 판정뿐 아니라 조치(확인 · 차단 · 메모)도 그렇다.
    actions 는 incidents 에 ON DELETE CASCADE 로 걸려 있어, 지우면 조치 기록이 함께 사라지고
    이 기록은 원문에서 다시 만들 수 없다. 새 버전에서만 억제가 적용된다.
    두 문장으로 나눈다. 먼저 지울 행을 잠그되 남이 잠근 행(콘솔이 판정 · 조치를 넣는 중이면 FK 로
    잡힌다)은 건너뛴다. 기다리면 적재 때 잠근 행을 기다리는 콘솔과 서로 기다리다 교착한다.
    판정 · 조치는 잠근 뒤의 새 문장(새 스냅샷)에서 보므로, 잠그기 직전에 커밋된 조치도 놓치지 않는다.

    흡수된 것도 한 잠금 문장에 넣는다(키 순서 · SKIP LOCKED 그대로). 지우는 문장(ABSORB_SQL)은 지운 행을 그대로
    incident_absorbed 에 첫 사건 키와 함께 넣는다. 그래서 지운 것은 모두 표에 있고(상한 없음), 표에 넣지 못하면
    지우지도 않는다. 첫 사건의 근거가 판정으로 굳어도 표에는 붙으므로 판정 뒤에 온 중복도 지운다. 첫 사건이
    incidents 에 없으면(억제 등으로 지워졌다) 지우지 않는다.
    via 는 억제를 지운 뒤에 넣는다. 그 낮은 알림이 실제로 지워졌고 가린 인시던트가 흡수로 표에 있을 때만, 그 첫 사건
    아래 kind=suppressed 로 넣는다. 가린 인시던트가 지워지지 않고 남았으면 보통의 억제이므로 넣지 않는다.
    흡수가 없으면 문장 · 인자가 전과 같다(두 문장).
    """
    first_of = {a["victim"]: a for a in absorbed}
    sup = set(victims)
    keys = list(victims) + [k for k in first_of if k not in sup]
    if not keys:
        return {}
    cur.execute(SUPPRESS_LOCK_SQL, (keys,))
    locked = [k for k, in cur.fetchall()]
    gone = [k for k in locked if k in sup]
    if gone:
        cur.execute(SUPPRESS_DELETE_SQL, (gone,))
    dup = [first_of[k] for k in locked if k not in sup]
    removed = {}
    if dup:
        cur.execute(ABSORB_SQL, (json.dumps(dup, ensure_ascii=False),))
        removed = dict(cur.fetchall())
    if via:
        cur.execute(ABSORB_VIA_SQL, (json.dumps(list(via), ensure_ascii=False, default=str),))
    return removed


# 억제 · 흡수 삭제 (remove_incidents). 잠글 권한(FOR UPDATE)은 탐지 역할의 열 UPDATE 권한으로 충분하다
SUPPRESS_LOCK_SQL = ("SELECT incident_key FROM incidents WHERE incident_key = ANY(%s) "
                     "ORDER BY incident_key FOR UPDATE SKIP LOCKED")
SUPPRESS_DELETE_SQL = ("DELETE FROM incidents i WHERE i.incident_key = ANY(%s) "
                       "AND NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.incident_key = i.incident_key) "
                       "AND NOT EXISTS (SELECT 1 FROM actions a WHERE a.incident_key = i.incident_key)")
# 흡수 삭제 · 기록. 판정 · 조치가 없고 첫 사건이 있는 것만 지우고, 지운 행을 같은 문장에서 incident_absorbed 에
# 넣는다(세션 · 페이로드는 탐지가 넘긴 전부). 다시 돌린 회차처럼 이미 있으면 그대로 둔다. 규칙별 지운 건수를 돌려준다.
# 첫 사건(f)은 읽기만 하고 잠그지 않는다. 탐지 역할의 incidents 읽기 · 지우기, incident_absorbed 읽기 · 넣기 권한으로 된다
ABSORB_SQL = (
    "WITH d AS (SELECT * FROM jsonb_to_recordset(%s::jsonb) "
    "AS x(victim text, first_key text, sessions jsonb, payloads jsonb)), "
    "gone AS (DELETE FROM incidents i USING d WHERE i.incident_key = d.victim "
    "AND EXISTS (SELECT 1 FROM incidents f WHERE f.incident_key = d.first_key) "
    "AND NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.incident_key = i.incident_key) "
    "AND NOT EXISTS (SELECT 1 FROM actions a WHERE a.incident_key = i.incident_key) "
    "RETURNING d.first_key, i.incident_key, i.rule_id, i.rule_version, i.actor_ip, i.first_ts, i.last_ts, "
    "i.signal_count, d.sessions, d.payloads), "
    "rec AS (INSERT INTO incident_absorbed (first_key, member_key, kind, rule_id, rule_version, actor_ip, "
    "first_ts, last_ts, signal_count, sessions, payloads) "
    "SELECT first_key, incident_key, 'absorbed', rule_id, rule_version, actor_ip, first_ts, last_ts, signal_count, "
    "ARRAY(SELECT jsonb_array_elements_text(sessions)), ARRAY(SELECT jsonb_array_elements_text(payloads)) FROM gone "
    "ON CONFLICT (first_key, member_key) DO NOTHING) "
    "SELECT rule_id, count(*) FROM gone GROUP BY 1 ORDER BY 1")
# 가린 것이 흡수된 인시던트뿐인 억제. 억제로 실제로 지워졌고 가린 인시던트(via)가 흡수로 표에 있을 때만 그 첫 사건 아래 넣는다
ABSORB_VIA_SQL = (
    "INSERT INTO incident_absorbed (first_key, member_key, kind, via_key, rule_id, rule_version, actor_ip, "
    "first_ts, last_ts, signal_count, sessions) "
    "SELECT a.first_key, x.member, 'suppressed', x.via, x.rule_id, x.rule_version, x.actor_ip::inet, x.first_ts, "
    "x.last_ts, x.signal_count, ARRAY(SELECT jsonb_array_elements_text(x.sessions)) "
    "FROM jsonb_to_recordset(%s::jsonb) AS x(member text, via text, rule_id text, rule_version text, actor_ip text, "
    "first_ts timestamptz, last_ts timestamptz, signal_count integer, sessions jsonb) "
    "JOIN incident_absorbed a ON a.member_key = x.via AND a.kind = 'absorbed' "
    "WHERE NOT EXISTS (SELECT 1 FROM incidents i WHERE i.incident_key = x.member) "
    "ON CONFLICT (first_key, member_key) DO NOTHING")


def run(conn, rules_doc, since, until, verbose=True):
    version = rules_doc["rule_version"]
    gap = rules_doc["aggregation"]["window_gap_seconds"]
    cur = conn.cursor()

    # 규칙 정의를 남긴다. 나중에 "그때 임계치가 뭐였지"를 코드가 아니라 DB 가 답한다.
    cur.execute(
        """INSERT INTO rule_versions (rule_version, definition, reason)
           VALUES (%s, %s::jsonb, %s)
           ON CONFLICT (rule_version) DO NOTHING""",
        (version, json.dumps(rules_doc, ensure_ascii=False), rules_doc.get("note")))

    # 흡수 · 이전 7일 기준선(v3)은 incident_absorbed 를 쓰고 읽는다. 표가 없으면 문장 중간이 아니라 여기서 멈춘다
    if any(r.get("enabled", True) and (absorb_conf(r) or "baseline_days" in r.get("params", {}))
           for r in rules_doc["rules"]):
        cur.execute("SELECT to_regclass('incident_absorbed') IS NOT NULL")
        if not cur.fetchone()[0]:
            raise RuntimeError("incident_absorbed 표가 없습니다. infra/migrations/20260925_v3_absorbed.sql 을 먼저 적용합니다")

    created = skipped = 0
    summary = []
    staged = []   # (rule, rows, signal_count)
    absorb_rows, planned, sessions_of = [], {}, {}   # 흡수 [{victim, first_key, sessions, payloads}], {규칙: 고른 건수}
    since_ts = None

    for rule in rules_doc["rules"]:
        if not rule.get("enabled", True):
            continue
        collector = COLLECTORS.get(rule["type"])
        if collector is None:
            raise ValueError(f"{rule['id']}: 알 수 없는 규칙 유형 {rule['type']}")

        # 고정 시간창으로 신호를 만드는 규칙은 슬롯 경계 때문에 전역 창과
        # 같은 값을 쓰면 연속 활동이 쪼개진다. 규칙별 지정을 우선한다.
        rule_gap = rule.get("aggregation_gap_seconds", gap)
        prepare_rule(rules_doc, rule)
        absorb = absorb_conf(rule)
        # 흡수 규칙은 구간 실행(--since)에서도 신호를 처음부터 읽는다. 어느 투하가 닻(첫 사건)인지는 앞선 닻에 달려
        # 있어(창은 닻에서 잰다) since 앞 창만 읽어서는 전 기간 실행과 닻이 달라질 수 있다. 적재는 아래에서 구간에 닿은
        # 묶음과 그 묶음이 흡수된 첫 사건만 한다
        if absorb and since and since_ts is None:
            cur.execute("SELECT %s::timestamptz", (since,))
            since_ts = cur.fetchone()[0]
        signals = collector(cur, rule, None if absorb else since, until)
        groups = aggregate(signals, rule_gap)

        built = []   # (행 앞 10열, 대상, 근거 dict, {페이로드: 처음 본 시각}, 세션 목록, 페이로드 없는 신호 수)
        for (ip, target), items in groups:
            # 끝난 시각(_end)이 있는 신호는 last_ts 를 거기까지 늘린다. 없으면 전처럼 마지막 신호 시각이다
            ends = [i[2]["_end"] for i in items if isinstance(i[2], dict) and i[2].get("_end") is not None]
            first_ts, last_ts = items[0][0], max([items[-1][0]] + ends)
            sessions = sorted({i[1] for i in items if i[1]})
            key = f"{rule['id']}|{version}|{target or ip or '-'}|{first_ts.isoformat()}"
            details = [strip_control(i[2]) for i in items]
            # 임계치와 비교되는 값을 신호 전체에서 뽑아 남긴다. 표본 몇 개만
            # 보고 나중에 다시 계산하면 큰 인시던트에서 최댓값을 놓친다.
            metrics = [d for d in details if isinstance(d, dict)]
            counts = [m["count"] for m in metrics if "count" in m]
            # z 가 있으면(v3 기준선) 반올림 전 값으로 잰 것이다. 없으면 전처럼 근거의 반올림 값으로 잰다(v1 · v2 그대로)
            devs = [m["z"] if "z" in m else (m["count"] - m["mean"]) / m["sigma"]
                    for m in metrics if m.get("sigma")]
            observed = {}
            if counts:
                observed["observed_count_max"] = max(counts)
            if devs:
                observed["observed_sigma_max"] = round(max(devs), 2)

            payloads, bare = {}, 0
            if absorb:
                # 신호는 시각순이므로 처음 넣은 값이 그 인시던트에서 그 페이로드를 처음 본 시각이다
                for ts, _, d in items:
                    got = (d.get("_payload") or []) if isinstance(d, dict) else []
                    for pid in got:
                        payloads.setdefault(pid, ts)
                    bare += not got
            evidence = {"sample": details[:5], "sessions": sessions[:10], **observed}
            if bare:
                evidence["payloadless_signals"] = bare
            built.append(((key, rule["id"], version, rule["name"], rule["severity"], ip,
                           first_ts, last_ts, len(items), len(sessions)), target, evidence, payloads, sessions, bare))

        n_signals = len(signals)
        if absorb:
            taken = absorb_same_payload([(h[0], h[5], h[6], pl, ev, ss, nb) for h, _, ev, pl, ss, nb in built],
                                        *absorb)
            if since_ts is not None:
                keep = {h[0] for h, *_ in built if h[7] >= since_ts}
                keep |= {taken[v] for v in keep if v in taken}
                built = [b for b in built if b[0][0] in keep]
                taken = {v: f for v, f in taken.items() if v in keep}
                n_signals = sum(1 for s in signals if s[0] >= since_ts)
            own = {h[0]: (ss, sorted(pl)) for h, _, _, pl, ss, _ in built}
            absorb_rows += [{"victim": v, "first_key": f, "sessions": own[v][0], "payloads": own[v][1]}
                            for v, f in sorted(taken.items())]
            planned[rule["id"]] = len(taken)
        for head, _, _, _, ss, _ in built:
            sessions_of[head[0]] = ss

        rows, target_rows = [], []
        for head, target, evidence, _, _, _ in built:
            row = head + (json.dumps(evidence, ensure_ascii=False, default=str),)
            if target is None:
                rows.append(row)
            else:
                target_rows.append(row + (target,))

        staged.append((rule, rows + target_rows, n_signals, rule_gap))

        # 이 규칙의 인시던트를 바로 넣는다. 뒤 규칙(기준선 이탈)이 앞 규칙의
        # 결과를 보아야 하므로 억제 판단보다 적재가 먼저다. 억제된 것은
        # 아래에서 지운다. 대상 행이 없는 규칙은 전과 같은 문장 하나만 낸다.
        execute_batch(cur, INSERT_BASE, rows, page_size=200)
        if target_rows:
            execute_batch(cur, INSERT_TARGET, target_rows, page_size=200)

    # 억제와 흡수를 모두 고른 뒤 한 번에 잠그고 지운다. 흡수가 없으면 전의 suppress() 와 같은 문장이다.
    # 흡수된 인시던트도 억제 판단에는 들어간다(같은 출발지 · 같은 구간의 더 낮은 알림을 가린다). 판정 기준에서 그 낮은
    # 알림은 흡수된 사건의, 흡수된 사건은 첫 사건의 중복이기 때문이다. 대신 가린 것이 흡수된 인시던트뿐인 낮은 알림은
    # incident_absorbed 에 첫 사건 아래 kind=suppressed 로 남겨 그 출발지의 행위(세션)가 어디에도 없게 되지 않게 한다
    dup_keys = {a["victim"] for a in absorb_rows}
    by = {} if dup_keys else None
    suppressed, sup_victims = plan_suppression(rules_doc, staged, by) if rules_doc.get("suppression") else ({}, [])
    via = []
    if dup_keys:
        rows_of = {r[0]: r for _, rows, _, _ in staged for r in rows}
        for k in sup_victims:
            if all(s in dup_keys for s in by[k]):
                r = rows_of[k]
                via += [{"member": k, "via": s, "rule_id": r[1], "rule_version": r[2], "actor_ip": r[5],
                         "first_ts": r[6].isoformat(), "last_ts": r[7].isoformat(), "signal_count": r[8],
                         "sessions": sessions_of.get(k, [])} for s in sorted(by[k])]
    absorbed = remove_incidents(cur, sup_victims, absorb_rows, via)

    for rule, rows, n_signals, rule_gap in staged:
        cur.execute("SELECT count(*) FROM incidents WHERE rule_id = %s AND rule_version = %s",
                    (rule["id"], version))
        n_now = cur.fetchone()[0]
        n_sup = suppressed.get(rule["id"], 0)
        created += n_now
        # 흡수 칸은 실제로 지운 수다(ABSORB_SQL). 고른 수와 다르면 아래에 따로 적는다
        summary.append((rule["id"], rule["name"], n_signals, len(rows), n_now, rule_gap, n_sup,
                        absorbed.get(rule["id"], 0)))

    # 실행 기록. 첫 수신 확인(node_first_receipt 4단계)이 "적재 뒤에 탐지가 돌았는가"를 여기서 본다.
    # 구 스키마에는 표가 없으므로 건너뛴다. incidents.created_at 의 기본값 now() 는 트랜잭션
    # 시작 시각이므로, 그 값을 가진 행이 이번 실행에서 새로 생기고 억제 뒤에도 남은 인시던트다.
    cur.execute("SELECT to_regclass('detector_runs') IS NOT NULL")
    if cur.fetchone()[0]:
        cur.execute(
            """INSERT INTO detector_runs (rule_version, since, until, started_at, finished_at, incidents)
               SELECT %s, %s::timestamptz, %s::timestamptz, now(), clock_timestamp(), count(*)
               FROM incidents WHERE rule_version = %s AND created_at = now()""",
            (version, since, until, version))

    conn.commit()
    cur.close()

    if verbose:
        # 흡수 칸은 흡수를 쓰는 규칙이 있을 때만 보인다. 없으면 표가 전과 같다
        show = any(absorb_conf(rule) for rule, _, _, _ in staged)
        width = 82 + (7 if show else 0)
        print("=" * width)
        print(f" 탐지 실행  규칙버전 {version}   범위 {since or '전체'} ~ {until or '전체'}")
        print("=" * width)
        head = f" {'흡수':>6}" if show else ""
        print(f"{'규칙':<6} {'이름':<18} {'신호':>8} {'통합':>8} {'억제':>6}{head} {'인시던트':>9}  압축률   통합창")
        print("-" * width)
        tot_s = tot_i = tot_x = tot_a = 0
        for rid, name, ns, ni, nn, g, nx, na in summary:
            comp = f"{100 * (1 - (ni - nx - na) / ns):5.1f}%" if ns else "    -"
            col = f" {na:>6,}" if show else ""
            print(f"{rid:<6} {name:<18} {ns:>8,} {ni:>8,} {nx:>6,}{col} {nn:>9,}  {comp}  {g // 60:>4}분")
            tot_s += ns; tot_i += ni; tot_x += nx; tot_a += na
        print("-" * width)
        comp = f"{100 * (1 - (tot_i - tot_x - tot_a) / tot_s):5.1f}%" if tot_s else "-"
        col = f" {tot_a:>6,}" if show else ""
        print(f"{'합계':<25} {tot_s:>8,} {tot_i:>8,} {tot_x:>6,}{col} {created:>9,}  {comp}")
        if tot_x:
            print(f"\n  억제 {tot_x}건 — 같은 행위자·같은 구간에 더 높은 심각도 알림이 있어")
            print(f"  관제자에게 새 정보를 주지 않는 인시던트를 만들지 않았다")
        if tot_a:
            print(f"\n  흡수 {tot_a}건 — 출발지가 달라도 같은 페이로드를 첫 사건에서 정한 시간 안에 다시 가져와")
            print(f"  첫 사건에 묶어 지웠다. 지운 인시던트(출발지 · 첫 시각 · 세션 · 키)는 incident_absorbed 에 남는다")
        n_via = len({v["member"] for v in via})
        if n_via:
            print(f"  억제 가운데 {n_via}건은 가린 것이 흡수된 인시던트뿐이라 그 첫 사건 아래(incident_absorbed)에 남겼다")
        left = sum(planned.values()) - tot_a
        if left:
            print(f"\n  흡수 대상 {sum(planned.values())}건 중 {left}건은 판정 · 조치가 있거나 콘솔이 잡고 있어 남겼다")
        print(f"  기본 통합 창 {gap}초 ({gap // 60}분), 규칙별 지정이 있으면 그 값을 쓴다\n")
    return summary


def list_incidents(conn, limit, severity=None, status=None):
    cur = conn.cursor()
    c, p = [], []
    if severity:
        c.append("severity = %s"); p.append(severity)
    if status:
        c.append("status = %s"); p.append(status)
    w = ("WHERE " + " AND ".join(c)) if c else ""
    cur.execute(f"""
        SELECT rule_id, rule_version, severity, host(actor_ip), first_ts,
               signal_count, session_count, status
        FROM incidents {w}
        ORDER BY CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1
                               WHEN 'medium' THEN 2 ELSE 3 END, first_ts DESC
        LIMIT %s""", p + [limit])
    print(f"{'규칙':<6} {'버전':<5} {'심각도':<9} {'출발지':<17} {'시작':<20} {'신호':>6} {'세션':>5} {'상태'}")
    print("-" * 96)
    for r in cur.fetchall():
        print(f"{r[0]:<6} {r[1]:<5} {r[2]:<9} {(r[3] or '-'):<17} "
              f"{r[4].strftime('%Y-%m-%d %H:%M:%S'):<20} {r[5]:>6,} {(r[6] or 0):>5} {r[7]}")
    print()
    cur.close()


def compare(conn, v1, v2):
    """두 규칙 버전의 결과를 비교한다. 리플레이 평가의 출력부."""
    cur = conn.cursor()
    cur.execute("""
        SELECT rule_id, severity,
               count(*) FILTER (WHERE rule_version = %s) a,
               count(*) FILTER (WHERE rule_version = %s) b
        FROM incidents WHERE rule_version IN (%s, %s)
        GROUP BY rule_id, severity ORDER BY rule_id""", (v1, v2, v1, v2))
    print(f"\n{'규칙':<6} {'심각도':<9} {v1:>10} {v2:>10} {'증감':>10}")
    print("-" * 50)
    ta = tb = 0
    for rid, sev, a, b in cur.fetchall():
        print(f"{rid:<6} {sev:<9} {a:>10,} {b:>10,} {b - a:>+10,}")
        ta += a; tb += b
    print("-" * 50)
    print(f"{'합계':<16} {ta:>10,} {tb:>10,} {tb - ta:>+10,}\n")
    cur.close()


def quality(conn):
    """규칙 버전별 오탐률·비조치율. 판정이 쌓인 뒤에 의미가 생긴다."""
    cur = conn.cursor()
    cur.execute("SELECT * FROM rule_quality ORDER BY rule_id, rule_version")
    rows = cur.fetchall()
    print(f"\n{'규칙':<6} {'버전':<5} {'인시던트':>8} {'판정':>6} {'위협':>6} "
          f"{'무시가능':>8} {'오탐':>6} {'오탐률':>8} {'비조치율':>9}")
    print("-" * 76)
    for r in rows:
        fp = f"{r[7]}%" if r[7] is not None else "-"
        na = f"{r[8]}%" if r[8] is not None else "-"
        print(f"{r[0]:<6} {r[1]:<5} {r[2]:>8,} {r[3]:>6,} {r[4]:>6,} "
              f"{r[5]:>8,} {r[6]:>6,} {fp:>8} {na:>9}")
    if not any(r[3] for r in rows):
        print("\n  판정 기록이 없습니다. 콘솔에서 인시던트를 판정하면 여기에 반영됩니다.")
    print()
    cur.close()


def main():
    ap = argparse.ArgumentParser(description="OpsLoop 탐지 엔진 (PostgreSQL)")
    ap.add_argument("--db-url", dest="url", help="미지정 시 환경변수 DATABASE_URL 사용")
    ap.add_argument("--rules", default=DEFAULT_RULES)
    ap.add_argument("--run", action="store_true")
    ap.add_argument("--since"); ap.add_argument("--until")
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--limit", type=int, default=20)
    ap.add_argument("--severity"); ap.add_argument("--status")
    ap.add_argument("--compare", nargs=2, metavar=("V1", "V2"))
    ap.add_argument("--quality", action="store_true", help="오탐률·비조치율 집계")
    ap.add_argument("--quiet", action="store_true", help="--run 의 요약 표를 찍지 않는다")
    args = ap.parse_args()

    conn = psycopg2.connect(db_url(args.url))

    if args.run:
        with open(args.rules, encoding="utf-8") as f:
            run(conn, json.load(f), args.since, args.until, verbose=not args.quiet)
    if args.list:
        list_incidents(conn, args.limit, args.severity, args.status)
    if args.compare:
        compare(conn, *args.compare)
    if args.quality:
        quality(conn)
    if not (args.run or args.list or args.compare or args.quality):
        ap.print_help()

    conn.close()


if __name__ == "__main__":
    main()
