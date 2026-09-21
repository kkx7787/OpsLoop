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

사용
  export DATABASE_URL='postgresql://opsloop:PASSWORD@호스트:5432/opsloop'
  python3 detect.py --run
  python3 detect.py --run --since 2026-09-05 --until 2026-09-06
  python3 detect.py --run --rules rules_v2.json
  python3 detect.py --run --rules rules_self.json --quiet     요약 표 없이
  python3 detect.py --list
  python3 detect.py --compare v1 v2
  python3 detect.py --quality
"""

import argparse
import json
import os
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
# ----------------------------------------------------------------------

CONTROL_FIELDS = ("_target", "_end")


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
    cur.execute(
        f"SELECT ts, src_ip, session, eventid, coalesce(shasum, url, input, message) "
        f"FROM events WHERE {w} AND {cond}", prm + extra)
    return [(ts, ip, s, {"eventid": ev, "detail": d}) for ts, ip, s, ev, d in cur.fetchall()]


def signals_baseline_deviation(cur, rule, since, until):
    """시간당 이벤트 수가 평균 + kσ 를 넘는 구간을 신호로 만든다.

    학습 모델이 아니라 기술 통계다. 관측 구간의 평균과 표준편차로 임계선을
    정한다. 규칙에 없는 새 패턴을 잡기 위한 보완 장치.
    sensors 가 없으면 허니팟 · 콘솔(BASELINE_SENSORS)만 센다.
    """
    p = rule["params"]
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


def signals_actor_rate(cur, rule, since, until):
    """동일 출발지의 이벤트 누적 빈도를 본다.

    관측 결과 봇은 한 세션에 로그인 1회만 시도하고 끊는다. 무차별 대입이
    세션 안이 아니라 세션들 사이에 퍼져 있어, 세션 단위 임계치로는 잡히지 않는다.
    그래서 IP 단위로 고정 시간창을 잘라 누적 횟수를 센다.

    params.http_status(정수 목록)가 있으면 그 응답 코드의 요청만 센다 (w1 R102 404 반복).
    자리는 eventid 조건 바로 뒤다. 없으면 문장과 인자가 전과 한 글자도 같다.
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
    """지표를 올리던 노드의 수신이 threshold_seconds 넘게 끊긴 구간 (i1 R301).

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
    """
    p = rule["params"]
    threshold, ratio = p["threshold_seconds"], p["alive_ratio"]
    if not (isinstance(threshold, int) and not isinstance(threshold, bool) and threshold > 0):
        raise ValueError(f"{rule['id']}: threshold_seconds 는 양의 정수여야 합니다")
    if not (isinstance(ratio, (int, float)) and not isinstance(ratio, bool) and 0 <= ratio <= 1):
        raise ValueError(f"{rule['id']}: alive_ratio 는 0 이상 1 이하의 수여야 합니다")
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
    return [(start, None, None,
             {"_target": f"node:{node}", "_end": end, "last_receipt": start.isoformat(),
              "alive_minutes": alive, "threshold_seconds": threshold, "ongoing": end is None})
            for node, start, end, alive in cur.fetchall() if alive >= need]


COLLECTORS = {
    "session_threshold": signals_session_threshold,
    "actor_rate": signals_actor_rate,
    "session_compound": signals_session_compound,
    "event_match": signals_event_match,
    "baseline_deviation": signals_baseline_deviation,
    "operator_rate": signals_operator_rate,
    "node_silence": signals_node_silence,
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

# 인시던트 적재. INSERT_BASE 는 대상 열이 생기기 전 문장을 글자 그대로 옮긴 것이다(허니팟 v1 · v2 가 쓴다).
# _target 이 있는 행만 INSERT_TARGET 으로 target 열을 함께 넣는다.
INSERT_BASE = """
            INSERT INTO incidents (incident_key, rule_id, rule_version, rule_name, severity,
                                   actor_ip, first_ts, last_ts, signal_count, session_count,
                                   evidence)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
            ON CONFLICT (incident_key) DO NOTHING"""

INSERT_TARGET = """
            INSERT INTO incidents (incident_key, rule_id, rule_version, rule_name, severity,
                                   actor_ip, first_ts, last_ts, signal_count, session_count,
                                   evidence, target)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb,%s)
            ON CONFLICT (incident_key) DO NOTHING"""


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
    conf = rules_doc["suppression"]
    if not conf.get("absorb_by_higher_severity"):
        return {}
    gap = conf.get("window_seconds", 900)

    flat = [(rule["id"], r) for rule, rows, _, _ in staged for r in rows]
    victims, counts = [], {}

    for rid, r in flat:
        rank, ip, first_ts, last_ts = SEVERITY_RANK[r[4]], r[5], r[6], r[7]
        if ip is None:
            continue
        for orid, o in flat:
            if o[0] == r[0] or o[5] != ip:
                continue
            if SEVERITY_RANK[o[4]] < rank and \
               (o[6] - last_ts).total_seconds() <= gap and \
               (first_ts - o[7]).total_seconds() <= gap:
                victims.append(r[0])
                counts[rid] = counts.get(rid, 0) + 1
                break

    if victims:
        # 사람이 손댄 인시던트는 지우지 않는다. 판정뿐 아니라 조치(확인 · 차단 · 메모)도 그렇다.
        # actions 는 incidents 에 ON DELETE CASCADE 로 걸려 있어, 지우면 조치 기록이 함께 사라지고
        # 이 기록은 원문에서 다시 만들 수 없다. 새 버전에서만 억제가 적용된다.
        cur.execute("""DELETE FROM incidents i WHERE i.incident_key = ANY(%s)
                       AND NOT EXISTS (SELECT 1 FROM verdicts v
                                       WHERE v.incident_key = i.incident_key)
                       AND NOT EXISTS (SELECT 1 FROM actions a
                                       WHERE a.incident_key = i.incident_key)""",
                    (victims,))
    return counts


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

    created = skipped = 0
    summary = []
    staged = []   # (rule, rows, signal_count)

    for rule in rules_doc["rules"]:
        if not rule.get("enabled", True):
            continue
        collector = COLLECTORS.get(rule["type"])
        if collector is None:
            raise ValueError(f"{rule['id']}: 알 수 없는 규칙 유형 {rule['type']}")

        # 고정 시간창으로 신호를 만드는 규칙은 슬롯 경계 때문에 전역 창과
        # 같은 값을 쓰면 연속 활동이 쪼개진다. 규칙별 지정을 우선한다.
        rule_gap = rule.get("aggregation_gap_seconds", gap)
        rule.setdefault("params", {})["_version"] = version
        signals = collector(cur, rule, since, until)
        groups = aggregate(signals, rule_gap)

        rows, target_rows = [], []
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
            devs = [(m["count"] - m["mean"]) / m["sigma"]
                    for m in metrics if m.get("sigma")]
            observed = {}
            if counts:
                observed["observed_count_max"] = max(counts)
            if devs:
                observed["observed_sigma_max"] = round(max(devs), 2)

            evidence = json.dumps(
                {"sample": details[:5], "sessions": sessions[:10],
                 **observed},
                ensure_ascii=False, default=str)
            row = (key, rule["id"], version, rule["name"], rule["severity"], ip,
                   first_ts, last_ts, len(items), len(sessions), evidence)
            if target is None:
                rows.append(row)
            else:
                target_rows.append(row + (target,))

        staged.append((rule, rows + target_rows, len(signals), rule_gap))

        # 이 규칙의 인시던트를 바로 넣는다. 뒤 규칙(기준선 이탈)이 앞 규칙의
        # 결과를 보아야 하므로 억제 판단보다 적재가 먼저다. 억제된 것은
        # 아래에서 지운다. 대상 행이 없는 규칙은 전과 같은 문장 하나만 낸다.
        execute_batch(cur, INSERT_BASE, rows, page_size=200)
        if target_rows:
            execute_batch(cur, INSERT_TARGET, target_rows, page_size=200)

    suppressed = suppress(cur, rules_doc, staged) if rules_doc.get("suppression") else {}

    for rule, rows, n_signals, rule_gap in staged:
        cur.execute("SELECT count(*) FROM incidents WHERE rule_id = %s AND rule_version = %s",
                    (rule["id"], version))
        n_now = cur.fetchone()[0]
        n_sup = suppressed.get(rule["id"], 0)
        created += n_now
        summary.append((rule["id"], rule["name"], n_signals, len(rows), n_now, rule_gap, n_sup))

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
        print("=" * 82)
        print(f" 탐지 실행  규칙버전 {version}   범위 {since or '전체'} ~ {until or '전체'}")
        print("=" * 82)
        print(f"{'규칙':<6} {'이름':<18} {'신호':>8} {'통합':>8} {'억제':>6} {'인시던트':>9}  압축률   통합창")
        print("-" * 82)
        tot_s = tot_i = tot_x = 0
        for rid, name, ns, ni, nn, g, nx in summary:
            comp = f"{100 * (1 - (ni - nx) / ns):5.1f}%" if ns else "    -"
            print(f"{rid:<6} {name:<18} {ns:>8,} {ni:>8,} {nx:>6,} {nn:>9,}  {comp}  {g // 60:>4}분")
            tot_s += ns; tot_i += ni; tot_x += nx
        print("-" * 82)
        comp = f"{100 * (1 - (tot_i - tot_x) / tot_s):5.1f}%" if tot_s else "-"
        print(f"{'합계':<25} {tot_s:>8,} {tot_i:>8,} {tot_x:>6,} {created:>9,}  {comp}")
        if tot_x:
            print(f"\n  억제 {tot_x}건 — 같은 행위자·같은 구간에 더 높은 심각도 알림이 있어")
            print(f"  관제자에게 새 정보를 주지 않는 인시던트를 만들지 않았다")
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
