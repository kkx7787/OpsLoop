#!/usr/bin/env python3
"""탐지기 발생원 범위 · 실행 기록 · --quiet 단위 시험. DB 없이 돈다.  python3 detector/test_detect_sensors.py

SQL 과 인자를 기록하는 가짜 커서로 신호 함수를 돌린다. BEFORE 는 변경 전 detect.py(760c779)가
v1 · v2 규칙마다 만든 SQL 과 인자를 그대로 옮긴 것이다. 병합 조건은 v1 · v2 결과가 바뀌지 않는
것이므로, 기준선 이탈(R005)에 발생원 한정이 붙는 것 말고는 한 글자도 달라지면 안 된다.

규칙군 확장(이슈 #14: w1 · a1 · i1)도 같은 조건이다. OLD_* 는 확장 전 detect.py(07da78f)의 적재 문장 ·
actor_rate 문장 · aggregate · 행 만들기를 그대로 옮긴 것이고, 대상(_target)이 없는 규칙은 이것과 같아야 한다.
"""
import contextlib
import copy
import io
import json
import os
import sys
import types
import unittest
from datetime import datetime, timedelta, timezone
from unittest import mock

# psycopg2 가 없는 곳에서도 돌게 가짜를 넣는다 (DB 에는 붙지 않는다)
if "psycopg2" not in sys.modules:
    fake = types.ModuleType("psycopg2")
    extras = types.ModuleType("psycopg2.extras")
    extras.execute_batch = lambda *a, **k: None
    fake.extras = extras
    sys.modules["psycopg2"], sys.modules["psycopg2.extras"] = fake, extras

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
    rule.setdefault("params", {})["_version"] = doc["rule_version"]
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
    """rules_self.json(s1) · rules_node.json(n1) · rules_w1.json(w1) · rules_audit.json(a1) · rules_infra.json(i1)."""

    def test_형식은_rules_json_과_같다(self):
        base = load("rules.json")
        for name, ver in (("rules_self.json", "s1"), ("rules_node.json", "n1"), ("rules_w1.json", "w1"),
                          ("rules_audit.json", "a1"), ("rules_infra.json", "i1")):
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
                     "rules_w1.json", "rules_audit.json", "rules_infra.json"):
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
    rule.setdefault("params", {})["_version"] = doc["rule_version"]
    return detect.COLLECTORS[rule["type"]](FakeCursor(answer), rule, since, until)


def rule_of(name, rid):
    doc = load(name)
    return doc, next(r for r in doc["rules"] if r["id"] == rid)


class InsertTest(unittest.TestCase):
    """적재 문장. 대상이 없는 행은 확장 전 문장 그대로다."""

    def test_INSERT_BASE_는_옛_문장과_글자가_같다(self):
        self.assertEqual(detect.INSERT_BASE, OLD_INSERT)

    def test_INSERT_TARGET_은_target_열만_더한다(self):
        self.assertEqual(
            detect.INSERT_TARGET,
            OLD_INSERT.replace("evidence)", "evidence, target)").replace("%s::jsonb)", "%s::jsonb,%s)"))
        self.assertEqual(detect.INSERT_TARGET.count("%s"), 12)
        self.assertTrue(detect.INSERT_TARGET.endswith("ON CONFLICT (incident_key) DO NOTHING"))


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
        doc, rule = rule_of("rules_w1.json", "R102")
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
        doc, rule = rule_of("rules_w1.json", "R102")
        sig = signals_of(doc, rule, lambda sql: [(at(0), "5.5.5.5", None, 6)])
        self.assertEqual(sig, [(at(0), "5.5.5.5", None, {"count": 6, "window_seconds": 600, "threshold": 5})])

    def test_형식이_틀리면_규칙_오류(self):
        doc, rule = rule_of("rules_w1.json", "R102")
        for bad in ([], "404", 404, [404.0], [True], ["404"], None):
            with self.subTest(bad=bad):
                r = copy.deepcopy(rule)
                r["params"]["http_status"] = bad
                with self.assertRaises(ValueError):
                    collect(doc, r)


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
                want.append((OLD_INSERT, old_rows(rule, doc["rule_version"],
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


class NodeSilenceTest(unittest.TestCase):
    """i1 R301 노드 수신 끊김."""

    def rule(self, **params):
        doc, rule = rule_of("rules_infra.json", "R301")
        rule = copy.deepcopy(rule)
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
        doc = load("rules_infra.json")
        rows = {"now": [("web-01", at(0), None, 10)]}

        def answer(sql):
            if "lead(loaded_at)" in sql:
                return rows["now"]
            return db_answer()(sql)

        cur, _, _ = run_quiet(doc, answer)
        [(_, _), (_, [ongoing])] = cur.batches
        rows["now"] = [("web-01", at(0), at(31), 31)]
        cur, _, _ = run_quiet(doc, answer)
        [(_, _), (_, [recovered])] = cur.batches
        self.assertEqual(ongoing[0], f"R301|i1|node:web-01|{at(0).isoformat()}")
        self.assertEqual(recovered[0], ongoing[0])
        self.assertEqual((ongoing[7], recovered[7]), (at(0), at(31)))
        self.assertTrue(json.loads(ongoing[10])["sample"][0]["ongoing"])
        self.assertEqual(ongoing[11], "node:web-01")

    def test_형식이_틀리면_규칙_오류(self):
        for params in ({"threshold_seconds": 0}, {"threshold_seconds": "600"}, {"threshold_seconds": True},
                       {"alive_ratio": 1.5}, {"alive_ratio": -0.1}, {"alive_ratio": "0.8"}):
            with self.subTest(params=params):
                doc, rule = self.rule(**params)
                with self.assertRaises(ValueError):
                    collect(doc, rule)


class NewRuleFileTest(unittest.TestCase):
    """w1 · a1 · i1 규칙 파일의 내용."""

    def test_w1(self):
        doc = load("rules_w1.json")
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
        self.assertEqual(r102["params"], {"eventids": ["nginx.request", "decoy.request"], "http_status": [404],
                                          "window_seconds": 600, "threshold": 5})
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

    def test_i1(self):
        doc = load("rules_infra.json")
        [rule] = doc["rules"]
        self.assertEqual((rule["id"], rule["name"], rule["severity"], rule["type"]),
                         ("R301", "노드 수신 끊김", "high", "node_silence"))
        self.assertEqual(rule["params"], {"threshold_seconds": 600, "alive_ratio": 0.8})
        self.assertEqual(rule["aggregation_gap_seconds"], 1800)

    def test_n1_은_그대로(self):
        doc = load("rules_node.json")
        self.assertEqual(doc["rule_version"], "n1")
        self.assertEqual([r["id"] for r in doc["rules"]], ["R101"])

    def test_새_버전은_기존_버전과_겹치지_않는다(self):
        versions = [load(n)["rule_version"] for n in ("rules.json", "rules_v2.json", "rules_self.json",
                                                      "rules_node.json", "rules_w1.json", "rules_audit.json",
                                                      "rules_infra.json")]
        self.assertEqual(len(set(versions)), len(versions))

    def test_기준선_입력이_바뀌지_않는다(self):
        # 감사 이벤트(sensor=audit)는 기준선 발생원 밖이라 v1 · v2 R005 가 세지 않는다
        self.assertEqual(detect.BASELINE_SENSORS, ["cowrie", "decoy", "console"])
        self.assertNotIn("audit", detect.BASELINE_SENSORS)


if __name__ == "__main__":
    unittest.main(verbosity=2)
