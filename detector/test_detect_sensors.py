#!/usr/bin/env python3
"""탐지기 발생원 범위 · 실행 기록 · --quiet 단위 시험. DB 없이 돈다.  python3 detector/test_detect_sensors.py

SQL 과 인자를 기록하는 가짜 커서로 신호 함수를 돌린다. BEFORE 는 변경 전 detect.py(760c779)가
v1 · v2 규칙마다 만든 SQL 과 인자를 그대로 옮긴 것이다. 병합 조건은 v1 · v2 결과가 바뀌지 않는
것이므로, 기준선 이탈(R005)에 발생원 한정이 붙는 것 말고는 한 글자도 달라지면 안 된다.
"""
import contextlib
import copy
import io
import json
import os
import sys
import types
import unittest
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
    """rules_self.json(s1) · rules_node.json(n1)."""

    def test_형식은_rules_json_과_같다(self):
        base = load("rules.json")
        for name, ver in (("rules_self.json", "s1"), ("rules_node.json", "n1")):
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
        for name in ("rules_self.json", "rules_node.json", "rules.json", "rules_v2.json"):
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


if __name__ == "__main__":
    unittest.main(verbosity=2)
