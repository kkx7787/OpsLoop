#!/usr/bin/env python3
"""AI 판정 추천 DB 시험. 격리 DB 에 schema.sql 과 마이그레이션을 두 번씩 적용하고 역할별 권한 · 회차 동작을 본다.
  OPSLOOP_TEST_DATABASE_URL=postgresql://… python3 recommend/test_opsloop_recommend_db.py
운영 DB 는 건드리지 않는다. AI 서버는 부르지 않는다(가짜 클라이언트).
"""
import json
import os
import re
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT / "infra"))
import opsloop_recommend as r  # noqa: E402
import test_block_enforce_db as base  # noqa: E402

MIGRATION = ROOT / "infra/migrations/20261006_ai_recommend.sql"
CFG = {"url": "http://127.0.0.1:21434", "model": "gpt-oss:20b", "limit": 10}
REASONS = ["가", "나", "다"]


class FakeClient:
    """R002 는 위협, 나머지는 무시 가능을 돌려준다. mode: ok · broken · down · down_after_first"""
    def __init__(self, mode="ok"):
        self.mode, self.calls = mode, []

    def healthy(self):
        if self.mode == "down":
            raise r.Unreachable("AI 서버에 닿지 않음: [Errno 111] Connection refused")
        return "0.35.1"

    def chat(self, case, seed, keep_alive):
        self.calls.append((case["rule_id"], case["source_ip"], seed, keep_alive))
        if self.mode == "down_after_first" and len(self.calls) > 1:
            raise r.Unreachable("AI 서버에 닿지 않음: timed out")
        if self.mode == "broken":
            raise ValueError("응답이 약속한 JSON 이 아니다")
        rec = "threat" if case["rule_id"] == "R002" else "non_actionable"
        return {"recommendation": rec, "needs_human": False, "confidence": "high",
                "block_hours": 24, "reason_ko": REASONS}


@unittest.skipUnless(base.URL and base.psycopg2, "PostgreSQL 시험 연결 미지정")
class RecommendDbTests(base.DbCase):
    @classmethod
    def setUpClass(cls):
        cls.create()
        for source in (ROOT / "infra/schema.sql", ROOT / "infra/schema.sql", MIGRATION, MIGRATION):
            cls.scur.execute(cls.sub(source.read_text()))
        cls.connect()

    def setUp(self):
        s = self.scur
        s.execute("TRUNCATE ai_status; DELETE FROM verdicts; DELETE FROM ai_recommendations; DELETE FROM incidents; DELETE FROM events")
        # 판정 대기 셋(공인 SSH 위협 · 시험 공격 VM · 내부 출발지 웹), 판정된 것 하나, 종결된 것 하나
        rows = [("K1", "R002", "198.51.100.7", "open", "1 hour"), ("K2", "R002", "203.0.113.10", "open", "30 minutes"),
                ("K3", "R202", "192.168.60.1", "acknowledged", "10 minutes"), ("K4", "R001", "198.51.100.8", "open", "2 hours"),
                ("K5", "R001", "198.51.100.9", "resolved", "3 hours")]
        for key, rule, ip, status, ago in rows:
            s.execute("""INSERT INTO incidents (incident_key, rule_id, rule_version, rule_name, severity, actor_ip, first_ts, last_ts,
                                                signal_count, session_count, evidence, status, created_at)
                         VALUES (%s, %s, 'v3', '시험', 'high', %s, now() - %s::interval, now() - %s::interval, 1, 1,
                                 '{"sessions": ["s1"]}', %s, now() - %s::interval)""", (key, rule, ip, ago, ago, status, ago))
        s.execute("""INSERT INTO events (line_hash, ts, eventid, session, src_ip, input)
                     VALUES ('h1', now() - interval '1 hour', 'cowrie.command.input', 's1', '198.51.100.7', 'uname -a')""")
        s.execute("""INSERT INTO events (line_hash, ts, eventid, session, src_ip, username, password)
                     VALUES ('h2', now() - interval '1 hour', 'cowrie.login.success', 's1', '198.51.100.7', 'root', 'Secr3t!Pw')""")
        s.execute("INSERT INTO verdicts (incident_key, verdict, operator) VALUES ('K4', 'non_actionable', 'han')")

    def run_as_ai(self, client, cfg=CFG):
        lines = []
        with self.as_role("ai"):
            got = r.run(self.conn, client, cfg, out=lines.append)
        return got, lines

    def recs(self):
        self.scur.execute("""SELECT incident_key, status, recommendation, needs_human, guard, block_hours, cardinality(reasons)
                             FROM ai_recommendations ORDER BY incident_key, id""")
        return self.scur.fetchall()

    def status_row(self):
        self.scur.execute("SELECT reachable, last_ok_at IS NOT NULL, pending, error FROM ai_status")
        return self.scur.fetchone()

    def test_근거가_늘면_재추천하고_같은_근거는_반복하지_않는다(self):
        self.run_as_ai(FakeClient())
        self.assertEqual(self.run_as_ai(FakeClient())[0]['done'], 0)
        self.scur.execute("UPDATE incidents SET signal_count = signal_count + 1, evidence = '{\"sessions\":[\"s1\"],\"new\":true}' WHERE incident_key = 'K1'")
        self.assertEqual(self.run_as_ai(FakeClient())[0]['done'], 1)
        self.scur.execute("SELECT count(DISTINCT evidence_fingerprint) FROM ai_recommendations WHERE incident_key = 'K1'")
        self.assertEqual(self.scur.fetchone()[0], 2)

    def test_추론_중_근거가_바뀌면_다음_회차에_다시_처리한다(self):
        outer = self
        class DuringInference(FakeClient):
            def chat(self, case, seed, keep_alive):
                if case['source_ip'] == '198.51.100.7':
                    outer.scur.execute("UPDATE incidents SET signal_count = signal_count + 1 WHERE incident_key = 'K1'")
                return super().chat(case, seed, keep_alive)
        self.run_as_ai(DuringInference())
        self.assertEqual(self.run_as_ai(FakeClient())[0]['done'], 1)

    # ── 권한 ─────────────────────────────────────────────────────
    def test_작업기_역할은_추천_표와_상태만_쓴다(self):
        with self.as_role("ai"):
            self.one("SELECT count(*) FROM incidents")
            self.one("SELECT count(*) FROM events")
            self.one("SELECT count(incident_key) FROM verdicts")
            self.denied("SELECT verdict FROM verdicts")
            for sql in ("INSERT INTO verdicts (incident_key, verdict) VALUES ('K1', 'threat')",
                        "INSERT INTO actions (incident_key, action) VALUES ('K1', 'block_ip')",
                        "INSERT INTO blocklist (actor_ip, reason) VALUES ('198.51.100.7', 'x')",
                        "UPDATE incidents SET status = 'resolved'",
                        "UPDATE ai_recommendations SET recommendation = 'threat'",
                        "DELETE FROM ai_recommendations",
                        "DELETE FROM ai_status",
                        "SELECT * FROM console_users",
                        "SELECT * FROM blocklist"):
                self.denied(sql)

    def test_역할_검증_스크립트_줄이_시험_DB_에서_같은_답을_낸다(self):
        text = (ROOT / "infra/vmware/scripts/verify-db-roles.sh").read_text()
        sec = text[text.index('echo "== AI 판정 추천 (이슈 #120'):]
        sec = sec[sec.index("\n"):].split("\necho", 1)[0]
        pat = re.compile(r'^([qp]) (opsloop_[a-z]+) +"(.+)" (허용|거부|t|f)$')
        lines = [m.groups() for m in map(pat.match, sec.splitlines()) if m]
        self.assertEqual(len(lines), 22)
        for kind, role, stmt, want in lines:
            with self.subTest(role=role, stmt=stmt):
                if kind == "p":
                    got = "t" if self.one("SELECT " + self.sub(stmt))[0] else "f"
                else:
                    self.cur.execute("SAVEPOINT v")
                    self.cur.execute(f"SET SESSION AUTHORIZATION {self.roles[role.removeprefix('opsloop_')]}")
                    try:
                        self.cur.execute(self.sub(stmt))
                        got = "허용"
                    except base.psycopg2.Error as e:
                        got = "거부" if e.pgcode == "42501" else f"오류 {e.pgcode}"
                    self.cur.execute("ROLLBACK TO SAVEPOINT v")
                    self.cur.execute("RESET SESSION AUTHORIZATION")
                self.assertEqual(got, want)

    def test_콘솔은_읽기만_다른_역할은_못_본다(self):
        with self.as_role("console"):
            self.one("SELECT count(*) FROM ai_recommendations")
            self.one("SELECT count(*) FROM ai_status")
            self.denied("INSERT INTO ai_recommendations (incident_key, model, prompt_version, status, error) VALUES ('K1','m','p','failed','x')")
            self.denied("UPDATE ai_status SET reachable = true")
        for role in ("detector", "ingest", "gate", "enforcer", "cti"):
            with self.as_role(role):
                self.denied("SELECT * FROM ai_recommendations")

    def test_표_제약(self):
        ok = "INSERT INTO ai_recommendations (incident_key, model, prompt_version, status, recommendation, needs_human, reasons, block_hours, error) VALUES "
        for bad in (ok + "('K1','m','p','ok','threat',false, ARRAY['가','나'], 24, NULL)",             # 근거는 세 줄
                    ok + "('K1','m','p','ok','non_actionable',false, ARRAY['가','나','다'], 24, NULL)",  # 위협이 아니면 차단 제안 없음
                    ok + "('K1','m','p','ok','false_positive',false, ARRAY['가','나','다'], 0, NULL)",   # 오탐은 추천값이 아니다
                    ok + "('K1','m','p','failed',NULL,NULL,NULL,NULL,NULL)",                            # 실패는 사유가 있다
                    ok + "('K1','m','p','ok','threat',false, ARRAY['가','나','다'], 12, NULL)"):        # 차단 제안은 0 · 24
            with self.subTest(sql=bad[-60:]):
                e = self.fails(bad)
                self.assertEqual(e.pgcode, "23514")

    # ── 회차 ─────────────────────────────────────────────────────
    def test_판정_대기_사건만_추천하고_안전장치가_저장된다(self):
        client = FakeClient()
        got, lines = self.run_as_ai(client)
        self.assertEqual((got["reachable"], got["done"], got["failed"], got["waiting"]), (True, 3, 0, 0))
        self.assertEqual(self.recs(), [
            ("K1", "ok", "threat", False, [], 24, 3),
            ("K2", "ok", "threat", False, [], 24, 3),                                         # 시험 공격 VM 도 차단 제안
            ("K3", "ok", "non_actionable", True, ["SSH 규칙 밖 사건", "차단 금지 대역 출발지"], 0, 3)])
        # 새 사건부터, 회차의 마지막 요청에서 모델을 내린다
        self.assertEqual([(c[0], c[1], c[3]) for c in client.calls],
                         [("R202", "192.168.60.1", "5m"), ("R002", "203.0.113.10", "5m"), ("R002", "198.51.100.7", "0")])
        self.assertEqual(self.status_row(), (True, True, 0, None))
        # 다음 회차는 할 일이 없다
        got, _ = self.run_as_ai(FakeClient())
        self.assertEqual((got["done"], len(self.recs())), (0, 3))

    def test_근거에_명령이_들어간다(self):
        with self.as_role("ai"):
            self.cur.execute(r.EVIDENCE_SQL, {"key": "K1"})
            case = self.cur.fetchone()[0]
        self.assertEqual(case["commands"], [{"input": "uname -a", "count": 1}])
        self.assertEqual(case["logins"], [{"user": "root", "result": "cowrie.login.success", "count": 1}])
        self.assertNotIn("Secr3t!Pw", json.dumps(case, ensure_ascii=False))     # 비밀번호 원문은 모델에 가지 않는다
        self.assertEqual((case["rule_id"], case["source_ip"]), ("R002", "198.51.100.7"))

    def test_닿지_않으면_넘어가고_마지막_성공은_지킨다(self):
        self.run_as_ai(FakeClient())                       # 한 번 성공
        self.scur.execute("INSERT INTO incidents (incident_key, rule_id, rule_version, severity, actor_ip, first_ts, last_ts, signal_count) "
                          "VALUES ('K6', 'R001', 'v3', 'low', '198.51.100.10', now(), now(), 1)")
        got, lines = self.run_as_ai(FakeClient("down"))
        self.assertEqual((got["reachable"], got["done"], got["waiting"]), (False, 0, 1))
        reachable, kept, pending, error = self.status_row()
        self.assertEqual((reachable, kept, pending), (False, True, 1))
        self.assertIn("닿지 않음", error)
        self.assertEqual(len(self.recs()), 3)              # 실패 행도 쌓지 않는다(사건 탓이 아니다)

    def test_회차_도중_끊기면_멈추고_남은_사건은_다음_회차로(self):
        got, _ = self.run_as_ai(FakeClient("down_after_first"))
        self.assertEqual((got["reachable"], got["done"]), (False, 1))
        self.assertEqual(self.status_row()[0], False)
        got, _ = self.run_as_ai(FakeClient())
        self.assertEqual(got["done"], 2)

    def test_연속_실패면_회차를_멈추고_사건마다_세_번까지만(self):
        got, _ = self.run_as_ai(FakeClient("broken"))
        self.assertEqual((got["done"], got["failed"]), (0, 2))       # 연속 두 번에 멈춘다
        self.assertIn("연속 2회 실패", self.status_row()[3])
        # 회차마다 새 사건 둘에서 멈추므로 K3 · K2 가 상한(3)에 닿은 뒤에야 K1 차례가 온다. 6회차면 모두 3번
        for _ in range(5):
            self.run_as_ai(FakeClient("broken"))
        self.scur.execute("SELECT incident_key, count(*) FROM ai_recommendations WHERE status = 'failed' GROUP BY 1 ORDER BY 1")
        self.assertEqual(self.scur.fetchall(), [("K1", 3), ("K2", 3), ("K3", 3)])
        client = FakeClient()
        got, _ = self.run_as_ai(client)
        self.assertEqual((got["done"], client.calls), (0, []))      # 상한에 닿은 사건은 다시 묻지 않는다
        # 지시문을 바꾸면(PROMPT_VERSION) 다시 묻는다
        with unittest.mock.patch.object(r, "PROMPT_VERSION", "p3-test"):
            got, _ = self.run_as_ai(FakeClient())
        self.assertEqual(got["done"], 3)

    def test_상한만큼만_묻는다(self):
        got, _ = self.run_as_ai(FakeClient(), CFG | {"limit": 1})
        self.assertEqual((got["done"], got["waiting"]), (1, 2))

    def test_판정에_본_추천을_남기고_일치를_센다(self):
        self.run_as_ai(FakeClient())
        self.scur.execute("SELECT id FROM ai_recommendations WHERE incident_key = 'K1'")
        rid = self.scur.fetchone()[0]
        with self.as_role("console"):
            self.cur.execute("INSERT INTO verdicts (incident_key, verdict, operator, recommendation_id) VALUES ('K1', 'threat', 'han', %s)", (rid,))
            self.cur.execute("""SELECT count(*) FILTER (WHERE v.verdict = a.recommendation), count(*)
                                FROM verdicts v JOIN ai_recommendations a ON a.id = v.recommendation_id""")
            self.assertEqual(self.cur.fetchone(), (1, 1))
            e = self.fails("INSERT INTO verdicts (incident_key, verdict, operator, recommendation_id) VALUES ('K2', 'threat', 'han', 999999)")
            self.assertEqual(e.pgcode, "23503")

    def test_상태_보기(self):
        lines = []
        with self.as_role("ai"):
            r.show_status(self.conn, out=lines.append)
        self.assertEqual(lines, ["아직 돈 회차가 없다"])
        self.run_as_ai(FakeClient("down"))
        lines = []
        with self.as_role("ai"):
            r.show_status(self.conn, out=lines.append)
        self.assertIn("AI 서버 닿지 않음, 마지막 성공 없음", lines[0])


import unittest.mock  # noqa: E402

if __name__ == "__main__":
    unittest.main()
