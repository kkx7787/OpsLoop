"""#120: 콘솔의 AI 추천 구역 · 판정의 추천 연결 · 추천 일치 수. 실제 DB 를 콘솔 역할로 읽고 쓴다."""
from types import SimpleNamespace
from unittest.mock import patch

from fastapi import HTTPException
from test_accounts_db import DbCase
import main
import workflow

REASONS = ["출발지가 로그인 뒤 명령을 실행했다.", "로그인 성공 뒤 명령 실행은 위협 조건이다.", "출발지 차단을 검토한다."]


class AiRecommendDB(DbCase):
    async def asyncSetUp(self):
        await super().asyncSetUp()
        await self.owner.execute("TRUNCATE ai_status")
        await self.seed(("one", "operator"))
        for key, rule, ip in (("a", "R002", "198.51.100.7"), ("b", "R001", "198.51.100.8"), ("c", "R003", "198.51.100.9")):
            await self.owner.execute("""INSERT INTO incidents (incident_key, rule_id, rule_version, severity, actor_ip,
                first_ts, last_ts, signal_count) VALUES ($1, $2, 'v3', 'high', $3, now(), now(), 1)""", key, rule, ip)
        ins = """INSERT INTO ai_recommendations (incident_key, model, prompt_version, status, recommendation, needs_human,
                     guard, reasons, block_hours, seconds, error) VALUES ($1, 'gpt-oss:20b', 'p3-1006', $2, $3, $4, $5, $6, $7, 5.2, $8)
                 RETURNING id"""
        self.a_failed = await self.owner.fetchval(ins, "a", "failed", None, None, [], None, None, "응답이 약속한 JSON 이 아니다")
        self.a_ok = await self.owner.fetchval(ins, "a", "ok", "threat", False, [], REASONS, 24, None)
        self.b_ok = await self.owner.fetchval(ins, "b", "ok", "non_actionable", True, ["미결 추천"], REASONS, 0, None)
        await self.owner.execute("""INSERT INTO ai_status (reachable, last_ok_at, model, pending, error)
                                    VALUES (false, now() - interval '2 hours', 'gpt-oss:20b', 1, 'AI 서버에 닿지 않음: timed out')""")

    def req(self):
        return SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(pool=self.pool)),
                               state=SimpleNamespace(user={"u": "one", "r": "operator"}))

    async def verdict(self, key, rid=None, verdict="threat"):
        version = await self.owner.fetchval(workflow.VERSION_SQL, key)
        with patch.object(main.app.state, "pool", self.pool, create=True):
            return await main.add_verdict(key, main.VerdictIn(verdict=verdict, expected_version=version,
                                                              recommendation_id=rid), self.req())

    async def test_사건_상세에_최신_정상_추천과_실패_수와_상태가_실린다(self):
        with patch.object(main.app.state, "pool", self.pool, create=True):
            a, c = await main.get_incident("a"), await main.get_incident("c")
        rec = a["ai"]["recommendation"]
        self.assertEqual((rec["id"], rec["recommendation"], rec["needs_human"], rec["block_hours"], rec["reasons"]),
                         (self.a_ok, "threat", False, 24, REASONS))
        self.assertNotIn("confidence", rec)                         # 확신도는 내지 않는다
        self.assertEqual(a["ai"]["failed"], 1)
        st = a["ai"]["status"]
        self.assertEqual((st["reachable"], st["pending"], st["error"]), (False, 1, "AI 서버에 닿지 않음: timed out"))
        self.assertIsNotNone(st["last_ok_at"])
        self.assertEqual((c["ai"]["recommendation"], c["ai"]["failed"]), (None, 0))

    async def test_옛추천_근거변경_작업기중단을_구별한다(self):
        import ai_recommend
        async def detail():
            return await ai_recommend.incident(self.console, 'a')
        self.assertEqual((await detail())['recommendation']['evidence_status'], 'unknown')
        await self.owner.execute("UPDATE ai_recommendations a SET evidence_fingerprint = " + ai_recommend.EVIDENCE_FINGERPRINT_SQL + " FROM incidents i WHERE i.incident_key = a.incident_key")
        self.assertEqual((await detail())['recommendation']['evidence_status'], 'current')
        await self.owner.execute("UPDATE incidents SET signal_count = signal_count + 1 WHERE incident_key = 'a'")
        self.assertEqual((await detail())['recommendation']['evidence_status'], 'changed')
        await self.owner.execute("UPDATE ai_status SET reachable = true, checked_at = clock_timestamp() - interval '16 minutes'")
        self.assertTrue((await detail())['status']['stale'])

    async def test_판정에는_같은_사건의_정상_추천만_붙고_일치를_센다(self):
        for rid in (self.b_ok, self.a_failed, 999999):              # 다른 사건 · 실패 행 · 없는 번호
            with self.subTest(rid=rid), self.assertRaises(HTTPException) as e:
                await self.verdict("a", rid)
            self.assertEqual(e.exception.status_code, 400)
        self.assertEqual(await self.owner.fetchval("SELECT count(*) FROM verdicts"), 0)
        got = await self.verdict("a", self.a_ok)
        self.assertEqual(got["recommendation_id"], self.a_ok)
        await self.verdict("b", self.b_ok, verdict="false_positive")  # 추천(무시 가능)과 다르다
        with patch.object(main.app.state, "pool", self.pool, create=True):
            s = await main.summary()
        self.assertEqual((s["ai"]["agreed"], s["ai"]["judged"]), (1, 2))
        self.assertEqual(s["ai"]["status"]["reachable"], False)
        with patch.object(main.app.state, "pool", self.pool, create=True):
            v = (await main.get_incident("a"))["verdicts"]
        self.assertEqual(v[-1]["recommendation_id"], self.a_ok)

    async def test_추천을_보지_않은_판정은_옛_문장으로_남는다(self):
        got = await self.verdict("c")
        self.assertNotIn("recommendation_id", got)
        self.assertIsNone(await self.owner.fetchval("SELECT recommendation_id FROM verdicts WHERE incident_key = 'c'"))
        with patch.object(main.app.state, "pool", self.pool, create=True):
            s = await main.summary()
        self.assertEqual((s["ai"]["agreed"], s["ai"]["judged"]), (0, 0))

    async def test_표를_읽을_수_없으면_AI_구역을_빼고_추천_연결은_거부(self):
        await self.owner.execute(f"REVOKE SELECT ON ai_recommendations FROM {self.role}")
        try:
            with patch.object(main.app.state, "pool", self.pool, create=True):
                d, s = await main.get_incident("a"), await main.summary()
            self.assertIsNone(d["ai"])
            self.assertNotIn("ai", s)
            self.assertNotIn("recommendation_id", d["verdicts"][0] if d["verdicts"] else {})
            with self.assertRaises(HTTPException) as e:
                await self.verdict("a", self.a_ok)
            self.assertEqual(e.exception.status_code, 400)
            await self.verdict("a")                                  # 추천 없는 판정은 그대로 된다
        finally:
            await self.owner.execute(f"GRANT SELECT ON ai_recommendations TO {self.role}")

    async def test_콘솔은_추천을_고치지_못한다(self):
        import asyncpg
        for sql in ("UPDATE ai_recommendations SET recommendation = 'threat'", "DELETE FROM ai_recommendations",
                    "INSERT INTO ai_status (reachable) VALUES (true)"):
            with self.subTest(sql=sql), self.assertRaises(asyncpg.InsufficientPrivilegeError):
                await self.console.execute(sql)
