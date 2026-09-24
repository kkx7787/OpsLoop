"""화면 제안 정책과 상세 API의 이력 반환 계약. python3 -m unittest discover -s app"""
import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from proposals import CIRCULAR_RULES, SSH_RULES, propose


class ProposalTests(unittest.TestCase):
    def test_independent_behavior_is_required_for_threat(self):
        for rule in ("R001", "R005"):
            with self.subTest(rule=rule):
                self.assertEqual(propose(rule, {"cowrie.login.failed": 10000})["verdict"], "non_actionable")
                for event in ("cowrie.command.input", "cowrie.session.file_download", "cowrie.direct-tcpip.request"):
                    self.assertEqual(propose(rule, {event: 1})["verdict"], "threat")

    def test_missing_evidence_is_not_benign(self):
        self.assertIsNone(propose("R001", {})["verdict"])

    def test_circular_evidence_does_not_confirm_itself(self):
        # R006(키 심기)은 조건과 판정 근거가 모두 authorized_keys 쓰기다. R003 은 v3 에서도 순환이다(판정 기준 §6)
        for rule in ("R002", "R003", "R004", "R006"):
            self.assertIsNone(propose(rule, {"cowrie.command.input": 100})["verdict"])

    def test_key_plant_duplicate_is_still_proposed(self):
        # 순환 규칙에서도 중복(같은 출발지 · 겹치는 구간의 위협 판정)은 규칙 조건과 무관한 근거라 제안한다
        proposal = propose("R006", {"cowrie.command.input": 1}, "R003|v3|representative")
        self.assertEqual(proposal["verdict"], "non_actionable")

    def test_console_and_proposal_lists_agree(self):
        import test_web
        self.assertEqual(set(test_web.main.CIRCULAR), CIRCULAR_RULES)
        self.assertLessEqual(CIRCULAR_RULES, SSH_RULES)

    def test_previously_judged_overlap_can_be_reviewed_as_duplicate(self):
        proposal = propose("R003", {}, "R002|representative")
        self.assertEqual(proposal["verdict"], "non_actionable")
        self.assertIn("R002|representative", proposal["reasons"][0])

    def test_ssh_policy_is_not_applied_to_web_audit_or_infra(self):
        for rule in ("R101", "R201", "R301", "unknown"):
            self.assertIsNone(propose(rule, {"cowrie.command.input": 1}, "overlap")["verdict"])


class DetailContractTests(unittest.TestCase):
    def test_reloaded_history_preserves_proposal_and_duration(self):
        # test_web supplies an asyncpg fallback on machines without the driver.
        import test_web
        main = test_web.main
        conn = AsyncMock()
        conn.fetchrow.return_value = {
            "incident_key": "review-fixture", "actor_ip": None,
            "rule_id": "R201", "first_ts": None, "last_ts": None, "evidence": None,
        }
        verdict = {"id": 1, "verdict": "false_positive", "proposed": "threat",
                   "decision_seconds": 125, "operator": "tester", "reason": "verified",
                   "observed_value": 3, "created_at": "2026-09-23T00:00:00Z"}

        async def fetch(sql, *_args):
            if "FROM verdicts" in sql:
                # Return only projected columns, as PostgreSQL does.
                projection = sql.split(" FROM verdicts")[0]
                return [{key: value for key, value in verdict.items() if key in projection}]
            return []

        conn.fetch.side_effect = fetch

        class Pool:
            def acquire(self):
                class Acquire:
                    async def __aenter__(self):
                        return conn
                    async def __aexit__(self, *_args):
                        return False
                return Acquire()

        with patch.object(main.app.state, "pool", Pool(), create=True):
            response = asyncio.run(main.get_incident("review-fixture"))
        self.assertEqual(response["verdicts"][0]["proposed"], "threat")
        self.assertEqual(response["verdicts"][0]["decision_seconds"], 125)
        self.assertIsNone(response["proposal"]["verdict"])

    def test_duplicate_basis_is_limited_to_same_rule_version(self):
        # DB 없이 계약만 본다. 중복 후보 조회에 이 사건의 규칙 버전이 조건으로 들어가야 한다.
        # 실제 조회 결과는 test_proposals_db 가 임시 테이블로 확인한다.
        import datetime as dt
        import test_web
        main = test_web.main
        t0 = dt.datetime(2026, 9, 20, 3, tzinfo=dt.timezone.utc)
        incident = {"incident_key": "R003|v2-target", "actor_ip": "192.0.2.8", "rule_id": "R003",
                    "rule_version": "v2", "first_ts": t0, "last_ts": t0, "evidence": None}
        conn = AsyncMock()
        conn.fetchrow.side_effect = lambda sql, *_a: incident if "FROM incidents WHERE incident_key" in sql else None
        conn.fetch.return_value = []
        conn.fetchval.return_value = None

        class Pool:
            def acquire(self):
                class Acquire:
                    async def __aenter__(self):
                        return conn
                    async def __aexit__(self, *_args):
                        return False
                return Acquire()

        with patch.object(main.app.state, "pool", Pool(), create=True):
            asyncio.run(main.get_incident("R003|v2-target"))
        # 상세는 fetchval 을 여러 번 부른다(중복 후보 · 흡수 규칙 여부). 중복 후보 조회를 골라 본다
        [(sql, *args)] = [c.args for c in conn.fetchval.call_args_list if "FROM incidents i" in c.args[0]]
        self.assertIn("i.rule_version = $5", sql)
        self.assertEqual(args[4], "v2")
        # 키 심기(R006)도 중복 후보를 찾는 규칙이다
        self.assertIn("'R006'", sql)


if __name__ == "__main__":
    unittest.main()
