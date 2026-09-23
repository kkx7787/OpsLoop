"""화면 제안 정책과 상세 API의 이력 반환 계약. python3 -m unittest discover -s app"""
import asyncio
import unittest
from unittest.mock import AsyncMock, patch

from proposals import propose


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
        for rule in ("R002", "R003", "R004"):
            self.assertIsNone(propose(rule, {"cowrie.command.input": 100})["verdict"])

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


if __name__ == "__main__":
    unittest.main()
