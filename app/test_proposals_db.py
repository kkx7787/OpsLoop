"""상세 API 제안 근거(중복 후보)의 PostgreSQL 시험. OPSLOOP_TEST_DATABASE_URL 이 있을 때만 돈다.

연결 전용 임시 테이블만 쓰고 search_path=pg_temp 로 운영 테이블을 가린다.
규칙 버전이 다른 사건의 위협 판정은 중복 제안의 근거가 되지 않아야 한다.
"""
import os
import unittest
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import main

ACTOR = "192.0.2.8"
T0 = datetime(2026, 9, 20, 3, tzinfo=timezone.utc)


@unittest.skipUnless(os.environ.get("OPSLOOP_TEST_DATABASE_URL"), "PostgreSQL 시험 연결 미지정")
class ProposalBasisDatabaseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import asyncpg
        self.conn = await asyncpg.connect(os.environ["OPSLOOP_TEST_DATABASE_URL"])
        await self.conn.execute("SET search_path TO pg_temp")
        await self.conn.execute("""
            CREATE TEMP TABLE incidents (incident_key text PRIMARY KEY, rule_id text, rule_version text NOT NULL,
                rule_name text, severity text, actor_ip inet, target text, first_ts timestamptz,
                last_ts timestamptz, signal_count integer, session_count integer, evidence jsonb,
                status text DEFAULT 'open', created_at timestamptz DEFAULT now());
            CREATE TEMP TABLE verdicts (id bigint GENERATED ALWAYS AS IDENTITY, incident_key text, verdict text,
                reason text, observed_value double precision, operator text, proposed text,
                decision_seconds integer, created_at timestamptz DEFAULT now());
            CREATE TEMP TABLE actions (id bigint GENERATED ALWAYS AS IDENTITY, incident_key text, action text,
                operator text, note text, created_at timestamptz DEFAULT now());
            CREATE TEMP TABLE events (ts timestamptz, sensor text, eventid text, session text, username text,
                password text, input text, url text, shasum text, http_method text, http_status integer,
                user_agent text, message text, src_ip inet, provenance text);
            CREATE TEMP TABLE blocklist (actor_ip inet PRIMARY KEY, reason text, method text,
                created_at timestamptz DEFAULT now(), expires_at timestamptz, released_at timestamptz,
                enforced_at timestamptz, incident_key text, requested_by text, released_by text);
            -- 상세는 같은 페이로드 흡수 기록 · 후속 차단 약속(규칙 v3)과 규칙 정의도 읽는다. 여기서는 비어 있다
            CREATE TEMP TABLE incident_absorbed (first_key text, member_key text, kind text, via_key text,
                rule_id text, rule_version text, actor_ip inet, first_ts timestamptz, last_ts timestamptz,
                signal_count integer, sessions text[] DEFAULT '{}', payloads text[] DEFAULT '{}');
            CREATE TEMP TABLE absorbed_blocks (first_key text PRIMARY KEY, expires_at timestamptz NOT NULL,
                requested_by text, created_at timestamptz DEFAULT now(), released_at timestamptz, released_by text);
            CREATE TEMP TABLE rule_versions (rule_version text PRIMARY KEY, definition jsonb NOT NULL);
        """)
        self.pool = type("Pool", (), {"acquire": lambda _self: self.acquire()})()

    @asynccontextmanager
    async def acquire(self):
        yield self.conn

    async def asyncTearDown(self):
        await self.conn.close()

    async def incident(self, key, rule, version, minutes=0, verdict=None):
        await self.conn.execute("""INSERT INTO incidents
            (incident_key, rule_id, rule_version, rule_name, severity, actor_ip, first_ts, last_ts,
             signal_count, session_count)
            VALUES ($1, $2, $3, '시험 규칙', 'high', $4, $5::timestamptz, $5::timestamptz + interval '1 minute', 1, 1)""",
            key, rule, version, ACTOR, T0 + timedelta(minutes=minutes))
        if verdict:
            await self.conn.execute(
                "INSERT INTO verdicts (incident_key, verdict, operator) VALUES ($1, $2, 'tester')", key, verdict)

    async def detail(self, key):
        with patch.object(main.app.state, "pool", self.pool, create=True):
            return await main.get_incident(key)

    async def test_threat_of_other_rule_version_is_not_duplicate_basis(self):
        # 같은 출발지 · 겹치는 구간이지만 판정은 앞 버전(v1) 사건에 있다. v2 사건의 근거가 되면 안 된다.
        await self.incident("R002|v1-rep", "R002", "v1", verdict="threat")
        await self.incident("R003|v2-target", "R003", "v2", minutes=2)
        proposal = (await self.detail("R003|v2-target"))["proposal"]
        self.assertIsNone(proposal["verdict"])
        self.assertNotIn("R002|v1-rep", " ".join(proposal["reasons"]))

    async def test_threat_of_newer_rule_version_is_not_duplicate_basis(self):
        # 반대 방향도 같다. v2 판정은 v1 사건의 근거가 되지 않는다.
        await self.incident("R002|v2-rep", "R002", "v2", verdict="threat")
        await self.incident("R003|v1-target", "R003", "v1", minutes=2)
        proposal = (await self.detail("R003|v1-target"))["proposal"]
        self.assertIsNone(proposal["verdict"])
        self.assertNotIn("R002|v2-rep", " ".join(proposal["reasons"]))

    async def test_same_rule_version_threat_is_still_duplicate_basis(self):
        # 버전을 가리지 않으면 더 이른 v1 사건이 뽑힌다. 같은 버전의 v2 사건이 근거여야 한다.
        await self.incident("R002|v1-rep", "R002", "v1", verdict="threat")
        await self.incident("R002|v2-rep", "R002", "v2", minutes=1, verdict="threat")
        await self.incident("R003|v2-target", "R003", "v2", minutes=2)
        proposal = (await self.detail("R003|v2-target"))["proposal"]
        self.assertEqual(proposal["verdict"], "non_actionable")
        self.assertIn("R002|v2-rep", proposal["reasons"][0])
        self.assertNotIn("R002|v1-rep", " ".join(proposal["reasons"]))

if __name__ == "__main__":
    unittest.main()
