"""알림 발송기 · API PostgreSQL 통합 시험. OPSLOOP_TEST_DATABASE_URL 이 있을 때만 돈다.

연결 전용 임시 테이블만 쓰고 audit_event 는 임시 감사 삽입으로 교체한다. HTTP 는 가짜로 바꿔 밖으로 나가지 않는다.
집기(SKIP LOCKED) 시험만은 연결 둘이 같은 표를 봐야 하므로 이름이 무작위인 스키마를 만들고 끝나면 지운다.
"""
import json
import os
import secrets
import unittest
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch
from fastapi import HTTPException, Response
import notifier
import notify
import operations

MIGRATION = Path(__file__).resolve().parents[1] / "infra/migrations/20260924_notify.sql"
TEAMS_URL = ("https://default0123456789abcdef.cd.environment.api.powerplatform.com:443/powerautomate/automations/direct"
             "/workflows/abc/triggers/manual/paths/invoke?api-version=1&sig=SECRETSIG")
TABLES = """
    CREATE TABLE incidents(incident_key text PRIMARY KEY, rule_id text, rule_version text, rule_name text, severity text,
        actor_ip inet, target text, first_ts timestamptz, last_ts timestamptz, status text DEFAULT 'open',
        evidence jsonb, created_at timestamptz DEFAULT now());
    CREATE TABLE verdicts(id bigserial, incident_key text, verdict text, created_at timestamptz DEFAULT now());
    CREATE TABLE nodes(node_id text PRIMARY KEY, hostname text, status text, logs text[] DEFAULT '{}',
        registered_at timestamptz, last_seen_at timestamptz);
    CREATE TABLE events(ts timestamptz, eventid text, username text, src_ip inet, input text, sensor text);
"""


def card_texts(body):
    """Teams 카드(RichTextBlock · TextRun) 본문의 글을 덩이 순서대로 꺼낸다. 첫째가 머리말, 나머지가 항목 줄이다."""
    return ["".join(run["text"] for run in block["inlines"]) for block in body["attachments"][0]["content"]["body"]]


class FakeHttp:
    """post_json 대역. 받은 주소 · 본문을 기록하고 정해진 결과를 돌려준다."""

    def __init__(self, code=202, error=None):
        self.code, self.error, self.calls = code, error, []

    def __call__(self, url, body):
        self.calls.append((url, body))
        return self.code, self.error


@unittest.skipUnless(os.environ.get("OPSLOOP_TEST_DATABASE_URL"), "PostgreSQL 시험 연결 미지정")
class NotifyDatabaseTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        import asyncpg
        self.conn = await asyncpg.connect(os.environ["OPSLOOP_TEST_DATABASE_URL"])
        await self.conn.execute("SET search_path TO pg_temp")
        await self.conn.execute(TABLES.replace("CREATE TABLE", "CREATE TEMP TABLE") + """
            CREATE FUNCTION pg_temp.audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN RAISE EXCEPTION 'audit events are append-only'; END $$;""")
        await self.conn.execute(MIGRATION.read_text().replace("EXECUTE FUNCTION audit_append_only()",
                                                              "EXECUTE FUNCTION pg_temp.audit_append_only()"))
        self.pool = SimpleNamespace(acquire=self.acquire)
        self.request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(pool=self.pool)),
                                       state=SimpleNamespace(user={"u": "test-admin", "r": "admin"}))
        self.notifier = notifier.Notifier(self.pool, "test-a")
        self.audit_patch = patch.object(notify, "audit", self.temp_audit)
        self.audit_patch.start()

    @asynccontextmanager
    async def acquire(self):
        yield self.conn

    async def temp_audit(self, c, actor, event, detail):
        await c.execute("INSERT INTO events VALUES(now(),$1,$2,'192.0.2.1',$3,'audit')", event, actor, detail)

    async def asyncTearDown(self):
        self.audit_patch.stop()
        await self.conn.close()

    async def channel(self, name="팀즈", kind="teams", url=TEAMS_URL, grade="immediate", batch_seconds=0, min_severity="low",
                      events=("incident.created", "pending.overdue", "node.silent"), enabled=True, created_ago="1 hour"):
        return await self.conn.fetchval(f"""
            INSERT INTO notify_channels(name, kind, url, grade, events, min_severity, batch_seconds, enabled, created_at, enabled_at)
            VALUES($1, $2, $3, $4, $5, $6, $7, $8, now() - interval '{created_ago}', now() - interval '{created_ago}') RETURNING id""",
            name, kind, url, grade, list(events), min_severity, batch_seconds, enabled)

    async def incident(self, key, severity="high", first_ago="5 minutes", created_ago="1 minute", rule="R001", actor="192.0.2.8"):
        await self.conn.execute(f"""
            INSERT INTO incidents(incident_key, rule_id, rule_version, rule_name, severity, actor_ip, first_ts, last_ts, evidence, created_at)
            VALUES($1, $2, 'v2', '시험 규칙', $3, $4::inet, now() - interval '{first_ago}', now(), '{{"raw": "비밀 원문"}}',
                   now() - interval '{created_ago}')""", key, rule, severity, actor)

    async def deliveries(self, **where):
        clause = " AND ".join(f"{k} = ${i + 1}" for i, k in enumerate(where)) or "true"
        return [dict(r) for r in await self.conn.fetch(
            f"SELECT * FROM notify_deliveries WHERE {clause} ORDER BY id", *where.values())]

    async def test_fill_once_with_severity_window_channel_age_and_events(self):
        channel = await self.channel(min_severity="high")
        await self.incident("new-high")
        await self.incident("new-low", severity="low")
        await self.incident("old", created_ago="25 hours")
        await self.incident("before-channel", created_ago="2 hours")
        await self.incident("overdue-critical", severity="critical", first_ago="2 hours")
        await self.incident("overdue-low", severity="low", first_ago="25 hours")
        await self.incident("judged", severity="critical", first_ago="2 hours")
        # 채널보다 먼저 생기고 채널 기준 시각 전에 이미 목표를 넘긴 미판정은 넣지 않는다(켜자마자 쏟아지지 않게)
        await self.incident("stale-overdue", severity="critical", first_ago="3 hours", created_ago="3 hours")
        await self.conn.execute("INSERT INTO verdicts(incident_key, verdict) VALUES('judged', 'threat')")
        await self.conn.execute("""INSERT INTO nodes(node_id, hostname, status, logs, registered_at, last_seen_at) VALUES
            ('silent', 'web-01', 'active', '{metrics,nginx}', now() - interval '1 day', now() - interval '11 minutes'),
            ('fresh', 'web-02', 'active', '{metrics}', now() - interval '1 day', now() - interval '9 minutes'),
            ('nometrics', 'web-03', 'active', '{nginx}', now() - interval '1 day', now() - interval '1 hour'),
            ('revoked', 'web-04', 'revoked', '{metrics}', now() - interval '1 day', now() - interval '1 hour'),
            ('never', 'web-05', 'active', '{metrics}', now() - interval '20 minutes', NULL)""")
        await self.channel(name="꺼짐", enabled=False)
        await self.channel(name="노드만", events=("node.silent",))
        for _ in range(2):
            await self.notifier.fill(self.conn)
        rows = await self.deliveries(channel_id=channel)
        self.assertEqual({(r["event"], r["subject_key"].split("@")[0]) for r in rows},
                         {("incident.created", "new-high"), ("incident.created", "overdue-critical"), ("incident.created", "judged"),
                          ("pending.overdue", "overdue-critical"), ("node.silent", "node:silent"), ("node.silent", "node:never")})
        self.assertTrue(all(r["status"] == "queued" and r["attempts"] == 0 for r in rows))
        payload = json.loads(next(r for r in rows if r["subject_key"] == "new-high")["payload"])
        self.assertEqual((payload["rule_id"], payload["severity"], payload["who"]), ("R001", "high", "192.0.2.8"))
        self.assertNotIn("비밀 원문", json.dumps(rows, default=str, ensure_ascii=False))
        silent = next(r for r in rows if r["subject_key"].startswith("node:silent@"))
        self.assertEqual(json.loads(silent["payload"])["hostname"], "web-01")
        self.assertEqual(len(await self.deliveries(event="node.silent")), 4)
        self.assertEqual(await self.conn.fetchval("SELECT count(*) FROM notify_deliveries d JOIN notify_channels c ON c.id=d.channel_id WHERE NOT c.enabled"), 0)

    async def test_daily_summary_once_after_nine_kst(self):
        channel = await self.channel(name="요약", grade="daily")
        await self.incident("a", severity="critical", first_ago="3 hours")
        await self.incident("b", severity="low", first_ago="1 hour")
        # 기준 시각은 DB 의 now() 에서 만든다. 09:00 KST 전이면 같은 날 09:00 이후로 미룬다(경과는 최대 9시간 늘어난다).
        now = await self.conn.fetchval("SELECT now()")
        local = now.astimezone(notifier.KST)
        late = now if local.hour >= 9 else now + timedelta(hours=9 - local.hour)
        early = late.astimezone(notifier.KST).replace(hour=8, minute=0)
        await self.notifier.fill_daily(self.conn, channel, early)
        self.assertEqual(await self.deliveries(), [])
        for _ in range(2):
            await self.notifier.fill_daily(self.conn, channel, late)
        rows = await self.deliveries()
        self.assertEqual([(r["event"], r["subject_key"]) for r in rows],
                         [("daily.summary", late.astimezone(notifier.KST).strftime("%Y-%m-%d"))])
        payload = json.loads(rows[0]["payload"])
        self.assertEqual((payload["pending_total"], payload["overdue"], payload["incidents_24h"]), (2, 1, 2))
        self.assertGreaterEqual(payload["oldest_seconds"], 3 * 3600)
        self.assertEqual(payload["severity_counts"], "critical 1 · low 1")
        await self.notifier.fill(self.conn)
        self.assertEqual(len(await self.deliveries()), 1)

    async def test_send_groups_by_channel_and_event_and_marks_sent(self):
        teams = await self.channel()
        hook = await self.channel(name="웹훅", kind="webhook", url="https://hooks.example.com/opsloop/ABCD")
        for key in ("a", "b", "c"):
            await self.incident(key)
        await self.incident("late", severity="critical", first_ago="2 hours")
        await self.notifier.fill(self.conn)
        http = FakeHttp(202)
        with patch.object(notifier, "post_json", http):
            groups = await self.notifier.send(self.conn)
        self.assertEqual(groups, 4)
        urls = sorted(url for url, _ in http.calls)
        self.assertEqual(urls, sorted([TEAMS_URL, TEAMS_URL, "https://hooks.example.com/opsloop/ABCD", "https://hooks.example.com/opsloop/ABCD"]))
        card = next(body for url, body in http.calls if url == TEAMS_URL and "새 인시던트 4건" in card_texts(body)[0])
        self.assertEqual(len(card_texts(card)) - 1, 4)
        plain = next(body for url, body in http.calls if url != TEAMS_URL and body["event"] == "pending.overdue")
        self.assertEqual([item["incident_key"] for item in plain["items"]], ["late"])
        rows = await self.deliveries()
        self.assertEqual({(r["status"], r["attempts"], r["response_code"], r["error"]) for r in rows}, {("sent", 1, 202, None)})
        self.assertTrue(all(r["sent_at"] is not None and r["claimed_by"] == "test-a" for r in rows))
        self.assertEqual(await self.notifier.send(self.conn), 0)
        self.assertNotIn("SECRETSIG", json.dumps([b for _, b in http.calls], ensure_ascii=False))
        listing = await notify.list_deliveries(self.request, channel_id=hook, status="sent", limit=10, offset=0)
        self.assertEqual(listing["total"], 5)
        self.assertEqual((await notify.list_deliveries(self.request, status="queued", limit=10, offset=0))["total"], 0)
        self.assertEqual(listing["rows"][0]["channel_name"], "웹훅")
        self.assertNotIn("SECRETSIG", json.dumps(listing, default=str))
        self.assertNotIn("payload", listing["rows"][0])

    async def test_retry_schedule_then_failed(self):
        await self.channel()
        await self.incident("a")
        await self.notifier.fill(self.conn)
        http = FakeHttp(500, "HTTP 500")
        expected = [("queued", 1, 60), ("queued", 2, 300), ("queued", 3, 900), ("failed", 4, None)]
        with patch.object(notifier, "post_json", http):
            for status, attempts, delay in expected:
                self.assertEqual(await self.notifier.send(self.conn), 1)
                row = (await self.deliveries())[0]
                self.assertEqual((row["status"], row["attempts"], row["response_code"], row["error"]), (status, attempts, 500, "HTTP 500"))
                if delay is not None:
                    wait = (row["next_attempt_at"] - await self.conn.fetchval("SELECT now()")).total_seconds()
                    self.assertTrue(delay - 5 < wait <= delay, wait)
                    self.assertIsNone(row["claimed_at"])
                    self.assertEqual(await self.notifier.send(self.conn), 0)
                    await self.conn.execute("UPDATE notify_deliveries SET next_attempt_at = now()")
            self.assertEqual(await self.notifier.send(self.conn), 0)
        self.assertEqual(len(http.calls), 4)
        http = FakeHttp(None, "URLError")
        await self.incident("b")
        await self.notifier.fill(self.conn)
        with patch.object(notifier, "post_json", http):
            await self.notifier.send(self.conn)
        row = (await self.deliveries(subject_key="b"))[0]
        self.assertEqual((row["status"], row["response_code"], row["error"]), ("queued", None, "URLError"))

    async def test_batch_window_groups_late_arrivals_into_one_message(self):
        """창은 무리의 첫 행부터 잰다. 창 안에 늦게 들어온 사건도 같은 메시지로 나간다."""
        channel = await self.channel(batch_seconds=300, events=("incident.created",))
        daily = await self.channel(name="요약", grade="daily", batch_seconds=300)
        await self.incident("a")
        await self.notifier.fill(self.conn)
        await self.conn.execute("UPDATE notify_deliveries SET created_at = now() - interval '200 seconds'")
        await self.incident("b")
        await self.notifier.fill(self.conn)
        await self.conn.execute("UPDATE notify_deliveries SET created_at = now() - interval '100 seconds' WHERE subject_key = 'b'")
        await self.notifier.fill_daily(self.conn, daily, datetime(2026, 9, 25, 1, 0, tzinfo=timezone.utc))
        http = FakeHttp(202)
        with patch.object(notifier, "post_json", http):
            # 첫 행이 200초라 아직 창 안이다. 일일 요약만 바로 나간다
            self.assertEqual(await self.notifier.send(self.conn), 1)
            self.assertEqual({r["status"] for r in await self.deliveries(channel_id=channel)}, {"queued"})
            self.assertEqual({r["status"] for r in await self.deliveries(channel_id=daily)}, {"sent"})
            await self.conn.execute("UPDATE notify_deliveries SET created_at = created_at - interval '101 seconds' WHERE channel_id = $1", channel)
            await self.incident("c")
            await self.notifier.fill(self.conn)
            # a(301초) 가 창을 넘겼으므로 b(201초) · c(방금) 까지 한 메시지다
            self.assertEqual(await self.notifier.send(self.conn), 1)
        texts = card_texts(http.calls[-1][1])
        self.assertEqual(texts[0], "[OpsLoop] 새 인시던트 3건")
        self.assertEqual(len(texts) - 1, 3)
        self.assertEqual({r["status"] for r in await self.deliveries()}, {"sent"})
        self.assertEqual(len(http.calls), 2)
        # 보낸 뒤 들어온 사건은 새 창을 연다
        await self.incident("d")
        await self.notifier.fill(self.conn)
        with patch.object(notifier, "post_json", http):
            self.assertEqual(await self.notifier.send(self.conn), 0)

    async def test_disabled_channel_is_not_claimed(self):
        channel = await self.channel(batch_seconds=0)
        await self.incident("a")
        await self.notifier.fill(self.conn)
        http = FakeHttp(202)
        with patch.object(notifier, "post_json", http):
            await self.conn.execute("UPDATE notify_channels SET enabled = false WHERE id = $1", channel)
            self.assertEqual(await self.notifier.send(self.conn), 0)
            await self.conn.execute("UPDATE notify_channels SET enabled = true WHERE id = $1", channel)
            self.assertEqual(await self.notifier.send(self.conn), 1)
        self.assertEqual({r["status"] for r in await self.deliveries()}, {"sent"})

    async def test_disable_cancels_queued_and_reenable_starts_from_now(self):
        body = notify.ChannelIn(name="야간 팀즈", kind="teams", url=TEAMS_URL, grade="immediate", batch_seconds=300,
                                events=["incident.created", "pending.overdue"])
        created = await notify.create_channel(body, self.request, Response())
        await self.conn.execute("UPDATE notify_channels SET created_at = now() - interval '2 hours', enabled_at = now() - interval '2 hours'")
        await self.incident("before-off", severity="critical", first_ago="90 minutes")
        await self.notifier.fill(self.conn)
        self.assertEqual({r["subject_key"] for r in await self.deliveries(status="queued")}, {"before-off"})
        update = notify.ChannelUpdate(**(body.model_dump() | {"url": None}))
        await notify.update_channel(created["id"], notify.ChannelUpdate(**(update.model_dump() | {"enabled": False})), self.request, Response())
        rows = await self.deliveries()
        self.assertEqual({(r["status"], r["error"]) for r in rows}, {("failed", "ChannelDisabled")})
        # 꺼져 있는 동안 생긴 사건 · 목표를 넘긴 미판정은 다시 켜도 한꺼번에 나가지 않는다
        await self.incident("while-off", severity="critical", first_ago="70 minutes", created_ago="30 minutes")
        before = await self.conn.fetchval("SELECT enabled_at FROM notify_channels")
        await notify.update_channel(created["id"], update, self.request, Response())
        self.assertGreater(await self.conn.fetchval("SELECT enabled_at FROM notify_channels"), before)
        await self.notifier.fill(self.conn)
        self.assertEqual(await self.deliveries(status="queued"), [])
        await self.incident("after-on", severity="critical")
        await self.notifier.fill(self.conn)
        self.assertEqual({r["subject_key"] for r in await self.deliveries(status="queued")}, {"after-on"})
        # 사건 종류를 빼면 그 종류의 대기 행은 닫고, 이름만 바꾸면 기준 시각을 옮기지 않는다
        narrowed = notify.ChannelUpdate(**(update.model_dump() | {"events": ["pending.overdue"]}))
        await notify.update_channel(created["id"], narrowed, self.request, Response())
        self.assertEqual({(r["subject_key"], r["status"], r["error"]) for r in await self.deliveries(subject_key="after-on")},
                         {("after-on", "failed", "ChannelChanged")})
        before = await self.conn.fetchval("SELECT enabled_at FROM notify_channels")
        await notify.update_channel(created["id"], notify.ChannelUpdate(**(narrowed.model_dump() | {"name": "야간 팀즈 2"})), self.request, Response())
        self.assertEqual(await self.conn.fetchval("SELECT enabled_at FROM notify_channels"), before)
        await notify.update_channel(created["id"], update, self.request, Response())
        self.assertGreater(await self.conn.fetchval("SELECT enabled_at FROM notify_channels"), before)

    async def test_settle_and_send_leave_rows_taken_by_a_peer_alone(self):
        """되찾아 간 행은 결과를 덮어쓰지 않고, 보내기 직전에 내 것이 아니면 보내지 않는다."""
        channel = await self.channel()
        for key in ("a", "b"):
            await self.incident(key)
        await self.notifier.fill(self.conn)
        rows = await self.conn.fetch(notifier.CLAIM, "test-a")
        self.assertEqual(len(rows), 2)
        # 5분 회수 뒤 다른 콘솔이 다시 집었다
        await self.conn.execute("UPDATE notify_deliveries SET claimed_by = 'test-b', claimed_at = now() WHERE subject_key = 'a'")
        await self.notifier.settle(self.conn, rows, 500, "HTTP 500")
        state = {r["subject_key"]: (r["status"], r["attempts"], r["claimed_by"]) for r in await self.deliveries()}
        self.assertEqual(state, {"a": ("sending", 0, "test-b"), "b": ("queued", 1, None)})
        await self.notifier.settle(self.conn, [r for r in rows if r["subject_key"] == "a"], 202, None)
        self.assertEqual((await self.deliveries(subject_key="a"))[0]["status"], "sending")
        http = FakeHttp(202)
        with patch.object(notifier, "post_json", http):
            self.assertFalse(await self.notifier.send_group(self.conn, channel, "incident.created",
                                                            [r for r in rows if r["subject_key"] == "a"]))
        self.assertEqual(http.calls, [])

    async def test_sending_rows_recover_on_start_and_stale_claims_release(self):
        channel = await self.channel()
        await self.conn.execute("""INSERT INTO notify_deliveries(channel_id, event, subject_key, payload, status, claimed_at, claimed_by) VALUES
            ($1, 'incident.created', 'mine', '{}', 'sending', now(), 'test-a'),
            ($1, 'incident.created', 'peer-live', '{}', 'sending', now(), 'test-b'),
            ($1, 'incident.created', 'peer-dead', '{}', 'sending', now() - interval '6 minutes', 'test-b')""", channel)

        async def idle(self_, interval, step):
            return None
        with patch.object(notifier.Notifier, "loop", idle):
            await self.notifier.start()
            await self.notifier.stop()
        self.assertEqual({r["subject_key"]: r["status"] for r in await self.deliveries()},
                         {"mine": "queued", "peer-live": "sending", "peer-dead": "sending"})
        http = FakeHttp(202)
        with patch.object(notifier, "post_json", http):
            self.assertEqual(await self.notifier.send(self.conn), 1)
        rows = {r["subject_key"]: (r["status"], r["claimed_by"]) for r in await self.deliveries()}
        self.assertEqual(rows, {"mine": ("sent", "test-a"), "peer-live": ("sending", "test-b"), "peer-dead": ("sent", "test-a")})

    async def test_api_masks_url_audits_names_only_and_tests_channel(self):
        body = notify.ChannelIn(name="운영 웹훅", kind="webhook", url="https://hooks.example.com/opsloop/SECRETPATH", grade="immediate",
                                events=["incident.created"], template_header="머리 {count}", template_item="{rule_id} {who}")
        response = Response()
        created = await notify.create_channel(body, self.request, response)
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertNotIn("url", created)
        self.assertEqual((created["url_host"], created["url_tail"], created["last_delivery"]), ("hooks.example.com", "PATH", None))
        with self.assertRaises(HTTPException) as error:
            await notify.create_channel(body, self.request, Response())
        self.assertEqual(error.exception.status_code, 409)
        listing = await notify.list_channels(self.request, Response())
        self.assertEqual([c["name"] for c in listing], ["운영 웹훅"])
        update = notify.ChannelUpdate(**(body.model_dump() | {"url": "", "name": "웹훅2", "batch_seconds": 60}))
        changed = await notify.update_channel(created["id"], update, self.request, Response())
        self.assertEqual((changed["name"], changed["batch_seconds"], changed["url_tail"], changed["updated_by"]), ("웹훅2", 60, "PATH", "test-admin"))
        self.assertEqual(await self.conn.fetchval("SELECT url FROM notify_channels"), "https://hooks.example.com/opsloop/SECRETPATH")
        same = await notify.update_channel(created["id"], update, self.request, Response())
        self.assertEqual(same["updated_at"], changed["updated_at"])
        with self.assertRaises(HTTPException) as error:
            await notify.update_channel(created["id"], notify.ChannelUpdate(**(update.model_dump() | {"kind": "teams"})), self.request, Response())
        self.assertEqual(error.exception.status_code, 422)
        with self.assertRaises(HTTPException) as error:
            await notify.update_channel(created["id"] + 99, update, self.request, Response())
        self.assertEqual(error.exception.status_code, 404)
        audit = [dict(r) for r in await self.conn.fetch("SELECT eventid, detail FROM audit_log ORDER BY ts")]
        self.assertEqual([a["eventid"] for a in audit], ["console.notify.channel.created", "console.notify.channel.changed"])
        self.assertEqual(audit[0]["detail"], f"channel=운영_웹훅 id={created['id']} kind=webhook host=hooks.example.com grade=immediate")
        self.assertEqual(audit[1]["detail"], f"channel=운영_웹훅 id={created['id']} fields=name,batch_seconds")
        # 감사 조회 API 는 channel= 을 대상으로 뽑아 대상 검색이 된다
        found = await operations.audit_log(self.request, actor="", target="운영_웹", since=None, until=None, limit=10, offset=0)
        self.assertEqual([(r["eventid"], r["target"]) for r in found["rows"]],
                         [("console.notify.channel.changed", "운영_웹훅"), ("console.notify.channel.created", "운영_웹훅")])
        self.assertNotIn("SECRETPATH", json.dumps(audit, ensure_ascii=False))
        self.assertNotIn("머리", audit[1]["detail"])
        http = FakeHttp(202)
        with patch.object(notifier, "post_json", http):
            result = await notify.test_channel(created["id"], self.request)
        self.assertEqual(result, {"status": "sent", "response_code": 202, "error": None})
        self.assertEqual(http.calls[0][0], "https://hooks.example.com/opsloop/SECRETPATH")
        self.assertEqual(http.calls[0][1]["title"], "머리 1")
        self.assertEqual(http.calls[0][1]["lines"], ["R001 192.0.2.8"])
        self.assertTrue(http.calls[0][1]["console_url"].endswith("/alerts"))
        with patch.object(notifier, "post_json", FakeHttp(None, "TimeoutError")):
            result = await notify.test_channel(created["id"], self.request)
        self.assertEqual(result, {"status": "failed", "response_code": None, "error": "TimeoutError"})
        rows = await self.deliveries(event="test")
        self.assertEqual([(r["status"], r["attempts"], r["sent_at"] is not None) for r in rows], [("sent", 1, True), ("failed", 1, False)])
        self.assertTrue(all(r["subject_key"].startswith("test:") for r in rows))
        listing = await notify.list_channels(self.request, Response())
        last = listing[0]["last_delivery"]
        self.assertEqual((last["status"], last["error"], last["sent_at"]), ("failed", "TimeoutError", None))
        self.assertIsNotNone(last["at"])
        self.assertNotIn("SECRETPATH", json.dumps(listing, default=str, ensure_ascii=False))
        for sql in ["DELETE FROM events", "UPDATE events SET input = 'x'"]:
            import asyncpg
            with self.assertRaises(asyncpg.RaiseError):
                await self.conn.execute(sql)


@unittest.skipUnless(os.environ.get("OPSLOOP_TEST_DATABASE_URL"), "PostgreSQL 시험 연결 미지정")
class NotifyClaimLockTests(unittest.IsolatedAsyncioTestCase):
    """연결 둘이 같은 표를 봐야 하는 집기 시험. 무작위 이름의 스키마를 만들고 끝나면 지운다."""

    async def asyncSetUp(self):
        import asyncpg
        self.schema = "notify_test_" + secrets.token_hex(4)
        self.a = await asyncpg.connect(os.environ["OPSLOOP_TEST_DATABASE_URL"])
        self.b = await asyncpg.connect(os.environ["OPSLOOP_TEST_DATABASE_URL"])
        await self.a.execute(f"CREATE SCHEMA {self.schema}")
        for conn in (self.a, self.b):
            await conn.execute(f"SET search_path TO {self.schema}")
        await self.a.execute(TABLES + """
            CREATE FUNCTION audit_append_only() RETURNS trigger LANGUAGE plpgsql AS $$
                BEGIN RAISE EXCEPTION 'audit events are append-only'; END $$;""")
        await self.a.execute(MIGRATION.read_text())
        self.channel = await self.a.fetchval("""INSERT INTO notify_channels(name, kind, url, grade, batch_seconds)
            VALUES('팀즈', 'teams', $1, 'immediate', 0) RETURNING id""", TEAMS_URL)
        await self.a.execute("""INSERT INTO notify_deliveries(channel_id, event, subject_key, payload)
            VALUES($1, 'incident.created', 'one', '{}'), ($1, 'incident.created', 'two', '{}')""", self.channel)

    async def asyncTearDown(self):
        await self.b.close()
        await self.a.execute(f"DROP SCHEMA {self.schema} CASCADE")
        await self.a.close()

    async def test_claim_skips_rows_locked_by_a_peer(self):
        transaction = self.a.transaction()
        await transaction.start()
        await self.a.execute("SELECT 1 FROM notify_deliveries WHERE subject_key = 'one' FOR UPDATE")
        claimed = await self.b.fetch(notifier.CLAIM, "console-b")
        self.assertEqual([r["subject_key"] for r in claimed], ["two"])
        await transaction.rollback()
        claimed = await self.b.fetch(notifier.CLAIM, "console-b")
        self.assertEqual([r["subject_key"] for r in claimed], ["one"])
        self.assertEqual(await self.b.fetch(notifier.CLAIM, "console-b"), [])
        rows = await self.a.fetch("SELECT subject_key, status, claimed_by FROM notify_deliveries ORDER BY subject_key")
        self.assertEqual([tuple(r) for r in rows], [("one", "sending", "console-b"), ("two", "sending", "console-b")])
