# 알림 채널 · 발송 대기 · 켜고 끈 기록 (읽기 전용). 채널 주소(url)는 읽지도 찍지도 않는다.
#   실행(콘솔 A 컨테이너 안, 앱 모듈을 쓴다):
#   ssh -F ~/.ssh/config.opsloop console-a "docker exec -i -e SINCE=<ISO> -w /app opsloop-api python3 -" < notify_state.py
#   SINCE  이 시각 뒤의 알림 감사 · 발송 이력 · 끈 동안 놓친 사건을 본다(없으면 최근 2시간)
import asyncio, os, re
from datetime import timedelta
import asyncpg
from dashboard import PENDING          # 판정 목표 시간 정의(notifier.FILL_OVERDUE 와 같은 것)

RANK = "CASE {s} WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 ELSE 3 END"
SEV = {"critical": 0, "high": 1, "medium": 2, "low": 3}
SLACK = timedelta(minutes=1)            # notifier.FILL_SLACK


def show(label, rows):
    print(label)
    for r in rows:
        print("   ", {k: (str(v) if v is not None else None) for k, v in dict(r).items()})
    if not rows:
        print("    (없음)")


async def run():
    c = await asyncpg.connect(os.environ["DATABASE_URL"],
                              server_settings={"default_transaction_read_only": "on",
                                               "application_name": "opsloop-retest-ro"})
    async with c.transaction(isolation="repeatable_read", readonly=True):
        now = await c.fetchval("SELECT now()")
        since = await c.fetchval("SELECT coalesce($1::text::timestamptz, now() - interval '2 hours')",
                                 os.environ.get("SINCE") or None)
        print("기준", now, "· 범위 시작", since)
        chans = await c.fetch("""
            SELECT id, name, kind, grade, events, min_severity, batch_seconds, enabled, enabled_at, updated_by, updated_at
              FROM notify_channels ORDER BY id""")
        show("== 채널 (주소 제외)", chans)
        show("== 채널별 대기 · 보내는 중 (0 이어야 끈다)", await c.fetch("""
            SELECT ch.id, ch.name, d.status, count(*) AS n, min(d.created_at) AS oldest, min(d.next_attempt_at) AS next_at
              FROM notify_deliveries d JOIN notify_channels ch ON ch.id = d.channel_id
             WHERE d.status IN ('queued', 'sending') GROUP BY 1, 2, 3 ORDER BY 1, 3"""))
        show("== 끄기로 닫힌 대기 행(error ChannelDisabled) 채널별 누계 · 마지막", await c.fetch("""
            SELECT channel_id, count(*) AS n, max(created_at) AS last_created
              FROM notify_deliveries WHERE error = 'ChannelDisabled' GROUP BY 1 ORDER BY 1"""))
        audit = await c.fetch("""
            SELECT ts, eventid, actor, detail FROM audit_log
             WHERE eventid LIKE 'console.notify.%' AND ts >= $1 ORDER BY ts""", since)
        show("== 범위 안 알림 감사(console.notify.*)", audit)
        show("== 범위 안 발송 이력", await c.fetch("""
            SELECT id, channel_id, event, subject_key, status, attempts, response_code, error, created_at, sent_at
              FROM notify_deliveries WHERE created_at >= $1 ORDER BY created_at, id""", since))

        for ch in chans:
            if ch["grade"] != "immediate":
                continue
            rank = SEV.get(ch["min_severity"], 3)
            tag = f"채널 {ch['id']} {ch['name']}"
            if not ch["enabled"]:
                # 지금 켜면 곧바로 넣을 것(켜는 순간 enabled_at = now(), 그보다 1분 앞선 것까지 넣는다)
                lo = now - SLACK - timedelta(seconds=60)
                if "incident.created" in ch["events"]:
                    show(f"== [{tag}] 지금 켜면 보낼 새 사건(최근 2분 · {ch['min_severity']} 이상, 0 이어야 켠다)", await c.fetch(f"""
                        SELECT incident_key, severity, created_at, is_test_source(actor_ip) AS test_src FROM incidents
                         WHERE created_at >= $1 AND {RANK.format(s='severity')} <= $2 ORDER BY created_at""", lo, rank))
                if "pending.overdue" in ch["events"]:
                    show(f"== [{tag}] 지금 켜면 보낼 판정 지연(최근 2분에 목표를 넘김)", await c.fetch(PENDING + f"""
                        SELECT incident_key, severity, first_ts + make_interval(secs => target_seconds) AS due FROM pending
                         WHERE age >= target_seconds AND first_ts + make_interval(secs => target_seconds) >= $2
                           AND {RANK.format(s='severity')} <= $3 ORDER BY due""", now, lo, rank))
                if "node.silent" in ch["events"]:
                    show(f"== [{tag}] 지금 켜면 보낼 노드 수신 끊김(기준 시각과 무관)", await c.fetch("""
                        SELECT node_id, hostname, coalesce(last_seen_at, registered_at) AS since FROM nodes n
                         WHERE status = 'active' AND 'metrics' = ANY(logs)
                           AND coalesce(last_seen_at, registered_at) < now() - interval '10 minutes'
                           AND NOT EXISTS (SELECT 1 FROM notify_deliveries d WHERE d.channel_id = $1 AND d.event = 'node.silent'
                                             AND d.subject_key = 'node:' || n.node_id || '@'
                                                 || (to_jsonb(coalesce(n.last_seen_at, n.registered_at)) #>> '{}'))""", ch["id"]))
                print(f"!! 경고: {tag} ({ch['kind']}) 가 꺼져 있다. 시험이 끝났으면 알림 화면에서 '사용' 을 켠다")
            # 범위 안에서 이 채널을 바꾼 감사(끔 → 켬). 끈 동안 생겨 보내지 않은 사건을 보인다
            marks = [a["ts"] for a in audit if re.search(rf"\bid={ch['id']}\b", a["detail"] or "")
                     and "enabled" in (a["detail"] or "")]
            if marks:
                off = marks[0]
                on = marks[-1] if len(marks) > 1 and ch["enabled"] else None
                hi = (on - SLACK) if on else now
                print(f"== [{tag}] 끈 시각 {off} · 켠 시각 {on or '(아직 꺼짐)'} · 보내지 않는 사건 범위 [{off}, {hi})")
                show("   그 범위에 생긴 사건(채널 조건 안). test_src 거짓인 것은 실제 사건이라 미판정 목록에서 따로 본다", await c.fetch(f"""
                    SELECT incident_key, severity, created_at, is_test_source(actor_ip) AS test_src FROM incidents
                     WHERE created_at >= $1 AND created_at < $2 AND {RANK.format(s='severity')} <= $3
                     ORDER BY created_at""", off, hi, rank))
    await c.close()

asyncio.run(run())
