"""AI 판정 추천 (이슈 #120). 콘솔은 추천 표(ai_recommendations)와 작업기 상태 한 행(ai_status)을 읽기만 한다.

추천은 판정이 아니다. 데이터 노드의 추천 작업기(recommend/opsloop_recommend.py)가 판정 대기 사건마다 남기고, 관제자는 사건 상세에서
보고 직접 판정한다. 판정할 때 본 추천을 판정 기록(verdicts.recommendation_id)에 함께 남겨 추천 일치 수를 센다.
확신도는 내지 않는다(평가 100건에서 틀린 추천 4건이 모두 확신도 high 였다, docs/evidence/2026-10-06-ai-pilot).
"""

# 표가 있고 콘솔 역할이 읽을 수 있는가. 마이그레이션(20261006_ai_recommend) 전 DB 와, 역할 블록만 다시 적용해 콘솔의 읽기가 빠진
# DB 에서도 콘솔이 뜨게 한다(absorbed.EXEMPT_READABLE_SQL 과 같은 방식). 그때는 사건 상세 · 요약에서 AI 구역을 뺀다
READABLE_SQL = ("SELECT CASE WHEN to_regclass('ai_recommendations') IS NULL OR to_regclass('ai_status') IS NULL THEN false"
                " ELSE has_table_privilege('ai_recommendations', 'SELECT') AND has_table_privilege('ai_status', 'SELECT') END")

# 사건의 최신 추천. 실패한 시도는 따로 센다(작업기가 사건마다 세 번까지만 묻는다)
LATEST_SQL = """
SELECT id, created_at, model, prompt_version, recommendation, needs_human, guard, reasons, block_hours, seconds
FROM ai_recommendations WHERE incident_key = $1 AND status = 'ok'
ORDER BY created_at DESC, id DESC LIMIT 1"""
FAILED_SQL = "SELECT count(*) FROM ai_recommendations WHERE incident_key = $1 AND status = 'failed'"
STATUS_SQL = "SELECT checked_at, reachable, last_ok_at, model, pending, error FROM ai_status"

# 추천 일치: 관제자가 추천을 보고 남긴 판정 중 판정값이 추천값과 같은 것. 오탐 · 양성 정탐은 추천값이 될 수 없어 다름으로 센다.
#   재판정이 있으면 판정마다 센다(그때 본 추천과 그때의 판정을 맞춘다)
AGREEMENT_SQL = """
SELECT count(*) FILTER (WHERE v.verdict = a.recommendation) AS agreed, count(*) AS judged
FROM verdicts v JOIN ai_recommendations a ON a.id = v.recommendation_id"""

# 판정에 붙이는 추천은 같은 사건의 정상 추천이어야 한다(다른 사건 · 실패 행을 붙여 일치 수를 꾸미지 못하게)
CHECK_SQL = "SELECT EXISTS (SELECT 1 FROM ai_recommendations WHERE id = $1 AND incident_key = $2 AND status = 'ok')"


async def readable(c) -> bool:
    return bool(await c.fetchval(READABLE_SQL))


async def incident(c, key):
    """사건 상세의 AI 구역. 표를 읽을 수 없으면 None(화면이 구역을 그리지 않는다)."""
    if not await readable(c):
        return None
    rec = await c.fetchrow(LATEST_SQL, key)
    status = await c.fetchrow(STATUS_SQL)
    return {"recommendation": dict(rec) if rec else None,
            "failed": await c.fetchval(FAILED_SQL, key),
            "status": dict(status) if status else None}


async def summary(c):
    """대시보드의 추천 일치 한 줄과 작업기 상태. 표를 읽을 수 없으면 None."""
    if not await readable(c):
        return None
    row = await c.fetchrow(AGREEMENT_SQL)
    status = await c.fetchrow(STATUS_SQL)
    return {"agreed": row["agreed"], "judged": row["judged"], "status": dict(status) if status else None}


async def belongs(c, recommendation_id: int, key: str) -> bool:
    return await readable(c) and bool(await c.fetchval(CHECK_SQL, recommendation_id, key))
