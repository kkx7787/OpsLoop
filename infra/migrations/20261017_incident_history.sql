-- #129. AI 추천 마이그레이션 뒤 적용. 삭제·재생성은 운영 표의 동작이며 감사 근거는 별도로 남긴다.
BEGIN;
CREATE TABLE IF NOT EXISTS incident_history (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    recorded_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    kind text NOT NULL CHECK (kind IN ('removed', 'absorption_materialized')),
    incident_key text NOT NULL,
    snapshot jsonb NOT NULL,
    recommendations jsonb NOT NULL DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS incident_history_key ON incident_history(incident_key, kind);
REVOKE ALL ON incident_history FROM PUBLIC;

CREATE OR REPLACE FUNCTION incident_history_immutable() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    RAISE EXCEPTION 'incident history is append-only';
END $$;
DROP TRIGGER IF EXISTS trg_incident_history_immutable ON incident_history;
CREATE TRIGGER trg_incident_history_immutable BEFORE UPDATE OR DELETE ON incident_history
    FOR EACH ROW EXECUTE FUNCTION incident_history_immutable();

CREATE OR REPLACE FUNCTION incident_history_capture() RETURNS trigger
LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, public AS $$
DECLARE recs jsonb; old_relation record;
BEGIN
    IF TG_OP = 'DELETE' THEN
        -- CASCADE보다 먼저 추천을 보관한다. 발송 이력은 원래 표에서 subject_key로 유지된다.
        SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY r.id), '[]') INTO recs
          FROM public.ai_recommendations r WHERE r.incident_key = OLD.incident_key;
        INSERT INTO public.incident_history(kind, incident_key, snapshot, recommendations)
        SELECT 'removed', OLD.incident_key, to_jsonb(OLD), recs
        WHERE NOT EXISTS (SELECT 1 FROM public.incident_history h
                          WHERE h.incident_key=OLD.incident_key AND h.kind='removed'
                            AND h.snapshot - 'created_at' = to_jsonb(OLD) - 'created_at'
                            AND h.recommendations = recs);
        RETURN OLD;
    END IF;
    -- 재생성된 사건을 계속 흡수 목록으로 세거나 후속 차단 대상으로 삼지 않는다.
    -- 다시 흡수되면 탐지기가 현재 부모·근거로 새 행을 넣는다. 이전 관계는 감사 표로 옮긴다.
    FOR old_relation IN DELETE FROM public.incident_absorbed a
        WHERE a.member_key=NEW.incident_key OR a.via_key=NEW.incident_key RETURNING a.*
    LOOP
        INSERT INTO public.incident_history(kind, incident_key, snapshot)
        SELECT 'absorption_materialized', old_relation.member_key, to_jsonb(old_relation)
        WHERE NOT EXISTS (SELECT 1 FROM public.incident_history h
                          WHERE h.incident_key=old_relation.member_key AND h.kind='absorption_materialized'
                            AND h.snapshot - 'recorded_at' = to_jsonb(old_relation) - 'recorded_at');
    END LOOP;
    RETURN NEW;
END $$;
REVOKE ALL ON FUNCTION incident_history_capture() FROM PUBLIC;
DROP TRIGGER IF EXISTS trg_incident_history_delete ON incidents;
CREATE TRIGGER trg_incident_history_delete BEFORE DELETE ON incidents
    FOR EACH ROW EXECUTE FUNCTION incident_history_capture();
DROP TRIGGER IF EXISTS trg_incident_history_insert ON incidents;
CREATE TRIGGER trg_incident_history_insert AFTER INSERT ON incidents
    FOR EACH ROW EXECUTE FUNCTION incident_history_capture();

-- 이미 재등장한 사건과 옛 흡수 관계가 함께 있는 경우에도 원래 관계를 보존한 뒤 정리한다.
WITH stale AS (
    DELETE FROM incident_absorbed a WHERE EXISTS (
        SELECT 1 FROM incidents i WHERE i.incident_key=a.member_key OR i.incident_key=a.via_key)
    RETURNING a.*
)
INSERT INTO incident_history(kind, incident_key, snapshot)
SELECT 'absorption_materialized', s.member_key, to_jsonb(s) FROM stale s;

DO $$ BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname='opsloop_console') THEN
        GRANT SELECT ON incident_history TO opsloop_console;
    END IF;
END $$;
COMMIT;
