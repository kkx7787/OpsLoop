-- #109: 원장에서 재생성하는 node_metrics와 분리된 데이터 노드의 최신 상태 한 행.
BEGIN;
CREATE TABLE IF NOT EXISTS data_node_health (
    singleton boolean PRIMARY KEY DEFAULT true CHECK (singleton),
    checked_at timestamptz NOT NULL DEFAULT clock_timestamp(),
    cpu_pct real CHECK (cpu_pct BETWEEN 0 AND 100),
    mem_used_pct real CHECK (mem_used_pct BETWEEN 0 AND 100),
    load1 real CHECK (load1 >= 0 AND load1 < 'Infinity'::real),
    disks jsonb NOT NULL CHECK (jsonb_typeof(disks) = 'array' AND jsonb_array_length(disks) BETWEEN 1 AND 3),
    problems text[] NOT NULL DEFAULT '{}'
);
REVOKE ALL ON data_node_health FROM PUBLIC;
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_ingest') THEN
        GRANT SELECT, INSERT, UPDATE ON data_node_health TO opsloop_ingest;
    END IF;
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_console') THEN
        GRANT SELECT ON data_node_health TO opsloop_console;
    END IF;
END
$$;
COMMIT;
