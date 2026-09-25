-- #43: 콘솔 역할(opsloop_console)의 접속 한도를 20 → 30 으로 올린다.
--   콘솔 한 대 = asyncpg 풀 최대 10 + LISTEN 1. 콘솔 B 를 켜면 두 대 22 에 triage.py(같은 역할)가 더해지고,
--   리스너 재연결 · 컨테이너 교체 때 옛 접속과 새 접속이 잠깐 겹친다. 20 이면 B 를 켤 때 한도에 닿아 새 접속이 거부된다.
--   역할은 비밀번호 때문에 여기서 만들지 않는다 (collector/install-collector.sh · infra/vmware/scripts/db-console-role.sh,
--   둘 다 30 으로 만든다). 역할이 있을 때만 한도를 정확히 30 으로 둔다. 여러 번 적용해도 같다.
--   한도는 새 접속에만 걸린다. 이미 붙어 있는 접속은 끊기지 않으므로 콘솔을 다시 띄울 필요가 없다.
--   문장이 DO 블록 하나라 따로 BEGIN · COMMIT 을 두지 않는다 (블록 하나가 한 트랜잭션이다).
-- 적용 (Mac, 저장소 루트):
--   ssh -F ~/.ssh/config.opsloop data01 'sudo -n docker exec -i opsloop-db psql -U opsloop -d opsloop -v ON_ERROR_STOP=1 -q' \
--     < infra/migrations/20260926_console_connlimit.sql
-- 확인: infra/vmware/scripts/verify-db-roles.sh 의 '접속 한도' 항목 (30 이상)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'opsloop_console') THEN
        ALTER ROLE opsloop_console WITH CONNECTION LIMIT 30;
    END IF;
END
$$;
