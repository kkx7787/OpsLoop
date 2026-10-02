# 재시험(콘솔 이중화 정지 3회) DB 연결 표본 한 번 — data01 에서 'bash -s' 로 돈다. 읽기만 한다.
#   1) pg_stat_activity: 콘솔 역할(opsloop_console) 연결의 이름표(application_name)별 수. opsloop_backup · 읽기 전용 트랜잭션.
#      백업 역할은 다른 역할 세션의 client_addr 를 못 보지만 이름표는 본다(app/targets.py CONSOLE_LINKS_SQL 주석).
#      이름표가 콘솔 이름이면 상태판 'DB 연결 확인' 과 같은 판정이다(있음 = 1 이상).
#   2) DB 컨테이너 망 이름공간의 5432 연결 상대 주소별 수(README '이중화 후속 반영 뒤' 의 ss 명령). 콘솔 A 192.168.50.11 · B .12
# 출력 한 줄: app <이름표=수 …> | peer <주소=수 …>
q="SELECT coalesce(string_agg(n || '=' || c, ' ' ORDER BY n), '-') FROM (SELECT coalesce(nullif(application_name, ''), '(none)') AS n, count(*) AS c FROM pg_stat_activity WHERE datname = current_database() AND usename = 'opsloop_console' GROUP BY 1) s"
a=$(sudo -n docker exec -e PGOPTIONS=--default_transaction_read_only=on opsloop-db psql -U opsloop_backup -d opsloop -At -c "$q" 2>&1 | tr '\n' ' ')
pid=$(sudo -n docker inspect -f '{{.State.Pid}}' opsloop-db)
p=$(sudo -n nsenter -t "$pid" -n ss -tnH state established '( sport = :5432 )' 2>&1 \
    | awk '{sub(/:[0-9]+$/, "", $4); n[$4]++} END {for (k in n) printf "%s=%d ", k, n[k]}')
echo "app ${a}| peer ${p:--}"
