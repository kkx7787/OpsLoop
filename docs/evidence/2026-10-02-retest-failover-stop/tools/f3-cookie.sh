#!/usr/bin/env bash
# 장애 전환 재측정 11 · 12 · 13단계: 프로브 쿠키(비밀번호 없이 서버 비밀로 발급) · me 5초 확인 · 두 콘솔 응답 확인 · 진입점 감시 점검 창 180분
set -u
source /Users/hanseongmin/opsloop-work/retest/failover-stop.env; cd /Users/hanseongmin/opsloop-repo || exit 1
python3 infra/vmware/failover/probe_http.py --mint-cookie console-a && python3 infra/vmware/failover/probe_http.py --run-dir "$E/raw/v00-check" --streams me --duration 5
python3 - "$E/raw/v00-check/http.jsonl" <<'PY' 2>&1 | tee "$E/pre/cookie-check.txt"
import collections, json, sys
c = collections.Counter()
for line in open(sys.argv[1], encoding="utf-8"):
    if line.strip():
        r = json.loads(line)
        c[(r.get("stream"), r.get("status"), r.get("error"), r.get("console"))] += 1
for k, v in sorted(c.items(), key=str):
    print(v, *k)
PY
"$HOME/Library/Application Support/OpsLoop/bin/console-watch.sh" --pause 180
echo "== f3 끝 $(date '+%H:%M:%S') · 위에 me 200 이 opsloop-console-a · b 둘 다 있고 http_401 이 없어야 한다"
