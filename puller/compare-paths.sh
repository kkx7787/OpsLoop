#!/usr/bin/env bash
# 기록용: 옛 앱 노드(AWS DB)가 2026-09-25 종료되어(이슈 #37) 더는 돌릴 수 없다. 전환 때 대조 결과는 docs/2026-09-21-수집-파이프라인-결과.md 7장.
# 병행 대조 (WBS 3.4 · 전환 조건): 허니팟 옛 경로(AWS DB)와 새 경로(내부 DB)의 결과를 같은 기준 시각으로 비교한다.
# events · sessions 는 건수와 지문(md5)이 정확히 같아야 한다 (다르면 종료 1).
# 인시던트는 탐지 주기가 달라(내부 5분 · AWS 10분) 갈릴 수 있으므로 참고로만 보인다 (결과 문서 7장의 리플레이 비교 참고).
# 판정은 전환 뒤 내부에만 쌓이므로(9/21 R202 3건부터) 역시 참고다.
# 콘솔 이벤트는 원문 로그가 없으므로 빼고 cowrie · decoy 만 본다.
#
# 사용 (Mac): puller/compare-paths.sh [기준 시각]      기본 = 지금 - 40분 (두 경로 지연을 넘도록)
# 필요: ~/.ssh/config.opsloop 의 data01, aws CLI 로그인 (앱 노드 SSM)
set -euo pipefail
CUT=${1:-$(date -u -v-40M '+%Y-%m-%d %H:%M:00+00' 2>/dev/null || date -u -d '-40 min' '+%Y-%m-%d %H:%M:00+00')}
APP_NODE=${APP_NODE:-i-0030bed49b6ef0356}
REGION=${AWS_DEFAULT_REGION:-ap-northeast-2}
SQL=$(cat <<'Q'
SELECT 'events', sensor, count(*), md5(string_agg(line_hash, ',' ORDER BY line_hash)) FROM events
  WHERE sensor IN ('cowrie','decoy') AND ts < :'cut' GROUP BY sensor
UNION ALL SELECT 'sessions', sensor, count(*), md5(string_agg(session, ',' ORDER BY session)) FROM sessions
  WHERE sensor IN ('cowrie','decoy') AND first_ts < :'cut' GROUP BY sensor
UNION ALL SELECT 'incidents', rule_version, count(*), md5(string_agg(incident_key, ',' ORDER BY incident_key)) FROM incidents
  WHERE first_ts < :'cut' AND rule_version IN ('v1','v2') GROUP BY rule_version
UNION ALL SELECT 'verdicts', '-', count(*), '' FROM verdicts
ORDER BY 1, 2;
Q
)
echo "기준 시각 $CUT"
inner=$(printf '%s\n' "$SQL" | ssh -F "$HOME/.ssh/config.opsloop" -o BatchMode=yes data01 \
  "sudo -n docker exec -i opsloop-db psql -U opsloop -d opsloop -At -v cut='$CUT'")
script=$(printf '%s\n' "docker exec -i opsloop-db psql -U opsloop -d opsloop -At -v cut='$CUT' <<'SQLEOF'" "$SQL" "SQLEOF")
cid=$(aws ssm send-command --region "$REGION" --instance-ids "$APP_NODE" --document-name AWS-RunShellScript \
  --parameters "commands=[\"echo $(printf '%s' "$script" | base64 | tr -d '\n') | base64 -d | bash\"]" \
  --query Command.CommandId --output text)
for _ in $(seq 1 30); do
  st=$(aws ssm get-command-invocation --region "$REGION" --command-id "$cid" --instance-id "$APP_NODE" --query Status --output text 2>/dev/null || true)
  [ "$st" = Success ] || [ "$st" = Failed ] && break
  sleep 2
done
outer=$(aws ssm get-command-invocation --region "$REGION" --command-id "$cid" --instance-id "$APP_NODE" \
  --query StandardOutputContent --output text)
[ "$st" = Success ] || { echo "AWS 쪽 조회 실패 ($st)" >&2; exit 2; }

printf '%-10s %-8s %22s %22s  %s\n' 항목 구분 "내부 (건수 · 지문)" "AWS (건수 · 지문)" 판정
bad=0
while IFS='|' read -r kind key n md5; do
  [ -n "$kind" ] || continue
  other=$(printf '%s\n' "$outer" | awk -F'|' -v k="$kind" -v s="$key" '$1==k && $2==s {print $3 "|" $4}')
  mine="$n|$md5"
  if [ "$mine" = "$other" ]; then verdict=같음
  elif [ "$kind" = incidents ] || [ "$kind" = verdicts ]; then verdict="다름(참고)"
  else verdict=다름; bad=1; fi
  printf '%-10s %-8s %22s %22s  %s\n' "$kind" "$key" "$n · ${md5:0:8}" "${other%%|*} · $(printf '%s' "${other#*|}" | cut -c1-8)" "$verdict"
done <<< "$inner"
[ "$bad" = 0 ] && echo "events · sessions 모두 같다" || { echo "events 또는 sessions 가 다르다" >&2; exit 1; }
