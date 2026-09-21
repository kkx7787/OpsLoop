#!/usr/bin/env bash
# 네트워크 설계 4장의 검증 표를 그대로 실행한다. 결과는 테스트 결과서(WBS 4.2)에 넣는다.
# 사용: scripts/verify.sh   (Mac 에서 실행 · 관리망 경유)
set -uo pipefail
KEY="${SSH_KEY:-$HOME/.ssh/opsloop_ed25519}"
FW=192.168.70.254
S1=192.168.50.11   # console-a
D1=192.168.60.11   # data-01
W1=192.168.50.21   # web-01 (관제 대상)
SSHO=(-o BatchMode=yes -o ConnectTimeout=5 -o IdentitiesOnly=yes -i "$KEY")
ssh_fw()  { ssh "${SSHO[@]}" ops@$FW "$@"; }
# ProxyJump 는 점프 구간에 -i 를 넘기지 않는다. ProxyCommand 로 같은 키를 쓴다
ssh_in()  { ssh "${SSHO[@]}" -o ProxyCommand="ssh -q -W %h:%p ${SSHO[*]} ops@$FW" ops@"$1" "${@:2}"; }
tcp() { echo "timeout ${3:-5} bash -c '</dev/tcp/$1/$2'"; }
ok=0; ng=0
check() { # $1 설명  $2 기대(통과/실패)  $3.. 명령
  local desc=$1 expect=$2; shift 2
  if "$@" >/dev/null 2>&1; then got=통과; else got=실패; fi
  if [ "$got" = "$expect" ]; then echo "  [정상] $desc · 기대 $expect"; ok=$((ok+1));
  else echo "  [문제] $desc · 기대 $expect · 실제 $got"; ng=$((ng+1)); fi
}
echo "== 1. 세그먼트 간 허용된 통신만 열려 있는가"
check "콘솔 → 데이터 노드 5432" 통과 ssh_in $S1 "timeout 5 bash -c '</dev/tcp/$D1/5432'"
check "콘솔 → 데이터 노드 22 (규칙에 없음)" 실패 ssh_in $S1 "timeout 5 bash -c '</dev/tcp/$D1/22'"
echo "== 2. 내부에서 관리망으로 가지 못하는가"
check "데이터 노드 → 관리망 Mac" 실패 ssh_in $D1 "timeout 5 bash -c '</dev/tcp/192.168.70.1/22'"
echo "== 3. 내부에서 인터넷으로 나가는 경로"
check "데이터 노드 → S3 443" 통과 ssh_in $D1 "timeout 8 bash -c '</dev/tcp/s3.ap-northeast-2.amazonaws.com/443'"
check "콘솔 → 임의 주소 80 (규칙에 없음)" 실패 ssh_in $S1 "timeout 5 bash -c '</dev/tcp/example.com/80'"
echo "== 4. 거부 기록이 남는가"
if ssh_fw "sudo journalctl -k --since '-5 min' | grep -c 'fw-forward-drop'" 2>/dev/null | grep -qv '^0$'; then
  echo "  [정상] 방화벽 거부 로그 기록됨"; ok=$((ok+1)); else echo "  [문제] 거부 로그가 없음"; ng=$((ng+1)); fi
echo "== 5. 부하분산과 헬스체크"
check "HAProxy 통계 페이지" 통과 curl -fsS --max-time 5 http://$FW:8404/
check "콘솔 진입점 응답" 통과 curl -fsS --max-time 5 http://$FW:8443/health
echo "== 6. 관제 대상 web-01 (이슈 #11 · 수집 설계 6장)"
check "web-01 → 데이터 노드 수집 관문 3101" 통과 ssh_in $W1 "$(tcp $D1 3101)"
check "web-01 → 데이터 노드 DB 5432" 실패 ssh_in $W1 "$(tcp $D1 5432)"
check "web-01 → 데이터 노드 Loki 3100" 실패 ssh_in $W1 "$(tcp $D1 3100)"
check "web-01 → 데이터 노드 22" 실패 ssh_in $W1 "$(tcp $D1 22)"
check "web-01 → 콘솔 A 8000 (콘솔 가드)" 실패 ssh_in $W1 "$(tcp $S1 8000)"
check "web-01 → 콘솔 A 22 (콘솔 가드)" 실패 ssh_in $W1 "$(tcp $S1 22)"
ll=$(ssh_in $S1 "ip -6 -o addr show scope link | awk '/fe80/{split(\$4,a,\"/\"); print a[1]; exit}'" 2>/dev/null)
if [ -n "$ll" ]; then
  check "web-01 → 콘솔 A [$ll]:8000 (IPv6 링크 로컬)" 실패 ssh_in $W1 "curl -gsS -m 5 -o /dev/null 'http://[$ll%25enp2s0]:8000/health'"
fi
check "web-01 → 방화벽 콘솔 진입점 8443" 실패 ssh_in $W1 "$(tcp 192.168.50.1 8443)"
check "web-01 → 관리망 Mac 22" 실패 ssh_in $W1 "$(tcp 192.168.70.1 22)"
check "web-01 → S3 443 (구성 창 밖)" 실패 ssh_in $W1 "$(tcp s3.ap-northeast-2.amazonaws.com 443 8)"
check "web-01 → 임의 주소 443 (구성 창 밖)" 실패 ssh_in $W1 "$(tcp example.com 443 8)"
check "데이터 노드 → web-01 80 (단방향)" 실패 ssh_in $D1 "$(tcp $W1 80)"
check "콘솔 A → 데이터 노드 3101" 실패 ssh_in $S1 "$(tcp $D1 3101)"
check "콘솔 A → 데이터 노드 3100" 실패 ssh_in $S1 "$(tcp $D1 3100)"
check "콘솔 A → 데이터 노드 5432 (회귀)" 통과 ssh_in $S1 "$(tcp $D1 5432)"
check "관문 · Loki · 다리 동작" 통과 ssh_in $D1 "systemctl is-active -q opsloop-gate opsloop-agents.timer && curl -fsS -m 5 http://127.0.0.1:3100/ready"
if ssh_fw "sudo journalctl -k --since '-5 min' | grep -c 'fw-forward-drop.*SRC=$W1'" 2>/dev/null | grep -qv '^0$'; then
  echo "  [정상] 방화벽 거부 로그에 web-01 출발이 있음"; ok=$((ok+1)); else echo "  [문제] web-01 출발 거부 로그가 없음"; ng=$((ng+1)); fi
echo "  (토큰 없이 · 임의 키 · 주소 불일치 · 폐기 키 전송은 R202 인시던트를 만들므로 여기서 돌리지 않는다. 결과 문서 참고)"

echo
echo "정상 $ok · 문제 $ng"
