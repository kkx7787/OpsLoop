#!/usr/bin/env bash
# 네트워크 설계 4장의 검증 표를 그대로 실행한다. 결과는 테스트 결과서(WBS 4.2)에 넣는다.
# 사용: scripts/verify.sh   (Mac 에서 실행 · 관리망 경유)
set -uo pipefail
KEY="${SSH_KEY:-$HOME/.ssh/opsloop_ed25519}"
FW=192.168.70.254
S1=192.168.50.11   # console-a
D1=192.168.60.11   # data-01
ssh_fw()  { ssh -o BatchMode=yes -o ConnectTimeout=5 -i "$KEY" ops@$FW "$@"; }
ssh_in()  { ssh -o BatchMode=yes -o ConnectTimeout=5 -o ProxyJump=ops@$FW -i "$KEY" ops@"$1" "${@:2}"; }
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
echo
echo "정상 $ok · 문제 $ng"
