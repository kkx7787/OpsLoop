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
# 통계 페이지는 방화벽 안(127.0.0.1)에서만 열린다. 관리망에서 바로는 닿지 않아야 한다 (이슈 #41)
check "HAProxy 통계 페이지 (방화벽 안 127.0.0.1)" 통과 ssh_fw "curl -fsS --max-time 5 http://127.0.0.1:8404/"
check "HAProxy 통계 페이지 관리망 직접 (막힘)" 실패 curl -fsS --max-time 5 http://$FW:8404/
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
echo "== 7. 외부 역할 세그먼트 · 차단 집행 (이슈 #51)"
A1=203.0.113.10    # 시연용 공격자 VM (netplan/attacker.yaml)
FWX=203.0.113.1    # 방화벽의 ext 주소
# 기록 줄(log prefix "fw-block-drop ")이 아니라 거부 줄만 본다. 동기화의 DROP_RULE_RE 와 같은 경계다
check "방화벽 차단 집합 · forward 거부 규칙 존재" 통과 ssh_fw "sudo -n nft list set inet filter opsloop_block >/dev/null && sudo -n nft list chain inet filter forward | grep -Eq 'ip saddr @opsloop_block (counter packets [0-9]+ bytes [0-9]+ )?drop( |\$)'"
check "방화벽 차단 동기화 타이머 동작" 통과 ssh_fw "systemctl is-active -q opsloop-block-sync.timer"
if ssh_in $A1 true >/dev/null 2>&1; then
  # 공격자 주소가 차단 집합에 있으면 web-01 접속은 실패를, 없으면 통과를 기대한다 (차단 전 · 후 · 해제 뒤 세 상태를 같은 표로 본다)
  inset=$(ssh_fw "sudo -n nft -j list set inet filter opsloop_block 2>/dev/null | grep -c '\"$A1\"'" 2>/dev/null | tr -dc '0-9')
  if [ "${inset:-0}" != 0 ]; then exp=실패; echo "  (공격자 주소가 차단 집합에 있음 · web-01 은 실패를 기대)"; else exp=통과; fi
  check "공격자 → web-01 80 (차단 $([ "$exp" = 실패 ] && echo 뒤 || echo 전))" $exp ssh_in $A1 "$(tcp $W1 80)"
  check "공격자 → web-01 22 (열지 않음)" 실패 ssh_in $A1 "$(tcp $W1 22)"
  check "공격자 → 콘솔 A 8000" 실패 ssh_in $A1 "$(tcp $S1 8000)"
  check "공격자 → 데이터 노드 5432" 실패 ssh_in $A1 "$(tcp $D1 5432)"
  check "공격자 → 방화벽 콘솔 진입점 8443" 실패 ssh_in $A1 "$(tcp $FWX 8443)"
  check "공격자 → 방화벽 22" 실패 ssh_in $A1 "$(tcp $FWX 22)"
  check "공격자 → 관리망 Mac 22" 실패 ssh_in $A1 "$(tcp 192.168.70.1 22)"
  check "공격자 → 인터넷 443 (출구 없음)" 실패 ssh_in $A1 "$(tcp 1.1.1.1 443)"
  check "정상 출발지 유지: 콘솔 → 데이터 노드 5432" 통과 ssh_in $S1 "$(tcp $D1 5432)"
  check "정상 출발지 유지: web-01 → 수집 관문 3101" 통과 ssh_in $W1 "$(tcp $D1 3101)"
  if [ "$exp" = 실패 ]; then
    if ssh_fw "sudo journalctl -k --since '-5 min' | grep -c 'fw-block-drop.*SRC=$A1'" 2>/dev/null | grep -qv '^0$'; then
      echo "  [정상] 방화벽 차단 거부 로그(fw-block-drop)에 공격자 출발이 있음"; ok=$((ok+1))
    else echo "  [문제] 공격자 출발의 fw-block-drop 로그가 없음"; ng=$((ng+1)); fi
  fi
else
  echo "  (공격자 VM $A1 에 닿지 않아 공격자 항목은 건너뜀 · 켜져 있는지 · fw 에서 ssh 가 되는지 본다)"
fi

echo
echo "정상 $ok · 문제 $ng"
