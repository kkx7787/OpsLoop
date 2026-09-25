# 내부망 구축 (VMware Fusion · Mac)

WBS 3.3 · 이슈 #8. 보호 자산을 인터넷에서 닿지 않는 내부망으로 내린다.
관제 대상 서버 web-01 은 서비스망에 VM 으로 둔다 (이슈 #11). 학교 AWS 계정의 web-02 는 VM 쪽이 끝난 뒤 추가 여부를 정한다.

## 구성

| VM | 메모리 · CPU | 세그먼트 · 주소 | 역할 |
|---|---|---|---|
| opsloop-fw | 1GB · 2 | NAT(uplink) · 서비스망 192.168.50.1 · 데이터망 192.168.60.1 · 관리망 192.168.70.254 | 내부 방화벽(nftables) 겸 부하분산(HAProxy) |
| opsloop-console-a | 1GB · 1 | 서비스망 192.168.50.11 | 관제 콘솔 |
| opsloop-console-b | 1GB · 1 | 서비스망 192.168.50.12 | 관제 콘솔 예비 (평소 꺼 둠 · 시험 · 시연 때 켬, 아래 '콘솔 B 운용') |
| opsloop-data-01 | 2GB · 2 | 데이터망 192.168.60.11 | PostgreSQL · Loki · 수집 · 탐지 |
| opsloop-web-01 | 768MB · 1 | 서비스망 192.168.50.21 | 관제 대상 서버 (nginx · sshd · 에이전트). DB 에는 닿지 않는다 |

- 관리망 192.168.70.1 은 Mac(작업자 단말)이다.
- 가상 네트워크는 DHCP 를 끄고 주소를 고정한다.
- 서비스망 · 데이터망은 호스트(Mac)에 연결하지 않는다. Mac 은 관리망으로만 들어간다.
- 연결 복제를 쓰므로 디스크는 기본 VM 한 벌 + 바뀐 부분만 차지한다.

## 순서

```bash
# 1. 가상 네트워크 3개 만들기 (비밀번호 필요)
sudo scripts/create-networks.sh

# 2. 무인 설치용 seed 이미지 만들기 (콘솔 비밀번호를 입력받는다)
scripts/make-seed.sh

# 3. 기본 VM 만들기 — Fusion 화면에서 (README 아래 "기본 VM" 참고)

# 4. 복제 4대
scripts/clone.sh

# 5. 호스트명 · 주소 · 방화벽 규칙 넣기
GUEST_PW='2번에서 정한 비밀번호' scripts/configure.sh

# 6. 검증 (네트워크 설계 4장의 표)
scripts/verify.sh

# 노드 하나 추가 (관제 대상 등). 콘솔 비밀번호를 입력받는다
scripts/add-node.sh opsloop-web-01 768 1 vmnet2 00:50:56:20:02:21 netplan/web-01.yaml 192.168.50.1 192.168.50.21

# 7. 수집 파이프라인 (데이터 노드). 설치 방법은 puller/install-ingest.sh 머리말
# 8. 내부 DB 를 Mac 으로 백업 (VERIFY=restore 면 임시 DB 복원 시험까지)
scripts/backup-db.sh
```

## 기본 VM

Fusion 에서 한 번만 만든다. 설치는 seed 이미지 덕분에 자동으로 진행된다.

1. 파일 → 새로 만들기 → **디스크 또는 이미지에서 설치**
2. `~/Downloads/ubuntu-24.04.5-live-server-arm64.iso` 선택
3. **설정 커스터마이즈** → 이름 `opsloop-base`
4. 설정에서
   - 프로세서 · 메모리: 2코어 · 2GB (복제 뒤 노드별로 바뀐다)
   - 하드 디스크: 20GB, "미리 할당" 해제
   - CD/DVD 를 하나 더 추가해 `opsloop-seed.iso` 연결
   - 네트워크 어댑터: NAT
5. 시작하면 설치가 자동으로 끝나고 재부팅된다 (약 10분)
6. 설치가 끝나면 **VM 을 끄고** 4번 단계로 간다

## 시간 동기화

내부 노드는 인터넷 시간 서버에 닿지 않는다(데이터망 · 서비스망 → 인터넷 udp 123 불허).
방화벽이 인터넷에서 받은 시각을 안쪽에 나눠 준다.

| 노드 | 설정 | 파일 |
|---|---|---|
| 방화벽 | 서비스망 · 데이터망에 시간 제공, udp 123 허용 | `fw/chrony-server.conf` → `/etc/chrony/conf.d/opsloop-server.conf` |
| 내부 노드 | 방화벽만 시간원으로, `makestep 1 -1` | `netplan/chrony-client.conf.template` → `/etc/chrony/conf.d/opsloop-fw.conf` (`__FW__` 를 각 세그먼트의 방화벽 주소로) |

`makestep 1 -1` 은 Mac 이 잠들었다 깨어나 시계가 크게 어긋나도 즉시 한 번에 맞추게 한다.
빠뜨리면 VM 시계가 몇 시간씩 앞서 S3 요청이 거부되고 미판정 경과 시간이 틀어진다 (2026-09-21 실제로 겪음).

부팅 직후에는 시계가 9시간 앞선 채 시작할 수 있다. VMware 가 가상 RTC 를 Mac 지역 시각으로 주는데 게스트는 UTC 로 읽기 때문이다.
chrony 가 몇 초 뒤 되돌리지만 그 사이 잡힌 달력 타이머(`OnCalendar`)는 다음 실행이 8시간 뒤로 밀린다 (2026-09-22 web-01 지표 끊김).
그래서 vmx 마다 `rtc.startInUTC = "TRUE"` 를 넣어 RTC 를 UTC 로 받고(clone.sh · add-node.sh 가 쓴다. 손으로 만든 VM 은 끈 상태에서 vmx 에 직접 넣는다),
주기 단위는 단조 시계(`OnBootSec` · `OnUnitActiveSec`)만 쓴다.
확인: 부팅 저널 `journalctl -b -k | grep rtc-efi` 의 시각이 그때의 `date -u` 와 같고, `journalctl -b -u chrony` 에 `System clock wrong by` 가 없어야 한다.

확인: `chronyc tracking` 의 Reference 가 방화벽이고, `docker exec opsloop-db psql ... -c "select now()"` 가 Mac 의 `date -u` 와 같아야 한다.

## 접근 경로

```
Mac(관리망 192.168.70.1)
  └─ ssh ops@192.168.70.254            # 방화벽
       └─ ssh -J ops@192.168.70.254 ops@192.168.50.11   # 콘솔 A
       └─ ssh -J ops@192.168.70.254 ops@192.168.60.11   # 데이터 노드
```

콘솔 화면은 `http://192.168.70.254:8443` 로 본다 (관리망 · VPN).

### HAProxy 통계 페이지 (이슈 #41)

통계 페이지(`8404`)는 방화벽 VM 안(`127.0.0.1:8404`)에서만 연다. 관리망 · VPN 에서 바로 열지 않는다
(`haproxy/haproxy.cfg` 의 `listen stats` · `fw/nftables.conf` input 체인의 mgmt · tailscale0 허용 포트).

- 통계 페이지는 인증이 없고 콘솔 노드 주소 · 상태를 보인다.
- 방화벽 주소(192.168.70.254)에 두면 콘솔(`:8443`)과 같은 사이트가 된다. 콘솔 쿠키(SameSite=Lax)가 딸려 가는 요청을 보낼 수 있는 출처가 하나 더 생긴다.
- 터널로 여는 `127.0.0.1` 은 콘솔과 다른 사이트다.

보는 법 (Mac. 이중화 시연 때 이렇게 연다):

```bash
ssh -F ~/.ssh/config.opsloop -L 8404:127.0.0.1:8404 fw      # 셸이 필요 없으면 -N. 보는 동안 열어 둔다
# 브라우저로 http://127.0.0.1:8404 를 연다 (5초마다 새로 고침)
#   시연: 콘솔 A 컨테이너를 멈추면 console-a 가 약 6초 안에 DOWN(VM 을 끄면 약 12초), 다시 띄우면 연속 정상 3회 뒤 UP
# 브라우저 없이 상태만 보기 (프록시 · 서버 · 상태)
ssh -F ~/.ssh/config.opsloop fw 'curl -fsS "http://127.0.0.1:8404/;csv"' | cut -d, -f1,2,18
```

휴대폰처럼 SSH 를 쓰지 못하는 VPN 단말에서는 통계 페이지를 보지 않는다. 콘솔 화면(`:8443`)은 그대로 열린다.

같은 이슈에서 콘솔 쪽도 바뀐다. 방화벽 설정은 바꾸지 않아도 된다.

- `/health` 는 세션 없이 `{"status": "ok"}` 만 준다(접속 수는 빠진다).
  HAProxy 헬스체크(`option httpchk GET /health` · `expect status 200`)는 상태 코드만 보므로 그대로 둔다.
- API 문서 화면(`/docs` · `/openapi.json`)은 기본으로 꺼진다.
  `compose/console.yml` 은 `OPSLOOP_API_DOCS` 를 넘기지 않으므로 운영 콘솔은 끈 채로 뜬다.

### 방화벽 설정 올리기 · 되돌리기

처음 구축 때 `fw/nftables.conf` 는 `scripts/configure.sh` 가 VMware Tools 로 넣는다(`/etc/nftables.conf`).
`haproxy/haproxy.cfg` 를 올리는 스크립트는 없다(패키지 기본 경로 `/etc/haproxy/haproxy.cfg`).
네트워크가 선 뒤 두 파일을 바꿀 때는 아래처럼 SSH 로 올린다. 커밋된 판만 올린다.

```bash
# 0. 배포본 확인 (Mac, 저장소 루트). 실행 중인 HAProxy 의 설정 경로(-f)와, 배포본 · 저장소 판의 차이를 본다
C=$(git rev-parse --short HEAD)
ssh -F ~/.ssh/config.opsloop fw 'pgrep -a haproxy'      # -f /etc/haproxy/haproxy.cfg
ssh -F ~/.ssh/config.opsloop fw 'cat /etc/haproxy/haproxy.cfg' | diff - <(git show "$C:infra/vmware/haproxy/haproxy.cfg")
ssh -F ~/.ssh/config.opsloop fw 'cat /etc/nftables.conf' | diff - <(git show "$C:infra/vmware/fw/nftables.conf")
#    다른 곳은 이번에 올리는 변경뿐이어야 한다. 주석만 다른 줄은 괜찮다.
#      #41: 통계 bind 한 줄 · 8404 두 줄   #43: global 의 user · group · chroot 세 줄 · frontend 의 X-Forwarded-For 두 줄
#    그 밖의 설정 줄이 다르면 배포본이 저장소 밖에서 바뀐 것이다. 덮어쓰지 말고 멈춰 어느 쪽이 맞는지 먼저 정한다.
#    web01.yml 의 구성 창(provision 집합)이 열려 있으면 끝난 뒤에 한다. nftables.conf 첫 줄 flush ruleset 이 집합을 비운다
#    flush ruleset 은 Tailscale 이 iptables-nft 로 넣은 규칙(ts-input · ts-forward · ts-postrouting)도 지운다.
#    방화벽은 50 · 60 · 70 대역을 VPN 에 광고하므로, 2번 뒤 tailscaled 를 다시 띄워 그 규칙을 되살린다

# 1. HAProxy: 문법 검사 → 이전 판을 .prev 로 → 교체 → reload (reload 는 맺은 연결을 끊지 않는다)
git show "$C:infra/vmware/haproxy/haproxy.cfg" | ssh -F ~/.ssh/config.opsloop fw 'set -e
  cat > /tmp/opsloop-haproxy.cfg
  sudo -n haproxy -c -f /tmp/opsloop-haproxy.cfg
  if sudo -n cmp -s /tmp/opsloop-haproxy.cfg /etc/haproxy/haproxy.cfg; then echo "이미 같은 판이다"; exit 0; fi
  sudo -n cp -p /etc/haproxy/haproxy.cfg /etc/haproxy/haproxy.cfg.prev
  sudo -n install -m 644 /tmp/opsloop-haproxy.cfg /etc/haproxy/haproxy.cfg
  sudo -n systemctl reload haproxy
  sleep 2; sudo -n ss -ltnp | grep haproxy'
#    기대: 127.0.0.1:8404 · 0.0.0.0:8443. 관리망 주소(192.168.70.254)의 8404 는 없어야 한다

# 2. nftables: 문법 검사 → 이전 판을 .prev 로 → 교체 → 적용 (파일 전체가 한 번에 바뀐다. 맺은 SSH 연결은 이어진다)
git show "$C:infra/vmware/fw/nftables.conf" | ssh -F ~/.ssh/config.opsloop fw 'set -e
  cat > /tmp/opsloop-nftables.conf
  sudo -n nft -c -f /tmp/opsloop-nftables.conf
  if sudo -n cmp -s /tmp/opsloop-nftables.conf /etc/nftables.conf; then echo "이미 같은 판이다"; exit 0; fi
  sudo -n cp -p /etc/nftables.conf /etc/nftables.conf.prev
  sudo -n install -m 644 /tmp/opsloop-nftables.conf /etc/nftables.conf
  sudo -n nft -f /etc/nftables.conf
  sudo -n systemctl restart tailscaled
  sleep 5; sudo -n nft list chain inet filter input | grep "tcp dport"
  sudo -n nft list ruleset 2>/dev/null | grep -c "chain ts-"; tailscale status --self --peers=false'
#    기대: mgmt · tailscale0 줄이 { 22, 8443 }, ts- 체인이 다시 있다(0 이 아니다). VPN 은 몇 초 끊겼다 이어진다
#    부팅 때는 nftables.service 가 같은 /etc/nftables.conf 를 먼저 읽고 tailscaled 가 뒤에 규칙을 더한다

# 3. 확인 (Mac). 5번 항목: 통계 페이지 방화벽 안 통과 · 관리망 직접 실패 · 콘솔 진입점 응답
infra/vmware/scripts/verify.sh
#    VPN 단말에서도 콘솔(:8443)은 열리고 :8404 는 닿지 않는지 본다
```

되돌리기는 올린 반대 순서다. `.prev` 를 다시 넣으면 통계 페이지가 관리망 · VPN 에 다시 열린다.

```bash
ssh -F ~/.ssh/config.opsloop fw 'set -e
  sudo -n nft -c -f /etc/nftables.conf.prev
  sudo -n install -m 644 /etc/nftables.conf.prev /etc/nftables.conf
  sudo -n nft -f /etc/nftables.conf
  sudo -n systemctl restart tailscaled'
ssh -F ~/.ssh/config.opsloop fw 'set -e
  sudo -n haproxy -c -f /etc/haproxy/haproxy.cfg.prev
  sudo -n install -m 644 /etc/haproxy/haproxy.cfg.prev /etc/haproxy/haproxy.cfg
  sudo -n systemctl reload haproxy
  sleep 2; sudo -n ss -ltnp | grep haproxy'
```

- `.prev` 는 1 · 2번이 실제로 파일을 바꿀 때만 만든다. 없는 쪽은 검사에서 멈추므로 건너뛴다.
- 그 뒤 다른 판을 또 올려 `.prev` 가 바뀌었으면 `.prev` 대신 1 · 2번을 `C` 를 되돌릴 커밋으로 두고 다시 돌린다.

### 출발지 주소 · 작업 프로세스 권한 (이슈 #43)

로그인 기록의 출발지가 모두 192.168.50.1(HAProxy)로 남던 것을 실제 주소로 바꾸고, HAProxy 작업 프로세스를 root 에서 내린다.

- HAProxy 진입점(`frontend console`)이 클라이언트가 보낸 `X-Forwarded-For` 를 지우고(`http-request del-header`) 자기가 본 주소 하나를 싣는다(`option forwardfor`).
- 콘솔 uvicorn 은 `FORWARDED_ALLOW_IPS`(`compose/console.yml`, 기본 `${OPSLOOP_TRUSTED_PROXY:-192.168.50.1}`)에서 온 요청의 이 헤더만 믿는다. 서비스망에서 콘솔 8000 에 닿는 곳은 호스트 가드가 이 주소 하나로 막아 두었다(`infra/ansible/files/console-guard.nft`). `*` 나 대역으로 넓히지 않는다.
- 작업 프로세스는 `haproxy` 사용자로 `/var/lib/haproxy` chroot 안에서 돈다. master 는 root 로 남아 reload 를 받는다. 로그는 chroot 안의 `/var/lib/haproxy/dev/log` 로 나간다. haproxy.service 의 `BindReadOnlyPaths=/dev/log:/var/lib/haproxy/dev/log` 가 그 자리에 journald 소켓을 붙여 두므로 지금처럼 journald → rsyslog `49-haproxy.conf` → `/var/log/haproxy.log` 로 간다(패키지 기본. 2026-09-25 방화벽에서 사용자 · 폴더 · 소켓 · haproxy 프로세스의 바인드를 읽어 확인했다).
- 순서: HAProxy 먼저(위 1번), 콘솔 compose 는 나중. 거꾸로 하면 그 사이에 클라이언트가 보낸 `X-Forwarded-For` 를 콘솔이 믿는다. HAProxy 만 먼저 올린 동안은 콘솔이 헤더를 무시해 지금처럼 192.168.50.1 로 남는다.

```bash
# HAProxy 를 올린 뒤 (위 1번). 작업 프로세스 사용자 · 로그가 이어지는지
ssh -F ~/.ssh/config.opsloop fw 'ps -o user=,args= -C haproxy'            # master 는 root, 작업 프로세스는 haproxy
ssh -F ~/.ssh/config.opsloop fw 'sudo -n tail -n 3 /var/log/haproxy.log'  # reload 뒤 요청 줄이 계속 쌓인다
# 콘솔마다 compose 를 옮기고 다시 띄운다 (이미지는 그대로. 컨테이너를 다시 만들므로 B 가 꺼져 있으면 몇 초 끊긴다)
ssh -F ~/.ssh/config.opsloop console-a 'cp -p ~/opsloop/console.yml ~/opsloop/console.yml.prev && cat > ~/opsloop/console.yml' \
  < infra/vmware/compose/console.yml
ssh -F ~/.ssh/config.opsloop console-a 'cd ~/opsloop && docker compose -f console.yml up -d'
ssh -F ~/.ssh/config.opsloop console-a 'docker exec opsloop-api printenv FORWARDED_ALLOW_IPS'   # 192.168.50.1
#    확인: 로그인한 뒤 감사 화면의 로그인 기록 출발지가 Mac 은 192.168.70.1, VPN 단말은 100.x 로 남는다
```

되돌리기: HAProxy 는 위 되돌리기 절차(`.prev`), 콘솔은 `console.yml.prev` 를 다시 넣고 `up -d`. 콘솔을 먼저 되돌린다.

## 콘솔 B 운용 (이슈 #43)

콘솔 B(`opsloop-console-b`, 192.168.50.12)는 평소 꺼 둔다. 이중화 시험 · 시연 때만 켜서 HAProxy 분배에 넣고, 끝나면 뺀 뒤 끈다.
켜 두면 A 와 함께 요청을 받는다(roundrobin). 두 대는 상태를 갖지 않고 같은 DB · 같은 `SESSION_SECRET` 을 쓴다.

- 단계는 `scripts/console-join.sh` 가 함수로 갖고 있다. 기본은 드라이런(명령만 찍고 원격 · VM 에 아무것도 하지 않는다)이고 `--apply` 로 돌린다. `--step <이름>` 은 한 단계만, `--from <이름>` 은 그 단계부터 끝까지. 실패한 단계에서 멈춘다.
- HAProxy 상태는 방화벽의 master 소켓(`/run/haproxy-master.sock`, systemd 단위의 `-S`)으로 바꾼다. `@1` 은 지금 작업 프로세스다.
- **reload 하면 maint · drain 이 풀린다.** 런타임 상태를 파일로 남기지 않으므로 reload 뒤 console-b 는 헬스체크만 보고 다시 들어온다. 합류 · 떼기 중에는 `systemctl reload haproxy` 를 하지 않는다. 했으면 상태를 다시 읽고 maint 를 다시 건다.
- 떼기에서 컨테이너를 `restart=no` 로 멈춰 두므로, VM 만 켜져도 콘솔이 뜨지 않아 헬스체크에서 빠진다. 합류의 `stop-old` 는 그렇지 않은 옛 컨테이너(restart: always 라 부팅과 함께 뜬다)를 멈춘다.
- B 가 켜져 서비스 중일 때 `db-console-role.sh` 를 돌리면 비밀번호가 바뀐다. 그때는 `console-a console-b` 둘 다 적는다.

master 소켓 명령 (방화벽. 읽기는 언제든, 상태 바꾸기는 아래 절차 안에서만):

```bash
ssh -F ~/.ssh/config.opsloop fw 'echo "@1 show servers state consoles" | sudo -n nc -N -U /run/haproxy-master.sock'
#   서버 줄 6번째 열 = 운영 상태(0 멈춤 · 1 slowstart 30초 동안 · 2 동작), 7번째 열 = 관리 상태(0 정상 · 1 maint · 8 drain)
#   maint 와 drain 은 서로를 푼다(HAProxy 2.8 srv_adm_set_maint · srv_adm_set_drain). drain 을 걸면 maint 가 풀리고 헬스체크가 다시 돈다
ssh -F ~/.ssh/config.opsloop fw 'echo "@1 set server consoles/console-b state maint" | sudo -n nc -N -U /run/haproxy-master.sock'
#   state ready · state drain 도 같은 꼴. 성공하면 빈 줄만 돌아온다
```

켜는 절차 (Mac, 저장소 루트. 첫 열은 `console-join.sh` 단계 이름):

| 단계 | 하는 일 |
|---|---|
| `precheck` | A /health 200 · `opsloop_console` 접속 한도 30 이상(`infra/migrations/20260926_console_connlimit.sql` 을 먼저 적용한다. 두 대 22 + triage.py) · HAProxy 상태 · VM 상태 |
| `maint` | HAProxy console-b → maint. VM 이 켜지는 동안 요청이 가지 않게 |
| `vm-start` | `vmrun start <vmx> nogui` · SSH 응답 대기. console-b 가 maint 가 아니면 멈춘다 |
| `stop-old` | 옛 컨테이너를 `docker update --restart=no` 로 바꾸고 멈춘다. 옛 이미지 · 옛 `.env` 의 발송기가 돌지 않게 |
| `chrony` | `netplan/chrony-client.conf.template`(add-node.sh 와 같은 설정: 시간원 192.168.50.1 · `makestep 1 -1`, pool 줄 주석) · `chronyc waitsync`. 시계가 틀리면 다음 단계의 HTTPS 가 실패한다 |
| `upgrade` | `apt-get full-upgrade` · 재부팅 · 부팅 id 가 바뀐 뒤 SSH 응답 · 옛 컨테이너가 멈춘 채인지 |
| `guard` | 호스트 가드 `ansible-playbook consoles.yml --limit console-b` 두 번. 두 번째가 changed=0 |
| `image` | A 의 `docker save opsloop-api:latest \| gzip -1` → B 의 `docker load`. 이미지 ID 가 같은지 |
| `env` | `.env` 동기화. `SESSION_SECRET` · `OPSLOOP_CONSOLE_DB_PASSWORD` 두 줄만 A → B ssh 파이프로 옮긴다(Mac 화면 · 파일 · 명령행에 남지 않는다). POSTGRES_PASSWORD 는 옮기지 않는다. `OPSLOOP_WORKER=opsloop-console-b` · 0600. 두 줄을 받지 못하면 파일을 바꾸지 않는다 |
| `up` | A 의 `console.yml` 을 옮기고(`console.yml.prev` 남김) `docker compose up -d --no-build --force-recreate` · B /health 200 |
| `verify` | 이미지 ID · `console.yml` 해시 · 비밀값 두 줄의 해시가 A 와 같은지(해시도 찍지 않는다) · 재시작 정책 always · 발송기 이름 · DB 역할 `opsloop_console` · 방화벽에서 B /health · 역할 접속 수 / 한도 |
| `ready` | HAProxy console-b → ready. UP(운영 2 · 관리 0)이 될 때까지(rise 3 × 2초, 그 뒤 slowstart 30초 동안 가중치가 오른다) |
| `assets` | `scripts/collect-assets.sh --only console-b` (자산 · 취약점 화면의 B 정보를 새로) |

```bash
infra/vmware/scripts/console-join.sh                        # 드라이런: 단계별 명령을 본다
infra/vmware/scripts/console-join.sh --apply                # 실패하면 고친 뒤 --from <그 단계> --apply
```

끄는 절차:

| 단계 | 하는 일 |
|---|---|
| `drain` | console-b → drain. 새 요청은 A 로만. B 의 연결 수가 0 이 되거나 60초(30번 × 2초)까지 기다린다. 웹소켓은 남을 수 있다. `stop` 에서 끊기면 화면이 A 로 다시 붙는다 |
| `maint` | console-b → maint |
| `stop` | 컨테이너 `restart=no` · 멈춤. console-b 가 maint 가 아니면 멈춘다 |
| `vm-stop` | `vmrun stop <vmx> soft` · 꺼질 때까지. console-b 가 maint 가 아니면 멈춘다 |
| `state` | HAProxy 상태 (console-b 운영 0 · 관리 1. 앞의 maint 가 drain 을 풀었다) |

```bash
infra/vmware/scripts/console-join.sh --leave                # 드라이런
infra/vmware/scripts/console-join.sh --leave --apply
```

### 실시간 통보 점검 (이슈 #43)

콘솔마다 LISTEN 연결 하나로 `opsloop_incident`(사건) · `opsloop_event`(판정 · 조치)를 듣는다. 그래서 콘솔 A 에서 한 판정도 콘솔 B 화면에 간다.
서버가 연결을 끊으면 곧바로, 망이 조용히 끊기면 15초마다 보내는 `SELECT 1`(5초 한도)로 끊김을 안다. 그 뒤 1초 → 2배 → 최대 30초 간격으로 다시 붙고,
붙으면 화면에 `resync` 를 보내 목록을 전부 다시 받게 한다. 이 상태는 `/health` 에 넣지 않았다(DB 가 잠깐 흔들려도 두 콘솔이 함께 빠지지 않게). 로그로 본다.

```bash
ssh -F ~/.ssh/config.opsloop console-a "docker logs opsloop-api 2>&1 | grep '실시간 통보: LISTEN'"   # 끊김 · N회째 실패 · 다시 붙음
```

- 발송기 경고 'OPSLOOP_WORKER 가 비어…' · '같은 이름(…)의 다른 발송기가 살아 있을 수 있습니다' 가 보이면 `.env` 의 `OPSLOOP_WORKER` 를 콘솔마다 다르게 준다.
- 어느 콘솔이 답했는지는 로그인한 뒤 `/api/me` 의 `console` 값, 화면 상단 연결 표시(웹소켓이 붙은 콘솔)로 본다. 응답 헤더에는 내지 않는다(이슈 #41).

## 콘솔 장애 주입 시험 (이슈 #43)

콘솔 한 대가 죽었을 때 다른 콘솔로 넘어가는 시간과 세션이 유지되는지를 잰다. 도구는 `infra/vmware/failover/` 에 있고 표준 라이브러리만 쓴다. 사용법은 각 파일 머리 주석에 있다.
도구가 운영에서 하는 일은 읽기뿐이다(HTTP · 웹소켓 요청, 방화벽 통계 · 로그 읽기). 주입 명령은 도구가 돌리지 않는다. 사람이 승인한 뒤 `mark.py` 바로 다음에 돌린다.

| 파일 | 하는 일 | 쓰는 파일(회차 폴더) |
|---|---|---|
| `probe_http.py` | 100ms 열린 루프로 `/health?p=<회차>-<번호>` · `/api/me`(쿠키 · 응답 콘솔 이름 기록)를 보낸다. 한도 70초 | `http.jsonl` |
| `probe_ws.py` | 최소 웹소켓 클라이언트. browser(live.ts 와 같은 백오프, 핑 없음) · net(1초 핑, 2초 안에 퐁이 없으면 끊김) | `ws.jsonl` |
| `collect_fw.sh` | 방화벽 통계(127.0.0.1:8404 CSV)의 consoles 행을 0.5초마다 읽는다. 끝나면 haproxy.log 에서 시험 동안의 부분을 발췌한다 | `fw.csv` · `fw-meta.json` · `fw-haproxy.log` |
| `mark.py` | 주입 · 복귀 직전의 T0 를 원격 시각과 Mac 시각으로 남긴다. `--list` 는 시나리오별 명령 | `marks.jsonl` |
| `summarize.py` | 감지 · 실패 구간 · 지연 · 전환 완료 · 좀비 · 재연결 · 401 · 복귀를 계산한다. 여러 회차는 중앙값 · 최댓값으로 묶는다 | `results.json` · `sha256.json` |

프로브 쿠키: `python3 infra/vmware/failover/probe_http.py --mint-cookie console-a` 를 돌리면 콘솔 A 컨테이너 안에서 `auth.issue("failover-probe", "viewer")` 를 부른다. 비밀번호 없이 서버 비밀로 발급한 viewer 12시간 쿠키다. 이 쿠키는 `~/.config/opsloop/probe-cookie`(0600)에만 두고 화면 · 로그에는 찍지 않는다. 시험 뒤 `--drop-cookie` 로 지운다.

회차 하나 (콘솔 B 를 켠 뒤. 터미널 넷, 저장소 루트, `R=~/opsloop-failover/r01-stop-a`):

```bash
infra/vmware/failover/collect_fw.sh $R --duration 300
python3 infra/vmware/failover/probe_http.py --run-dir $R --duration 300
python3 infra/vmware/failover/probe_ws.py --run-dir $R --mode browser --conns 4 --duration 300
python3 infra/vmware/failover/probe_ws.py --run-dir $R --mode net --conns 4 --duration 300
# 기준선 30초 뒤 (주입은 승인 뒤 사람이)
python3 infra/vmware/failover/mark.py $R inject --scenario stop --target console-a && ssh -F ~/.ssh/config.opsloop console-a 'docker stop opsloop-api'
# 150초 뒤 (좀비 감지 창 120초를 넘긴 뒤)
python3 infra/vmware/failover/mark.py $R recover --scenario stop --target console-a && ssh -F ~/.ssh/config.opsloop console-a 'docker start opsloop-api'
# 모든 회차가 끝나면
python3 infra/vmware/failover/summarize.py ~/opsloop-failover --out docs/evidence/<날짜>-failover
python3 infra/vmware/failover/probe_http.py --drop-cookie
```

합격선: 전환 ≤ 30초이고 401 = 0 이어야 한다. 전환은 감지와 실패 구간 끝 가운데 늦은 쪽이다. 대상 시나리오는 stop · kill · vm-off 이다. 마지막 실패 뒤 성공이 20번 넘게 이어지지 않으면 전환을 확인하지 못한 것으로 보고 불합격이다. net-cut · db-cut · drain 은 관찰 시나리오라 같은 표에 참고로만 남긴다.

## 데이터베이스 역할 (이슈 #31)

구성요소마다 최소 권한 역할로 붙는다. 소유자 `opsloop` 는 스키마 적용 · `nodes.py` · `auth.py add` 에만 쓴다.
권한은 `infra/schema.sql` 끝의 역할 블록이 주고(역할이 있을 때만, 여러 번 적용해도 같다), 역할과 비밀번호는 아래 스크립트가 만든다.

| 역할 | 쓰는 곳 | 접속 파일 | 할 수 있는 것 |
|---|---|---|---|
| `opsloop_gate` | 수집 관문 | 데이터 노드 `/etc/opsloop/gate.env` | nodes 네 열 읽기 · `enroll_node` |
| `opsloop_ingest` | 다리(pull_loki) · 파서 | `/etc/opsloop/collector.env` | events · sessions · node_metrics 적재, nodes 수신 기록 |
| `opsloop_detector` | 탐지기(detect.py) | `/etc/opsloop/detector.env` | 규칙 입력 읽기, incidents 생성 · 억제 · 이어지는 사건 갱신(끝 시각 · 건수 · 근거 네 열), detector_runs |
| `opsloop_console` | 콘솔 API · triage.py | 콘솔 `~/opsloop/.env` · 데이터 노드 `/etc/opsloop/triage.env` | 판정 · 조치 · 차단 · 등록 토큰 · 감사 · 로그인 기록 · CTI 표 읽기. 토큰 해시 · 계정 역할은 못 본다/못 고친다 |
| `opsloop_cti` | CTI 수집기(`opsloop-cti`: 공개 정보 갱신 · 자산 적재, 이슈 #39) | `/etc/opsloop/cti.env` | 공개 정보 · 자산 표(`cti_*` · `asset_*`) 쓰기(`cti_snapshots` 는 추가만), `rule_versions` 읽기. 이벤트 · 사건 · 판정은 못 본다 |
| `opsloop_backup` | `backup-db.sh` 의 pg_dump | 없음 (컨테이너 안 로컬 접속) | 읽기 전부 |
| `opsloop` (소유자) | 스키마 · `nodes.py` · `auth.py add` | `/etc/opsloop/admin.env` (root 만) · compose `.env` | 전부 |

절차 (Mac, 저장소 루트):

```bash
# 1. 데이터 노드: 코드 · 역할 · 접속 파일 · 스키마. collector.env 가 소유자였으면 .prev 로 옮기고 적재 역할로 새로 만든다
C=$(git rev-parse --short HEAD)
git archive "$C" collector parser detector puller infra | ssh -F ~/.ssh/config.opsloop data01 \
  "rm -rf /tmp/ol && mkdir /tmp/ol && tar -x -C /tmp/ol && sudo bash /tmp/ol/puller/install-ingest.sh $C && sudo bash /tmp/ol/collector/install-collector.sh $C"
# 2. 콘솔 역할 비밀번호 → DB · 콘솔 .env · triage.env, API 컨테이너 재기동 (비밀번호는 화면에 안 나온다)
infra/vmware/scripts/db-console-role.sh console-a
# 3. 검증: 역할별 거부 · 허용, 실제 접속 역할, web-01 에서 5432 차단
infra/vmware/scripts/verify-db-roles.sh
```

- 계정 추가 · 역할 변경은 콘솔 역할로는 안 된다. 콘솔 노드에서 소유자 접속으로 돌린다:
  `docker exec -it -e DATABASE_URL="postgresql://opsloop:<compose .env 의 POSTGRES_PASSWORD>@192.168.60.11:5432/opsloop" opsloop-api python3 auth.py add <아이디> <역할>`
- `detector/triage.py` 는 `set -a; . /etc/opsloop/triage.env; set +a` 뒤에 돌린다 (콘솔 역할).
- 흡수 기록(`incident_absorbed`, 규칙 v3)을 읽는 콘솔 · triage 를 올리기 전에 `infra/migrations/20260925_round2.sql` 다음 `20260925_v3_absorbed.sql` 을 먼저 적용한다(흡수 기록 · 후속 차단 약속 `absorbed_blocks` 표). 표가 없으면 사건 상세와 triage 가 오류로 멈춘다. 알림 트리거 `infra/notify.sql` 도 다시 적용한다(`psql -1`).
- 적재기는 규칙 파일을 `OPSLOOP_RULES`(기본 `rules_v3.json`, `/etc/default/opsloop-ingest` 로 바꾼다)로 탐지에 넘긴다. `puller/install-ingest.sh` 는 흡수 기록 표 · 탐지 역할 쓰기 권한이 없으면 코드를 바꾸지 않고 멈춘다. 전환은 다음 회차 뒤 `detector_runs` 의 최근 버전으로 확인한다.
- 소유자로 붙는 서비스가 남아 있는지는 `verify-db-roles.sh` 의 pg_stat_activity 항목이 알려 준다.
- 콘솔 역할의 접속 한도는 30 이다(이슈 #43. 콘솔 한 대 = 풀 10 + LISTEN 1, 두 대 22 + triage.py 가 같은 역할).
  `db-console-role.sh` · `install-collector.sh` 는 30 으로 만들고, 이미 있는 역할은 마이그레이션으로 올린다(역할이 있을 때만 바꾸고
  여러 번 적용해도 같다. 붙어 있는 접속은 끊기지 않는다). `verify-db-roles.sh` 가 30 이상인지 본다. 콘솔 B 를 켜기 전에 한다.
  `ssh -F ~/.ssh/config.opsloop data01 'sudo -n docker exec -i opsloop-db psql -U opsloop -d opsloop -v ON_ERROR_STOP=1 -q' < infra/migrations/20260926_console_connlimit.sql`

## 알림 발송 경로

알림 발송기는 따로 띄우는 프로세스가 아니라 콘솔 API 안에서 돈다. 콘솔 → 채널 주소(Microsoft Teams Workflows 웹훅 · 일반 웹훅) 방향으로만 나가고, 밖에서 콘솔로 들어오는 경로는 없다.
방화벽은 지금 콘솔 → 인터넷 443 을 전체 허용하므로(`fw/nftables.conf` 59행) 채널을 추가해도 규칙을 바꿀 일이 없다. 등록된 채널 주소만 허용하도록 좁히는 것은 후속이다.
Teams 쪽 준비: Power Automate 에서 "Teams 웹훅 요청을 받으면 채널에 게시" 흐름을 만들고, 거기서 나온 주소(https · 호스트 `*.environment.api.powerplatform.com`)를 콘솔 알림 화면에 입력한다. 옛 `*.logic.azure.com` 주소는 2025-11-30 부터 동작하지 않고 Office 365 커넥터(`*.webhook.office.com`)도 없어져 받지 않는다. 옛 주소만 있으면 흐름을 다시 저장해 새 주소를 받는다. 콘솔은 Adaptive Card 로 보내고 2xx(보통 202) 응답을 성공으로 본다. 일반 웹훅도 https 만 받고 사설 · 링크로컬 · localhost 등 공인 인터넷이 아닌 IP 와 줄임 · 16진 IP 표기는 거부한다.
메시지 틀: 채널마다 머리말 · 항목 한 줄을 두고 자리표시자 `{event_label}` `{count}` `{severity_counts}` `{rule_id}` `{rule_name}` `{severity}` `{who}` `{elapsed}` `{first_ts}` `{incident_key}` `{link}` 만 문자 치환한다(형식 지정자 없음, 모르는 자리표시자는 그대로, 빈 값은 `-`). 원문 로그 · 입력된 비밀번호 · 내부 주소는 본문에 넣지 않는다.
알림 본문의 콘솔 링크 기준 주소는 콘솔 서비스의 환경변수 `OPSLOOP_CONSOLE_URL` 로 정한다(기본 `http://192.168.70.254:8443`).
배포 순서: 새 콘솔 이미지를 올리기 전에 `infra/migrations/20260924_notify.sql` 을 먼저 적용한다. 표가 없으면 알림만 멈추고 콘솔의 다른 기능은 뜬다.
콘솔 VM 마다 compose `.env` 에 `OPSLOOP_WORKER=opsloop-console-a`(B 는 `-b`)를 둔다. 발송기가 집은 알림을 이 이름으로 표시하므로, 재기동 때 자기가 보내던 알림을 바로 되찾는다.

### 콘솔 진입점 감시 (Mac, 이슈 #43)

알림 발송기는 콘솔 안에서 돈다. 그래서 콘솔 두 대가 다 죽거나 DB 가 멈춰 `/health` 가 실패하면 알릴 경로가 없다.
Mac 의 launchd(`local.opsloop.console-watch`)가 60초마다 진입점 `http://192.168.70.254:8443/health` 를 5초 간격으로 최대 3번 본다(curl -m 3).
3번 모두 실패하면 DOWN 이다. UP→DOWN 에 한 번, DOWN 이 이어지면 30분마다 다시, DOWN→UP 에 복구를 한 번 알린다.
알림은 macOS 알림과 기록 `~/Library/Logs/opsloop/console-watch.log` 에 남는다.

```bash
infra/vmware/scripts/install-console-watch.sh            # 설치 · 갱신 (다시 실행해도 된다). --uninstall 로 내린다
S="$HOME/Library/Application Support/OpsLoop/bin/console-watch.sh"
"$S" --status                                             # 마지막 상태 · 점검 창 · 웹훅 설정 여부 (주소는 내지 않는다)
"$S" --test-alert                                         # 알림 경로 시험
"$S" --pause 120                                          # 점검 창 2시간. --resume 로 없앤다
```

- 웹훅(선택): `~/.config/opsloop/console-watch.env` 에 `WEBHOOK_URL=https://...` 한 줄을 둔다. 권한이 0600 이 아니거나 본인 소유가 아니면 쓰지 않는다.
  주소를 복사한 뒤 화면에 찍지 않고 넣는다: `( umask 077; mkdir -p ~/.config/opsloop; printf 'WEBHOOK_URL=%s\n' "$(pbpaste)" > ~/.config/opsloop/console-watch.env )`
  본문은 `{"text": "..."}` 하나다. Teams Workflows 는 이 `text` 를 게시하는 흐름을 따로 만든다. 콘솔 알림 채널과 따로 두는 경로다(콘솔이 죽었을 때 쓴다).
  주소는 기록 · 화면 · 명령줄에 남지 않고, 본문에는 내부 주소를 넣지 않는다.
- 점검 창(`--pause`)에는 알리지 않고 상태만 적는다. 창 안에서 시작된 DOWN 이 창이 끝난 뒤에도 이어지면 그때 알린다.
  VM 을 일부러 끄거나 장애 주입 시험을 할 때 둔다.
- Mac 이 잠든 동안은 돌지 않는다(VM 도 함께 멈춘다). 깨어나면 다음 간격에 다시 본다.
- 시험: `python3 infra/vmware/scripts/test_console_watch.py` (임시 HOME · 가짜 curl · osascript · launchctl, 진짜 curl 은 127.0.0.1 에만)

## CVE · KEV 연계 (이슈 #39)

공개 취약점 정보(CISA KEV · EPSS · 배포판 취약점 OSV · NVD)와 노드 자산 조사 결과를 사건 옆에 붙여 보인다.
판정값이 아니라 조사 우선순위 정보다(`docs/2026-09-08-판정-기준.md` §8). 원본은 S3 `cti/` 에 한 번만 쓰고,
원본을 남기지 못한 회차는 DB 도 갱신하지 않는다(`infra/terraform/README.md` 'CTI 원본 보관').

```
데이터 노드  opsloop-cti.timer (하루 1회) ─ KEV · EPSS · OSV · NVD 받기 ─→ S3 cti/ (원본) ─→ DB cti_*
Mac          collect-assets.sh (매일 05:10) ─ 노드마다 cti/probe.py ─→ data01 opsloop-cti load-assets ─→ S3 cti/ ─→ DB asset_*
콘솔 API     DB 읽기 ─→ 사건 상세 '취약점 연계' 구역 · 자산 · 취약점 화면(/inventory, 맨 위 '주목 CVE' 표)
```

| 구성 | 위치 |
|---|---|
| 수집기 | 데이터 노드 `/opt/opsloop/cti` (root 소유. `install-ingest.sh` 의 앱 폴더 교체와 따로 둔다) · 실행 래퍼 `/usr/local/bin/opsloop-cti` (`fetch` · `load-assets` · `status`) |
| 주기 | `opsloop-cti.timer` 부팅 15분 뒤 · 하루 간격 · 무작위 30분. 달력 타이머는 쓰지 않는다(위 '시간 동기화') |
| 설정 | `/etc/default/opsloop-cti` (비밀 아님. 처음 설치 때만 만든다) · 상태 폴더 `/var/lib/opsloop-cti` |
| 비밀 | `/etc/opsloop/cti.env` (DB 역할 `opsloop_cti`, 설치기가 만든다) · `/etc/opsloop/s3-cti.env` (S3 쓰기 사용자 키, Mac 에서 파이프로 넣는다). 둘 다 0640 root:opsloop-cti 이고 셸로 읽지 않는다 |
| 자산 수집 | Mac `scripts/collect-assets.sh` (SSH 다섯 대 · SSM 두 대) · `scripts/install-assets-agent.sh` (launchd `local.opsloop.assets`, 기록 `~/opsloop-assets/assets.log`) |
| 주목 CVE 목록 | 저장소 `cti/watchlist.json` → 설치기가 `/opt/opsloop/cti/watchlist.json` 으로 함께 둔다 (아래 '주목 CVE 목록 바꾸기') |
| 탐지 규칙 | `detector/rules_cve.json`(c1: R105 제품 식별 탐색 · R106 알려진 취약점 공격 시도). 1분 다리(`opsloop-agents`)가 s1 · w2 · a1 · i2 다음에 돌린다 |
| 화면 | 사건 상세 '취약점 연계' 구역(R105 · R106 사건에만) · 자산 · 취약점 화면 `/inventory` (사이드 메뉴 '자산 · 취약점') |

설치 순서 (Mac, 저장소 루트):

```bash
# 1. S3 cti/ 경계 · 쓰기 사용자: infra/terraform/README.md 'CTI 원본 보관' 1단계 (plan 기대값을 확인한 뒤 apply)
# 2. 탐지 규칙 c1 (detector/rules_cve.json · detect.py 의 url_signature · pull_loki.py 의 c1 레그): 같은 커밋으로
#    install-ingest.sh 를 먼저, install-collector.sh 를 다음에 (위 '데이터베이스 역할' 절 1번과 같은 명령).
#    install-ingest.sh 가 앱 폴더(detector 포함)를 바꾸고 install-collector.sh 가 다리와 스키마(CTI 절 포함)를 올린다.
#    거꾸로 올리면 새 다리가 옛 detect.py 로 c1 을 돌려 매 회차 실패(종료 1)로 끝난다 (install-collector.sh 가
#    'url_signature 를 모른다' 경고를 낸다). 3번 설치기도 이 둘이 만든 /etc/opsloop · rule_versions 표를 먼저 본다
C=$(git rev-parse --short HEAD)
git archive "$C" collector parser detector puller infra | ssh -F ~/.ssh/config.opsloop data01 \
  "rm -rf /tmp/ol && mkdir /tmp/ol && tar -x -C /tmp/ol && sudo bash /tmp/ol/puller/install-ingest.sh $C && sudo bash /tmp/ol/collector/install-collector.sh $C"
#    확인 (1 ~ 2분 뒤): 탐지 실행 기록에 c1 이 있고, 다리 기록에 '탐지 실패 rules_cve.json' 이 없다
ssh -F ~/.ssh/config.opsloop data01 'sudo -n docker exec opsloop-db psql -U opsloop -d opsloop -Atc "SELECT rule_version, max(started_at) FROM detector_runs GROUP BY 1 ORDER BY 2 DESC LIMIT 8"'
ssh -F ~/.ssh/config.opsloop data01 'sudo -n journalctl -u opsloop-agents --since -5min --no-pager | grep -c "탐지 실패"'   # 0
#    c1 이 rule_versions 에 들어가야 수집기가 서명 CVE 를 EPSS · NVD 관심 집합에 넣는다. 그래서 수집기 첫 회차(5번)보다 먼저 한다
# 3. 데이터 노드: 사용자 · 코드 · 주목 CVE 목록 · 설정 · 접속 파일 · DB 역할 · 마이그레이션(20260925_cti.sql) · 단위 (타이머는 켜지 않는다)
git archive "$C" cti infra/migrations/20260925_cti.sql | ssh -F ~/.ssh/config.opsloop data01 \
  "rm -rf /tmp/ol && mkdir /tmp/ol && tar -x -C /tmp/ol && sudo bash /tmp/ol/cti/install-cti.sh $C"
# 4. S3 쓰기 키 · 검증: infra/terraform/README.md 'CTI 원본 보관' 2 · 3단계 (3번이 만든 opsloop-cti 그룹이 있어야 키를 넣을 수 있다)
# 5. 한 번 돌려 확인한다. 끝날 때까지 기다린다 (NVD 는 요청 사이 6.5초를 쉰다. 상한 1시간)
ssh -F ~/.ssh/config.opsloop data01 'sudo -n systemctl start opsloop-cti.service; sudo -n journalctl -u opsloop-cti -n 60 --no-pager'
ssh -F ~/.ssh/config.opsloop data01 'sudo -n -u opsloop-cti /usr/local/bin/opsloop-cti status'
#    출처별 마지막 성공 시각을 본다. 실패한 출처는 cti_snapshots 의 error 에 이유가 남고 그 출처의 DB 는 바뀌지 않는다
# 6. 타이머를 켠다 (부팅 15분이 이미 지났으므로 30분 안에 한 번 더 돈다. 같은 원본은 412 로 끝나 겹치지 않는다)
ssh -F ~/.ssh/config.opsloop data01 'sudo -n systemctl enable --now opsloop-cti.timer'
# 7. 자산 수집: 보내지 않고 묶음 · 요약만 본 뒤 적재하고, 매일 돌게 올린다
infra/vmware/scripts/collect-assets.sh --dry-run > /dev/null
infra/vmware/scripts/collect-assets.sh
infra/vmware/scripts/install-assets-agent.sh
# 8. 콘솔 이미지 갱신 (app/cti.py · 화면). 3번의 마이그레이션이 먼저 들어가 있어야 한다.
#    확인: 사이드 메뉴 '자산 · 취약점'(/inventory) 맨 위 '주목 CVE' 표와 자산 표, R105 · R106 사건 상세의 '취약점 연계' 구역
```

- 적재기는 받은 자산의 배포판 대조(OSV)를 바로 한다. 자산 CVE 의 NVD 정보는 다음 회차에 채워진다.
- **AWS 두 대(gateway · honeypot-dmz)는 로그인 뒤 손으로 돌린다.** launchd 안에서는 AWS 로그인이 대개 만료돼 있어
  빠진다. `aws login` 뒤 `infra/vmware/scripts/collect-assets.sh --only gateway,honeypot-dmz --aws`. 빠진 날은 옛
  결과가 남고, 48시간이 지나면 콘솔에 '정보 오래됨'(해당 여부 미확인)으로 보인다.
- 평소 꺼 둔 console-b 는 연결 실패로 보내져 옛 결과를 두고 시도 기록만 고친다(종료 코드 1, 알림 없음).
- **`20260924_db_roles.sql` 을 다시 적용하면 `20260925_cti.sql` 도 다시 적용한다.** `20260924_db_roles.sql` 은 콘솔
  역할의 표 권한을 먼저 모두 거두고 정해 둔 표만 다시 주므로 콘솔의 CTI 표 읽기가 사라진다(콘솔 API 의 취약점 연계 ·
  자산 조회가 권한 오류로 멈춘다). 수집기 역할(`opsloop_cti`)의 권한은 거두지 않는다. `20260925_round2.sql` 은 탐지
  역할만 거두고 `20260925_v3_absorbed.sql` 은 권한을 거두지 않으므로 CTI 권한과 무관하다. `opsloop_cti` 의 권한을
  거두는 곳은 `20260925_cti.sql` 과 `infra/schema.sql` 의 CTI 절뿐이고 둘 다 거둔 뒤 곧바로 다시 준다.
  `20260925_cti.sql` 은 여러 번 적용해도 같다. `install-collector.sh` 는 `infra/schema.sql` 전체(끝에 같은 CTI 절이
  있다)를 적용하므로 따로 할 일이 없다.

```bash
ssh -F ~/.ssh/config.opsloop data01 'sudo -n docker exec -i opsloop-db psql -U opsloop -d opsloop -v ON_ERROR_STOP=1 -q' \
  < infra/migrations/20260925_cti.sql
infra/vmware/scripts/verify-db-roles.sh     # opsloop_cti 와 콘솔 역할의 CTI 표 권한까지 본다
```

- 콘솔: CTI 표가 없으면 API 가 `available: false` 로 답해 취약점 연계 구역 · 자산 화면만 비고 다른 기능은 그대로 뜬다.

### 주목 CVE 목록 바꾸기

주목 CVE 는 자산에 걸리지 않은(이미 고친) 널리 알려진 CVE 도 자산마다 설치 버전과 배포판(Ubuntu) 수정판을 비교해
보이려고 정해 둔 목록이다(`docs/2026-09-08-판정-기준.md` §8 '주목 CVE'). 수집기 `fetch` 의 osv 단계가 하루 한 번
CVE 마다 `UBUNTU-<CVE>` 기록을 받아 `cti_watch` 를 목록과 같게 맞추고, 콘솔 자산 · 취약점 화면(`/inventory`) 맨 위
'주목 CVE' 표가 자산별 판정(해당 · 비해당 · 미확인)을 보인다. 데이터 노드의 사본 `/opt/opsloop/cti/watchlist.json` 은
설치기가 코드 폴더와 함께 통째로 바꾸므로 거기서 직접 고치지 않는다.

1. 저장소의 `cti/watchlist.json` 을 고치고 커밋한다. 항목은 `{"cve": "CVE-YYYY-NNNN", "reason": "…"}` 이고 이유는
   200자 이하, 중복 없이 50개 이하다. 목록에서 뺀 CVE 는 다음 fetch 가 `cti_watch` 에서 지운다.
2. 같은 커밋으로 `install-cti.sh` 를 다시 돌린다(위 설치 순서 3번 명령). 설치기는 목록을 실행기의 검증 함수로 먼저
   보고, 틀리면 코드를 바꾸지 않고 멈춘다. 이미 있는 역할 · 비밀번호 · 설정 · 키는 그대로 두고 타이머 상태도 바꾸지 않는다.
3. 다음 fetch 에 반영된다(타이머, 하루 한 번). 바로 보려면 osv · nvd 만 돌린다. osv 단계가 기록을 받고 EPSS 는
   마지막 EPSS 사본에서 채우며, NVD 는 주목 CVE 를 맨 앞에 받는다(요청 사이 6.5초).

```bash
ssh -F ~/.ssh/config.opsloop data01 'sudo -n -u opsloop-cti /usr/local/bin/opsloop-cti fetch --only osv,nvd'
ssh -F ~/.ssh/config.opsloop data01 'sudo -n -u opsloop-cti /usr/local/bin/opsloop-cti status'
#    '주목 CVE' 줄마다 기록 있음(UBUNTU-…) · 배포판 기록 없음 · 조회 전 과 조회 시각이 나온다
```

- OSV 에 `UBUNTU-<CVE>` 기록이 없는(404) CVE 는 화면에 미확인('배포판(Ubuntu) 기록이 없다')으로 보인다. 비해당으로
  읽지 않는다. 기록은 있는데 이 릴리스(Ubuntu 24.04)의 영향 항목이 없는 CVE(2026-09-25 조회로 CVE-2021-4034 ·
  CVE-2021-3156)는 비해당('배포판 기록에 이 릴리스(…)의 영향 패키지가 없다')이다.
- 타이머 회차가 돌고 있으면 끝날 때까지 기다린다(20분이 넘으면 종료 1). 그때는 타이머 회차가 끝난 뒤 다시 돌린다.

## 파일

| 경로 | 내용 |
|---|---|
| `seed/user-data.template` | 무인 설치 정의. 비밀번호 해시와 공개 키는 만들 때 채운다 |
| `netplan/*.yaml` | 노드별 고정 주소 |
| `fw/nftables.conf` | 내부 방화벽 규칙 (설계 3.2 규칙표) |
| `haproxy/haproxy.cfg` | 콘솔 분배 · 헬스체크 2초 × 3회 · 통계 페이지 `127.0.0.1:8404` · 작업 프로세스 haproxy 사용자 · chroot · 출발지 헤더 |
| `test_fw_haproxy.py` | 위 두 설정 시험 (통계 페이지 노출 · 허용 포트 · 전환 관련 줄 · 권한 · 출발지 헤더 · `verify.sh` · 이 문서). `python3 infra/vmware/test_fw_haproxy.py` |
| `compose/console.yml` | 콘솔 API 컨테이너 (DB 역할 · 세션 비밀 · 발송기 이름 · 믿는 프록시 주소) |
| `scripts/console-join.sh` | 콘솔 B 합류 · 떼기 단계 (기본 드라이런). 시험 `python3 infra/vmware/scripts/test_console_join.py` (가짜 ssh · 접속 한도 30) |
| `scripts/console-watch.sh` · `scripts/install-console-watch.sh` | Mac 에서 콘솔 진입점 감시(두 대 모두 죽으면 알림). 시험 `python3 infra/vmware/scripts/test_console_watch.py` |
| `failover/` | 장애 주입 시험 도구(요청 · 웹소켓 프로브, 방화벽 통계 수집, T0 기록, 지표 요약). 시험 `python3 infra/vmware/failover/test_failover_tools.py` |
| `scripts/*.sh` | 네트워크 생성 · seed · 복제 · 구성 · 검증 · DB 백업 · 자산 수집 |

비밀번호와 개인 키는 저장소에 넣지 않는다. seed 이미지도 저장소 밖(`~/Virtual Machines.localized`)에 만든다.
