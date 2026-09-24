# 내부망 구축 (VMware Fusion · Mac)

WBS 3.3 · 이슈 #8. 보호 자산을 인터넷에서 닿지 않는 내부망으로 내린다.
관제 대상 서버 web-01 은 서비스망에 VM 으로 둔다 (이슈 #11). 학교 AWS 계정의 web-02 는 VM 쪽이 끝난 뒤 추가 여부를 정한다.

## 구성

| VM | 메모리 · CPU | 세그먼트 · 주소 | 역할 |
|---|---|---|---|
| opsloop-fw | 1GB · 2 | NAT(uplink) · 서비스망 192.168.50.1 · 데이터망 192.168.60.1 · 관리망 192.168.70.254 | 내부 방화벽(nftables) 겸 부하분산(HAProxy) |
| opsloop-console-a | 1GB · 1 | 서비스망 192.168.50.11 | 관제 콘솔 |
| opsloop-console-b | 1GB · 1 | 서비스망 192.168.50.12 | 관제 콘솔 예비 (평소 꺼 둠) |
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

콘솔 화면은 `http://192.168.70.254:8443`, HAProxy 상태는 `:8404` 로 본다.

## 데이터베이스 역할 (이슈 #31)

구성요소마다 최소 권한 역할로 붙는다. 소유자 `opsloop` 는 스키마 적용 · `nodes.py` · `auth.py add` 에만 쓴다.
권한은 `infra/schema.sql` 끝의 역할 블록이 주고(역할이 있을 때만, 여러 번 적용해도 같다), 역할과 비밀번호는 아래 스크립트가 만든다.

| 역할 | 쓰는 곳 | 접속 파일 | 할 수 있는 것 |
|---|---|---|---|
| `opsloop_gate` | 수집 관문 | 데이터 노드 `/etc/opsloop/gate.env` | nodes 네 열 읽기 · `enroll_node` |
| `opsloop_ingest` | 다리(pull_loki) · 파서 | `/etc/opsloop/collector.env` | events · sessions · node_metrics 적재, nodes 수신 기록 |
| `opsloop_detector` | 탐지기(detect.py) | `/etc/opsloop/detector.env` | 규칙 입력 읽기, incidents 생성 · 억제, detector_runs |
| `opsloop_console` | 콘솔 API · triage.py | 콘솔 `~/opsloop/.env` · 데이터 노드 `/etc/opsloop/triage.env` | 판정 · 조치 · 차단 · 등록 토큰 · 감사 · 로그인 기록. 토큰 해시 · 계정 역할은 못 본다/못 고친다 |
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
- 소유자로 붙는 서비스가 남아 있는지는 `verify-db-roles.sh` 의 pg_stat_activity 항목이 알려 준다.

## 알림 발송 경로

알림 발송기는 따로 띄우는 프로세스가 아니라 콘솔 API 안에서 돈다. 콘솔 → 채널 주소(Microsoft Teams Workflows 웹훅 · 일반 웹훅) 방향으로만 나가고, 밖에서 콘솔로 들어오는 경로는 없다.
방화벽은 지금 콘솔 → 인터넷 443 을 전체 허용하므로(`fw/nftables.conf` 59행) 채널을 추가해도 규칙을 바꿀 일이 없다. 등록된 채널 주소만 허용하도록 좁히는 것은 후속이다.
Teams 쪽 준비: Power Automate 에서 "Teams 웹훅 요청을 받으면 채널에 게시" 흐름을 만들고, 거기서 나온 주소(https · 호스트 `*.environment.api.powerplatform.com`)를 콘솔 알림 화면에 입력한다. 옛 `*.logic.azure.com` 주소는 2025-11-30 부터 동작하지 않고 Office 365 커넥터(`*.webhook.office.com`)도 없어져 받지 않는다. 옛 주소만 있으면 흐름을 다시 저장해 새 주소를 받는다. 콘솔은 Adaptive Card 로 보내고 2xx(보통 202) 응답을 성공으로 본다. 일반 웹훅도 https 만 받고 사설 · 링크로컬 · localhost 등 공인 인터넷이 아닌 IP 와 줄임 · 16진 IP 표기는 거부한다.
메시지 틀: 채널마다 머리말 · 항목 한 줄을 두고 자리표시자 `{event_label}` `{count}` `{severity_counts}` `{rule_id}` `{rule_name}` `{severity}` `{who}` `{elapsed}` `{first_ts}` `{incident_key}` `{link}` 만 문자 치환한다(형식 지정자 없음, 모르는 자리표시자는 그대로, 빈 값은 `-`). 원문 로그 · 입력된 비밀번호 · 내부 주소는 본문에 넣지 않는다.
알림 본문의 콘솔 링크 기준 주소는 콘솔 서비스의 환경변수 `OPSLOOP_CONSOLE_URL` 로 정한다(기본 `http://192.168.70.254:8443`).
배포 순서: 새 콘솔 이미지를 올리기 전에 `infra/migrations/20260924_notify.sql` 을 먼저 적용한다. 표가 없으면 알림만 멈추고 콘솔의 다른 기능은 뜬다.
콘솔 VM 마다 compose `.env` 에 `OPSLOOP_WORKER=opsloop-console-a`(B 는 `-b`)를 둔다. 발송기가 집은 알림을 이 이름으로 표시하므로, 재기동 때 자기가 보내던 알림을 바로 되찾는다.

## 파일

| 경로 | 내용 |
|---|---|
| `seed/user-data.template` | 무인 설치 정의. 비밀번호 해시와 공개 키는 만들 때 채운다 |
| `netplan/*.yaml` | 노드별 고정 주소 |
| `fw/nftables.conf` | 내부 방화벽 규칙 (설계 3.2 규칙표) |
| `haproxy/haproxy.cfg` | 콘솔 분배 · 헬스체크 2초 × 3회 |
| `scripts/*.sh` | 네트워크 생성 · seed · 복제 · 구성 · 검증 · DB 백업 |

비밀번호와 개인 키는 저장소에 넣지 않는다. seed 이미지도 저장소 밖(`~/Virtual Machines.localized`)에 만든다.
