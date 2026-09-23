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

## 파일

| 경로 | 내용 |
|---|---|
| `seed/user-data.template` | 무인 설치 정의. 비밀번호 해시와 공개 키는 만들 때 채운다 |
| `netplan/*.yaml` | 노드별 고정 주소 |
| `fw/nftables.conf` | 내부 방화벽 규칙 (설계 3.2 규칙표) |
| `haproxy/haproxy.cfg` | 콘솔 분배 · 헬스체크 2초 × 3회 |
| `scripts/*.sh` | 네트워크 생성 · seed · 복제 · 구성 · 검증 · DB 백업 |

비밀번호와 개인 키는 저장소에 넣지 않는다. seed 이미지도 저장소 밖(`~/Virtual Machines.localized`)에 만든다.
