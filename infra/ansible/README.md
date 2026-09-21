# web-01 수집 · 콘솔 가드 (Ansible)

이슈 #11 · WBS 3.4.2~3.4.4. 설계는 `docs/2026-09-21-web01-수집-설계.md`, 구현 계약 11장.
Mac 이 제어 노드다. 모든 접속은 방화벽(관리망 192.168.70.254)을 거친다.

| 플레이북 | 대상 | 하는 일 |
|---|---|---|
| `web01.yml` | web01 | 구성 창 → 불필요 서비스 끔 → nginx JSON 기록 → rsyslog 반복 축약 끔 → 지표 타이머 → Alloy 1.19.2 → 에이전트 키 → 자기 등록 → Alloy 기동 → 첫 수신 4단계 확인 |
| `consoles.yml` | console-a · console-b | 호스트 가드 `opsloop-guard.service` (서비스망에서 HAProxy 외 직접 접속 차단) |

## 준비

- Mac 에 ansible-core 2.16 이상 (`ansible-playbook --version`). 이 저장소는 설치하지 않는다.
- `~/.ssh/opsloop_ed25519` 와 known_hosts 의 노드 주소 (add-node.sh 가 넣는다). 인벤토리는 `~/.ssh/config.opsloop` 와 같은 경로를 ProxyCommand 로 적었다.
  (`ssh -F ~/...` 는 `~` 를 풀지 않고, 주소로 접속하면 config 의 Host 별칭이 맞지 않는다)
- 먼저 끝나 있어야 하는 것
  - 방화벽 `infra/vmware/fw/nftables.conf` 새 판: `provision` 집합(timeout), web-01 → data-01:3101
  - 데이터 노드: 스키마 · `opsloop-gate` · Loki · `opsloop-agents` · `detector/rules_node.json`(n1) · exclusions 의 127.0.0.1

## 순서

```bash
cd infra/ansible

# 1. 콘솔 가드. 콘솔 B 를 끄기 전에 돌린다 (끈 뒤에 다시 켜도 부팅과 함께 가드가 걸린다)
ansible-playbook consoles.yml
#    콘솔 B 가 이미 꺼져 있으면 --limit console-a. 콘솔 B 를 켜서 서비스에 넣기 전에 --limit console-b

# 2. 등록 토큰 (1시간 · 1회용). 화면과 셸 이력에 남지 않게 변수에만 담는다
export OPSLOOP_ENROLL_TOKEN="$(ssh -F ~/.ssh/config.opsloop data01 sudo /opt/opsloop/app/collector/nodes.py \
    issue web-01 --host opsloop-web-01 --addr 192.168.50.21 --logs nginx,auth,metrics)"

# 3. web-01 (첫 수신 확인까지 최대 10분)
ansible-playbook web01.yml
unset OPSLOOP_ENROLL_TOKEN

# 4. 다시 돌려 changed=0 확인 (등록은 표식이 키와 같아 건너뛴다. 토큰이 없어도 된다)
ansible-playbook web01.yml
ansible-playbook web01.yml --skip-tags receipt     # 탐침 · 확인 없이 구성만
```

## 비밀값

- 에이전트 키는 web-01 이 만든다 (`opsloop-agent-key`, `/etc/alloy/opsloop.token` root:alloy 0640). Mac 에는 sha256 만 온다.
- 등록 토큰은 Mac 환경변수 → Ansible `stdin` → `opsloop-enroll` 로만 간다 (`no_log`).
  `environment` 로 넘기면 sudo 가 명령줄째 auth.log 에 남기고, 그 줄이 Alloy 를 거쳐 원장(Loki)에 영구히 들어간다.
- 등록 표식 `/etc/alloy/opsloop.enrolled` 에는 키의 sha256 을 쓴다. 키를 바꾸면(파일을 지우고 다시 돌리면) 새 토큰으로 다시 등록한다.

## 첫 수신 확인이 실패하면

`nodes.py check` 의 종료 코드가 처음 실패한 단계다.

| 코드 | 단계 | 볼 곳 |
|---|---|---|
| 1 | 등록 | 토큰 만료 · 재사용이면 다시 issue |
| 2 | 첫 로그 | web-01 `journalctl -u alloy`, 관문 원장 `/var/lib/opsloop/gate/collector-*.jsonl` 의 401 사유, 방화벽 3101 |
| 3 | 형식 변환 | nginx log_format, rsyslog 반복 축약(repeated), 호스트명(foreign_host), 지표 줄(malformed) |
| 4 | 규칙 적용 | rules_node.json(n1) 적재 · detector_runs. 플레이북이 없는 사용자 로그인 한 줄(127.0.0.1, fixture)을 남겨 R101 이 이 노드를 보게 한다 |
| 5 | DB | 데이터 노드 `/etc/opsloop/collector.env` · PostgreSQL |

## 시험

```bash
python3 infra/ansible/test_web01_files.py
```

metrics.py(번호 · 줄 모양 · CPU 차분), opsloop-agent-key(한 번만 만듦 · sha256 만 냄 · 권한),
opsloop-enroll(가짜 관문 요청 모양 · 표식 · 거부 · 재지정 · 토큰 비출력), 플레이북이 가리키는 파일과 처리기를 본다.
원격 노드와 ansible 없이 돈다 (플레이북 구조 시험은 PyYAML 이 있을 때만).
