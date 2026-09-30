# OpsLoop 인프라 코드

콘솔에서 손으로 만든 자원을 코드의 관리 아래로 옮긴다.

## 관리하는 자원

| 파일 | 자원 |
|---|---|
| `dmz.tf` | DMZ VPC · 공개 · DMZ 서브넷 · 라우트 표 · S3 게이트웨이 엔드포인트 |
| `gateway.tf` | 관문 방화벽 인스턴스 · ENI · EIP · 보안그룹 |
| `honeypot_dmz.tf` | DMZ 허니팟(허니팟 · 웹 디코이 한 대) · 보안그룹 |
| `ssm_endpoints.tf` | SSM 전용 인터페이스 엔드포인트 3개 |
| `iam.tf` | 센서 역할 · 관문 역할(차단 목록 읽기 포함) · 원장 읽기 사용자 · CTI 쓰기 사용자(`cti/` 올리기만, 이슈 #39) · 차단 목록 쓰기 사용자(`block/v1/latest.json` 쓰기만, 이슈 #47) |
| `s3.tf` | 원장 버킷 · 버킷 정책(인스턴스별 쓰기 경계 · `cti/` 쓰기 경계 · `block/` 쓰기 경계) |

처음에는 콘솔에서 손으로 만든 수집 노드(허니팟)와 앱 노드를 `import` 로 가져와 관리했다.
2026-09-25 두 노드를 종료하며 정의(`instances.tf` · `security_groups.tf` · 앱 노드 전용 SSM 역할)를
걷어냈다(이슈 #37). 앱 노드 디스크는 스냅샷 `snap-0e36ac5b0cf30b362` 로 보관한다. 옛 허니팟의 원문은
원장(`host=i-058726c1a0671fe1d`)에 남아 있고 이미 적재돼 있다.

## 준비 · 절차

로컬에 AWS 자격증명이 필요하다. 저장소에는 어떤 키도 두지 않는다.

```bash
aws login                                  # 또는 aws configure
eval "$(aws configure export-credentials --format env)"
cp terraform.tfvars.example terraform.tfvars   # 처음 한 번. 값은 저장소에 올리지 않는다
terraform init
terraform plan
```

**계획에 `destroy` 나 `replace` 가 보이면 적용하지 않는다.** 인스턴스 교체는 원장에 아직 오르지 않은
원문을 잃고 공인 주소가 바뀐다. 이유를 확인한 뒤에만 적용한다.

## 이후

```bash
terraform plan     # 콘솔에서 누가 무엇을 바꿨는지 드러난다
```

계획에 차이가 잡히면 둘 중 하나다. 콘솔에서 직접 손댔거나, 코드를 고치고
아직 적용하지 않았거나. 어느 쪽이든 원인을 확인한 뒤 한쪽으로 맞춘다.

## DMZ 재구성 (이슈 #15 · #19)

허니팟을 관문 방화벽 뒤 DMZ 서브넷으로 내린다. 새 VPC(`dmz.tf`) · 방화벽(`gateway.tf`) ·
SSM 엔드포인트(`ssm_endpoints.tf`) · DMZ 허니팟(`honeypot_dmz.tf`)이 더해졌다. 옛 노드는 이전 뒤
종료했다(4단계). 설계는 `docs/2026-09-18-네트워크-설계.md` 2.1 · 3.1 · 4장.

미리 알아둘 것 둘.

- **공인 주소가 바뀐다.** 유입구가 허니팟의 자동 공인 IP(43.201.71.8)에서 방화벽의 EIP 로
  옮겨간다. 데이터는 원장으로 이어지고, 이전 전후는 host(인스턴스 ID)로 구분한다.
- **DMZ 허니팟에는 `prevent_destroy` 가 없다.** `count` 로 켜고 끄는 자원이라 두지 않았다.
  `honeypot_dmz_ami` 를 비우거나 바꾸면 계획에 destroy · replace 가 나온다. 아직 원장에
  오르지 않은 원문을 잃으므로, 그 계획은 확인 없이 적용하지 않는다.

### 1. VPC · 방화벽 생성

```bash
aws s3api get-bucket-policy --bucket opsloop-archive-739272173045 --query Policy --output text \
  > bucket-policy.before.json   # 되돌릴 때 put-bucket-policy 로 다시 넣는다 (저장소에 넣지 않는다)
terraform plan      # 새 자원 추가 · 제자리 변경 2(aws_iam_role_policy.sensor_put · aws_s3_bucket_policy.archive) · 삭제 0.
                    # 그 밖의 변경(~) · 삭제(-)가 보이면 적용하지 않는다
terraform apply
terraform output gateway_public_ip
```

`honeypot_dmz_ami` 가 비어 있으므로 DMZ 허니팟은 아직 생기지 않는다. 이 단계에서 생기는 것은
VPC · 방화벽 · SSM 인터페이스 엔드포인트 3개(`ssm_endpoints.tf`: ssm · ssmmessages · ec2messages,
DMZ 서브넷, 사설 DNS 켬) · 관문 역할(`iam.tf`, 허니팟의 센서 역할과 다르다)이고, 센서 역할 정책과
버킷 정책은 제자리에서 바뀐다(계획의 change 2 · destroy 0). 방화벽은 첫 부팅에
cloud-init(`../aws/gateway/cloud-init.yaml.tftpl`)으로 nftables · rsyslog · logrotate 파일을
놓고 전달을 켠다. DMZ 에서 나가는 것은 방화벽이 전부 거부 · 기록한다(`gw-forward-drop`). 원장(S3)과
SSM 은 VPC 엔드포인트로 가서 방화벽을 지나지 않는다. 규칙을 나중에 고칠 때는
`../aws/gateway/nftables.conf` 를 바꿔 SSM 으로 `/etc/nftables.conf` 에 옮기고 `nft -c -f` 확인
뒤 `systemctl restart nftables` 한다. user_data 변경은 계획에 잡히지 않는다(첫 부팅에만 도는
것이라 무시한다).

적용 직후 버킷 정책과 옛 허니팟의 업로드를 확인한다. 정책의 인스턴스 ARN 은 apply 때 정해지므로 계획에서는
보이지 않는다. 버킷 정책에 host 경계가 생기므로, 업로드가 끊겼다면 `s3.tf` 의 `ledger_writers` 와 옛
인스턴스의 짝이 어긋난 것이다(되돌리기: 위에서 보관한 정책을 `put-bucket-policy` 로 다시 넣는다).

```bash
aws s3api get-bucket-policy --bucket opsloop-archive-739272173045 --query Policy --output text \
  | python3 -c 'import json,sys; d=json.load(sys.stdin)["Statement"]; print(len(d)); [print(s["Sid"], s["Condition"]) for s in d if s["Sid"].startswith("OnlyOwnHost")]'
                                          # 문 10개(DMZ 허니팟이 생기면 11개. CTI 문 두 개를 더해 12개, 차단 목록 문 하나를 더해 13개, 내부 방화벽 보고 문 하나를 더한 지금은 14개 — 아래 'CTI 원본 보관' · '차단 목록 전달' · '내부 방화벽 동기화'). OnlyOwnHost* 의 ARN 이 terraform state show 의 인스턴스 ARN 과 같다
aws s3api head-object --bucket opsloop-archive-739272173045 \
  --key hb/v1/host=i-058726c1a0671fe1d/latest.json --query LastModified   # 한 회차(6분) 뒤, 적용 완료보다 늦은 시각
aws ssm send-command --instance-ids i-058726c1a0671fe1d --document-name AWS-RunShellScript \
  --parameters 'commands=["journalctl -u opsloop-upload -n 20 --no-pager"]' --query Command.CommandId --output text
                                          # get-command-invocation 으로 본다. AccessDenied 없이 올림 · 완료
```

쓰기 경계는 여러 겹이다. S3 엔드포인트 정책은 원장 버킷만 허용하고, SSM 엔드포인트 정책은 두 인스턴스
역할만 통과시킨다. 허니팟 보안그룹은 유출을 전부 열어 두어(보안그룹이 먼저 버리면 방화벽에 기록이 남지
않는다) 원장 · SSM 밖의 모든 시도가 방화벽까지 가서 `gw-forward-drop` 으로 남고, 방화벽 규칙이 잘못돼도
관문 보안그룹(443 · 53 만 유출)과 인터넷 게이트웨이(공인 주소 짝이 없는 사설 출발지는 버린다)가 남는다.
다른 리전 S3 · 가속 엔드포인트도 이래서 닿지 않는다. 역할은 허니팟(센서: cowrie · decoy · hb)과
방화벽(관문: gateway · hb)이 다르고, 버킷 정책은 인스턴스마다 자기 host 경로
(`raw/v1/sensor=<발생원>/host=<자기 ID>/*` · `hb/v1/host=<자기 ID>/latest.json`)에만 PutObject 를
허용하며 그 밖의 경로는 누구도 쓰지 못한다(`ec2:SourceInstanceARN` 조건. `migration/` 같은 원장 밖
접두사도 닫힌다 — 이 버킷은 원장과 공개 정보 원본(`cti/`. CTI 쓰기 사용자만 쓴다, 아래 'CTI 원본 보관')만
담고, DB 를 다시 넘길 일이 있으면 다른 버킷을 쓴다). 새 노드는 `s3.tf` 의 `ledger_writers` 에 더해야 원장에
쓴다. 풀러의 발생원 · 호스트 짝 확인(`OPSLOOP_GATEWAY_HOSTS`, 아래 2단계)은 그 뒤의 둘째 벽이다.
DNS(VPC 리졸버)는 남는 유출 통로다(DNS 방화벽은 범위 밖).

### 2. 방화벽 확인 · 업로더 설치

```bash
GW=$(terraform state show aws_instance.gateway | awk -F'"' '/^ *id /{print $2; exit}')
aws ssm start-session --target "$GW"
```

세션 안에서 확인한다.

```bash
cloud-init status --wait                  # done. 아니면 /var/log/cloud-init-output.log
sudo nft list ruleset | grep -c dnat      # 2 (prerouting 의 dnat to 와 forward 의 ct status dnat)
sysctl net.ipv4.ip_forward                # 1
systemctl is-enabled ssh.socket ssh.service   # masked · masked
ss -ltnu                                  # 127.0.0.53/54 (resolved) · 68 (networkd) 뿐이어야 한다
nslookup ssm.ap-northeast-2.amazonaws.com # 10.0.21.x (SSM 엔드포인트). 공인 주소면 사설 DNS 가 안 켜진 것
                                          # 이 세션 자체가 ssmmessages 엔드포인트로 붙어 있다
tail /var/log/opsloop/gateway.log         # 22 · 23 · 8080 밖의 포트를 두드리면 gw-input-drop 줄이 남는다
                                          # (세 포트는 DNAT 되어 forward 로 가고, 허니팟이 기록한다)
sha256sum /etc/nftables.conf /etc/rsyslog.d/10-opsloop-gateway.conf /etc/logrotate.d/opsloop-gateway
                                          # 저장소 infra/aws/gateway/ 의 세 파일과 같아야 한다. 규칙을 고친 뒤에도 같은 비교
```

업로더는 기존 허니팟과 같은 `sensor/` 네 파일(`upload.py` · `install-uploader.sh` ·
`opsloop-upload.service` · `opsloop-upload.timer`)을 SSM Run Command 에 base64 로 실어
넣고, 설치 스크립트의 세 번째 인자로 발생원을 준다.

```bash
sudo bash install-uploader.sh opsloop-archive-739272173045 "$GW" "gateway:/var/log/opsloop/gateway.log*"
sudo -u opsloop-up bash -c 'set -a; . /etc/default/opsloop-upload; set +a; python3 /usr/local/lib/opsloop/upload.py --dry-run'
sudo systemctl enable --now opsloop-upload.timer
sudo systemctl start opsloop-upload.service && journalctl -u opsloop-upload -n 20 --no-pager
                                          # dry-run 은 S3 를 건드리지 않는다. 첫 실제 올리기가 AccessDenied 없이 끝나야
                                          # 관문 역할 · 버킷 정책 · 엔드포인트 경로가 확인된 것이다
```

원장에 `raw/v1/sensor=gateway/host=<방화벽 ID>/` 가 생기면 데이터 노드의
`/etc/default/opsloop-ingest` 의 `OPSLOOP_HOSTS` 에 방화벽 ID 를 쉼표로 덧붙인다(회차마다 읽으므로
재시작은 필요 없다). 같은 파일의 `OPSLOOP_GATEWAY_HOSTS` 에도 방화벽 ID 를 넣는다. 풀러는 이 목록의
호스트가 올린 gateway 조각만 받고, 목록 밖 호스트의 gateway 조각과 이 호스트의 다른 발생원 조각은
거부한다(역할과 버킷 정책의 host 경계가 먼저 막고, 풀러가 한 번 더 확인한다).
풀러 · 적재 · 파서(`parser/parse_gateway.py`)는 이미 gateway 를 안다.

### 3. 허니팟 이미지 · DMZ 허니팟 생성

이미지는 기존 허니팟에서 뜬다. 뜨기 전에 `infra/aws/scripts/pre-image-scan.sh` 를 SSM 으로 옛
허니팟에서 돌려 결과 0 을 확인한다(장악 흔적이 이미지에 실리지 않게). `--no-reboot` 는 파일 시스템
일관성이 떨어지므로 재부팅을 허용하고, 유지 보수 시간에 한다(재부팅 동안 유입이 몇 분 끊긴다).

```bash
aws ec2 create-image --instance-id i-058726c1a0671fe1d --reboot \
  --name "opsloop-honeypot-$(date +%Y%m%d)" --description "DMZ move"
aws ec2 describe-images --owners self --query 'Images[].[ImageId,Name,State]' --output table   # available 까지
```

재부팅한 옛 인스턴스에서 cowrie · 디코이 · 업로더 타이머가 돌아왔는지 확인한다(SSM:
`systemctl is-active opsloop-upload.timer`, 원장에 새 조각이 이어지는지).

`terraform.tfvars` 에 `honeypot_dmz_ami = "ami-…"` 를 넣고 적용한다. 계획에는
`aws_instance.honeypot_dmz[0]` 추가와 `aws_s3_bucket_policy.archive` 변경(새 host 경계)만 있어야 한다.

```bash
terraform plan
terraform apply
HP=$(terraform state show 'aws_instance.honeypot_dmz[0]' | awk -F'"' '/^ *id /{print $2; exit}')
aws ssm start-session --target "$HP"
```

새 인스턴스는 이미지에 담긴 업로더 설정을 그대로 갖고 온다. 첫 부팅의 user_data(honeypot_dmz.tf)가
타이머를 끄고, 위치 기억(state.json)을 지우고, `OPSLOOP_HOST` 를 새 인스턴스 ID 로 바꾼다.
그래서 새 host 세대는 0 부터 다시 올라간다(이벤트는 line_hash 로 중복 없이 들어간다. 중간부터
이어 올리면 풀러가 원장 구멍으로 보고 탐지를 보류한다). 확인한 뒤 타이머를 켠다.

```bash
grep OPSLOOP_HOST= /etc/default/opsloop-upload      # 새 인스턴스 ID. 아니면 손으로 고친다
ls /var/lib/opsloop-upload/state.json 2>/dev/null   # 없어야 한다
systemctl is-enabled opsloop-upload.timer           # disabled
sudo -u opsloop-up bash -c 'set -a; . /etc/default/opsloop-upload; set +a; python3 /usr/local/lib/opsloop/upload.py --dry-run'
systemctl is-active cowrie                          # cowrie · 디코이도 기존과 같은 방법으로 확인
chronyc sources                                     # 169.254.169.123 (링크로컬 시간원). 없으면 이미지 뜨기 전에 옛 허니팟의
                                                    # /etc/chrony/conf.d 에 넣어 둔다. DMZ 는 인터넷 NTP 에 닿지 않는다
curl -m 5 https://1.1.1.1 ; echo $?                 # 실패(28). 방화벽 gateway.log 에 gw-forward-drop 으로 남는다
sudo systemctl enable --now opsloop-upload.timer
sudo systemctl start opsloop-upload.service && journalctl -u opsloop-upload -n 20 --no-pager
                                                    # 첫 실제 올리기가 AccessDenied 없이 끝나야 host 경계 · 엔드포인트 경로가 확인된 것
```

데이터 노드의 `/etc/default/opsloop-ingest` 의 `OPSLOOP_HOSTS` 에 새 허니팟 ID 를 덧붙인다.

이미지가 물려준 배경 통신(apt · snap 갱신, motd, 인터넷 NTP 풀)은 전부 방화벽에서 막히면서 `gw-forward-drop`
기록을 채운다(첫 한 시간에 200줄). 공격자가 만든 유출 시도만 남게 끈다. 2026-09-23 DMZ 허니팟에 적용했고,
다음 이미지를 뜰 때는 옛 허니팟에서 먼저 해 두면 된다.

```bash
sudo systemctl disable --now apt-daily.timer apt-daily-upgrade.timer motd-news.timer unattended-upgrades
sudo snap refresh --hold                              # SSM 에이전트가 snap 이라 snapd 는 끄지 않는다
sudo sed -i -E 's/^(pool |server ntp\.ubuntu)/#\1/' /etc/chrony/chrony.conf
printf 'server 169.254.169.123 prefer iburst minpoll 4 maxpoll 4\n' | sudo tee /etc/chrony/conf.d/opsloop-aws.conf
sudo systemctl restart chrony && chronyc sources     # 169.254.169.123 만
```

격리 시험(허니팟 안에서, 인스턴스 역할로): 인터넷 · 내부망 접속은 실패하고 `gateway.log` 에 남는다. 원장은
목록 · 읽기 · 삭제 · 다른 host 경로 쓰기 · 관문 발생원 행세 · 모르는 host · 원장 밖 접두사 모두 AccessDenied,
자기 조각 덮어쓰기는 PreconditionFailed(한 번 쓰기)여야 한다. 2026-09-23 1차 결과는 이슈 #19 PR 에 있다.

### 4. 전환 · 옛 인스턴스 종료 (2026-09-25 완료 · 이슈 #37)

DMZ 허니팟이 9/23 14시부터 관문 EIP 로 유입을 받았고, 내부망 적재 전환(#20)은 그 전에 끝났다.
옛 허니팟은 DMZ 밖에서 인터넷 유출이 열려 있어 격리 설계와 어긋나므로 9/25 종료했다. 순서:

1. 옛 허니팟에서 cowrie · 디코이를 멈추고 업로더를 한 번 돌려 마지막 조각을 올린 뒤 타이머를 끈다.
   데이터 노드 적재 한 회차로 받은 것을 확인한다(구멍 0).
2. 옛 앱 노드 디스크 스냅샷을 뜬다(보관).
3. `instances.tf` · `security_groups.tf` · 앱 노드 전용 SSM 역할 · 옛 변수 · 출력 · `s3.tf` 의
   `ledger_writers` 옛 허니팟 항목을 지우고 plan(추가 0 · 변경 1 · 삭제 15) → apply.
4. 데이터 노드 `/etc/default/opsloop-ingest` 의 `OPSLOOP_HOSTS` 에서 옛 ID 를 뺀다. 두면 옛 생존 신호가
   15분을 넘겨 매 회차 종료 코드 11(오래된 생존 신호)이 난다.

DMZ 허니팟 이미지(`honeypot_dmz_ami`)는 재구축용으로 남긴다. 이미지 전 비밀 검사로 원문 로그 · 옛 접속
정보가 없음을 확인한 이미지다.

## CTI 원본 보관 (이슈 #39)

데이터 노드의 CTI 수집기(`opsloop-cti`)가 받은 공개 취약점 정보 원본(KEV · EPSS · OSV · NVD)과 자산 조사
묶음을 같은 버킷의 `cti/` 에 한 번만 쓴다. DB 에는 정규화한 행과 원본 위치(`cti_snapshots` 의 S3 키 · sha256)만
두고, 원본을 남기지 못한 회차는 DB 도 갱신하지 않는다. 그날 무엇을 보고 판단했는지 원본으로 다시 만들기
위해서다(`docs/2026-09-08-판정-기준.md` §8). 수집기 설치는 `infra/vmware/README.md` 'CVE · KEV 연계'.

키는 `cti/v1/source=<kev|epss|osv|nvd|assets>/date=<UTC 날짜>/<sha256 앞 16자>.<json|csv.gz>` 다. 키에 내용
해시가 들어가므로 같은 날 같은 내용을 다시 받으면 412(이미 있음)로 끝나고, 한 번 쓰기와 매일 재실행이
부딪치지 않는다.

별도 버킷 대신 같은 버킷을 쓰므로 주체와 경로를 정책으로 나누고 실제 주체로 검증한다.
센서 권한으로는 CTI 원본을 쓰거나 덮어쓸 수 없어야 한다.

| 주체 | `cti/` | 원장(`raw/` · `hb/`) |
|---|---|---|
| CTI 쓰기 사용자 `opsloop-cti-writer` | `If-None-Match: *` 쓰기만. 읽기 · 목록 · 삭제 없음 | 쓰기 거부 |
| 센서 · 관문 역할 | 쓰기 거부 | 자기 host 경로에만 |
| 원장 읽기 사용자 `opsloop-archive-reader` | 목록 · 읽기 없음 | 목록 · 읽기 |
| 그 밖 (루트 · 관리자 포함) | 쓰기 · 삭제 거부. 읽기는 관리자 자격으로만(재현 작업) | 쓰기 · `raw/` 삭제 거부 |

`s3.tf` 에서 바뀐 곳:

- `OnlyCtiWriterWritesCti` (새 문): CTI 쓰기 사용자가 아닌 모든 주체의 `cti/` 쓰기를 거부한다(`aws:PrincipalArn`).
  장악된 센서가 신뢰 정보(KEV · 취약점 기록)를 심거나 바꾸지 못한다
- `CtiWriteOnce` (새 문): `If-None-Match` 없는 `cti/` 쓰기를 거부한다. 올린 원본을 조작본으로 바꿔치기할 수 없다
- `LedgerKnownHostsOnly` 의 예외(`not_resources`)에 `cti/*` 를 더했다. 빠지면 IAM 허용이 있어도 이 거부가 이긴다
- 저장 등급 · 기본 암호화 · 고객 키 · 삭제 거부 문의 대상에 `cti/*` 를 더했다

CTI 적용 때 정책 문은 12개였다(관문 · DMZ 허니팟 두 대 기준. DMZ 허니팟이 없으면 11개. 이슈 #47 뒤에는 13개 — 아래 '차단 목록 전달'): `DenyInsecureTransport` ·
`OnlySensorWritesLedger` · `OnlyOwnHostGateway` · `OnlyOwnHostHoneypotDmz0` · `LedgerKnownHostsOnly` ·
`OnlyCtiWriterWritesCti` · `CtiWriteOnce` · `LedgerWriteOnce` · `LedgerStandardStorageOnly` ·
`LedgerDefaultEncryptionOnly` · `LedgerNoCustomerKey` · `DenyLedgerDelete`.

### 1. 정책 · 쓰기 사용자 적용

```bash
aws s3api get-bucket-policy --bucket opsloop-archive-739272173045 --query Policy --output text \
  > bucket-policy.before.json   # 되돌릴 때 put-bucket-policy 로 다시 넣는다 (저장소에 넣지 않는다)
terraform plan      # 추가 2(aws_iam_user.cti_writer · aws_iam_user_policy.cti_put) · 변경 1(aws_s3_bucket_policy.archive) · 삭제 0.
                    # 그 밖이 보이면 적용하지 않는다
terraform apply
aws s3api get-bucket-policy --bucket opsloop-archive-739272173045 --query Policy --output text \
  | python3 -c 'import json,sys; d=json.load(sys.stdin)["Statement"]; print(len(d)); [print(s["Sid"], s.get("Condition") or s.get("NotResource")) for s in d if "Cti" in s["Sid"] or s["Sid"] == "LedgerKnownHostsOnly"]'
                    # 문 12개. OnlyCtiWriterWritesCti 의 ARN 이 …:user/opsloop-cti-writer, CtiWriteOnce 가 s3:if-none-match,
                    # LedgerKnownHostsOnly 의 NotResource 에 …/cti/* 가 있다
```

원장 쪽 문은 대상에 `cti/*` 가 더해질 뿐이지만 정책 전체가 바뀌므로, 한 회차 뒤 두 인스턴스의 업로드가
이어지는지 본다(끊겼으면 보관한 정책을 `put-bucket-policy` 로 다시 넣는다).

```bash
for r in aws_instance.gateway 'aws_instance.honeypot_dmz[0]'; do
  id=$(terraform state show "$r" | awk -F'"' '/^ *id /{print $2; exit}')
  aws s3api head-object --bucket opsloop-archive-739272173045 --key "hb/v1/host=$id/latest.json" --query LastModified
done                # 둘 다 적용 완료보다 늦은 시각
```

### 2. 쓰기 키 넣기

데이터 노드 설치기(`cti/install-cti.sh`)를 먼저 돌려 `opsloop-cti` 그룹과 `/etc/opsloop` 통과 권한이 있어야
한다. 키는 Terraform 으로 만들지 않는다(`aws_iam_access_key` 를 두면 비밀값이 상태 파일에 평문으로 남는다).
CLI 로 발급한 출력을 ssh 파이프로 바로 넘겨 데이터 노드에서 파일로 쓴다(`infra/vmware/scripts/db-console-role.sh`
와 같은 방식). 비밀값은 파이프로만 지나간다. Mac 디스크 · 셸 이력 · 화면 · 명령행 인자 · tfstate 에 남지 않고,
원격의 `read` · `printf` 는 bash 내장이라 ps 에도 보이지 않는다. 발급 출력이 비면(`aws` 실패) 파일을 쓰지 않는다.

```bash
# Mac, aws login 뒤, 저장소 루트. 먼저 닿는지 · 그룹이 있는지 본다 (아니면 키를 발급하지 않는다)
ssh -F ~/.ssh/config.opsloop data01 'getent group opsloop-cti >/dev/null && test -d /etc/opsloop && echo "  준비됨"'
aws iam create-access-key --user-name opsloop-cti-writer \
    --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text \
  | ssh -F ~/.ssh/config.opsloop data01 'read -r id secret && test -n "$secret" && printf "AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n" "$id" "$secret" | sudo -n install -m 640 -o root -g opsloop-cti /dev/stdin /etc/opsloop/s3-cti.env && echo "  썼다"'
ssh -F ~/.ssh/config.opsloop data01 'sudo -n ls -l /etc/opsloop/s3-cti.env'   # -rw-r----- root opsloop-cti. 내용은 보지 않는다
```

- ssh 가 실패하면 발급된 비밀값은 다시 볼 수 없다. `aws iam list-access-keys --user-name opsloop-cti-writer` 로
  키 ID 를 보고 `aws iam delete-access-key` 로 지운 뒤 다시 발급한다(사용자 키는 최대 2개)
- 교체: 같은 명령으로 새 키를 넣고(파일을 덮어쓴다) 수집기 한 회차가 성공한 것을 본 뒤, 옛 키를
  `aws iam update-access-key --status Inactive` 로 끄고 며칠 뒤 지운다

### 3. 검증 (실제 주체로)

관리자 자격으로 대신 시험하지 않는다. 주체마다 그 주체의 자격으로 요청한다(`docs/2026-09-22-격리시험-결과.md` 2장과
같은 방식). 시험 객체는 지울 수 없으므로(삭제 거부) 수집기 원본(`cti/v1/`)과 섞이지 않게 `cti/_probe/` 아래에 둔다.

| 주체 | 시험 | 기대 |
|---|---|---|
| CTI 쓰기 사용자 | `cti/_probe/<시각>.json` 에 `If-None-Match: *` 로 쓰기 | 200 |
| CTI 쓰기 사용자 | 같은 키에 다시 (`If-None-Match: *`) | 412 PreconditionFailed |
| CTI 쓰기 사용자 | 새 키에 조건 없이 쓰기 | 403 AccessDenied (`CtiWriteOnce`) |
| CTI 쓰기 사용자 | `raw/` 에 쓰기 (`If-None-Match: *`) | 403 |
| CTI 쓰기 사용자 | `cti/` 목록 · 읽기 · 삭제 | 403 |
| 센서 · 관문 역할 | `cti/` 에 쓰기 (`If-None-Match: *`) | 403 (역할 권한 밖이고 `OnlyCtiWriterWritesCti` 도 막는다) |
| 원장 읽기 사용자 | `cti/` 목록 | 403 |

데이터 노드의 boto3(Ubuntu `python3-boto3`)는 `IfNoneMatch` 인자를 모르므로 업로더(`sensor/upload.py`)처럼
서명 직전에 헤더를 넣는다. 키 파일은 셸이 아니라 파이썬이 읽는다.

```bash
# CTI 쓰기 사용자 (데이터 노드, opsloop-cti 사용자로)
ssh -F ~/.ssh/config.opsloop data01 'sudo -n -u opsloop-cti python3 -' <<'EOF'
import time, boto3, botocore
env = dict(l.split("=", 1) for l in open("/etc/opsloop/s3-cti.env").read().splitlines() if "=" in l)
s = boto3.session.Session(aws_access_key_id=env["AWS_ACCESS_KEY_ID"],
                          aws_secret_access_key=env["AWS_SECRET_ACCESS_KEY"], region_name="ap-northeast-2")
arn = s.client("sts").get_caller_identity()["Arn"]
print(arn); assert arn.endswith(":user/opsloop-cti-writer"), "다른 주체다"
B, K = "opsloop-archive-739272173045", "cti/_probe/%d.json" % time.time()

def once(request, **_):
    request.headers["If-None-Match"] = "*"

def code(name, cond=False, **kw):
    c = s.client("s3")
    if cond:
        c.meta.events.register("before-sign.s3.PutObject", once)
    try:
        getattr(c, name)(Bucket=B, **kw)
        return 200
    except botocore.exceptions.ClientError as e:
        return e.response["ResponseMetadata"]["HTTPStatusCode"]

print("조건부 쓰기 ", code("put_object", True, Key=K, Body=b"{}"))                   # 200
print("같은 키 다시", code("put_object", True, Key=K, Body=b"{}"))                   # 412
print("조건 없이   ", code("put_object", Key=K + ".x", Body=b"{}"))                  # 403
print("raw/ 쓰기   ", code("put_object", True, Key="raw/_probe.json", Body=b"{}"))   # 403
print("목록 · 읽기 · 삭제", code("list_objects_v2", Prefix="cti/"), code("get_object", Key=K),
      code("delete_object", Key=K))                                                # 403 403 403
EOF
```

센서 · 관문 역할은 인스턴스마다 SSM 세션(`aws ssm start-session --target <인스턴스 ID>`) 안에서 인스턴스
역할로 돌린다(관문 · DMZ 허니팟 둘 다).

```bash
python3 - <<'EOF'
import boto3, botocore
c = boto3.client("s3", region_name="ap-northeast-2")

def once(request, **_):
    request.headers["If-None-Match"] = "*"

c.meta.events.register("before-sign.s3.PutObject", once)
try:
    c.put_object(Bucket="opsloop-archive-739272173045", Key="cti/_probe/instance.json", Body=b"{}")
    print(200)
except botocore.exceptions.ClientError as e:
    print(e.response["ResponseMetadata"]["HTTPStatusCode"])                        # 403
EOF
```

원장 읽기 사용자는 데이터 노드에서 `opsloop-pull` 사용자로(키 파일 `/etc/opsloop/s3-pull.env`) `cti/` 목록을
부른다.

```bash
ssh -F ~/.ssh/config.opsloop data01 'sudo -n -u opsloop-pull python3 -' <<'EOF'
import boto3, botocore
env = dict(l.split("=", 1) for l in open("/etc/opsloop/s3-pull.env").read().splitlines() if "=" in l)
c = boto3.client("s3", aws_access_key_id=env["AWS_ACCESS_KEY_ID"],
                 aws_secret_access_key=env["AWS_SECRET_ACCESS_KEY"], region_name="ap-northeast-2")
try:
    c.list_objects_v2(Bucket="opsloop-archive-739272173045", Prefix="cti/")
    print(200)
except botocore.exceptions.ClientError as e:
    print(e.response["ResponseMetadata"]["HTTPStatusCode"])                        # 403
EOF
```

결과는 수집기 타이머를 켜기 전에 이슈 #39 에 남긴다. 이 결과가 격리 시험 문서 2장의 유보('아직 만들지 않은
CTI 서비스 전체가 격리됐다는 뜻은 아니다')를 푸는 근거가 된다.

## 차단 목록 전달 (이슈 #47)

사람이 요청한 차단(콘솔 · 판정 도구 · 흡수 후속 차단)을 AWS 관문의 forward 체인에서 집행한다. 인터넷에서 닿는 곳은
관문 뒤 허니팟뿐이라 관문이 실효 있는 집행 지점이다. 관문은 인바운드 관리 포트가 없고 SSM 으로만 닿으므로
목록은 같은 버킷을 거쳐 넘긴다. 데이터 노드가 쓰고 관문이 읽으며, 관문은 적용 결과를 생존 신호 옆 경로에 보고한다.

```
데이터 노드  opsloop-enforcer (1분) ─ DB blocklist → 목록 ─(opsloop-block-writer)→ s3 block/v1/latest.json
관문         opsloop-block-sync (1분) ─(관문 역할)→ 목록 읽기 · 재검사 · fail2ban/nft ─→ s3 hb/v1/host=<관문 ID>-block/latest.json
데이터 노드  opsloop-enforcer ─(opsloop-archive-reader, 기존 s3-pull.env)→ 관문 보고 ─→ DB method · enforced_at · enforce_note
```

목록은 바뀔 때와 10분마다(생존 표시) 한 객체를 덮어쓴다. 버저닝이 켜져 있어 덮어쓴 판이 남는다(언제 무엇을 내렸는지.
회차당 수 KiB, 하루 150판 안팎). 형식 · digest · 관문 보고 형식은 `enforcer/block_enforcer.py` 머리말에 있다.
이슈 #77 부터 문서는 `entries`(관문 목록, 관문을 고른 요청) 옆에 `points.fw`(내부 방화벽 목록, 모든 행)를 싣는다. 키 · 판(`v:1`) · IAM ·
버킷 정책은 그대로이고 크기는 최대 약 2배다.

| 주체 | `block/v1/latest.json` | 관문 보고 `hb/v1/host=<관문 ID>-block/latest.json` |
|---|---|---|
| 목록 쓰기 사용자 `opsloop-block-writer` | 쓰기만 (덮어쓰기). 읽기 · 목록 · 삭제 없음. `block/` 의 다른 키 · `raw/` · `hb/` · `cti/` 쓰기 거부 | 없음 |
| 관문 역할 | 읽기만 | 쓰기 (자기 인스턴스만, `ec2:SourceInstanceARN`) |
| DMZ 허니팟(센서 역할) | 없음 | 쓰기 거부 (`OnlyOwnHostGateway`) |
| 원장 읽기 사용자 `opsloop-archive-reader` | 없음 | 읽기 (기존 `hb/*` 읽기 권한 그대로) |
| 그 밖 (루트 · 관리자 포함) | 쓰기 거부 (`OnlyBlockWriterWritesBlock` · `LedgerKnownHostsOnly`) | 관문 인스턴스 밖 쓰기 거부 |

`iam.tf` · `s3.tf` 에서 바뀐 곳:

- `aws_iam_user.block_writer` · `aws_iam_user_policy.block_put` (새 자원): `block/v1/latest.json` PutObject 만
- `aws_iam_role_policy.gateway_block_read` (새 자원): 관문 역할에 `block/v1/latest.json` GetObject 만. 목록 권한이 없어
  목록이 아직 없을 때는 404 가 아니라 403 이 온다(관문 동기화는 둘 다 '못 읽음'으로 보고 집합을 그대로 둔다)
- 관문 보고 경로: 관문 역할의 기존 `hb/v1/host=*/latest.json` 쓰기 권한이 덮으므로 IAM 은 그대로다. 버킷 정책의
  `ledger_writers` 에 hb 접미사(`-block`)를 더해 `OnlyOwnHostGateway` 의 대상과 `LedgerKnownHostsOnly` 의 예외에
  들어간다. 빠지면 `LedgerKnownHostsOnly` 가 관문의 보고 쓰기를 거부한다
- `OnlyBlockWriterWritesBlock` (새 문): 목록 쓰기 사용자가 아닌 모든 주체의 `block/` 쓰기를 거부한다(`aws:PrincipalArn`).
  관문이 이 목록대로 유입을 막으므로 장악된 허니팟이나 다른 주체가 목록을 바꿔 아무 주소나 막거나 풀게 하지 못한다.
  덮어쓰기가 설계라 한 번 쓰기 문은 두지 않는다
- `LedgerKnownHostsOnly` 의 예외에 `block/v1/latest.json` 한 객체만 더했다(`block/` 의 다른 키는 누구도 못 쓴다)
- 저장 등급 · 기본 암호화 · 고객 키 문의 대상에 `block/*` 를 더했다(`local.written_prefixes`). 삭제 거부는 두지 않는다
  (지워지면 관문은 옛 집합을 두고 만료로 저절로 빼며, 집행기가 10분 안에 다시 올린다)

정책 문은 13개가 된다: CTI 때의 12개에 `OnlyBlockWriterWritesBlock`.

### 1. 정책 · 쓰기 사용자 적용

```bash
aws s3api get-bucket-policy --bucket opsloop-archive-739272173045 --query Policy --output text \
  > bucket-policy.before.json   # 되돌릴 때 put-bucket-policy 로 다시 넣는다 (저장소에 넣지 않는다)
terraform plan      # 추가 3(aws_iam_user.block_writer · aws_iam_user_policy.block_put · aws_iam_role_policy.gateway_block_read)
                    # · 변경 1(aws_s3_bucket_policy.archive) · 삭제 0. 그 밖이 보이면 적용하지 않는다
terraform apply
aws s3api get-bucket-policy --bucket opsloop-archive-739272173045 --query Policy --output text \
  | python3 -c 'import json,sys; d=json.load(sys.stdin)["Statement"]; print(len(d)); [print(s["Sid"], s.get("Resource") or s.get("NotResource"), s.get("Condition", "")) for s in d if s["Sid"] in ("OnlyBlockWriterWritesBlock", "LedgerKnownHostsOnly", "OnlyOwnHostGateway")]'
                    # 문 13개(이슈 #51 뒤에는 14개). OnlyBlockWriterWritesBlock 의 ARN 이 …:user/opsloop-block-writer, LedgerKnownHostsOnly 의
                    # NotResource 에 …/block/v1/latest.json 과 …/hb/v1/host=<관문 ID>-block/latest.json, OnlyOwnHostGateway 의
                    # Resource 에 …/hb/v1/host=<관문 ID>-block/latest.json 이 있다
```

원장 쪽 문은 대상이 늘 뿐이지만 정책 전체가 바뀌므로, 한 회차 뒤 두 인스턴스의 업로드가 이어지는지 본다(끊겼으면
보관한 정책을 `put-bucket-policy` 로 다시 넣는다). 'CTI 원본 보관' 1단계의 `head-object` 반복문과 같다.

### 2. 쓰기 키 넣기

키는 Terraform 으로 만들지 않는다('CTI 원본 보관' 2단계와 같은 까닭 · 같은 방식). 파일은 0600 root:root 다.
데이터 노드의 집행기 서비스는 systemd `LoadCredential` 로 읽기 전용 사본을 받으므로 그룹이 필요 없다.
관문 보고를 읽는 키는 적재기의 `/etc/opsloop/s3-pull.env` 를 그대로 쓴다(새 키를 만들지 않는다).

```bash
# Mac, aws login 뒤, 저장소 루트. 먼저 닿는지 본다 (아니면 키를 발급하지 않는다)
ssh -F ~/.ssh/config.opsloop data01 'test -d /etc/opsloop && echo "  준비됨"'
aws iam create-access-key --user-name opsloop-block-writer \
    --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text \
  | ssh -F ~/.ssh/config.opsloop data01 'read -r id secret && test -n "$secret" && printf "AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n" "$id" "$secret" | sudo -n install -m 600 -o root -g root /dev/stdin /etc/opsloop/s3-block.env && echo "  썼다"'
ssh -F ~/.ssh/config.opsloop data01 'sudo -n ls -l /etc/opsloop/s3-block.env'   # -rw------- root root. 내용은 보지 않는다
```

- ssh 가 실패하면 발급된 비밀값은 다시 볼 수 없다. `aws iam list-access-keys --user-name opsloop-block-writer` 로
  키 ID 를 보고 `aws iam delete-access-key` 로 지운 뒤 다시 발급한다(사용자 키는 최대 2개)
- 교체: 같은 명령으로 새 키를 넣고 집행기 한 회차가 '목록을 올렸다'로 끝난 것을 본 뒤(10분 안에 생존 표시로 한 번은
  올린다), 옛 키를 `aws iam update-access-key --status Inactive` 로 끄고 며칠 뒤 지운다

### 3. 검증 (실제 주체로)

관리자 자격으로 대신 시험하지 않는다. 다만 `block/v1/latest.json` 은 관문이 실제로 읽는 목록이라 시험 객체를 쓰지
않는다. 허용 쪽(목록 쓰기 사용자의 쓰기 · 관문의 읽기와 보고 쓰기)은 집행기 · 관문 동기화의 첫 회차로 확인하고,
거부 쪽은 `block/_probe/` 아래 키로 본다(쓰이면 안 되는 키라 정책이 틀려도 목록에는 닿지 않는다).

| 주체 | 시험 | 기대 |
|---|---|---|
| 목록 쓰기 사용자 | 집행기 첫 회차 (`systemctl start opsloop-enforcer.service`) | '목록을 올렸다' |
| 목록 쓰기 사용자 | `block/_probe/<시각>.json` 쓰기 | 403 (`LedgerKnownHostsOnly`) |
| 목록 쓰기 사용자 | `raw/` · `hb/` · `cti/` 쓰기 | 403 |
| 목록 쓰기 사용자 | `block/v1/latest.json` 읽기 · `block/` 목록 · `block/_probe/x` 삭제 | 403 |
| 관문 역할 | 관문 동기화 첫 회차 (목록 읽기 · 보고 쓰기) | 보고가 생긴다 (`opsloop-enforcer status` 의 '관문 보고') |
| 관문 역할 | `block/_probe/instance.json` 쓰기 | 403 |
| DMZ 허니팟 역할 | `block/v1/latest.json` 읽기 | 403 |
| 관리자 | `block/v1/latest.json` 에 지금 내용 그대로 다시 쓰기 | 403 (`OnlyBlockWriterWritesBlock`. 정책이 틀려 써져도 같은 내용이다) |

```bash
# 목록 쓰기 사용자 (데이터 노드, root 로. 키 파일은 root 만 읽는다)
ssh -F ~/.ssh/config.opsloop data01 'sudo -n python3 -' <<'EOF'
import time, boto3, botocore
env = dict(l.split("=", 1) for l in open("/etc/opsloop/s3-block.env").read().splitlines() if "=" in l)
s = boto3.session.Session(aws_access_key_id=env["AWS_ACCESS_KEY_ID"],
                          aws_secret_access_key=env["AWS_SECRET_ACCESS_KEY"], region_name="ap-northeast-2")
arn = s.client("sts").get_caller_identity()["Arn"]
print(arn); assert arn.endswith(":user/opsloop-block-writer"), "다른 주체다"
B, c = "opsloop-archive-739272173045", s.client("s3")

def code(name, **kw):
    try:
        getattr(c, name)(Bucket=B, **kw)
        return 200
    except botocore.exceptions.ClientError as e:
        return e.response["ResponseMetadata"]["HTTPStatusCode"]

print("다른 block/ 키", code("put_object", Key="block/_probe/%d.json" % time.time(), Body=b"{}"))   # 403
print("raw/ hb/ cti/ ", [code("put_object", Key=k, Body=b"{}") for k in ("raw/_probe.json", "hb/_probe.json", "cti/_probe/x.json")])   # 403 ×3
print("읽기 · 목록 · 삭제", code("get_object", Key="block/v1/latest.json"), code("list_objects_v2", Prefix="block/"),
      code("delete_object", Key="block/_probe/x"))                                       # 403 403 403
EOF
# 관리자 (Mac): 지금 목록을 받아 같은 내용으로 다시 쓴다. AccessDenied 여야 한다
aws s3 cp s3://opsloop-archive-739272173045/block/v1/latest.json "$TMPDIR/bl.json" --quiet
aws s3api put-object --bucket opsloop-archive-739272173045 --key block/v1/latest.json \
  --body "$TMPDIR/bl.json" --content-type application/json; rm -f "$TMPDIR/bl.json"      # An error occurred (AccessDenied)
```

관문 · DMZ 허니팟 역할은 'CTI 원본 보관' 3단계처럼 SSM 세션 안에서 인스턴스 역할로 `block/_probe/instance.json` 쓰기 ·
`block/v1/latest.json` 읽기를 부른다(관문은 쓰기 403, 허니팟은 읽기 403).

### 4. 되돌리기

집행기 타이머를 끄고(`sudo systemctl disable --now opsloop-enforcer.timer`) 관문 동기화를 멈춘다. 관문 집합은 만료로
저절로 빈다(항목마다 남은 만료 · fail2ban bantime 24시간이 상한). 정책은 보관한 `bucket-policy.before.json` 을
`put-bucket-policy` 로 넣거나, 코드를 되돌려 `terraform apply` 한다(삭제 3 · 변경 1). 쓰기 사용자를 지우기 전에
`aws iam delete-access-key` 로 키를 먼저 지운다(키가 있으면 사용자 삭제가 실패한다).

## 관문 차단 집행 설치 (이슈 #47)

사람이 요청한 차단(콘솔 block_ip · 판정 도구 threat · 흡수 후속 차단) 가운데 관문을 고른 것(이슈 #77)을 관문 forward 체인에서 집행한다. 데이터 노드 집행기가
`block/v1/latest.json` 을 올리고, 관문 동기화(`infra/aws/gateway/block-sync.py`, 1분 타이머)가 읽어 nft 집합
`inet filter opsloop_block` 에 넣고 뺀 뒤 결과를 `hb/v1/host=<관문 ID>-block/latest.json` 에 올린다. 막는 것은 허니팟 유입
(DNAT 22 · 23 · 8080)뿐이다. 관문 자신의 관리 경로(SSM · DHCP, input 체인)는 그대로다. 이미 맺어진 연결은 끝까지 가고 새 연결부터 막힌다.

| 저장소 (`infra/aws/gateway/`) | 관문 |
|---|---|
| `nftables.conf` | `/etc/nftables.conf` (집합 `opsloop_block` · forward 규칙 두 줄) |
| `fail2ban/jail.d/opsloop-block.conf` | `/etc/fail2ban/jail.d/` (sshd jail 끔 · jail opsloop-block, bantime 24시간) |
| `fail2ban/action.d/opsloop-nft.conf` | `/etc/fail2ban/action.d/` (집합에 넣고 빼기만. 시작 · 멈춤은 아무것도 안 함) |
| `fail2ban/fail2ban.d/opsloop.conf` | `/etc/fail2ban/fail2ban.d/` (자체 DB 끔) |
| `block-sync.py` | `/usr/local/lib/opsloop/block-sync.py` |
| `opsloop-block-sync.service` · `.timer` | `/etc/systemd/system/` |
| (설치 때 만든다) | `/etc/default/opsloop-block-sync` (MODE · 버킷 · 관문 ID) · `/var/lib/opsloop-block-sync/` (자가 시험 결과 · 마지막 상태 · fail2ban 빈 로그) |

미리 알아둘 것.

- Terraform 변경(관문 역할의 `block/v1/latest.json` 읽기 · 버킷 정책의 `hb/v1/host=<관문 ID>-block` 경로)을 먼저 적용한다. 적용 전이면
  동기화는 목록을 못 읽고(AccessDenied) 상태도 못 올린다. 그래도 집합은 건드리지 않는다.
- `nft -f /etc/nftables.conf` 는 `flush ruleset` 으로 집합을 비운다. 동기화가 1분 안에 되살리지만, 규칙을 고친 뒤에는 바로
  `systemctl start opsloop-block-sync.service` 를 돌린다.
- 모드는 fail2ban 이 먼저다. 자가 시험이 `fail:` 이면 `MODE=nft` 로 바꾼다(5단계). 두 모드 모두 집합 · 규칙 · 상태 형식이 같고
  상태의 `mode` 만 다르다. fail2ban 모드는 동기화가 멈춰도 bantime(24시간) 안에, nft 모드는 항목의 만료(until)에 저절로 풀린다.
  동기화가 도는 동안 목록에서 빠진 주소(해제 · 관문 미요청 등)는 어느 모드든 다음 회차에 뺀다(fail2ban unbanip · nft del).
- 동기화 한 회차는 오류가 있으면 종료 코드 2 로 끝나 단위가 failed 로 보인다(집행기가 목록을 올리기 전의 `목록을 읽지 못함` 도 그렇다).
  타이머는 그래도 다음 회차를 돌린다. 오류가 없어지면 저절로 정상이 된다.
- 관문을 다시 만들면(cloud-init) 새 `nftables.conf` 는 들어가지만 fail2ban · 동기화는 이 절차로 다시 설치한다(업로더와 같다).
- 관문은 #77 판으로 바꾸지 않아도 된다. 동기화는 목록의 `entries`(관문 목록)만 적용하므로 옛 판 · 새 판이 같은 집합을 만들고, 새 판은
  보고에 `list:"gateway"` 만 더한다. 관문을 다시 만들 때 어느 판을 깔아도 맞다.

### 0. 준비 (Mac, 저장소 루트)

```bash
unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN   # 옛 값이 남아 있으면 만료 오류가 난다
aws login
eval "$(aws configure export-credentials --format env)"
GW=i-0ffeb29efad03546d
gwrun() {   # SSM 으로 관문에서 명령을 돌리고 끝날 때까지 기다린 뒤 상태 · 출력 · 오류를 찍는다
  local cid st        # aws ssm wait 는 100초에 포기하므로(apt 단계) 상태를 직접 본다
  cid=$(aws ssm send-command --region ap-northeast-2 --instance-ids "$GW" --document-name AWS-RunShellScript \
    --parameters "$(python3 -c 'import json,sys; print(json.dumps({"commands":[sys.argv[1]]}))' "$1")" \
    --query Command.CommandId --output text) || return 1
  while :; do
    st=$(aws ssm get-command-invocation --region ap-northeast-2 --command-id "$cid" --instance-id "$GW" \
      --query Status --output text 2>/dev/null)
    case "$st" in Pending|InProgress|Delayed|"") sleep 3 ;; *) break ;; esac
  done
  aws ssm get-command-invocation --region ap-northeast-2 --command-id "$cid" --instance-id "$GW" \
    --query '[Status,StandardOutputContent,StandardErrorContent]' --output text
}
```

### 1. 파일 올리기 · 지금 규칙 백업

macOS tar 의 `-z` 는 10KB 단위로 채우므로 gzip 을 따로 건다. 묶음은 base64 약 20KB 다(SSM 문서 상한 64KB 에 런타임 파라미터가
포함된다. 선례 pre-image-scan 은 12KB). 거부되면 `block-sync.py` 와 나머지를 두 묶음으로 나눠 같은 방법으로 두 번 보낸다.

```bash
PAYLOAD=$(cd infra/aws/gateway && COPYFILE_DISABLE=1 tar --no-xattrs --no-mac-metadata -cf - nftables.conf block-sync.py \
  opsloop-block-sync.service opsloop-block-sync.timer fail2ban | gzip -9 | base64 | tr -d '\n')
gwrun "rm -rf /root/opsloop-47 && mkdir -m 700 /root/opsloop-47 && echo $PAYLOAD | base64 -d | tar -xzf - --no-same-owner -C /root/opsloop-47 && cd /root/opsloop-47 && sha256sum nftables.conf block-sync.py opsloop-block-sync.* fail2ban/*/*"
(cd infra/aws/gateway && shasum -a 256 nftables.conf block-sync.py opsloop-block-sync.* fail2ban/*/*)   # 위와 같아야 한다
gwrun "cp -a /etc/nftables.conf /root/opsloop-47/nftables.conf.before && sha256sum /etc/nftables.conf"
git show 52820f9:infra/aws/gateway/nftables.conf | shasum -a 256
                  # 위와 같아야 한다(#47 전 저장소 판 = 마지막 변경 3515302 와 같은 내용). 다르면 운영에서 손댄 것이니 멈추고 차이를 본다
```

### 2. 방화벽 규칙 반영

```bash
gwrun "nft -c -f /root/opsloop-47/nftables.conf && echo 문법 OK"
gwrun "install -m 0644 /root/opsloop-47/nftables.conf /etc/nftables.conf && nft -f /etc/nftables.conf && nft list set inet filter opsloop_block && nft list chain inet filter forward | grep -n opsloop_block && nft list ruleset | grep -c dnat && systemctl is-enabled nftables"
```

빈 집합(`type ipv4_addr` · `flags timeout` · `size 4096`), forward 의 두 줄(`gw-block-drop` 기록 · drop)이 DNAT 허용 줄 앞에,
dnat 2, enabled 여야 한다. 연결 추적은 비우지 않으므로 맺어진 세션은 이어진다. rsyslog 는 그대로 둔다(`gw-[a-z-]+ IN=` 이 새 접두도 고른다).

### 3. fail2ban 설치 (설정을 먼저 둔다)

패키지는 설치 순간 fail2ban 을 켠다. 우분투 기본(`defaults-debian.conf`)이 켜는 sshd jail 이 그때 켜지지 않게 jail.d 파일을 먼저
둔다(이름순으로 뒤에 읽혀 덮는다). jail 이 뜨려면 빈 로그 파일도 먼저 있어야 한다.

```bash
gwrun "install -d -m 0700 /var/lib/opsloop-block-sync && install -m 0600 /dev/null /var/lib/opsloop-block-sync/fail2ban-empty.log && for f in jail.d/opsloop-block.conf action.d/opsloop-nft.conf fail2ban.d/opsloop.conf; do install -D -m 0644 /root/opsloop-47/fail2ban/\$f /etc/fail2ban/\$f; done && ls -l /etc/fail2ban/*/opsloop*"
gwrun "apt-get update -q >/dev/null && apt-cache policy fail2ban | head -3"
                  # 후보(Candidate)가 1.0.2-3ubuntu0.1(noble-updates) 이어야 한다. 이 판이 python3-pyasyncore 에 의존한다.
                  # 1.0.2-3 이면 우분투 24.04 의 python 3.12 에 asyncore 가 없어 서버가 뜨지 않는다. 멈추고 미러 · 업데이트 포켓을 본다
gwrun "DEBIAN_FRONTEND=noninteractive apt-get install -y -q --no-install-recommends fail2ban && sleep 3 && fail2ban-client status && fail2ban-client get dbfile && fail2ban-client get opsloop-block bantime && fail2ban-client get opsloop-block actions"
```

`Jail list: opsloop-block`(sshd 없음) · DB 꺼짐(`Database currently disabled`) · 86400 · opsloop-nft 여야 한다. fail2ban 이 뜨지 않으면
`gwrun "journalctl -u fail2ban -n 30 --no-pager"` 를 보고, 고치지 못하면 5단계(nft 모드)로 간다.

### 4. 동기화 설치 · 자가 시험 · 켜기

```bash
gwrun "install -d -m 0755 /usr/local/lib/opsloop && install -m 0755 /root/opsloop-47/block-sync.py /usr/local/lib/opsloop/ && install -m 0644 /root/opsloop-47/opsloop-block-sync.service /root/opsloop-47/opsloop-block-sync.timer /etc/systemd/system/ && printf 'MODE=fail2ban\nOPSLOOP_BUCKET=opsloop-archive-739272173045\nOPSLOOP_HOST=$GW\nAWS_DEFAULT_REGION=ap-northeast-2\n' > /etc/default/opsloop-block-sync && chmod 0644 /etc/default/opsloop-block-sync && systemctl daemon-reload && cat /etc/default/opsloop-block-sync"
gwrun "set -a; . /etc/default/opsloop-block-sync; set +a; python3 /usr/local/lib/opsloop/block-sync.py --dry-run"
                  # 읽기만 한다. 계획 · 거부 · 오류를 찍는다
gwrun "set -a; . /etc/default/opsloop-block-sync; set +a; python3 /usr/local/lib/opsloop/block-sync.py --selftest; nft list set inet filter opsloop_block; fail2ban-client get opsloop-block banned"
gwrun "systemctl start opsloop-block-sync.service; journalctl -u opsloop-block-sync -n 20 --no-pager"   # 샌드박스 안에서 한 회차
gwrun "systemctl enable --now opsloop-block-sync.timer && systemctl list-timers opsloop-block-sync.timer --no-pager"
aws s3 cp "s3://opsloop-archive-739272173045/hb/v1/host=$GW-block/latest.json" - | python3 -m json.tool
```

자가 시험은 `ok` 여야 한다. 문서용 주소 192.0.2.123 을 nft 에 60초 timeout 으로, fail2ban 으로 한 번 넣었다 빼고(원소 timeout 이
jail bantime 인지까지 본다) 끝나면 집합 · banned 에 남기지 않는다. 상태의 `mode` 는 fail2ban, `selftest` 는 ok 다. 집행기가 목록을
올리기 전에는 `errors` 에 `목록을 읽지 못함 (AccessDenied)`(목록 권한이 없어 없음도 403 이다)가 있고 `list_digest` 는 null 이며
단위는 종료 코드 2 로 failed 로 보인다(예상된 표시). 샌드박스 한 회차가 `nft` · `fail2ban-client` · S3 에 닿지 못하는 오류를 내면
journal 의 첫 오류 줄이 원인이다.

### 5. fail2ban 이 안 될 때: nft 모드

```bash
gwrun "systemctl disable --now fail2ban; sed -i 's/^MODE=.*/MODE=nft/' /etc/default/opsloop-block-sync && set -a && . /etc/default/opsloop-block-sync && set +a && python3 /usr/local/lib/opsloop/block-sync.py --selftest"
```

fail2ban 을 멈추면 actionflush 가 집합을 비우고, 이어 도는 한 회차가 남은 초를 timeout 으로 다시 넣는다. 바꾼 사유(자가 시험의
`fail:` 문구)를 이슈에 남긴다.

### 6. 확인

- 끝에서 끝: 집행기가 돈 뒤 콘솔에서 문서용 주소(예: 198.51.100.77)에 1시간 차단을 걸면 2분 안에
  `gwrun "nft list set inet filter opsloop_block"` 에 보이고 차단 목록의 집행 상태가 '관문 반영 · …' 이 된다. 해제하면 1~2분 안에 빠진다.
- flush 되살림: `gwrun "nft -f /etc/nftables.conf; nft list set inet filter opsloop_block; systemctl start opsloop-block-sync.service; nft list set inet filter opsloop_block"`
  에서 비었던 집합이 한 회차 뒤 다시 채워진다. fail2ban 모드면 상태 errors 에 '집합에서 빠진 원소 N개를 nft 로 되살림' 이 한 번 남고,
  nft 모드는 조용히 다시 넣는다.
- 실제 거부 기록: 막힌 출발지가 22 · 23 · 8080 을 두드리면 `gateway.log` 에 `gw-block-drop` 줄이 남고(초당 10줄까지), 적재 뒤
  `eventid = 'gateway.block.drop'` 으로 보인다(`python3 parser/parse_gateway.py --report` 의 '차단 거부 출발지').

### 7. 되돌리기

```bash
gwrun "systemctl disable --now opsloop-block-sync.timer; nft flush set inet filter opsloop_block; systemctl disable --now fail2ban"
                  # 막은 것을 바로 모두 푼다
gwrun "install -m 0644 /root/opsloop-47/nftables.conf.before /etc/nftables.conf && nft -c -f /etc/nftables.conf && nft -f /etc/nftables.conf && sha256sum /etc/nftables.conf"
                  # 규칙까지 되돌릴 때
gwrun "apt-get purge -y -q fail2ban && rm -f /etc/fail2ban/jail.d/opsloop-block.conf /etc/fail2ban/action.d/opsloop-nft.conf /etc/fail2ban/fail2ban.d/opsloop.conf"
                  # 패키지까지 뺄 때
```

되돌리면 집행기는 5분 뒤부터 관문을 요청한 행마다 '관문 불일치 · 관문 보고가 5분 넘게 멈춤' 을 쓴다(예상된 표시).

## 내부 방화벽 동기화 (이슈 #51)

온프레미스 내부 방화벽이 관문과 같은 차단 목록 `block/v1/latest.json` 의 내부 방화벽 갈래(`points.fw`, 없으면 `entries`, 이슈 #77)를 읽고, 적용 결과를 `hb/v1/host=fw-opsloop-block/latest.json` 에
쓴다. 방화벽은 EC2 가 아니라 인스턴스 역할이 없으므로 IAM 사용자 `opsloop-fw-sync` 의 키를 쓴다. 그 두 객체뿐이다.
설치 순서 전체는 `infra/vmware/README.md` '내부 방화벽 차단 집행'.

| 주체 | `block/v1/latest.json` | `hb/v1/host=fw-opsloop-block/latest.json` | 그 밖 |
|---|---|---|---|
| 동기화 사용자 `opsloop-fw-sync` | 읽기 | 쓰기 | 원장 · 다른 hb · cti/ · 목록 쓰기 거부 |
| 센서 · 관문 역할 · 다른 사용자 · 루트 | (관문 역할만 읽기) | 쓰기 거부 (`OnlyFwSyncWritesFwHb`) | 그대로 |

`s3.tf` 에서 바뀐 곳:

- `OnlySensorWritesLedger`: `hb/*` 쓰기 예외 주체에 동기화 사용자를 더했다. 그 밖의 hb 경로는 아래 두 문과 IAM 정책(그 키 하나)이 막는다
- `OnlyFwSyncWritesFwHb` (새 문): 그 보고 키는 동기화 사용자만 쓴다. 장악된 허니팟 · 관문이 '내부 방화벽 반영' 보고를 꾸미지 못한다
- `LedgerKnownHostsOnly`: 예외(`not_resources`)에 그 보고 키를 더했다

### 1. 정책 · 사용자 적용

```bash
aws s3api get-bucket-policy --bucket opsloop-archive-739272173045 --query Policy --output text > bucket-policy.before.json
terraform plan      # 추가 2(aws_iam_user.fw_sync · aws_iam_user_policy.fw_sync) · 변경 1(aws_s3_bucket_policy.archive) · 삭제 0
terraform apply
aws s3api get-bucket-policy --bucket opsloop-archive-739272173045 --query Policy --output text \
  | python3 -c 'import json,sys; d=json.load(sys.stdin)["Statement"]; print(len(d)); [print(s["Sid"], s.get("Condition") or s.get("NotResource")) for s in d if s["Sid"] in ("OnlySensorWritesLedger", "OnlyFwSyncWritesFwHb", "LedgerKnownHostsOnly")]'
                    # 문 14개. OnlySensorWritesLedger 에 …:user/opsloop-fw-sync, OnlyFwSyncWritesFwHb 가 그 사용자 하나,
                    # LedgerKnownHostsOnly 의 NotResource 에 …/hb/v1/host=fw-opsloop-block/latest.json
```

정책 전체가 바뀌므로 한 회차 뒤 관문 · 허니팟의 업로드와 관문 보고가 이어지는지 본다(끊겼으면 보관한 정책을 `put-bucket-policy` 로 다시 넣는다).

### 2. 키 넣기 (방화벽)

키는 Terraform 으로 만들지 않는다. CLI 로 발급한 출력을 ssh 파이프로 바로 넘겨 방화벽에서 파일로 쓴다('CTI 원본 보관' 2단계와 같은 방식).

```bash
ssh -F ~/.ssh/config.opsloop fw 'sudo -n install -d -m 0750 /etc/opsloop && echo "  준비됨"'
aws iam create-access-key --user-name opsloop-fw-sync --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text \
  | ssh -F ~/.ssh/config.opsloop fw 'read -r id secret && test -n "$secret" && printf "AWS_ACCESS_KEY_ID=%s\nAWS_SECRET_ACCESS_KEY=%s\n" "$id" "$secret" | sudo -n install -m 600 -o root -g root /dev/stdin /etc/opsloop/block-sync.env && echo "  썼다"'
ssh -F ~/.ssh/config.opsloop fw 'sudo -n ls -l /etc/opsloop/block-sync.env'   # -rw------- root root. 내용은 보지 않는다
```

### 3. 검증 (실제 주체로)

동기화의 `--dry-run` 이 목록을 읽고(`목록 fw 확인`), 한 회차가 보고를 올린다(`aws s3 cp s3://…/hb/v1/host=fw-opsloop-block/latest.json -`).
같은 키로 원장(`raw/…`) · 관문 보고 키에 쓰면 AccessDenied 여야 한다. 시험 객체가 남지 않게 거부될 쓰기만 해 본다.

### 4. 되돌리기

```bash
aws iam list-access-keys --user-name opsloop-fw-sync --query 'AccessKeyMetadata[].AccessKeyId' --output text
aws iam delete-access-key --user-name opsloop-fw-sync --access-key-id <위 ID>     # 사용자를 지우기 전에 키를 먼저 지운다
git revert <이 변경 커밋> && terraform plan && terraform apply                       # 삭제 2 · 변경 1
```

## 남은 과제

- 상태 파일을 S3 로 옮긴다. 백업용 버킷을 만들 때 함께 처리한다
- 노드 증설분(로드밸런서, 콘솔 백엔드 2대)을 코드에 추가한다
- cloud-init 으로 초기 설정을 코드화한다. 현재는 설치 스크립트가 그 역할을 한다
- 차단 목록(`block/v1/latest.json`)의 옛 판을 수명 주기 규칙으로 정리할지 정한다(지금은 버저닝으로 모두 남는다)
