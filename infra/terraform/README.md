# OpsLoop 인프라 코드

콘솔에서 손으로 만든 자원을 코드의 관리 아래로 옮긴다.

## 왜 새로 만들지 않는가

수집 노드에는 축적된 원문 로그가 있고, 공인 주소가 바뀌면 유입 중인
공격이 끊긴다. 재현성을 확보하려고 실측 데이터를 버리는 것은 순서가
뒤바뀐 일이므로, 기존 자원을 가져오는 방식을 택했다.

## 준비

로컬에 AWS 자격증명이 필요하다. 저장소에는 어떤 키도 두지 않는다.

```bash
aws configure          # ~/.aws/credentials 에 저장된다
aws sts get-caller-identity
```

## 절차

### 1. 값 채우기

```bash
cp terraform.tfvars.example terraform.tfvars
```

콘솔에서 확인할 값은 넷이다.

| 값 | 확인 위치 |
|---|---|
| `vpc_id`, `subnet_id` | EC2 → 인스턴스 → 네트워킹 탭 |
| `import_*_instance_id` | 인스턴스 목록의 인스턴스 ID |
| `import_*_sg_id` | EC2 → 보안 그룹 |
| `admin_cidr` | 현재 공인 IP + `/32` |

AMI 두 개는 아직 비워둔다. 3단계에서 채운다.

### 2. 초기화와 첫 가져오기

```bash
terraform init
terraform plan
```

AMI 가 비어 있어 이 단계에서는 오류가 난다. 임시로 아무 값이나 넣고
가져오기를 먼저 수행한다.

```bash
terraform plan  -var 'honeypot_ami=ami-0' -var 'app_ami=ami-0'
terraform apply -var 'honeypot_ami=ami-0' -var 'app_ami=ami-0'
```

가져오기가 끝나면 상태 파일에 실제 값이 들어온다.

### 3. 실제 AMI 채우기

```bash
terraform state show aws_instance.honeypot | grep -m1 '^ *ami'
terraform state show aws_instance.app      | grep -m1 '^ *ami'
```

두 값을 `terraform.tfvars` 에 옮겨 적는다.

### 4. 계획이 비워질 때까지 반복

```bash
terraform plan
```

`No changes` 가 나올 때까지 코드를 실제 상태에 맞춘다. 콘솔에서 만든
자원에는 코드에 적지 않은 기본값이 붙어 있어 몇 차례 조정이 필요하다.

**계획에 `destroy` 나 `replace` 가 보이면 적용하지 않는다.** 인스턴스에
`prevent_destroy` 를 걸어두어 실수로 지워지지는 않으나, 계획이 그렇게
나온다는 것은 코드가 실제와 어긋났다는 뜻이다.

### 5. 마무리

계획이 비워지면 가져오기용 잔재를 제거한다.

```bash
rm imports.tf
```

`variables.tf` 의 `import_*` 변수와 `terraform.tfvars` 의 해당 항목도
함께 지운다. 이 시점부터 코드가 인프라의 정본이다.

## 이후

```bash
terraform plan     # 콘솔에서 누가 무엇을 바꿨는지 드러난다
```

계획에 차이가 잡히면 둘 중 하나다. 콘솔에서 직접 손댔거나, 코드를 고치고
아직 적용하지 않았거나. 어느 쪽이든 원인을 확인한 뒤 한쪽으로 맞춘다.

## DMZ 재구성 (이슈 #15 · #19)

허니팟을 관문 방화벽 뒤 DMZ 서브넷으로 내린다. 새 VPC(`dmz.tf`) · 방화벽(`gateway.tf`) ·
SSM 엔드포인트(`ssm_endpoints.tf`) · DMZ 허니팟(`honeypot_dmz.tf`)이 더해지고, 기존
노드(`instances.tf`)는 이전이 끝날 때까지 그대로다. 설계는 `docs/2026-09-18-네트워크-설계.md`
2.1 · 3.1 · 4장.

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
                                          # 문 10개(DMZ 허니팟이 생기면 11개). OnlyOwnHost* 의 ARN 이 terraform state show 의 인스턴스 ARN 과 같다
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
접두사도 닫힌다 — 이 버킷은 원장만 담고, DB 를 다시 넘길 일이 있으면 다른 버킷을 쓴다). 새 노드는
`s3.tf` 의 `ledger_writers` 에 더해야 원장에 쓴다. 풀러의 발생원 · 호스트 짝 확인(`OPSLOOP_GATEWAY_HOSTS`,
아래 2단계)은 그 뒤의 둘째 벽이다. DNS(VPC 리졸버)는 남는 유출 통로다(DNS 방화벽은 범위 밖).

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

### 4. 전환 · 옛 인스턴스 종료

방화벽 EIP 로 공격이 들어오기 시작하면(`gateway.log` 의 gw-input-drop, 원장의 새 host 로
cowrie · decoy 조각) 48시간 두 인스턴스를 대조한다. 옛 인스턴스 종료는 #10 전환(옛 수집
끄기) 뒤에 하고, 그때 `instances.tf` 의 정의와 `prevent_destroy`, `s3.tf` 의 `ledger_writers`
옛 허니팟 항목을 함께 걷어낸다.
앱 노드 종료(3.1.5)도 그 뒤다.

옛 인스턴스를 종료한 뒤에 할 일:

- 데이터 노드 `OPSLOOP_HOSTS` 에서 옛 ID 를 뺀다. 두면 옛 생존 신호가 15분을 넘겨 매 회차
  종료 코드 11(오래된 생존 신호)이 난다. 옛 host 의 원장은 그대로 남고 이미 적재돼 있다.
- 이전에 쓴 AMI 와 그 스냅샷을 등록 해제 · 삭제한다(`aws ec2 deregister-image`, `delete-snapshot`).
  이미지에는 원문 로그와 업로더 설정이 담겨 있다.

## 남은 과제

- 상태 파일을 S3 로 옮긴다. 백업용 버킷을 만들 때 함께 처리한다
- 노드 증설분(로드밸런서, 콘솔 백엔드 2대)을 코드에 추가한다
- cloud-init 으로 초기 설정을 코드화한다. 현재는 설치 스크립트가 그 역할을 한다
