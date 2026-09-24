# ══════════════════════════════════════════════════════════════
#  DMZ 허니팟 (WBS 3.1.3 · 이슈 #15)
#
#  옛 허니팟(2026-09-25 종료 · 이슈 #37)의 이미지로 DMZ 서브넷에 다시 띄웠다. 공인 주소가
#  없고 방화벽을 거쳐서만 닿는다. 이미지가 있어야 만들 수 있으므로 count 로
#  켜고 끈다: honeypot_dmz_ami 가 비어 있으면 아무것도 만들지 않는다.
#
#  count 를 쓰므로 prevent_destroy 를 두지 않았다. 변수를 비우거나 AMI 를
#  바꾸면 계획에 destroy · replace 가 나온다. 그때 적용하면 아직 원장에
#  오르지 않은 원문 로그를 잃는다 (README "DMZ 재구성").
# ══════════════════════════════════════════════════════════════

resource "aws_security_group" "honeypot_dmz" {
  name        = "opsloop-honeypot-dmz-sg"
  description = "OpsLoop honeypot in DMZ"
  vpc_id      = aws_vpc.dmz.id

  tags = { Name = "opsloop-honeypot-dmz-sg" }

  lifecycle {
    create_before_destroy = true
  }
}

# 방화벽이 넘기는 세 포트. DNAT 는 출발지를 보존하므로 공격자 주소 그대로 온다.
# 그래서 인터넷 전체로 연다. DMZ 에는 방화벽을 거치지 않고는 닿을 수 없다
resource "aws_vpc_security_group_ingress_rule" "honeypot_dmz_ssh" {
  security_group_id = aws_security_group.honeypot_dmz.id
  description       = "honeypot ssh"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "honeypot_dmz_telnet" {
  security_group_id = aws_security_group.honeypot_dmz.id
  description       = "honeypot telnet"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 23
  to_port           = 23
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "honeypot_dmz_decoy" {
  security_group_id = aws_security_group.honeypot_dmz.id
  description       = "web decoy"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 8080
  to_port           = 8080
  ip_protocol       = "tcp"
}

# 유출은 전부 연다. 보안그룹이 먼저 버리면 시도가 방화벽에 닿지 않아 기록이 남지 않는다(관문 보안그룹의
# 유입을 전부 연 것과 같은 이유). 원장(S3)과 SSM 은 VPC 엔드포인트 경로로 가고, 그 밖의 모든 시도는 방화벽
# forward 체인이 거부 · 기록한다. 방화벽 규칙이 잘못돼도 관문 보안그룹(443 · 53 만 유출)과 인터넷 게이트웨이
# (공인 주소 짝이 없는 사설 출발지는 버린다)가 남는다 (이슈 #19). 허니팟과 디코이는 한 대라 가르지 않는다
resource "aws_vpc_security_group_egress_rule" "honeypot_dmz_all" {
  security_group_id = aws_security_group.honeypot_dmz.id
  description       = "all outbound; the gateway decides and logs"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# ──────────────────────────────────────────────────────────────

resource "aws_instance" "honeypot_dmz" {
  count = var.honeypot_dmz_ami == "" ? 0 : 1

  ami           = var.honeypot_dmz_ami
  instance_type = "t3.micro"
  subnet_id     = aws_subnet.dmz.id
  # 방화벽 규칙(nftables.conf 의 HONEYPOT)이 이 주소로 넘긴다. 같이 바꿔야 한다
  private_ip             = "10.0.21.10"
  vpc_security_group_ids = [aws_security_group.honeypot_dmz.id]
  # 센서 전용 역할. 원문을 S3 에 올리기만 한다 (iam.tf)
  iam_instance_profile = aws_iam_instance_profile.sensor.name
  key_name             = var.key_name

  associate_public_ip_address = false

  root_block_device {
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = false
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
    # 홉 제한 1: 컨테이너(인터넷에 노출된 디코이 포함)는 인스턴스 자격증명을 받지 못한다
    http_put_response_hop_limit = 1
  }

  # 첫 부팅에 이미지가 담고 온 업로더 설정을 새 인스턴스에 맞춘다. bootcmd 는 부팅마다 도므로
  # cloud-init-per instance 로 감싸 인스턴스당 한 번만 돌게 한다(재부팅 때 타이머 · 위치 기억을 건드리지 않는다).
  #   - 타이머를 먼저 끈다(OnBootSec 2분보다 bootcmd 가 빠르다). 옛 인스턴스 ID 로 한 회차가 올라가면
  #     옛 host 세대에 겹치는 조각이 생기고 옛 생존 신호를 덮는다.
  #   - 위치 기억(state.json)을 지워 0 부터 다시 올린다. 새 host 는 새 세대라 중간부터 시작하면 풀러가
  #     원장 구멍으로 보고 탐지를 보류한다. 이벤트는 line_hash 로 중복 없이 들어간다.
  #   - OPSLOOP_HOST 를 새 인스턴스 ID 로 바꾼다(IMDSv2).
  #   확인이 끝나면 운영자가 타이머를 켠다 (README "DMZ 재구성" 3단계).
  user_data = <<-EOT
    #cloud-config
    bootcmd:
      - [ cloud-init-per, instance, opsloop-upload-reset, sh, -c, "systemctl disable --now opsloop-upload.timer; rm -f /var/lib/opsloop-upload/state.json" ]
    runcmd:
      - |
        TOKEN=$(curl -s -X PUT http://169.254.169.254/latest/api/token -H "X-aws-ec2-metadata-token-ttl-seconds: 60")
        ID=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/instance-id)
        case "$ID" in i-*) sed -i "s/^OPSLOOP_HOST=.*/OPSLOOP_HOST=$ID/" /etc/default/opsloop-upload ;; esac
  EOT

  tags = { Name = "opsloop-honeypot-dmz" }

  lifecycle {
    ignore_changes = [user_data]
  }
}
