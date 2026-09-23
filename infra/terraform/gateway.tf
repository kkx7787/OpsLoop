# ══════════════════════════════════════════════════════════════
#  관문 방화벽 (WBS 3.1 · 이슈 #15)
#
#  공개 서브넷에 하나 있는 노드다. 인터넷에서 오는 22 · 23 · 8080 을 DMZ 의
#  허니팟으로 넘기고(DNAT), DMZ 에서 나가는 것은 전부 거부하고 기록한다. 원장(S3)과
#  SSM 은 VPC 엔드포인트로 가서 방화벽을 지나지 않는다 (dmz.tf · ssm_endpoints.tf).
#  규칙은 infra/aws/gateway/nftables.conf 에 있고 첫 부팅에 cloud-init 이 놓는다.
#
#  네트워크 인터페이스와 공인 주소(EIP)를 인스턴스와 따로 둔다. DMZ 라우트 표가
#  이 인터페이스를 가리키고 공인 주소가 여기 붙어 있으므로, 인스턴스를 교체해도
#  경로와 공인 주소는 남는다. 첫 부팅 때 이미 공인 주소가 있어 cloud-init 의
#  패키지 설치가 막히지 않는 것도 이 순서 덕분이다.
#
#  거부 기록을 원장(sensor=gateway)에 올리는 관문 역할을 쓴다. 허니팟의 센서 역할과
#  다르다. 그 역할에 SSM 권한도 있어 관리 접근은 SSM 으로 한다 (iam.tf).
# ══════════════════════════════════════════════════════════════

# Canonical 이 SSM 파라미터로 공개하는 최신 Ubuntu 24.04 AMI.
# 값이 주기적으로 바뀌므로 인스턴스에서는 ami 변경을 무시한다
data "aws_ssm_parameter" "ubuntu_2404" {
  name = "/aws/service/canonical/ubuntu/server/24.04/stable/current/amd64/hvm/ebs-gp3/ami-id"
}

# ── 보안그룹 ──────────────────────────────────────────────────
#
#  보안그룹은 방화벽이 전달하는 트래픽에도 적용된다. 그래서 유입 · 유출이
#  nftables 규칙과 짝을 이룬다. 방화벽 규칙이 잘못돼도 이 겹이 남는다.

resource "aws_security_group" "gateway" {
  name        = "opsloop-gateway-sg"
  description = "OpsLoop gateway firewall"
  vpc_id      = aws_vpc.dmz.id

  tags = { Name = "opsloop-gateway-sg" }

  lifecycle {
    create_before_destroy = true
  }
}

# 유입은 전부 연다. 설계 3.1 은 "어떤 포트를 얼마나 두드렸는지" 가 방화벽 기록에 남아야 한다고
# 정했는데, 보안그룹이 먼저 버리면 nftables 가 볼 수 없어 기록이 남지 않는다. 그래서 기록은
# nftables(input 정책 drop + gw-input-drop)가 맡고, 보안그룹은 유출 쪽만 좁힌다.
# 방화벽 자신은 듣는 포트가 없다. sshd 는 첫 부팅에 끄고(cloud-init) 관리는 SSM(밖으로 여는 연결)뿐이다.
# 22 · 23 · 8080 은 prerouting 에서 DNAT 되어 허니팟으로 간다.
resource "aws_vpc_security_group_ingress_rule" "gateway_all" {
  security_group_id = aws_security_group.gateway.id
  description       = "all inbound; nftables decides and logs"
  cidr_ipv4         = "0.0.0.0/0"
  ip_protocol       = "-1"
}

# 유출. 방화벽 자신의 apt(https 미러, 첫 부팅)와 SSM(사설 DNS 로 엔드포인트로 풀린다)이 쓴다.
# DMZ 의 통신은 nftables 가 전부 거부하므로 여기로 오지 않는다
resource "aws_vpc_security_group_egress_rule" "gateway_https" {
  security_group_id = aws_security_group.gateway.id
  description       = "apt mirror, SSM"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "gateway_dns" {
  security_group_id = aws_security_group.gateway.id
  description       = "name resolution"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 53
  to_port           = 53
  ip_protocol       = "udp"
}

# DNAT 로 허니팟에 넘기는 세 포트. DMZ 서브넷 밖으로는 열지 않는다
resource "aws_vpc_security_group_egress_rule" "gateway_to_dmz_ssh" {
  security_group_id = aws_security_group.gateway.id
  description       = "DNAT to honeypot ssh"
  cidr_ipv4         = aws_subnet.dmz.cidr_block
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "gateway_to_dmz_telnet" {
  security_group_id = aws_security_group.gateway.id
  description       = "DNAT to honeypot telnet"
  cidr_ipv4         = aws_subnet.dmz.cidr_block
  from_port         = 23
  to_port           = 23
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "gateway_to_dmz_decoy" {
  security_group_id = aws_security_group.gateway.id
  description       = "DNAT to web decoy"
  cidr_ipv4         = aws_subnet.dmz.cidr_block
  from_port         = 8080
  to_port           = 8080
  ip_protocol       = "tcp"
}

# ── 인터페이스 · 공인 주소 ────────────────────────────────────

resource "aws_network_interface" "gateway" {
  subnet_id       = aws_subnet.public.id
  private_ips     = ["10.0.1.10"]
  security_groups = [aws_security_group.gateway.id]
  # 자기 주소가 아닌 패킷을 받고 내보내는 장비다. 이 확인을 끄지 않으면 전달이 버려진다
  source_dest_check = false

  tags = { Name = "opsloop-gateway" }
}

resource "aws_eip" "gateway" {
  domain            = "vpc"
  network_interface = aws_network_interface.gateway.id

  tags = { Name = "opsloop-gateway" }

  # 인터넷 게이트웨이가 먼저 있어야 붙는다
  depends_on = [aws_internet_gateway.dmz]
}

# ── 인스턴스 ──────────────────────────────────────────────────

resource "aws_instance" "gateway" {
  ami           = data.aws_ssm_parameter.ubuntu_2404.insecure_value
  instance_type = var.gateway_instance_type
  # 관문 프로파일. SSM 접근과 자기 거부 기록 쓰기(sensor=gateway)만 있다 (iam.tf)
  iam_instance_profile = aws_iam_instance_profile.gateway.name
  # source_dest_check 는 인터페이스(aws_network_interface.gateway)에 둔다. network_interface 블록과는 같이 못 쓴다

  network_interface {
    network_interface_id = aws_network_interface.gateway.id
    device_index         = 0
  }

  # 첫 부팅: 방화벽 · 기록 · 회전 파일을 놓고 전달을 켠다. 16KB 상한 안이어야 한다
  user_data = templatefile("${path.module}/../aws/gateway/cloud-init.yaml.tftpl", {
    nftables_conf  = file("${path.module}/../aws/gateway/nftables.conf")
    rsyslog_conf   = file("${path.module}/../aws/gateway/rsyslog-opsloop.conf")
    logrotate_conf = file("${path.module}/../aws/gateway/logrotate-opsloop")
  })

  root_block_device {
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = false
  }

  # 메타데이터 서비스는 토큰을 요구하는 방식만 허용한다 (instances.tf 와 같다)
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
  }

  tags = { Name = "opsloop-gateway" }

  # ami: 파라미터가 새 AMI 를 가리켜도 교체하지 않는다.
  # user_data: cloud-init 은 첫 부팅에만 돈다. 차이가 잡혀 적용하면 인스턴스가 멈췄다
  # 켜질 뿐 규칙은 바뀌지 않으므로, 규칙 변경은 SSM 으로 파일을 바꿔 적용한다 (README)
  lifecycle {
    ignore_changes = [ami, user_data]
  }

  # 첫 부팅의 패키지 설치가 인터넷에 닿으려면 공인 주소와 기본 경로가 먼저 있어야 한다
  depends_on = [aws_eip.gateway, aws_route.public_default, aws_route_table_association.public]
}
