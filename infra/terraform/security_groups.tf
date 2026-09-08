# ══════════════════════════════════════════════════════════════
#  보안그룹
#
#  두 노드의 역할이 다르므로 규칙도 정반대다.
#  수집 노드는 인터넷 전체에 두 포트를 열고, 앱 노드는 아무에게도
#  열지 않는다. 노드 간 통신은 IP 가 아니라 보안그룹 참조로 허용해
#  주소가 바뀌어도 규칙이 따라가게 한다.
# ══════════════════════════════════════════════════════════════

resource "aws_security_group" "honeypot" {
  name        = "opsloop-honeypot-sg"
  description = "OpsLoop honeypot"
  vpc_id      = var.vpc_id

  tags = { Name = "opsloop-honeypot-sg" }

  lifecycle {
    create_before_destroy = true
  }
}

# 인터넷 전체에 여는 두 포트. 이것이 수집원이다.
resource "aws_vpc_security_group_ingress_rule" "honeypot_ssh" {
  security_group_id = aws_security_group.honeypot.id
  description       = "honeypot ssh"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 22
  to_port           = 22
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_ingress_rule" "honeypot_telnet" {
  security_group_id = aws_security_group.honeypot.id
  description       = "honeypot telnet"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 23
  to_port           = 23
  ip_protocol       = "tcp"
}

# 아웃바운드는 최소 집합만 남긴다.
# 침해 시 제3자를 향한 경유지로 쓰이는 것을 막기 위해서다.
resource "aws_vpc_security_group_egress_rule" "honeypot_https" {
  security_group_id = aws_security_group.honeypot.id
  description       = "SSM, container registry"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "honeypot_dns" {
  security_group_id = aws_security_group.honeypot.id
  description       = "name resolution"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 53
  to_port           = 53
  ip_protocol       = "udp"
}

# 수집 노드가 앱 노드 데이터베이스에 적재한다.
resource "aws_vpc_security_group_egress_rule" "honeypot_to_db" {
  security_group_id            = aws_security_group.honeypot.id
  description                  = "app node database"
  referenced_security_group_id = aws_security_group.app.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

# ──────────────────────────────────────────────────────────────

resource "aws_security_group" "app" {
  name = "opsloop-app-sg"
  # 콘솔 마법사가 붙인 문구다. AWS 는 보안그룹 설명을 생성 후 변경할 수 없어
  # 코드를 실물에 맞춘다. 여기를 고치면 보안그룹이 교체되고, 그 과정에서
  # 인스턴스 연결과 데이터베이스 접근 경로가 끊긴다.
  description = "launch-wizard-1 created 2026-09-07T14:11:09.162Z"
  vpc_id      = var.vpc_id

  tags = { Name = "opsloop-app-sg" }

  lifecycle {
    create_before_destroy = true
  }
}

# 개발 중 콘솔이 붙는 지점. 운영 전환 시 로드밸런서 뒤로 옮긴다.
resource "aws_vpc_security_group_ingress_rule" "app_api" {
  security_group_id = aws_security_group.app.id
  description       = "API (development)"
  cidr_ipv4         = var.admin_cidr
  from_port         = 8000
  to_port           = 8000
  ip_protocol       = "tcp"
}

# 데이터베이스는 수집 노드에게만 연다. 인터넷에서는 도달 불가.
resource "aws_vpc_security_group_ingress_rule" "app_db_from_collector" {
  security_group_id            = aws_security_group.app.id
  description                  = "collector node"
  referenced_security_group_id = aws_security_group.honeypot.id
  from_port                    = 5432
  to_port                      = 5432
  ip_protocol                  = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "app_https" {
  security_group_id = aws_security_group.app.id
  description       = "SSM, container registry"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

resource "aws_vpc_security_group_egress_rule" "app_dns" {
  security_group_id = aws_security_group.app.id
  description       = "name resolution"
  cidr_ipv4         = "0.0.0.0/0"
  from_port         = 53
  to_port           = 53
  ip_protocol       = "udp"
}
