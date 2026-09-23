# ══════════════════════════════════════════════════════════════
#  SSM 전용 엔드포인트 (이슈 #19)
#
#  DMZ 가 인터넷으로 나갈 유일한 이유였던 SSM 을 VPC 안으로 들인다. ssm · ssmmessages ·
#  ec2messages 세 인터페이스 엔드포인트가 DMZ 서브넷에 생기고, 사설 DNS 를 켜 두면
#  VPC 안의 노드(방화벽 포함)가 평소 이름으로 부르는 SSM 이 이 엔드포인트로 풀린다.
#  그래서 DMZ 에서 방화벽을 지나 나가는 통신은 하나도 남지 않는다 (nftables.conf 는 전부 거부 · 기록).
#
#  엔드포인트 정책은 이 계정의 두 인스턴스 역할만 통과시킨다. 장악된 허니팟이 남의 계정
#  자격증명이나 유출된 사용자 키로 이 길을 유출 통로로 쓰는 것을 막는다.
# ══════════════════════════════════════════════════════════════

data "aws_caller_identity" "current" {}

locals {
  # 엔드포인트 인터페이스 주소를 고정한다. AWS 가 고르게 두면 허니팟 고정 주소(10.0.21.10)를 선점할 수 있다
  ssm_services = { ssm = "10.0.21.251", ssmmessages = "10.0.21.252", ec2messages = "10.0.21.253" }
}

resource "aws_security_group" "ssm_endpoints" {
  name        = "opsloop-ssm-endpoints-sg"
  description = "OpsLoop SSM interface endpoints"
  vpc_id      = aws_vpc.dmz.id

  tags = { Name = "opsloop-ssm-endpoints-sg" }

  lifecycle {
    create_before_destroy = true
  }
}

# 엔드포인트는 VPC 안에서만 부른다. DMZ(허니팟)와 공개 서브넷(방화벽)의 443 만 받고, 유출 규칙은 없다
resource "aws_vpc_security_group_ingress_rule" "ssm_endpoints_https" {
  for_each = { dmz = aws_subnet.dmz.cidr_block, public = aws_subnet.public.cidr_block }

  security_group_id = aws_security_group.ssm_endpoints.id
  description       = "SSM from ${each.key} subnet"
  cidr_ipv4         = each.value
  from_port         = 443
  to_port           = 443
  ip_protocol       = "tcp"
}

data "aws_iam_policy_document" "ssm_endpoint" {
  statement {
    sid       = "ThisAccountOnly"
    actions   = ["*"]
    resources = ["*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    # 이 VPC 에서 SSM 을 쓸 주체는 두 인스턴스 역할뿐이다. 유출된 사용자 키로도 못 쓴다
    condition {
      test     = "ArnEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.sensor.arn, aws_iam_role.gateway.arn]
    }
  }
}

resource "aws_vpc_endpoint" "ssm" {
  for_each = local.ssm_services

  vpc_id            = aws_vpc.dmz.id
  service_name      = "com.amazonaws.${var.region}.${each.key}"
  vpc_endpoint_type = "Interface"
  # 주소를 고정해도 subnet_ids 는 있어야 한다 (SubnetConfigurations 의 서브넷이 SubnetIds 에도 있어야 함)
  subnet_ids          = [aws_subnet.dmz.id]
  security_group_ids  = [aws_security_group.ssm_endpoints.id]
  private_dns_enabled = true
  policy              = data.aws_iam_policy_document.ssm_endpoint.json

  subnet_configuration {
    subnet_id = aws_subnet.dmz.id
    ipv4      = each.value
  }

  tags = { Name = "opsloop-${each.key}" }
}
