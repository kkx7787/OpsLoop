# ══════════════════════════════════════════════════════════════
#  DMZ 구간 (WBS 3.1 · 이슈 #15)
#
#  허니팟을 관문 방화벽 뒤로 내리기 위한 새 VPC 다. 기본 VPC 의 노드들은
#  이전이 끝날 때까지 그대로 두므로(instances.tf) 여기 자원은 기존 자원과
#  섞이지 않는다. 주소는 네트워크 설계 2.1 을 따른다.
#
#  공개 서브넷(10.0.1.0/24)에는 방화벽만 있고 공인 주소도 여기에만 붙는다.
#  DMZ 서브넷(10.0.21.0/24)의 기본 경로는 인터넷 게이트웨이가 아니라
#  방화벽의 네트워크 인터페이스다. 그래서 DMZ 는 방화벽을 거치지 않고는
#  어디에도 닿지 못하고, 방화벽 규칙이 유입 · 유출을 통제 · 기록한다.
# ══════════════════════════════════════════════════════════════

resource "aws_vpc" "dmz" {
  cidr_block           = "10.0.0.0/16"
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = { Name = "opsloop-dmz" }
}

resource "aws_internet_gateway" "dmz" {
  vpc_id = aws_vpc.dmz.id
  tags   = { Name = "opsloop-dmz" }
}

# 공개 서브넷. 공인 주소는 EIP 로 방화벽에만 붙이므로 자동 부여는 끈다
resource "aws_subnet" "public" {
  vpc_id                  = aws_vpc.dmz.id
  cidr_block              = "10.0.1.0/24"
  availability_zone       = var.dmz_az
  map_public_ip_on_launch = false

  tags = { Name = "opsloop-public" }
}

# DMZ 서브넷. 공인 주소 없음. 방화벽과 같은 가용 영역에 둔다
resource "aws_subnet" "dmz" {
  vpc_id                  = aws_vpc.dmz.id
  cidr_block              = "10.0.21.0/24"
  availability_zone       = var.dmz_az
  map_public_ip_on_launch = false

  tags = { Name = "opsloop-dmz" }
}

# ── 라우트 표 ─────────────────────────────────────────────────

resource "aws_route_table" "public" {
  vpc_id = aws_vpc.dmz.id
  tags   = { Name = "opsloop-public" }
}

resource "aws_route" "public_default" {
  route_table_id         = aws_route_table.public.id
  destination_cidr_block = "0.0.0.0/0"
  gateway_id             = aws_internet_gateway.dmz.id
}

resource "aws_route_table_association" "public" {
  subnet_id      = aws_subnet.public.id
  route_table_id = aws_route_table.public.id
}

resource "aws_route_table" "dmz" {
  vpc_id = aws_vpc.dmz.id
  tags   = { Name = "opsloop-dmz" }
}

# DMZ 의 기본 경로는 방화벽 인터페이스다. 인스턴스가 아니라 인터페이스를
# 가리키므로 방화벽 인스턴스를 교체해도 경로는 그대로다 (gateway.tf)
resource "aws_route" "dmz_default" {
  route_table_id         = aws_route_table.dmz.id
  destination_cidr_block = "0.0.0.0/0"
  network_interface_id   = aws_network_interface.gateway.id
}

resource "aws_route_table_association" "dmz" {
  subnet_id      = aws_subnet.dmz.id
  route_table_id = aws_route_table.dmz.id
}

# ── S3 게이트웨이 엔드포인트 ──────────────────────────────────
#
#  센서가 원장에 올리는 길이다. 두 라우트 표에 S3 대역의 경로가 들어가므로
#  DMZ 에서 S3 로 가는 트래픽은 방화벽을 거치지 않는다. 정책은 원장 버킷으로만
#  좁혀, 같은 리전 S3 에서는 다른 버킷(다른 계정 포함)에 닿지 않는다. 할 수 있는
#  동작은 IAM(iam.tf) · 버킷 정책(s3.tf)이 따로 좁힌다. 다른 리전 S3 · 가속 엔드포인트는 접두사
#  목록 밖이라 인터넷 주소인데, 허니팟 보안그룹이 접두사 목록 · SSM 엔드포인트 밖 443 을 내보내지
#  않고 방화벽도 DMZ 유출을 전부 거부하므로 닿지 않는다 (이슈 #19).

data "aws_iam_policy_document" "s3_endpoint" {
  statement {
    sid       = "LedgerBucketOnly"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.archive.arn, "${aws_s3_bucket.archive.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

resource "aws_vpc_endpoint" "s3" {
  vpc_id            = aws_vpc.dmz.id
  service_name      = "com.amazonaws.${var.region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = [aws_route_table.public.id, aws_route_table.dmz.id]
  policy            = data.aws_iam_policy_document.s3_endpoint.json

  tags = { Name = "opsloop-s3" }
}
