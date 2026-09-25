# ══════════════════════════════════════════════════════════════
#  EC2 가 맡는 역할의 신뢰 정책 (센서 · 관문 역할이 함께 쓴다)
#
#  노드는 인바운드 관리 포트를 열지 않고 SSM 으로만 접근한다. 그 권한은 각 역할에 붙인
#  AmazonSSMManagedInstanceCore 에서 나온다. 옛 앱 노드 전용 역할은 노드와 함께 걷어냈다 (이슈 #37).
# ══════════════════════════════════════════════════════════════

data "aws_iam_policy_document" "ec2_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

# ══════════════════════════════════════════════════════════════
#  센서 역할 (WBS 3.4)
#
#  허니팟은 뚫리는 것이 전제인 장비다. 그래서 센서가 할 수 있는 일을
#  "원문 로그를 올리기"로만 좁힌다. 읽기 · 목록 · 삭제 권한이 없으므로
#  센서가 장악되어도 이미 올린 원장을 보거나 지울 수 없다.
#  DB 주소와 비밀번호는 센서에 두지 않는다.
# ══════════════════════════════════════════════════════════════

resource "aws_iam_role" "sensor" {
  name               = "opsloop-sensor-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  description        = "OpsLoop sensor: SSM access and put-only to the raw log archive"
}

resource "aws_iam_role_policy_attachment" "sensor_ssm_core" {
  role       = aws_iam_role.sensor.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# 허니팟 발생원(cowrie · decoy)만 쓴다. 관문 기록(sensor=gateway)은 아래 관문 역할의 몫이다 (이슈 #19)
data "aws_iam_policy_document" "sensor_put" {
  statement {
    sid     = "PutRawAndHeartbeatOnly"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.archive.arn}/raw/v1/sensor=cowrie/*",
      "${aws_s3_bucket.archive.arn}/raw/v1/sensor=decoy/*",
      "${aws_s3_bucket.archive.arn}/hb/v1/host=*/latest.json",
    ]
  }
}

resource "aws_iam_role_policy" "sensor_put" {
  name   = "opsloop-sensor-put"
  role   = aws_iam_role.sensor.id
  policy = data.aws_iam_policy_document.sensor_put.json
}

resource "aws_iam_instance_profile" "sensor" {
  name = "opsloop-sensor-role"
  role = aws_iam_role.sensor.name
}

# ══════════════════════════════════════════════════════════════
#  관문 역할 (이슈 #19)
#
#  허니팟과 역할을 나눈다. 장악된 허니팟이 관문 기록(sensor=gateway)을 흉내 내지 못하고,
#  관문이 허니팟 기록을 쓰지도 못한다. 어느 인스턴스가 어느 host 경로에 쓰는지는
#  버킷 정책이 인스턴스 단위로 다시 좁힌다 (s3.tf).
# ══════════════════════════════════════════════════════════════

resource "aws_iam_role" "gateway" {
  name               = "opsloop-gateway-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  description        = "OpsLoop gateway firewall: SSM access and put-only for its own deny log"
}

resource "aws_iam_role_policy_attachment" "gateway_ssm_core" {
  role       = aws_iam_role.gateway.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

data "aws_iam_policy_document" "gateway_put" {
  statement {
    sid     = "PutGatewayLogAndHeartbeatOnly"
    actions = ["s3:PutObject"]
    resources = [
      "${aws_s3_bucket.archive.arn}/raw/v1/sensor=gateway/*",
      "${aws_s3_bucket.archive.arn}/hb/v1/host=*/latest.json",
    ]
  }
}

resource "aws_iam_role_policy" "gateway_put" {
  name   = "opsloop-gateway-put"
  role   = aws_iam_role.gateway.id
  policy = data.aws_iam_policy_document.gateway_put.json
}

resource "aws_iam_instance_profile" "gateway" {
  name = "opsloop-gateway-role"
  role = aws_iam_role.gateway.name
}

# ══════════════════════════════════════════════════════════════
#  원장 읽기 사용자 (WBS 3.4)
#
#  내부망 데이터 노드가 S3 에서 원문을 가져갈 때 쓴다. 읽기와 목록만 된다.
#  액세스 키는 Terraform 으로 만들지 않는다. 만들면 비밀값이 상태 파일에
#  평문으로 남는다. 키는 CLI 로 발급해 데이터 노드에 바로 넣는다.
# ══════════════════════════════════════════════════════════════

resource "aws_iam_user" "archive_reader" {
  name = "opsloop-archive-reader"
  tags = { purpose = "internal data node pulls raw logs" }
}

data "aws_iam_policy_document" "archive_read" {
  statement {
    sid       = "ListLedger"
    actions   = ["s3:ListBucket"]
    resources = [aws_s3_bucket.archive.arn]
    condition {
      test     = "StringLike"
      variable = "s3:prefix"
      values   = ["raw/*", "hb/*"]
    }
  }
  statement {
    sid       = "ReadLedger"
    actions   = ["s3:GetObject", "s3:GetObjectVersion"]
    resources = ["${aws_s3_bucket.archive.arn}/raw/*", "${aws_s3_bucket.archive.arn}/hb/*"]
  }
}

resource "aws_iam_user_policy" "archive_read" {
  name   = "opsloop-archive-read"
  user   = aws_iam_user.archive_reader.name
  policy = data.aws_iam_policy_document.archive_read.json
}

# ══════════════════════════════════════════════════════════════
#  공개 취약점 정보 쓰기 사용자 (이슈 #39)
#
#  데이터 노드의 수집기(opsloop-cti)가 KEV · EPSS · OSV · NVD 원본과 자산 조사 결과를
#  cti/ 에 올릴 때 쓴다. 올리기만 된다. 읽기 · 목록 · 삭제가 없고 원장(raw/ · hb/)에는
#  쓰지 못한다(버킷 정책). 센서 · 관문 역할, 원장 읽기 사용자와 주체를 나눈다.
#  원본 키에 내용 해시가 들어가 같은 날 같은 내용은 412 로 끝나므로 읽기가 필요 없다.
#  원본을 다시 읽는 재현 작업은 관리자 자격으로 한다.
#  액세스 키는 Terraform 으로 만들지 않는다. 만들면 비밀값이 상태 파일에 평문으로 남는다.
#  키는 CLI 로 발급해 데이터 노드 /etc/opsloop/s3-cti.env 에 파이프로 바로 넣는다 (README).
# ══════════════════════════════════════════════════════════════

resource "aws_iam_user" "cti_writer" {
  name = "opsloop-cti-writer"
  tags = { purpose = "internal data node archives CTI originals" }
}

data "aws_iam_policy_document" "cti_put" {
  statement {
    sid       = "PutCtiOnly"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.archive.arn}/cti/*"]
  }
}

resource "aws_iam_user_policy" "cti_put" {
  name   = "opsloop-cti-put"
  user   = aws_iam_user.cti_writer.name
  policy = data.aws_iam_policy_document.cti_put.json
}
