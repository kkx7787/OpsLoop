# ══════════════════════════════════════════════════════════════
#  인스턴스 역할
#
#  두 노드 모두 인바운드 관리 포트를 열지 않고 SSM 으로만 접근한다.
#  그 접근 권한이 이 역할에서 나온다. 역할이 빠지면 키 페어도 없는
#  노드는 접근 경로 자체가 사라지므로, 인스턴스보다 먼저 만들어져야 한다.
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

resource "aws_iam_role" "ssm" {
  name               = "opsloop-ssm-role"
  assume_role_policy = data.aws_iam_policy_document.ec2_assume.json
  description        = "SSM Session Manager access for OpsLoop nodes"
}

resource "aws_iam_role_policy_attachment" "ssm_core" {
  role       = aws_iam_role.ssm.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

resource "aws_iam_instance_profile" "ssm" {
  name = "opsloop-ssm-role"
  role = aws_iam_role.ssm.name
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

data "aws_iam_policy_document" "sensor_put" {
  statement {
    sid       = "PutRawAndHeartbeatOnly"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.archive.arn}/raw/*", "${aws_s3_bucket.archive.arn}/hb/*"]
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
