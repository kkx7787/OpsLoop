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
