# ══════════════════════════════════════════════════════════════
#  노드
#
#  ami 와 user_data 는 변경 감지 대상에서 제외한다.
#  AMI 는 배포처에서 주기적으로 갱신되므로 그대로 두면 계획에
#  차이가 잡히고, 적용하면 인스턴스가 교체된다. 수집 노드가 교체되면
#  축적된 원문 로그와 공인 IP 를 함께 잃는다.
# ══════════════════════════════════════════════════════════════

resource "aws_instance" "honeypot" {
  ami                    = var.honeypot_ami
  instance_type          = "t3.micro"
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.honeypot.id]
  iam_instance_profile   = aws_iam_instance_profile.ssm.name
  key_name               = var.key_name

  associate_public_ip_address = true

  root_block_device {
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = false
  }

  # 메타데이터 서비스는 토큰을 요구하는 방식만 허용한다.
  # 애플리케이션 취약점을 통한 자격증명 탈취를 어렵게 만든다.
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = { Name = "opsloop-honeypot" }

  lifecycle {
    prevent_destroy = true
    ignore_changes  = [ami, user_data, user_data_base64]
  }
}

resource "aws_instance" "app" {
  ami                    = var.app_ami
  instance_type          = "t3.small"
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.app.id]
  iam_instance_profile   = aws_iam_instance_profile.ssm.name

  associate_public_ip_address = true

  root_block_device {
    volume_size           = 20
    volume_type           = "gp3"
    delete_on_termination = true
    encrypted             = false
  }

  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "required"
  }

  tags = { Name = "opsloop-app" }

  lifecycle {
    prevent_destroy = true
    ignore_changes  = [ami, user_data, user_data_base64]
  }
}
