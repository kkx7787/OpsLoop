# ══════════════════════════════════════════════════════════════
#  원문 로그 보관소 (WBS 3.4)
#
#  센서가 올리고 내부망이 가져가는 단방향 경로의 중간 지점이다.
#  원문 로그는 원장이다. DB 는 여기서 언제든 다시 만들 수 있지만,
#  원문이 사라지면 리플레이 평가도 재생성 대조도 할 수 없다.
#  그래서 쓰기는 센서 역할만, 덮어쓴 이전 판은 버저닝으로 남긴다.
#
#  버킷은 2026-09-21 CLI 로 먼저 만들었고 여기서 코드 관리로 가져온다.
# ══════════════════════════════════════════════════════════════

import {
  to = aws_s3_bucket.archive
  id = "opsloop-archive-739272173045"
}

import {
  to = aws_s3_bucket_public_access_block.archive
  id = "opsloop-archive-739272173045"
}

import {
  to = aws_s3_bucket_server_side_encryption_configuration.archive
  id = "opsloop-archive-739272173045"
}

resource "aws_s3_bucket" "archive" {
  bucket = "opsloop-archive-739272173045"
  tags   = { Name = "opsloop-archive" }

  lifecycle {
    prevent_destroy = true
  }
}

resource "aws_s3_bucket_public_access_block" "archive" {
  bucket                  = aws_s3_bucket.archive.id
  block_public_acls       = true
  ignore_public_acls      = true
  block_public_policy     = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "archive" {
  bucket = aws_s3_bucket.archive.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_versioning" "archive" {
  bucket = aws_s3_bucket.archive.id
  versioning_configuration {
    status = "Enabled"
  }
}

data "aws_iam_policy_document" "archive_bucket" {
  # 암호화되지 않은 연결은 거부한다
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.archive.arn, "${aws_s3_bucket.archive.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  # 원장에는 센서 역할만 쓴다. 루트 계정을 포함한 다른 모든 주체의 쓰기를 거부한다.
  # IAM 권한이 실수로 넓어져도 이 규칙이 남는다.
  statement {
    sid       = "OnlySensorWritesLedger"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.archive.arn}/raw/*", "${aws_s3_bucket.archive.arn}/hb/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_role.sensor.arn]
    }
  }

  # 원장은 한 번만 쓴다. "없을 때만 쓰기"(If-None-Match: *) 조건이 없는 쓰기는 거부한다.
  # 센서가 장악되어도 이미 올린 조각을 조작본으로 바꿔치기할 수 없다.
  # 생존 신호(hb/)는 매 회차 덮어쓰는 것이 설계이므로 제외한다.
  statement {
    sid       = "LedgerWriteOnce"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.archive.arn}/raw/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Null"
      variable = "s3:if-none-match"
      values   = ["true"]
    }
  }

  # 원장은 지우지 않는다
  statement {
    sid       = "DenyLedgerDelete"
    effect    = "Deny"
    actions   = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
    resources = ["${aws_s3_bucket.archive.arn}/raw/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
  }
}

resource "aws_s3_bucket_policy" "archive" {
  bucket = aws_s3_bucket.archive.id
  policy = data.aws_iam_policy_document.archive_bucket.json

  depends_on = [aws_s3_bucket_public_access_block.archive]
}
