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

# 원장에 쓰는 인스턴스와 각자의 경로. 옛 허니팟(instances.tf)은 이전이 끝나 정의를 걷어내면 함께 빠진다
locals {
  ledger_writers = merge(
    { honeypot = { sid = "OnlyOwnHostHoneypot", arn = aws_instance.honeypot.arn, id = aws_instance.honeypot.id, sensors = ["cowrie", "decoy"] } },
    { gateway = { sid = "OnlyOwnHostGateway", arn = aws_instance.gateway.arn, id = aws_instance.gateway.id, sensors = ["gateway"] } },
    { for idx, i in aws_instance.honeypot_dmz : "honeypot_dmz_${idx}" => { sid = "OnlyOwnHostHoneypotDmz${idx}", arn = i.arn, id = i.id, sensors = ["cowrie", "decoy"] } },
  )
  ledger_writer_paths = {
    for k, w in local.ledger_writers : k => concat(
      [for s in w.sensors : "${aws_s3_bucket.archive.arn}/raw/v1/sensor=${s}/host=${w.id}/*"],
      ["${aws_s3_bucket.archive.arn}/hb/v1/host=${w.id}/latest.json"],
    )
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

  # 원장에는 센서 · 관문 역할만 쓴다. 루트 계정을 포함한 다른 모든 주체의 쓰기를 거부한다.
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
      values   = [aws_iam_role.sensor.arn, aws_iam_role.gateway.arn]
    }
  }

  # 인스턴스는 자기 host 경로에만 쓴다 (이슈 #19). host 는 인스턴스 ID 이고(sensor/upload.py 경로 규칙),
  # 인스턴스 자격증명으로 온 요청에는 ec2:SourceInstanceARN 이 붙는다. 다른 인스턴스이거나 인스턴스가
  # 아니면(키가 없으면 부정 조건은 참) 거부된다. 장악된 허니팟이 다른 노드 행세를 못 한다.
  dynamic "statement" {
    for_each = local.ledger_writer_paths
    content {
      sid       = local.ledger_writers[statement.key].sid
      effect    = "Deny"
      actions   = ["s3:PutObject"]
      resources = statement.value
      principals {
        type        = "*"
        identifiers = ["*"]
      }
      condition {
        test     = "ArnNotEquals"
        variable = "ec2:SourceInstanceARN"
        values   = [local.ledger_writers[statement.key].arn]
      }
    }
  }

  # 알려진 인스턴스의 경로 밖에는 아무도 쓰지 못한다(원장 밖 접두사 포함. 이 버킷은 원장만 담는다).
  # 새 노드는 여기(ledger_writers)에 더해야 원장에 쓴다. 쓰는 인스턴스가 하나도 없으면 문을 내지 않는다
  dynamic "statement" {
    for_each = length(local.ledger_writer_paths) > 0 ? [1] : []
    content {
      sid           = "LedgerKnownHostsOnly"
      effect        = "Deny"
      actions       = ["s3:PutObject"]
      not_resources = flatten(values(local.ledger_writer_paths))
      principals {
        type        = "*"
        identifiers = ["*"]
      }
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

  # 원장 · 생존 신호는 기본 저장 등급으로만 쓴다. 센서가 GLACIER 같은 등급으로 올리면
  # 안쪽에서 바로 읽을 수 없어 가져오기가 막힌다. 헤더가 없으면(기본값 STANDARD) 허용한다.
  statement {
    sid       = "LedgerStandardStorageOnly"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.archive.arn}/raw/*", "${aws_s3_bucket.archive.arn}/hb/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Null"
      variable = "s3:x-amz-storage-class"
      values   = ["false"]
    }
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-storage-class"
      values   = ["STANDARD"]
    }
  }

  # 버킷 기본 암호화(SSE-S3)만 쓴다. 센서가 다른 계정의 KMS 키나 자기 키(SSE-C)로
  # 암호화해 올리면 안쪽에서 읽을 수 없어 가져오기가 막힌다. 헤더가 없으면 기본 암호화가 적용된다.
  statement {
    sid       = "LedgerDefaultEncryptionOnly"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.archive.arn}/raw/*", "${aws_s3_bucket.archive.arn}/hb/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["false"]
    }
    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["AES256"]
    }
  }

  statement {
    sid       = "LedgerNoCustomerKey"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.archive.arn}/raw/*", "${aws_s3_bucket.archive.arn}/hb/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Null"
      variable = "s3:x-amz-server-side-encryption-customer-algorithm"
      values   = ["false"]
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
