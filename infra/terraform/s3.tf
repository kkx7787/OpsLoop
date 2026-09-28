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

# 원장에 쓰는 인스턴스와 각자의 경로. 새 노드는 여기에 더해야 원장에 쓴다 (옛 허니팟은 2026-09-25 종료 · 이슈 #37)
# hb 는 생존 신호 경로의 host 접미사다. 관문은 차단 목록 적용 보고(hb/v1/host=<자기 ID>-block/latest.json, 이슈 #47)도 쓴다.
# 이 경로도 관문 인스턴스만 쓰므로(OnlyOwnHostGateway) 장악된 허니팟이 '적용됨' 보고를 꾸미지 못한다
locals {
  ledger_writers = merge(
    { gateway = { sid = "OnlyOwnHostGateway", arn = aws_instance.gateway.arn, id = aws_instance.gateway.id, sensors = ["gateway"], hb = ["", "-block"] } },
    { for idx, i in aws_instance.honeypot_dmz : "honeypot_dmz_${idx}" => { sid = "OnlyOwnHostHoneypotDmz${idx}", arn = i.arn, id = i.id, sensors = ["cowrie", "decoy"], hb = [""] } },
  )
  ledger_writer_paths = {
    for k, w in local.ledger_writers : k => concat(
      [for s in w.sensors : "${aws_s3_bucket.archive.arn}/raw/v1/sensor=${s}/host=${w.id}/*"],
      [for h in w.hb : "${aws_s3_bucket.archive.arn}/hb/v1/host=${w.id}${h}/latest.json"],
    )
  }
  # 차단 목록 (이슈 #47). 데이터 노드 집행기가 쓰고(iam.tf block_writer) 관문 동기화가 읽는다(gateway_block_read)
  block_list_key = "block/v1/latest.json"
  # 내부 방화벽의 적용 보고 (이슈 #51). block-sync.py 의 OPSLOOP_HOST=fw-opsloop 가 만드는 상태 키. 동기화 사용자(iam.tf fw_sync)만 쓴다
  fw_sync_host       = "fw-opsloop"
  fw_sync_status_key = "hb/v1/host=${local.fw_sync_host}-block/latest.json"
  # 저장 등급 · 기본 암호화 · 고객 키 조건을 거는 접두사 (원장 · 생존 신호 · 공개 정보 원본 · 차단 목록)
  written_prefixes = ["raw/*", "hb/*", "cti/*", "block/*"]
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
  # IAM 권한이 실수로 넓어져도 이 규칙이 남는다. 내부 방화벽 동기화 사용자는 hb/ 의 자기 보고 키 하나 때문에 예외에 들고
  # (이슈 #51), 그 밖의 경로는 아래 OnlyFwSyncWritesFwHb · LedgerKnownHostsOnly 와 IAM 정책(그 키 하나)이 막는다
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
      values   = [aws_iam_role.sensor.arn, aws_iam_role.gateway.arn, aws_iam_user.fw_sync.arn]
    }
  }

  # 내부 방화벽의 적용 보고 키는 동기화 사용자만 쓴다 (이슈 #51). 센서 · 관문 역할 · 다른 사용자 · 루트 모두 거부된다.
  # 장악된 허니팟이나 관문이 '내부 방화벽에 반영됨' 보고를 꾸미지 못한다
  statement {
    sid       = "OnlyFwSyncWritesFwHb"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.archive.arn}/${local.fw_sync_status_key}"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_user.fw_sync.arn]
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

  # 알려진 인스턴스의 경로 · 공개 정보 원본(cti/) · 차단 목록 한 객체(block/v1/latest.json) · 내부 방화벽 보고 키 밖에는
  # 아무도 쓰지 못한다. 이 버킷은 원장 · cti/ · 차단 목록 · 집행 보고만 담는다. 새 노드는 여기(ledger_writers)에 더해야 원장에 쓴다.
  # 쓰는 인스턴스가 하나도 없으면 문을 내지 않는다
  dynamic "statement" {
    for_each = length(local.ledger_writer_paths) > 0 ? [1] : []
    content {
      sid     = "LedgerKnownHostsOnly"
      effect  = "Deny"
      actions = ["s3:PutObject"]
      not_resources = concat(flatten(values(local.ledger_writer_paths)), [
        "${aws_s3_bucket.archive.arn}/cti/*",
        "${aws_s3_bucket.archive.arn}/${local.block_list_key}",
        "${aws_s3_bucket.archive.arn}/${local.fw_sync_status_key}",
      ])
      principals {
        type        = "*"
        identifiers = ["*"]
      }
    }
  }

  # 공개 정보 원본(cti/)은 전용 쓰기 사용자만 쓴다 (이슈 #39). 센서 · 관문 · 읽기 사용자 · 루트 모두 거부된다.
  # 원본은 그날 무엇을 보고 판단했는지 재현하는 근거라서 원장처럼 한 번만 쓰고 지우지 않는다(아래 문들).
  statement {
    sid       = "OnlyCtiWriterWritesCti"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.archive.arn}/cti/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_user.cti_writer.arn]
    }
  }

  statement {
    sid       = "CtiWriteOnce"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.archive.arn}/cti/*"]
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

  # 차단 목록(block/)은 목록 쓰기 사용자만 쓴다 (이슈 #47). 센서 · 관문 역할 · 읽기 · CTI 쓰기 사용자 · 루트 모두 거부된다.
  # 관문이 이 목록대로 유입을 막으므로, 장악된 허니팟이나 다른 주체가 목록을 바꿔 아무 주소나 막거나 풀게 하지 못한다.
  # 목록은 바뀔 때와 10분마다 덮어쓰는 것이 설계라 한 번 쓰기 조건은 두지 않는다. 이전 판은 버저닝이 남긴다.
  # 삭제 거부도 두지 않는다. 지워지면 관문은 옛 집합을 두고(만료로 저절로 빠진다) 집행기가 10분 안에 다시 올린다
  statement {
    sid       = "OnlyBlockWriterWritesBlock"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.archive.arn}/block/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "ArnNotEquals"
      variable = "aws:PrincipalArn"
      values   = [aws_iam_user.block_writer.arn]
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

  # 원장 · 생존 신호 · 공개 정보 원본 · 차단 목록은 기본 저장 등급으로만 쓴다. 센서가 GLACIER 같은 등급으로 올리면
  # 안쪽에서 바로 읽을 수 없어 가져오기가 막힌다. 헤더가 없으면(기본값 STANDARD) 허용한다.
  statement {
    sid       = "LedgerStandardStorageOnly"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = [for p in local.written_prefixes : "${aws_s3_bucket.archive.arn}/${p}"]
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

  # 버킷 기본 암호화(SSE-S3)만 쓴다(cti/ · block/ 포함). 센서가 다른 계정의 KMS 키나 자기 키(SSE-C)로
  # 암호화해 올리면 안쪽에서 읽을 수 없어 가져오기가 막힌다. 헤더가 없으면 기본 암호화가 적용된다.
  statement {
    sid       = "LedgerDefaultEncryptionOnly"
    effect    = "Deny"
    actions   = ["s3:PutObject"]
    resources = [for p in local.written_prefixes : "${aws_s3_bucket.archive.arn}/${p}"]
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
    resources = [for p in local.written_prefixes : "${aws_s3_bucket.archive.arn}/${p}"]
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

  # 원장과 공개 정보 원본은 지우지 않는다
  statement {
    sid       = "DenyLedgerDelete"
    effect    = "Deny"
    actions   = ["s3:DeleteObject", "s3:DeleteObjectVersion"]
    resources = ["${aws_s3_bucket.archive.arn}/raw/*", "${aws_s3_bucket.archive.arn}/cti/*"]
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
