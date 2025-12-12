resource "aws_s3_bucket" "gd_bucket" {
  bucket = var.gd_finding_bucket_name
}

resource "aws_s3_bucket_public_access_block" "gd_bucket_access_block" {
  bucket = aws_s3_bucket.gd_bucket.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

data "aws_iam_policy_document" "s3_bucket_policy" {
  statement {
    sid    = "DenyNonHTTPSAccess"
    effect = "Deny"

    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }

    actions = ["s3:*"]

    resources = [
      "${aws_s3_bucket.gd_bucket.arn}",
      "${aws_s3_bucket.gd_bucket.arn}/*"
    ]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid    = "DenyIncorrectEncryptionHeader"
    effect = "Deny"

    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.gd_bucket.arn}/*"]

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.gd_key.key_id]
    }
  }

  statement {
    sid    = "DenyUnencryptedObjectUploads"
    effect = "Deny"

    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.gd_bucket.arn}/*"]

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption"
      values   = ["aws:kms"]
    }
  }

  statement {
    sid    = "AllowPutObjectFromGuardDutyAccounts"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.gd_bucket.arn}/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values = [
        "516172020428",
        "178146987985",
        "974502855972",
        "523447765480",
        "544676427182",
        "460252569361",
        "026090552251",
        "519537597559",
        "659566604954",
        "818809930947",
        "866810612377",
        "071093231757",
        "512138226175",
        "001634221322"
      ]
    }

    condition {
      test     = "StringLike"
      variable = "aws:SourceArn"
      values = [
        "arn:aws:guardduty:*:516172020428:detector/*",
        "arn:aws:guardduty:*:178146987985:detector/*",
        "arn:aws:guardduty:*:974502855972:detector/*",
        "arn:aws:guardduty:*:523447765480:detector/*",
        "arn:aws:guardduty:*:544676427182:detector/*",
        "arn:aws:guardduty:*:460252569361:detector/*",
        "arn:aws:guardduty:*:026090552251:detector/*",
        "arn:aws:guardduty:*:519537597559:detector/*",
        "arn:aws:guardduty:*:659566604954:detector/*",
        "arn:aws:guardduty:*:818809930947:detector/*",
        "arn:aws:guardduty:*:866810612377:detector/*",
        "arn:aws:guardduty:*:071093231757:detector/*",
        "arn:aws:guardduty:*:512138226175:detector/*",
        "arn:aws:guardduty:*:001634221322:detector/*"
      ]
    }
  }
  statement {
    sid    = "AllowGetBucketLocationFromGuardDutyAccounts"
    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["guardduty.amazonaws.com"]
    }

    actions   = ["s3:GetBucketLocation"]
    resources = ["${aws_s3_bucket.gd_bucket.arn}"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values = [
        "516172020428",
        "178146987985",
        "974502855972",
        "523447765480",
        "544676427182",
        "460252569361",
        "026090552251",
        "519537597559",
        "659566604954",
        "818809930947",
        "866810612377",
        "071093231757",
        "512138226175",
        "001634221322"
      ]
    }

    condition {
      test     = "StringLike"
      variable = "aws:SourceArn"
      values = [
        "arn:aws:guardduty:*:516172020428:detector/*",
        "arn:aws:guardduty:*:178146987985:detector/*",
        "arn:aws:guardduty:*:974502855972:detector/*",
        "arn:aws:guardduty:*:523447765480:detector/*",
        "arn:aws:guardduty:*:544676427182:detector/*",
        "arn:aws:guardduty:*:460252569361:detector/*",
        "arn:aws:guardduty:*:026090552251:detector/*",
        "arn:aws:guardduty:*:519537597559:detector/*",
        "arn:aws:guardduty:*:659566604954:detector/*",
        "arn:aws:guardduty:*:818809930947:detector/*",
        "arn:aws:guardduty:*:866810612377:detector/*",
        "arn:aws:guardduty:*:071093231757:detector/*",
        "arn:aws:guardduty:*:512138226175:detector/*",
        "arn:aws:guardduty:*:001634221322:detector/*"
      ]
    }
  }
}

resource "aws_s3_bucket_policy" "gd_bucket_policy" {
  bucket = aws_s3_bucket.gd_bucket.id
  policy = data.aws_iam_policy_document.s3_bucket_policy.json
}

resource "aws_s3_bucket_ownership_controls" "ownership" {
  bucket = aws_s3_bucket.gd_bucket.id
  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "acl" {
  depends_on = [aws_s3_bucket_ownership_controls.ownership]

  bucket = aws_s3_bucket.gd_bucket.id
  acl    = "private"
}

resource "aws_s3_bucket_public_access_block" "block" {
  bucket = aws_s3_bucket.gd_bucket.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "gd_encryption" {
  bucket = aws_s3_bucket.gd_bucket.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.gd_key.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

resource "aws_kms_key" "gd_key" {
  description             = "KMS key for GuardDuty findings"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "alias" {
  name          = var.kms_alias
  target_key_id = aws_kms_key.gd_key.key_id
}

data "aws_caller_identity" "current" {}

resource "aws_kms_key_policy" "gd_key_policy" {
  key_id = aws_kms_key.gd_key.id
  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "key-default-1"
    Statement = [
      {
        Sid    = "EnableIAMUserPermissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowGuardDutyGenerateDataKeyFromListedAccounts"
        Effect = "Allow"
        Principal = {
          Service = "guardduty.amazonaws.com"
        }
        Action = [
          "kms:GenerateDataKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = [
              "516172020428",
              "178146987985",
              "974502855972",
              "523447765480",
              "544676427182",
              "460252569361",
              "260990552251",
              "519537597559",
              "659566604954",
              "818899930947",
              "866810612377",
              "071093231757",
              "512138226175",
              "001634221322"
            ]
          },
          ArnLike = {
            "aws:SourceArn" = [
              "arn:aws:guardduty:*:516172020428:detector/*",
              "arn:aws:guardduty:*:178146987985:detector/*",
              "arn:aws:guardduty:*:974502855972:detector/*",
              "arn:aws:guardduty:*:523447765480:detector/*",
              "arn:aws:guardduty:*:544676427182:detector/*",
              "arn:aws:guardduty:*:460252569361:detector/*",
              "arn:aws:guardduty:*:026090552251:detector/*",
              "arn:aws:guardduty:*:519537597559:detector/*",
              "arn:aws:guardduty:*:659566604954:detector/*",
              "arn:aws:guardduty:*:818809930947:detector/*",
              "arn:aws:guardduty:*:866810612377:detector/*",
              "arn:aws:guardduty:*:071093231757:detector/*",
              "arn:aws:guardduty:*:512138226175:detector/*",
              "arn:aws:guardduty:*:001634221322:detector/*"
            ]
          }
        }
      }
    ]
  })
}

data "aws_guardduty_detector" "regional" {
  provider = aws.us_east_1
}

resource "aws_guardduty_publishing_destination" "export" {
  detector_id      = data.aws_guardduty_detector.current.id
  destination_arn  = aws_s3_bucket.gd_bucket.arn
  kms_key_arn      = aws_kms_key.gd_key.arn
}