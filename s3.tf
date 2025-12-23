resource "aws_s3_bucket" "gd_bucket" {
  bucket   = var.gd_finding_bucket_name
  provider = aws.us_east_2
}

data "aws_iam_policy_document" "s3_bucket_policy" {

  statement {
    sid    = "Deny non-HTTPS access"
    effect = "Deny"

    principals {
      type = "Service"
      identifiers = [
        "guardduty.amazonaws.com",
        "guardduty.me-south-1.amazonaws.com",
        "guardduty.af-south-1.amazonaws.com",
        "guardduty.ap-east-1.amazonaws.com",
        "guardduty.eu-south-1.amazonaws.com",
        "guardduty.eu-south-2.amazonaws.com",
        "guardduty.eu-central-2.amazonaws.com"
      ]
    }

    actions   = ["s3:*"]
    resources = ["${aws_s3_bucket.gd_bucket.arn}/*"]

    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }

  statement {
    sid    = "Deny incorrect encryption header"
    effect = "Deny"

    principals {
      type = "Service"
      identifiers = [
        "guardduty.amazonaws.com",
        "guardduty.me-south-1.amazonaws.com",
        "guardduty.af-south-1.amazonaws.com",
        "guardduty.ap-east-1.amazonaws.com",
        "guardduty.eu-south-1.amazonaws.com",
        "guardduty.eu-south-2.amazonaws.com",
        "guardduty.eu-central-2.amazonaws.com"
      ]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.gd_bucket.arn}/*"]

    condition {
      test     = "StringNotEquals"
      variable = "s3:x-amz-server-side-encryption-aws-kms-key-id"
      values   = [aws_kms_key.gd_key.arn]
    }
  }

  statement {
    sid    = "Deny unencrypted object uploads"
    effect = "Deny"

    principals {
      type = "Service"
      identifiers = [
        "guardduty.amazonaws.com",
        "guardduty.me-south-1.amazonaws.com",
        "guardduty.af-south-1.amazonaws.com",
        "guardduty.ap-east-1.amazonaws.com",
        "guardduty.eu-south-1.amazonaws.com",
        "guardduty.eu-south-2.amazonaws.com",
        "guardduty.eu-central-2.amazonaws.com"
      ]
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
    sid    = "Allow PutObject"
    effect = "Allow"

    principals {
      type = "Service"
      identifiers = [
        "guardduty.amazonaws.com",
        "guardduty.me-south-1.amazonaws.com",
        "guardduty.af-south-1.amazonaws.com",
        "guardduty.ap-east-1.amazonaws.com",
        "guardduty.eu-south-1.amazonaws.com",
        "guardduty.eu-south-2.amazonaws.com",
        "guardduty.eu-central-2.amazonaws.com"
      ]
    }

    actions   = ["s3:PutObject"]
    resources = ["${aws_s3_bucket.gd_bucket.arn}/*"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values = [
        "782439390712",
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
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values = [
        "arn:aws:guardduty:*:782439390712:detector/*",
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
    sid    = "Allow GetBucketLocation"
    effect = "Allow"

    principals {
      type = "Service"
      identifiers = [
        "guardduty.amazonaws.com",
        "guardduty.me-south-1.amazonaws.com",
        "guardduty.af-south-1.amazonaws.com",
        "guardduty.ap-east-1.amazonaws.com",
        "guardduty.eu-south-1.amazonaws.com",
        "guardduty.eu-south-2.amazonaws.com",
        "guardduty.eu-central-2.amazonaws.com"
      ]
    }

    actions   = ["s3:GetBucketLocation"]
    resources = ["${aws_s3_bucket.gd_bucket.arn}"]

    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values = [
        "782439390712",
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
      test     = "ArnEquals"
      variable = "aws:SourceArn"
      values = [
        "arn:aws:guardduty:*:782439390712:detector/*",
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
  bucket   = aws_s3_bucket.gd_bucket.id
  provider = aws.us_east_2
  policy   = data.aws_iam_policy_document.s3_bucket_policy.json
}

resource "aws_s3_bucket_ownership_controls" "ownership" {
  bucket   = aws_s3_bucket.gd_bucket.id
  provider = aws.us_east_2

  rule {
    object_ownership = "BucketOwnerPreferred"
  }
}

resource "aws_s3_bucket_acl" "acl" {
  depends_on = [aws_s3_bucket_ownership_controls.ownership]
  provider   = aws.us_east_2
  bucket     = aws_s3_bucket.gd_bucket.id
  acl        = "private"
}

resource "aws_s3_bucket_public_access_block" "block" {
  bucket                  = aws_s3_bucket.gd_bucket.id
  provider                = aws.us_east_2
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "gd_encryption" {
  bucket   = aws_s3_bucket.gd_bucket.id
  provider = aws.us_east_2

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
  provider                = aws.us_east_2
}

resource "aws_kms_alias" "alias" {
  name          = var.kms_alias
  target_key_id = aws_kms_key.gd_key.key_id
  provider      = aws.us_east_2
}

resource "aws_kms_key_policy" "gd_key_policy" {
  key_id   = aws_kms_key.gd_key.id
  provider = aws.us_east_2

  policy = jsonencode({
    Version = "2012-10-17"
    Id      = "key-consolepolicy-3"

    Statement = [
      {
        Sid    = "Enable IAM User Permissions"
        Effect = "Allow"
        Principal = {
          AWS = "arn:aws:iam::782439390712:root"
        }
        Action   = "kms:*"
        Resource = "*"
      },
      {
        Sid    = "AllowGuardDutyToEncryptFindings"
        Effect = "Allow"
        Principal = {
          Service = [
            "guardduty.amazonaws.com",
            "guardduty.me-south-1.amazonaws.com",
            "guardduty.af-south-1.amazonaws.com",
            "guardduty.ap-east-1.amazonaws.com",
            "guardduty.eu-south-1.amazonaws.com",
            "guardduty.eu-south-2.amazonaws.com",
            "guardduty.eu-central-2.amazonaws.com"
          ]
        }
        Action = [
          "kms:GenerateDataKey",
          "kms:Encrypt"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = [
              "782439390712",
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
          ArnEquals = {
            "aws:SourceArn" = [
              "arn:aws:guardduty:*:782439390712:detector/*",
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

data "aws_guardduty_detector" "us_east_1" {
  count    = contains(var.aws_regions, "us-east-1") ? 1 : 0
  provider = aws.us_east_1
}

data "aws_guardduty_detector" "us_east_2" {
  count    = contains(var.aws_regions, "us-east-2") ? 1 : 0
  provider = aws.us_east_2
}

data "aws_guardduty_detector" "us_west_1" {
  count    = contains(var.aws_regions, "us-west-1") ? 1 : 0
  provider = aws.us_west_1
}

data "aws_guardduty_detector" "us_west_2" {
  count    = contains(var.aws_regions, "us-west-2") ? 1 : 0
  provider = aws.us_west_2
}

data "aws_guardduty_detector" "af_south_1" {
  count    = contains(var.aws_regions, "af-south-1") ? 1 : 0
  provider = aws.af_south_1
}

data "aws_guardduty_detector" "ap_east_1" {
  count    = contains(var.aws_regions, "ap-east-1") ? 1 : 0
  provider = aws.ap_east_1
}

data "aws_guardduty_detector" "ap_northeast_1" {
  count    = contains(var.aws_regions, "ap-northeast-1") ? 1 : 0
  provider = aws.ap_northeast_1
}

data "aws_guardduty_detector" "ap_northeast_2" {
  count    = contains(var.aws_regions, "ap-northeast-2") ? 1 : 0
  provider = aws.ap_northeast_2
}

data "aws_guardduty_detector" "ap_northeast_3" {
  count    = contains(var.aws_regions, "ap-northeast-3") ? 1 : 0
  provider = aws.ap_northeast_3
}

data "aws_guardduty_detector" "ap_southeast_1" {
  count    = contains(var.aws_regions, "ap-southeast-1") ? 1 : 0
  provider = aws.ap_southeast_1
}

data "aws_guardduty_detector" "ap_southeast_2" {
  count    = contains(var.aws_regions, "ap-southeast-2") ? 1 : 0
  provider = aws.ap_southeast_2
}

data "aws_guardduty_detector" "ap_south_1" {
  count    = contains(var.aws_regions, "ap-south-1") ? 1 : 0
  provider = aws.ap_south_1
}

data "aws_guardduty_detector" "ca_central_1" {
  count    = contains(var.aws_regions, "ca-central-1") ? 1 : 0
  provider = aws.ca_central_1
}

data "aws_guardduty_detector" "eu_central_1" {
  count    = contains(var.aws_regions, "eu-central-1") ? 1 : 0
  provider = aws.eu_central_1
}

data "aws_guardduty_detector" "eu_central_2" {
  count    = contains(var.aws_regions, "eu-central-2") ? 1 : 0
  provider = aws.eu_central_2
}

data "aws_guardduty_detector" "eu_north_1" {
  count    = contains(var.aws_regions, "eu-north-1") ? 1 : 0
  provider = aws.eu_north_1
}

data "aws_guardduty_detector" "eu_south_1" {
  count    = contains(var.aws_regions, "eu-south-1") ? 1 : 0
  provider = aws.eu_south_1
}

data "aws_guardduty_detector" "eu_south_2" {
  count    = contains(var.aws_regions, "eu-south-2") ? 1 : 0
  provider = aws.eu_south_2
}

data "aws_guardduty_detector" "eu_west_1" {
  count    = contains(var.aws_regions, "eu-west-1") ? 1 : 0
  provider = aws.eu_west_1
}

data "aws_guardduty_detector" "eu_west_2" {
  count    = contains(var.aws_regions, "eu-west-2") ? 1 : 0
  provider = aws.eu_west_2
}

data "aws_guardduty_detector" "eu_west_3" {
  count    = contains(var.aws_regions, "eu-west-3") ? 1 : 0
  provider = aws.eu_west_3
}

data "aws_guardduty_detector" "me_south_1" {
  count    = contains(var.aws_regions, "me-south-1") ? 1 : 0
  provider = aws.me_south_1
}

data "aws_guardduty_detector" "sa_east_1" {
  count    = contains(var.aws_regions, "sa-east-1") ? 1 : 0
  provider = aws.sa_east_1
}

resource "aws_guardduty_publishing_destination" "us_east_1" {
  count           = contains(var.aws_regions, "us-east-1") ? 1 : 0
  detector_id     = data.aws_guardduty_detector.us_east_1[0].id
  destination_arn = aws_s3_bucket.gd_bucket.arn
  kms_key_arn     = aws_kms_key.gd_key.arn
  provider        = aws.us_east_1

  depends_on = [
    aws_s3_bucket_policy.gd_bucket_policy,
    aws_kms_key_policy.gd_key_policy
  ]
}

resource "aws_guardduty_publishing_destination" "us_east_2" {
  count           = contains(var.aws_regions, "us-east-2") ? 1 : 0
  detector_id     = data.aws_guardduty_detector.us_east_2[0].id
  destination_arn = aws_s3_bucket.gd_bucket.arn
  kms_key_arn     = aws_kms_key.gd_key.arn
  provider        = aws.us_east_2

  depends_on = [
    aws_s3_bucket_policy.gd_bucket_policy,
    aws_kms_key_policy.gd_key_policy
  ]
}

resource "aws_guardduty_publishing_destination" "us_west_1" {
  count           = contains(var.aws_regions, "us-west-1") ? 1 : 0
  detector_id     = data.aws_guardduty_detector.us_west_1[0].id
  destination_arn = aws_s3_bucket.gd_bucket.arn
  kms_key_arn     = aws_kms_key.gd_key.arn
  provider        = aws.us_west_1

  depends_on = [
    aws_s3_bucket_policy.gd_bucket_policy,
    aws_kms_key_policy.gd_key_policy
  ]
}

resource "aws_guardduty_publishing_destination" "us_west_2" {
  count           = contains(var.aws_regions, "us-west-2") ? 1 : 0
  detector_id     = data.aws_guardduty_detector.us_west_2[0].id
  destination_arn = aws_s3_bucket.gd_bucket.arn
  kms_key_arn     = aws_kms_key.gd_key.arn
  provider        = aws.us_west_2

  depends_on = [
    aws_s3_bucket_policy.gd_bucket_policy,
    aws_kms_key_policy.gd_key_policy
  ]
}

resource "aws_guardduty_publishing_destination" "af_south_1" {
  count           = contains(var.aws_regions, "af-south-1") ? 1 : 0
  detector_id     = data.aws_guardduty_detector.af_south_1[0].id
  destination_arn = aws_s3_bucket.gd_bucket.arn
  kms_key_arn     = aws_kms_key.gd_key.arn
  provider        = aws.af_south_1

  depends_on = [
    aws_s3_bucket_policy.gd_bucket_policy,
    aws_kms_key_policy.gd_key_policy
  ]
}

resource "aws_guardduty_publishing_destination" "ap_east_1" {
  count           = contains(var.aws_regions, "ap-east-1") ? 1 : 0
  detector_id     = data.aws_guardduty_detector.ap_east_1[0].id
  destination_arn = aws_s3_bucket.gd_bucket.arn
  kms_key_arn     = aws_kms_key.gd_key.arn
  provider        = aws.ap_east_1

  depends_on = [
    aws_s3_bucket_policy.gd_bucket_policy,
    aws_kms_key_policy.gd_key_policy
  ]
}

resource "aws_guardduty_publishing_destination" "ap_northeast_1" {
  count           = contains(var.aws_regions, "ap-northeast-1") ? 1 : 0
  detector_id     = data.aws_guardduty_detector.ap_northeast_1[0].id
  destination_arn = aws_s3_bucket.gd_bucket.arn
  kms_key_arn     = aws_kms_key.gd_key.arn
  provider        = aws.ap_northeast_1

  depends_on = [
    aws_s3_bucket_policy.gd_bucket_policy,
    aws_kms_key_policy.gd_key_policy
  ]
}

resource "aws_guardduty_publishing_destination" "ap_northeast_2" {
  count           = contains(var.aws_regions, "ap-northeast-2") ? 1 : 0
  detector_id     = data.aws_guardduty_detector.ap_northeast_2[0].id
  destination_arn = aws_s3_bucket.gd_bucket.arn
  kms_key_arn     = aws_kms_key.gd_key.arn
  provider        = aws.ap_northeast_2

  depends_on = [
    aws_s3_bucket_policy.gd_bucket_policy,
    aws_kms_key_policy.gd_key_policy
  ]
}

resource "aws_guardduty_publishing_destination" "ap_northeast_3" {
  count           = contains(var.aws_regions, "ap-northeast-3") ? 1 : 0
  detector_id     = data.aws_guardduty_detector.ap_northeast_3[0].id
  destination_arn = aws_s3_bucket.gd_bucket.arn
  kms_key_arn     = aws_kms_key.gd_key.arn
  provider        = aws.ap_northeast_3

  depends_on = [
    aws_s3_bucket_policy.gd_bucket_policy,
    aws_kms_key_policy.gd_key_policy
  ]
}

resource "aws_guardduty_publishing_destination" "ap_southeast_1" {
  count           = contains(var.aws_regions, "ap-southeast-1") ? 1 : 0
  detector_id     = data.aws_guardduty_detector.ap_southeast_1[0].id
  destination_arn = aws_s3_bucket.gd_bucket.arn
  kms_key_arn     = aws_kms_key.gd_key.arn
  provider        = aws.ap_southeast_1

  depends_on = [
    aws_s3_bucket_policy.gd_bucket_policy,
    aws_kms_key_policy.gd_key_policy
  ]
}

resource "aws_guardduty_publishing_destination" "ap_southeast_2" {
  count           = contains(var.aws_regions, "ap-southeast-2") ? 1 : 0
  detector_id     = data.aws_guardduty_detector.ap_southeast_2[0].id
  destination_arn = aws_s3_bucket.gd_bucket.arn
  kms_key_arn     = aws_kms_key.gd_key.arn
  provider        = aws.ap_southeast_2

  depends_on = [
    aws_s3_bucket_policy.gd_bucket_policy,
    aws_kms_key_policy.gd_key_policy
  ]
}

resource "aws_guardduty_publishing_destination" "ap_south_1" {
  count           = contains(var.aws_regions, "ap-south-1") ? 1 : 0
  detector_id     = data.aws_guardduty_detector.ap_south_1[0].id
  destination_arn = aws_s3_bucket.gd_bucket.arn
  kms_key_arn     = aws_kms_key.gd_key.arn
  provider        = aws.ap_south_1

  depends_on = [
    aws_s3_bucket_policy.gd_bucket_policy,
    aws_kms_key_policy.gd_key_policy
  ]
}

resource "aws_guardduty_publishing_destination" "ca_central_1" {
  count           = contains(var.aws_regions, "ca-central-1") ? 1 : 0
  detector_id     = data.aws_guardduty_detector.ca_central_1[0].id
  destination_arn = aws_s3_bucket.gd_bucket.arn
  kms_key_arn     = aws_kms_key.gd_key.arn
  provider        = aws.ca_central_1

  depends_on = [
    aws_s3_bucket_policy.gd_bucket_policy,
    aws_kms_key_policy.gd_key_policy
  ]
}

resource "aws_guardduty_publishing_destination" "eu_central_1" {
  count           = contains(var.aws_regions, "eu-central-1") ? 1 : 0
  detector_id     = data.aws_guardduty_detector.eu_central_1[0].id
  destination_arn = aws_s3_bucket.gd_bucket.arn
  kms_key_arn     = aws_kms_key.gd_key.arn
  provider        = aws.eu_central_1

  depends_on = [
    aws_s3_bucket_policy.gd_bucket_policy,
    aws_kms_key_policy.gd_key_policy
  ]
}

resource "aws_guardduty_publishing_destination" "eu_central_2" {
  count           = contains(var.aws_regions, "eu-central-2") ? 1 : 0
  detector_id     = data.aws_guardduty_detector.eu_central_2[0].id
  destination_arn = aws_s3_bucket.gd_bucket.arn
  kms_key_arn     = aws_kms_key.gd_key.arn
  provider        = aws.eu_central_2

  depends_on = [
    aws_s3_bucket_policy.gd_bucket_policy,
    aws_kms_key_policy.gd_key_policy
  ]
}

resource "aws_guardduty_publishing_destination" "eu_north_1" {
  count           = contains(var.aws_regions, "eu-north-1") ? 1 : 0
  detector_id     = data.aws_guardduty_detector.eu_north_1[0].id
  destination_arn = aws_s3_bucket.gd_bucket.arn
  kms_key_arn     = aws_kms_key.gd_key.arn
  provider        = aws.eu_north_1

  depends_on = [
    aws_s3_bucket_policy.gd_bucket_policy,
    aws_kms_key_policy.gd_key_policy
  ]
}

resource "aws_guardduty_publishing_destination" "eu_south_1" {
  count           = contains(var.aws_regions, "eu-south-1") ? 1 : 0
  detector_id     = data.aws_guardduty_detector.eu_south_1[0].id
  destination_arn = aws_s3_bucket.gd_bucket.arn
  kms_key_arn     = aws_kms_key.gd_key.arn
  provider        = aws.eu_south_1

  depends_on = [
    aws_s3_bucket_policy.gd_bucket_policy,
    aws_kms_key_policy.gd_key_policy
  ]
}

resource "aws_guardduty_publishing_destination" "eu_south_2" {
  count           = contains(var.aws_regions, "eu-south-2") ? 1 : 0
  detector_id     = data.aws_guardduty_detector.eu_south_2[0].id
  destination_arn = aws_s3_bucket.gd_bucket.arn
  kms_key_arn     = aws_kms_key.gd_key.arn
  provider        = aws.eu_south_2

  depends_on = [
    aws_s3_bucket_policy.gd_bucket_policy,
    aws_kms_key_policy.gd_key_policy
  ]
}

resource "aws_guardduty_publishing_destination" "eu_west_1" {
  count           = contains(var.aws_regions, "eu-west-1") ? 1 : 0
  detector_id     = data.aws_guardduty_detector.eu_west_1[0].id
  destination_arn = aws_s3_bucket.gd_bucket.arn
  kms_key_arn     = aws_kms_key.gd_key.arn
  provider        = aws.eu_west_1

  depends_on = [
    aws_s3_bucket_policy.gd_bucket_policy,
    aws_kms_key_policy.gd_key_policy
  ]
}

resource "aws_guardduty_publishing_destination" "eu_west_2" {
  count           = contains(var.aws_regions, "eu-west-2") ? 1 : 0
  detector_id     = data.aws_guardduty_detector.eu_west_2[0].id
  destination_arn = aws_s3_bucket.gd_bucket.arn
  kms_key_arn     = aws_kms_key.gd_key.arn
  provider        = aws.eu_west_2

  depends_on = [
    aws_s3_bucket_policy.gd_bucket_policy,
    aws_kms_key_policy.gd_key_policy
  ]
}

resource "aws_guardduty_publishing_destination" "eu_west_3" {
  count           = contains(var.aws_regions, "eu-west-3") ? 1 : 0
  detector_id     = data.aws_guardduty_detector.eu_west_3[0].id
  destination_arn = aws_s3_bucket.gd_bucket.arn
  kms_key_arn     = aws_kms_key.gd_key.arn
  provider        = aws.eu_west_3

  depends_on = [
    aws_s3_bucket_policy.gd_bucket_policy,
    aws_kms_key_policy.gd_key_policy
  ]
}

resource "aws_guardduty_publishing_destination" "me_south_1" {
  count           = contains(var.aws_regions, "me-south-1") ? 1 : 0
  detector_id     = data.aws_guardduty_detector.me_south_1[0].id
  destination_arn = aws_s3_bucket.gd_bucket.arn
  kms_key_arn     = aws_kms_key.gd_key.arn
  provider        = aws.me_south_1

  depends_on = [
    aws_s3_bucket_policy.gd_bucket_policy,
    aws_kms_key_policy.gd_key_policy
  ]
}

resource "aws_guardduty_publishing_destination" "sa_east_1" {
  count           = contains(var.aws_regions, "sa-east-1") ? 1 : 0
  detector_id     = data.aws_guardduty_detector.sa_east_1[0].id
  destination_arn = aws_s3_bucket.gd_bucket.arn
  kms_key_arn     = aws_kms_key.gd_key.arn
  provider        = aws.sa_east_1

  depends_on = [
    aws_s3_bucket_policy.gd_bucket_policy,
    aws_kms_key_policy.gd_key_policy
  ]
}
