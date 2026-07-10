resource "aws_s3_bucket_policy" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowCloudTrailGetBucketAcl"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.audit_logs.arn
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.region}:${var.account_id}:trail/caucellcloud-research"
          }
        }
      },
      {
        Sid       = "AllowCloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.audit_logs.arn}/AWSLogs/${var.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.region}:${var.account_id}:trail/caucellcloud-research"
          }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.audit_logs.arn,
          "${aws_s3_bucket.audit_logs.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

resource "aws_cloudtrail" "research" {
  name                          = "caucellcloud-research"
  s3_bucket_name                = aws_s3_bucket.audit_logs.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true
  kms_key_id                    = aws_kms_key.audit.arn

  advanced_event_selector {
    name = "management-events"

    field_selector {
      field  = "eventCategory"
      equals = ["Management"]
    }
  }

  advanced_event_selector {
    name = "research-bucket-data-events"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }

    field_selector {
      field       = "resources.ARN"
      starts_with = ["arn:aws:s3:::research-"]
    }
  }

  advanced_event_selector {
    name = "audit-bucket-data-events"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }

    field_selector {
      field       = "resources.ARN"
      starts_with = ["${aws_s3_bucket.audit_logs.arn}/"]
    }
  }

  advanced_event_selector {
    name = "results-bucket-data-events"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }

    field_selector {
      field       = "resources.ARN"
      starts_with = ["arn:aws:s3:::caucellcloud-athena-results/"]
    }
  }

  # Vendor landing buckets (caucell-{vendor}-landing) — the inbound counterpart to
  # research-* above. The trailing hyphen on "caucell-" matches the vendor buckets and
  # excludes the caucellcloud-* audit/results buckets. ends_with can't be used: the
  # S3::Object resources.ARN is the full object ARN (ends in the key), so we anchor on
  # the bucket prefix exactly as the research selector does. (Appended last so the plan
  # diff is purely additive — selector order is irrelevant; CloudTrail OR's them.)
  advanced_event_selector {
    name = "vendor-landing-data-events"

    field_selector {
      field  = "eventCategory"
      equals = ["Data"]
    }

    field_selector {
      field  = "resources.type"
      equals = ["AWS::S3::Object"]
    }

    field_selector {
      field       = "resources.ARN"
      starts_with = ["arn:aws:s3:::caucell-"]
    }
  }

  depends_on = [aws_s3_bucket_policy.audit_logs]

  tags = {
    Purpose = "audit"
  }
}

resource "aws_kms_key_policy" "audit_cloudtrail" {
  key_id = aws_kms_key.audit.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableRootAccountPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowCloudTrailEncrypt"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action = [
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "aws:SourceArn" = "arn:aws:cloudtrail:${var.region}:${var.account_id}:trail/caucellcloud-research"
          }
        }
      },
      {
        Sid       = "AllowCloudTrailDecrypt"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${var.account_id}:root" }
        Action    = "kms:Decrypt"
        Resource  = "*"
        Condition = {
          Null = { "kms:EncryptionContext:aws:cloudtrail:arn" = "false" }
        }
      },
      {
        Sid       = "AllowAuditReaderDecrypt"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.audit_reader.arn }
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          Null = { "kms:EncryptionContext:aws:cloudtrail:arn" = "false" }
        }
      }
    ]
  })
}
