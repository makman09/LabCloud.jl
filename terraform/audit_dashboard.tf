resource "aws_s3_bucket" "athena_results" {
  bucket = "caucellcloud-athena-results"

  tags = {
    Purpose   = "athena-results"
    DataClass = "AuditTrail"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.audit.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  rule {
    id     = "expire-query-results"
    status = "Enabled"
    filter {}

    expiration {
      days = 7
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 1
    }
  }
}

resource "aws_s3_bucket_policy" "athena_results" {
  bucket = aws_s3_bucket.athena_results.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.athena_results.arn,
          "${aws_s3_bucket.athena_results.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

resource "aws_glue_catalog_database" "security_audit" {
  name = "security_audit"
}

resource "aws_glue_catalog_table" "cloudtrail_logs" {
  name          = "cloudtrail_logs"
  database_name = aws_glue_catalog_database.security_audit.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    "projection.enabled"            = "true"
    "projection.region.type"        = "enum"
    "projection.region.values"      = var.cloudtrail_regions
    "projection.date.type"          = "date"
    "projection.date.range"         = "${var.cloudtrail_start_date},NOW"
    "projection.date.format"        = "yyyy/MM/dd"
    "projection.date.interval"      = "1"
    "projection.date.interval.unit" = "DAYS"
    "storage.location.template"     = "s3://${aws_s3_bucket.audit_logs.id}/AWSLogs/${var.account_id}/CloudTrail/$${region}/$${date}"
  }

  partition_keys {
    name = "region"
    type = "string"
  }

  partition_keys {
    name = "date"
    type = "string"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.audit_logs.id}/AWSLogs/${var.account_id}/CloudTrail/"
    input_format  = "com.amazon.emr.cloudtrail.CloudTrailInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "com.amazon.emr.hive.serde.CloudTrailSerde"
    }

    columns {
      name = "eventversion"
      type = "string"
    }

    columns {
      name = "useridentity"
      type = "struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,username:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>>>"
    }

    columns {
      name = "eventtime"
      type = "string"
    }

    columns {
      name = "eventsource"
      type = "string"
    }

    columns {
      name = "eventname"
      type = "string"
    }

    columns {
      name = "awsregion"
      type = "string"
    }

    columns {
      name = "sourceipaddress"
      type = "string"
    }

    columns {
      name = "useragent"
      type = "string"
    }

    columns {
      name = "errorcode"
      type = "string"
    }

    columns {
      name = "errormessage"
      type = "string"
    }

    columns {
      name = "requestparameters"
      type = "string"
    }

    columns {
      name = "responseelements"
      type = "string"
    }

    columns {
      name = "additionaleventdata"
      type = "string"
    }

    columns {
      name = "requestid"
      type = "string"
    }

    columns {
      name = "eventid"
      type = "string"
    }

    columns {
      name = "resources"
      type = "array<struct<arn:string,accountid:string,type:string>>"
    }

    columns {
      name = "eventtype"
      type = "string"
    }

    columns {
      name = "apiversion"
      type = "string"
    }

    columns {
      name = "readonly"
      type = "string"
    }

    columns {
      name = "recipientaccountid"
      type = "string"
    }

    columns {
      name = "serviceeventdetails"
      type = "string"
    }

    columns {
      name = "sharedeventid"
      type = "string"
    }

    columns {
      name = "vpcendpointid"
      type = "string"
    }

    columns {
      name = "tlsdetails"
      type = "struct<tlsversion:string,ciphersuite:string,clientprovidedhostheader:string>"
    }
  }
}

resource "aws_athena_workgroup" "audit" {
  name = "audit"

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = true
    # Was 10 GiB (10737418240), sized for an early "tens of MB per 90-day scan"
    # estimate. The hourly dashboard refresh (quicksight.tf) now exceeds that as
    # actual CloudTrail volume (16-region x 90-day scan, no region filter) has
    # grown past the original estimate. Bumped to 50 GiB; revisit if it grows into
    # this too — Athena bills ~$5/TB scanned and this query runs 24x/day.
    bytes_scanned_cutoff_per_query = 53687091200

    # v3 (Trino) is required by the dataset's geo range-join: the IPADDRESS type used to
    # validate source IPs before the integer-range CIDR match. (IPPREFIX/contains() are
    # deliberately NOT used — Athena v3 lacks the IPPREFIX type.) Pinned explicitly so a
    # future account-default change can't silently break it.
    engine_version {
      selected_engine_version = "Athena engine version 3"
    }

    result_configuration {
      output_location = "s3://${aws_s3_bucket.athena_results.id}/"

      encryption_configuration {
        encryption_option = "SSE_KMS"
        kms_key_arn       = aws_kms_key.audit.arn
      }
    }
  }

  tags = {
    Purpose   = "audit-dashboard"
    DataClass = "AuditTrail"
  }
}

# ──────────────────────────────────────────────────────────────────────
# Phase 4: Post-deploy hardening
# ──────────────────────────────────────────────────────────────────────

# QuickSight audit logging → CloudWatch Logs
# NOTE: 2557 is the closest valid CW Logs retention to the 2555-day audit policy (~7 years).
resource "aws_cloudwatch_log_group" "quicksight_audit" {
  name              = "/aws/quicksight/audit"
  retention_in_days = 2557

  tags = {
    Purpose   = "audit-dashboard"
    DataClass = "AuditTrail"
  }
}

resource "aws_cloudwatch_log_resource_policy" "quicksight_audit" {
  policy_name = "quicksight-audit-logging"

  policy_document = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "quicksight.amazonaws.com" }
        Action = [
          "logs:CreateLogGroup",
          "logs:CreateLogStream",
          "logs:PutLogEvents",
          "logs:DescribeLogGroups",
          "logs:DescribeLogStreams"
        ]
        Resource = "${aws_cloudwatch_log_group.quicksight_audit.arn}:*"
        Condition = {
          StringEquals = {
            "aws:SourceAccount" = var.account_id
          }
        }
      }
    ]
  })
}

# QuickSight groups — AuditAdmins (create/edit), AuditViewers (view only)
resource "aws_quicksight_group" "audit_admins" {
  group_name     = "AuditAdmins"
  aws_account_id = var.account_id
  namespace      = "default"
  description    = "Full create/edit access to audit dashboards"
}

resource "aws_quicksight_group" "audit_viewers" {
  group_name     = "AuditViewers"
  aws_account_id = var.account_id
  namespace      = "default"
  description    = "View-only access to audit dashboards"
}
