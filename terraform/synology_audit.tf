# Synology NAS access-log streaming — on-prem DS1823xs+ file-access events into the
# existing audit pipeline:
#
#   NAS Log Center ─syslog─▶ Fluent Bit (Container Manager, see ../nas_collector/)
#     ─PutRecordBatch─▶ Firehose synology-audit-stream (JSON→Parquet via the Glue
#     schema below) ─▶ s3://caucellcloud-audit-logs/synology/dt=YYYY-MM-DD/
#     ─▶ Athena security_audit.synology_access ─▶ QuickSight "NAS Access" sheet
#
# Reuses the audit bucket/KMS key/Glue db/Athena workgroup/QuickSight data source.
# Field-name contract: the Fluent Bit capture groups must emit exactly the column
# names of the Glue table below — Firehose's Parquet conversion matches JSON keys
# to columns by name, and mismatched keys land as NULL.

# ──────────────────────────────────────────────────────────────────────
# Glue table — Firehose reads it for Parquet conversion, Athena queries it
# via partition projection (no crawler, no MSCK REPAIR)
# ──────────────────────────────────────────────────────────────────────

resource "aws_glue_catalog_table" "synology_access" {
  name          = "synology_access"
  database_name = aws_glue_catalog_database.security_audit.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    "classification"              = "parquet"
    "projection.enabled"          = "true"
    "projection.dt.type"          = "date"
    "projection.dt.format"        = "yyyy-MM-dd"
    "projection.dt.range"         = "${var.synology_start_date},NOW"
    "projection.dt.interval"      = "1"
    "projection.dt.interval.unit" = "DAYS"
    "storage.location.template"   = "s3://${aws_s3_bucket.audit_logs.id}/synology/dt=$${dt}/"
  }

  partition_keys {
    name = "dt"
    type = "string"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.audit_logs.id}/synology/"
    input_format  = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
    }

    # %Y-%m-%dT%H:%M:%S, no zone — parsed to a timestamp in the QuickSight dataset SQL
    columns {
      name = "ts"
      type = "string"
    }

    columns {
      name = "host"
      type = "string"
    }

    columns {
      name = "severity"
      type = "string"
    }

    # NOT `user` — reserved word in Trino; a bare `SELECT user` silently returns
    # the session user instead of the column
    columns {
      name = "username"
      type = "string"
    }

    columns {
      name = "src_ip"
      type = "string"
    }

    columns {
      name = "proto"
      type = "string"
    }

    columns {
      name = "action"
      type = "string"
    }

    columns {
      name = "path"
      type = "string"
    }
  }
}

# ──────────────────────────────────────────────────────────────────────
# Firehose error logging
# ──────────────────────────────────────────────────────────────────────

# Operational error logs, not audit evidence — short retention is deliberate.
resource "aws_cloudwatch_log_group" "firehose_synology" {
  name              = "/aws/kinesisfirehose/synology-audit-stream"
  retention_in_days = 90

  tags = {
    Purpose   = "audit-logs"
    DataClass = "AuditTrail"
  }
}

resource "aws_cloudwatch_log_stream" "firehose_synology" {
  name           = "DestinationDelivery"
  log_group_name = aws_cloudwatch_log_group.firehose_synology.name
}

# ──────────────────────────────────────────────────────────────────────
# Firehose service role — write S3, read Glue schema, log errors, use the
# audit CMK. Key use is granted via IAM policy alone: the audit key policy
# delegates to IAM through EnableRootAccountPermissions (cloudtrail.tf),
# same convention as LabCustomers/LabVendors.
# ──────────────────────────────────────────────────────────────────────

resource "aws_iam_role" "firehose_synology" {
  name = "FirehoseSynologyAudit"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "firehose.amazonaws.com" }
        Action    = "sts:AssumeRole"
        Condition = {
          StringEquals = { "sts:ExternalId" = var.account_id }
        }
      }
    ]
  })

  tags = {
    Purpose = "audit-logs"
  }
}

resource "aws_iam_role_policy" "firehose_synology" {
  name = "firehose-synology-delivery"
  role = aws_iam_role.firehose_synology.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3Delivery"
        Effect = "Allow"
        Action = [
          "s3:AbortMultipartUpload",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:ListBucket",
          "s3:ListBucketMultipartUploads",
          "s3:PutObject"
        ]
        Resource = [
          aws_s3_bucket.audit_logs.arn,
          "${aws_s3_bucket.audit_logs.arn}/synology/*",
          "${aws_s3_bucket.audit_logs.arn}/synology-errors/*"
        ]
      },
      {
        Sid    = "GlueSchemaForParquet"
        Effect = "Allow"
        Action = [
          "glue:GetTable",
          "glue:GetTableVersion",
          "glue:GetTableVersions"
        ]
        Resource = [
          "arn:aws:glue:${var.region}:${var.account_id}:catalog",
          "arn:aws:glue:${var.region}:${var.account_id}:database/${aws_glue_catalog_database.security_audit.name}",
          "arn:aws:glue:${var.region}:${var.account_id}:table/${aws_glue_catalog_database.security_audit.name}/${aws_glue_catalog_table.synology_access.name}"
        ]
      },
      {
        Sid      = "ErrorLogging"
        Effect   = "Allow"
        Action   = "logs:PutLogEvents"
        Resource = "${aws_cloudwatch_log_group.firehose_synology.arn}:*"
      },
      {
        Sid    = "AuditKeyUse"
        Effect = "Allow"
        Action = [
          "kms:GenerateDataKey",
          "kms:Decrypt"
        ]
        Resource = aws_kms_key.audit.arn
        Condition = {
          StringEquals = { "kms:ViaService" = "s3.${var.region}.amazonaws.com" }
        }
      }
    ]
  })
}

# ──────────────────────────────────────────────────────────────────────
# Delivery stream — Direct PUT, JSON→Parquet, ingestion-time partitioning
# ──────────────────────────────────────────────────────────────────────

resource "aws_kinesis_firehose_delivery_stream" "synology" {
  name        = "synology-audit-stream"
  destination = "extended_s3"

  # Firehose validates the role's S3/Glue/KMS access at create time; the inline
  # policy is a separate resource, so the role_arn reference alone doesn't order it.
  depends_on = [aws_iam_role_policy.firehose_synology]

  server_side_encryption {
    enabled  = true
    key_type = "AWS_OWNED_CMK"
  }

  extended_s3_configuration {
    role_arn   = aws_iam_role.firehose_synology.arn
    bucket_arn = aws_s3_bucket.audit_logs.arn

    prefix              = "synology/dt=!{timestamp:yyyy-MM-dd}/"
    error_output_prefix = "synology-errors/!{timestamp:yyyy-MM-dd}/!{firehose:error-output-type}/"

    # Parquet conversion needs the larger buffer floor (64 MB minimum).
    buffering_size     = 128
    buffering_interval = 300

    # Match the bucket's default SSE-KMS so delivered objects use the audit CMK.
    kms_key_arn = aws_kms_key.audit.arn

    # Must stay UNCOMPRESSED when format conversion is on — Parquet compresses
    # internally (SNAPPY).
    compression_format = "UNCOMPRESSED"

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.firehose_synology.name
      log_stream_name = aws_cloudwatch_log_stream.firehose_synology.name
    }

    data_format_conversion_configuration {
      enabled = true

      input_format_configuration {
        deserializer {
          open_x_json_ser_de {}
        }
      }

      output_format_configuration {
        serializer {
          parquet_ser_de {}
        }
      }

      schema_configuration {
        database_name = aws_glue_catalog_database.security_audit.name
        table_name    = aws_glue_catalog_table.synology_access.name
        role_arn      = aws_iam_role.firehose_synology.arn
        region        = var.region
        version_id    = "LATEST"
      }
    }
  }

  tags = {
    Purpose   = "audit-logs"
    DataClass = "AuditTrail"
  }
}

# ──────────────────────────────────────────────────────────────────────
# Collector identity — static scoped keys for v1 (the only principal the
# NAS holds; can put records to this one stream and nothing else).
# Fast-follow: IAM Roles Anywhere (see ../nas_collector/README.md).
# ──────────────────────────────────────────────────────────────────────

resource "aws_iam_user" "synology_collector" {
  name = "synology-log-collector"

  tags = {
    Purpose = "audit-logs"
  }
}

resource "aws_iam_access_key" "synology_collector" {
  user = aws_iam_user.synology_collector.name
}

resource "aws_iam_user_policy" "synology_collector" {
  name = "synology-firehose-put"
  user = aws_iam_user.synology_collector.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "PutToSynologyStreamOnly"
        Effect = "Allow"
        Action = [
          "firehose:PutRecord",
          "firehose:PutRecordBatch"
        ]
        Resource = aws_kinesis_firehose_delivery_stream.synology.arn
      }
    ]
  })
}

# ──────────────────────────────────────────────────────────────────────
# Delivery monitoring — DataFreshness catches stuck delivery, permission
# breaks, and Object-Lock rejections in one metric
# ──────────────────────────────────────────────────────────────────────

resource "aws_cloudwatch_metric_alarm" "synology_firehose_stalled" {
  alarm_name        = "synology-firehose-delivery-stalled"
  alarm_description = "Synology NAS audit stream: records buffered in Firehose are older than 15 min — delivery to s3://caucellcloud-audit-logs/synology/ is failing or stalled"

  namespace   = "AWS/Firehose"
  metric_name = "DeliveryToS3.DataFreshness"
  dimensions = {
    DeliveryStreamName = aws_kinesis_firehose_delivery_stream.synology.name
  }

  statistic           = "Maximum"
  period              = 300
  evaluation_periods  = 3
  threshold           = 900 # 3x the 300 s buffer interval
  comparison_operator = "GreaterThanThreshold"
  treat_missing_data  = "notBreaching" # a quiet NAS emits no metric — don't page on silence

  alarm_actions = [aws_sns_topic.phi_security_alerts.arn]

  tags = {
    Purpose = "security-monitoring"
  }
}

# ──────────────────────────────────────────────────────────────────────
# QuickSight dataset — SPICE over the Glue table, same Athena data source
# as the CloudTrail dataset
# ──────────────────────────────────────────────────────────────────────

resource "aws_quicksight_data_set" "synology_access" {
  aws_account_id = var.account_id
  data_set_id    = "synology-nas-access"
  name           = "Synology NAS Access"
  import_mode    = "SPICE"

  # custom_sql hides the Glue-table dependency from Terraform; the initial SPICE
  # ingestion at create fails if the table doesn't exist yet.
  depends_on = [aws_glue_catalog_table.synology_access]

  physical_table_map {
    physical_table_map_id = "synology-query"

    custom_sql {
      data_source_arn = aws_quicksight_data_source.athena.arn
      name            = "synology-access-query"
      # date_parse, not from_iso8601_timestamp: ts is zone-less. Rows with NULL
      # username/action (collector parse failures) are deliberately kept — a NULL
      # slice in the action donut is the cheapest parser-drift detector.
      sql_query = <<-SQL
        SELECT
          date_parse(ts, '%Y-%m-%dT%H:%i:%s') AS event_ts,
          host,
          severity,
          username,
          src_ip,
          proto,
          action,
          path
        FROM security_audit.synology_access
        WHERE dt >= date_format(date_add('day', -90, current_date), '%Y-%m-%d')
      SQL

      columns {
        name = "event_ts"
        type = "DATETIME"
      }
      columns {
        name = "host"
        type = "STRING"
      }
      columns {
        name = "severity"
        type = "STRING"
      }
      columns {
        name = "username"
        type = "STRING"
      }
      columns {
        name = "src_ip"
        type = "STRING"
      }
      columns {
        name = "proto"
        type = "STRING"
      }
      columns {
        name = "action"
        type = "STRING"
      }
      columns {
        name = "path"
        type = "STRING"
      }
    }
  }

  logical_table_map {
    logical_table_map_id = "synology-logical"
    alias                = "Synology NAS Access Events"

    source {
      physical_table_id = "synology-query"
    }
  }

  permissions {
    principal = "arn:aws:quicksight:${var.region}:${var.account_id}:user/default/${var.quicksight_admin_username}"
    actions = [
      "quicksight:DescribeDataSet",
      "quicksight:DescribeDataSetPermissions",
      "quicksight:PassDataSet",
      "quicksight:DescribeIngestion",
      "quicksight:ListIngestions",
      "quicksight:UpdateDataSet",
      "quicksight:UpdateDataSetPermissions",
      "quicksight:DeleteDataSet",
      "quicksight:CreateIngestion",
      "quicksight:CancelIngestion"
    ]
  }

  permissions {
    principal = aws_quicksight_group.audit_admins.arn
    actions = [
      "quicksight:DescribeDataSet",
      "quicksight:DescribeDataSetPermissions",
      "quicksight:PassDataSet",
      "quicksight:DescribeIngestion",
      "quicksight:ListIngestions",
      "quicksight:UpdateDataSet",
      "quicksight:UpdateDataSetPermissions",
      "quicksight:DeleteDataSet",
      "quicksight:CreateIngestion",
      "quicksight:CancelIngestion"
    ]
  }

  permissions {
    principal = aws_quicksight_group.audit_viewers.arn
    actions = [
      "quicksight:DescribeDataSet",
      "quicksight:DescribeDataSetPermissions",
      "quicksight:PassDataSet",
      "quicksight:DescribeIngestion",
      "quicksight:ListIngestions"
    ]
  }

  lifecycle {
    ignore_changes = [permissions]
  }
}

# Hourly is the closest QuickSight interval to the requested 4-hour cadence
# (supported intervals: 15m/30m/hourly/daily/weekly/monthly, max 5 schedules
# per dataset). One tiny Athena scan per hour over Parquet — negligible cost.
resource "aws_quicksight_refresh_schedule" "synology_hourly" {
  aws_account_id = var.account_id
  data_set_id    = aws_quicksight_data_set.synology_access.data_set_id
  schedule_id    = "synology-hourly-refresh"

  schedule {
    refresh_type = "FULL_REFRESH"

    schedule_frequency {
      interval = "HOURLY"
    }
  }
}
