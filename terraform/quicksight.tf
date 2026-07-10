resource "aws_iam_role" "quicksight_service" {
  name = "QuickSightAuditDashboard"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { Service = "quicksight.amazonaws.com" }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Purpose = "audit-dashboard"
  }
}

resource "aws_iam_role_policy" "quicksight_audit_access" {
  name = "quicksight-audit-access"
  role = aws_iam_role.quicksight_service.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadAuditLogsBucket"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.audit_logs.arn,
          "${aws_s3_bucket.audit_logs.arn}/*"
        ]
      },
      {
        Sid    = "ReadGeoIpBucket"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.geoip.arn,
          "${aws_s3_bucket.geoip.arn}/*"
        ]
      },
      {
        Sid    = "AthenaResultsBucket"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = [
          aws_s3_bucket.athena_results.arn,
          "${aws_s3_bucket.athena_results.arn}/*"
        ]
      },
      {
        Sid    = "AthenaQueryExecution"
        Effect = "Allow"
        Action = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
          "athena:StopQueryExecution",
          "athena:GetWorkGroup"
        ]
        Resource = "arn:aws:athena:${var.region}:${var.account_id}:workgroup/${aws_athena_workgroup.audit.name}"
      },
      {
        Sid    = "GlueCatalogAccess"
        Effect = "Allow"
        Action = [
          "glue:GetDatabase",
          "glue:GetTable",
          "glue:GetPartitions",
          "glue:GetPartition"
        ]
        Resource = [
          "arn:aws:glue:${var.region}:${var.account_id}:catalog",
          "arn:aws:glue:${var.region}:${var.account_id}:database/security_audit",
          "arn:aws:glue:${var.region}:${var.account_id}:table/security_audit/*"
        ]
      },
      {
        Sid    = "AuditKmsDecrypt"
        Effect = "Allow"
        Action = [
          "kms:Decrypt",
          "kms:DescribeKey",
          "kms:GenerateDataKey"
        ]
        Resource = aws_kms_key.audit.arn
      }
    ]
  })
}

resource "aws_quicksight_data_source" "athena" {
  aws_account_id = var.account_id
  data_source_id = "cloudtrail-athena"
  name           = "cloudtrail-athena"
  type           = "ATHENA"

  parameters {
    athena {
      work_group = aws_athena_workgroup.audit.name
    }
  }

  permission {
    principal = "arn:aws:quicksight:${var.region}:${var.account_id}:user/default/${var.quicksight_admin_username}"
    actions = [
      "quicksight:DescribeDataSource",
      "quicksight:DescribeDataSourcePermissions",
      "quicksight:PassDataSource",
      "quicksight:UpdateDataSource",
      "quicksight:UpdateDataSourcePermissions",
      "quicksight:DeleteDataSource"
    ]
  }

  permission {
    principal = aws_quicksight_group.audit_admins.arn
    actions = [
      "quicksight:DescribeDataSource",
      "quicksight:DescribeDataSourcePermissions",
      "quicksight:PassDataSource",
      "quicksight:UpdateDataSource",
      "quicksight:UpdateDataSourcePermissions",
      "quicksight:DeleteDataSource"
    ]
  }

  permission {
    principal = aws_quicksight_group.audit_viewers.arn
    actions = [
      "quicksight:DescribeDataSource",
      "quicksight:PassDataSource"
    ]
  }

  lifecycle {
    ignore_changes = [permission]
  }
}

resource "aws_quicksight_data_set" "audit_dashboard" {
  aws_account_id = var.account_id
  data_set_id    = "cloudtrail-audit-dashboard"
  name           = "CloudTrail Audit Dashboard"
  import_mode    = "SPICE"

  physical_table_map {
    physical_table_map_id = "cloudtrail-query"

    custom_sql {
      data_source_arn = aws_quicksight_data_source.athena.arn
      name            = "cloudtrail-audit-query"
      sql_query       = <<-SQL
        -- base: per-event projection + is_customer / is_vendor attribution flags
        -- (never-NULL flags the Customers / Source-IP-Access filters use via numeric
        -- equality — render-proof, unlike category null_option filters on nullable names).
        -- ip_geo (below) then enriches each distinct source IP with GeoLite2 geo.
        WITH base AS (
        SELECT *,
               CASE WHEN customer IS NOT NULL THEN 1 ELSE 0 END AS is_customer,
               CASE WHEN vendor   IS NOT NULL THEN 1 ELSE 0 END AS is_vendor,
               -- Credential-precise flags for the Source IP Access sheet: the principal
               -- IS the LabCustomer-/LabVendor- IAM user (the credential actually in use),
               -- NOT merely any activity touching the bucket. is_customer/is_vendor above are
               -- bucket-inclusive, so they also tag our own backend writes (PhiAppRole sync,
               -- provisioner) and AWS-service principals — whose source_ip is a service/AWS
               -- address, not the customer's. Matching on the principal drops all of that, so
               -- the IP sheet shows only real client-IP usage of the scoped credential.
               -- Legacy customers match on the LabCustomer- name; new customers have a bare
               -- username, so the credential is identified by the /lab-customers/ IAM path in
               -- the principal ARN instead (principal_name alone can't distinguish them).
               CASE WHEN principal_name LIKE 'LabCustomer-%'
                         OR principal_arn LIKE '%:user/lab-customers/%' THEN 1 ELSE 0 END AS is_customer_cred,
               CASE WHEN principal_name LIKE 'LabVendor-%'   THEN 1 ELSE 0 END AS is_vendor_cred,
               -- Render-proof "names a bucket" flag (numeric, like is_customer) so the detail
               -- tables can drop bucket-less S3 rows (e.g. ListBuckets) without a null bar —
               -- a category null_option filter on s3_bucket still renders the null group.
               CASE WHEN s3_bucket IS NOT NULL THEN 1 ELSE 0 END AS has_s3_bucket
        FROM (
        SELECT
          from_iso8601_timestamp(eventtime)            AS event_ts,
          eventname,
          eventsource,
          awsregion,
          sourceipaddress                              AS source_ip,
          useragent,
          errorcode,
          useridentity.type                            AS principal_type,
          useridentity.arn                             AS principal_arn,
          COALESCE(useridentity.username,
                   useridentity.sessioncontext.sessionissuer.username) AS principal_name,
          useridentity.sessioncontext.attributes.mfaauthenticated      AS mfa_used,
          recipientaccountid,
          readonly,
          json_extract_scalar(requestparameters, '$.bucketName')       AS s3_bucket,
          -- Customer attribution, normalized to one lowercased key (e.g. "mandakhbekhbat")
          -- so it joins cleanly to the principal and the lab_customers registry. Paths, in
          -- priority order (new users have a bare username under the /lab-customers/ IAM path,
          -- so the discriminator moved from the name to the ARN / requestparameters.path):
          --   1. data-plane / bucket ops        → research-{name} bucket  (already lowercased)
          --   2. legacy customer acting directly → LabCustomer-{Name} IAM user / assumed-role
          --   3. new customer acting directly    → useridentity.arn = …:user/lab-customers/{Name}
          --   4. legacy provisioning / lifecycle → requestparameters.userName LabCustomer-{Name}
          --   5. new provisioning / lifecycle    → requestparameters.path = /lab-customers/
          -- regexp_extract returns NULL on no match, so COALESCE falls through cleanly.
          COALESCE(
            regexp_extract(json_extract_scalar(requestparameters, '$.bucketName'),
                           '^research-(.+)$', 1),
            lower(regexp_extract(COALESCE(useridentity.username,
                       useridentity.sessioncontext.sessionissuer.username),
                       '^LabCustomer-(.+)$', 1)),
            lower(regexp_extract(useridentity.arn, ':user/lab-customers/(.+)$', 1)),
            lower(regexp_extract(json_extract_scalar(requestparameters, '$.userName'),
                       '^LabCustomer-(.+)$', 1)),
            CASE WHEN json_extract_scalar(requestparameters, '$.path') = '/lab-customers/'
                 THEN lower(json_extract_scalar(requestparameters, '$.userName')) END
          )                                            AS customer,
          -- Vendor attribution, mirror of customer above for the inbound landing path:
          --   1. data-plane / object ops    → caucell-{vendor}-landing bucket
          --   2. the vendor acting directly → LabVendor-{vendor} IAM user / assumed-role
          --   3. provisioning / lifecycle   → requestparameters.userName on IAM Create/Delete
          -- Vendor names are already lowercase slugs; lower() is harmless and keeps the
          -- two extractions identical in shape.
          COALESCE(
            regexp_extract(json_extract_scalar(requestparameters, '$.bucketName'),
                           '^caucell-(.+)-landing$', 1),
            lower(regexp_extract(COALESCE(useridentity.username,
                       useridentity.sessioncontext.sessionissuer.username),
                       '^LabVendor-(.+)$', 1)),
            lower(regexp_extract(json_extract_scalar(requestparameters, '$.userName'),
                       '^LabVendor-(.+)$', 1))
          )                                            AS vendor,
          CASE WHEN errorcode IS NOT NULL THEN 1 ELSE 0 END            AS is_error
        FROM security_audit.cloudtrail_logs
        WHERE date >= date_format(date_add('day', -90, current_date), '%Y/%m/%d')
        )
        ),
        -- Resolve distinct IPv4 source IPs to GeoLite2 country/city/lat-lon via one bounded
        -- range join. Keying on DISTINCT IPs (a few hundred at most) means the ~3.4M-row
        -- blocks table is scanned once, not multiplied by event volume. GeoLite2 CIDRs are
        -- disjoint, so each IP matches <=1 block (no fan-out); LEFT JOIN back leaves any
        -- unresolved IP with null geo.
        --
        -- Both sides are reduced to 32-bit integers and matched with
        -- ip_int BETWEEN net_start AND net_end. We deliberately AVOID the IPPREFIX type /
        -- contains(): Athena engine v3 has the IPADDRESS type but NOT IPPREFIX, so
        -- `CAST(... AS ipprefix)` fails ingestion with "Unknown type: ipprefix". Integer
        -- math is type-portable and equivalent for IPv4. The NOT LIKE '%:%' +
        -- try_cast(... AS ipaddress) guards still drop IPv6 and service-name "IPs"
        -- (e.g. s3.amazonaws.com) before the octet split; try_cast everywhere means a single
        -- malformed row yields null geo rather than failing the whole ingestion.
        ip_geo AS (
          SELECT d.source_ip,
                 loc.country_name                  AS geo_country,
                 loc.subdivision_1_name            AS geo_state,
                 loc.subdivision_2_name            AS geo_county,
                 loc.city_name                     AS geo_city,
                 try_cast(blk.latitude  AS double) AS geo_lat,
                 try_cast(blk.longitude AS double) AS geo_lon
          FROM (
            SELECT source_ip,
                   try_cast(split_part(source_ip, '.', 1) AS bigint) * 16777216
                 + try_cast(split_part(source_ip, '.', 2) AS bigint) * 65536
                 + try_cast(split_part(source_ip, '.', 3) AS bigint) * 256
                 + try_cast(split_part(source_ip, '.', 4) AS bigint) AS ip_int
            FROM (
              SELECT DISTINCT source_ip
              FROM base
              WHERE source_ip IS NOT NULL
                AND source_ip NOT LIKE '%:%'
                AND try_cast(source_ip AS ipaddress) IS NOT NULL
            )
          ) d
          JOIN (
            -- GeoLite2 IPv4 CIDRs as inclusive [net_start, net_end] integer ranges. The
            -- CIDRs are network-aligned, so the parsed address is the range start; the end
            -- is start + 2^(32 - prefix_len) - 1.
            SELECT geoname_id, latitude, longitude, net_start,
                   net_start + try_cast(power(2, 32 - prefix_len) AS bigint) - 1 AS net_end
            FROM (
              SELECT geoname_id, latitude, longitude,
                     try_cast(split_part(split_part(network, '/', 1), '.', 1) AS bigint) * 16777216
                   + try_cast(split_part(split_part(network, '/', 1), '.', 2) AS bigint) * 65536
                   + try_cast(split_part(split_part(network, '/', 1), '.', 3) AS bigint) * 256
                   + try_cast(split_part(split_part(network, '/', 1), '.', 4) AS bigint) AS net_start,
                     try_cast(split_part(network, '/', 2) AS integer) AS prefix_len
              FROM security_audit.geoip_blocks
              WHERE network LIKE '%.%/%'
            )
          ) blk
            ON d.ip_int BETWEEN blk.net_start AND blk.net_end
          LEFT JOIN security_audit.geoip_locations loc
            ON blk.geoname_id = loc.geoname_id
        )
        SELECT base.*,
               ip_geo.geo_country,
               ip_geo.geo_state,
               ip_geo.geo_county,
               ip_geo.geo_city,
               ip_geo.geo_lat,
               ip_geo.geo_lon
        FROM base
        LEFT JOIN ip_geo ON base.source_ip = ip_geo.source_ip
      SQL

      columns {
        name = "event_ts"
        type = "DATETIME"
      }
      columns {
        name = "eventname"
        type = "STRING"
      }
      columns {
        name = "eventsource"
        type = "STRING"
      }
      columns {
        name = "awsregion"
        type = "STRING"
      }
      columns {
        name = "source_ip"
        type = "STRING"
      }
      columns {
        name = "useragent"
        type = "STRING"
      }
      columns {
        name = "errorcode"
        type = "STRING"
      }
      columns {
        name = "principal_type"
        type = "STRING"
      }
      columns {
        name = "principal_arn"
        type = "STRING"
      }
      columns {
        name = "principal_name"
        type = "STRING"
      }
      columns {
        name = "mfa_used"
        type = "STRING"
      }
      columns {
        name = "recipientaccountid"
        type = "STRING"
      }
      columns {
        name = "readonly"
        type = "STRING"
      }
      columns {
        name = "s3_bucket"
        type = "STRING"
      }
      columns {
        name = "customer"
        type = "STRING"
      }
      columns {
        name = "vendor"
        type = "STRING"
      }
      columns {
        name = "is_error"
        type = "INTEGER"
      }
      columns {
        name = "is_customer"
        type = "INTEGER"
      }
      columns {
        name = "is_vendor"
        type = "INTEGER"
      }
      columns {
        name = "is_customer_cred"
        type = "INTEGER"
      }
      columns {
        name = "is_vendor_cred"
        type = "INTEGER"
      }
      columns {
        name = "has_s3_bucket"
        type = "INTEGER"
      }
      columns {
        name = "geo_country"
        type = "STRING"
      }
      columns {
        name = "geo_state"
        type = "STRING"
      }
      columns {
        name = "geo_county"
        type = "STRING"
      }
      columns {
        name = "geo_city"
        type = "STRING"
      }
      columns {
        name = "geo_lat"
        type = "DECIMAL"
      }
      columns {
        name = "geo_lon"
        type = "DECIMAL"
      }
    }
  }

  logical_table_map {
    logical_table_map_id = "cloudtrail-logical"
    alias                = "CloudTrail Audit Events"

    source {
      physical_table_id = "cloudtrail-query"
    }

    # Tag the geo columns with geographic roles so the Source IP Access maps can place
    # lat/lon as point coordinates (and country/city are map-aware for any later filled map).
    data_transforms {
      tag_column_operation {
        column_name = "geo_lat"
        tags {
          column_geographic_role = "LATITUDE"
        }
      }
    }
    data_transforms {
      tag_column_operation {
        column_name = "geo_lon"
        tags {
          column_geographic_role = "LONGITUDE"
        }
      }
    }
    data_transforms {
      tag_column_operation {
        column_name = "geo_country"
        tags {
          column_geographic_role = "COUNTRY"
        }
      }
    }
    data_transforms {
      tag_column_operation {
        column_name = "geo_city"
        tags {
          column_geographic_role = "CITY"
        }
      }
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

# Hourly like the Synology dataset: each refresh re-scans ~90 days of gzipped
# CloudTrail in Athena (tens of MB -> ~$1-5/month at 24/day); SPICE bills
# storage, not refresh count. HIPAA-critical signals don't ride on this —
# the immutable CloudTrail record and the EventBridge->SNS alerts are
# near-real-time regardless; this only bounds dashboard staleness to <=1h.
resource "aws_quicksight_refresh_schedule" "audit_hourly" {
  aws_account_id = var.account_id
  data_set_id    = aws_quicksight_data_set.audit_dashboard.data_set_id
  schedule_id    = "audit-hourly-refresh"

  schedule {
    refresh_type = "FULL_REFRESH"

    schedule_frequency {
      interval = "HOURLY"
    }
  }
}
