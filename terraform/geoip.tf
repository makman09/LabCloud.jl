# GeoIP reference data for the Source IP Access sheet's geo maps.
#
# Holds a GeoLite2 City (IPv4) extract — public, non-PHI reference data — that the
# dataset SQL range-joins source IPs against to derive country / city / lat-lon. The
# dashboard's Athena dataset reads these two Glue tables; the QuickSight role is granted
# S3 read on this bucket in quicksight.tf (ReadGeoIpBucket). Both tables live in the
# existing `security_audit` Glue DB, so the role's `table/security_audit/*` Glue grant
# already covers them.
#
# DATA LOAD (manual, forward-only like the vendor selector): download GeoLite2-City CSVs
# from MaxMind (free account + license key) and upload the two files:
#   GeoLite2-City-Blocks-IPv4.csv   -> s3://caucellcloud-geoip/blocks/
#   GeoLite2-City-Locations-en.csv  -> s3://caucellcloud-geoip/locations/
# The geo columns/maps stay null/empty until these exist. Re-upload to refresh (GeoLite2
# reissues ~weekly; for audit geo, country/city is stable enough that quarterly is fine).
# AES256 (not KMS): public reference data, and it keeps the upload free of KMS perms.

resource "aws_s3_bucket" "geoip" {
  bucket = "caucellcloud-geoip"

  tags = {
    Purpose   = "geoip-reference"
    DataClass = "Public"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "geoip" {
  bucket = aws_s3_bucket.geoip.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

resource "aws_s3_bucket_public_access_block" "geoip" {
  bucket = aws_s3_bucket.geoip.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "geoip" {
  bucket = aws_s3_bucket.geoip.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.geoip.arn,
          "${aws_s3_bucket.geoip.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

# GeoLite2-City-Blocks-IPv4.csv — CIDR network → geoname_id + lat/lon. OpenCSVSerde reads
# every column as a string (header skipped); the dataset SQL parses network into an integer
# [start,end] range (Athena v3 has no IPPREFIX type) and casts latitude/longitude→double.
resource "aws_glue_catalog_table" "geoip_blocks" {
  name          = "geoip_blocks"
  database_name = aws_glue_catalog_database.security_audit.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    "skip.header.line.count" = "1"
    "classification"         = "csv"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.geoip.id}/blocks/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.serde2.OpenCSVSerde"
      parameters = {
        "separatorChar" = ","
        "quoteChar"     = "\""
        "escapeChar"    = "\\"
      }
    }

    columns {
      name = "network"
      type = "string"
    }
    columns {
      name = "geoname_id"
      type = "string"
    }
    columns {
      name = "registered_country_geoname_id"
      type = "string"
    }
    columns {
      name = "represented_country_geoname_id"
      type = "string"
    }
    columns {
      name = "is_anonymous_proxy"
      type = "string"
    }
    columns {
      name = "is_satellite_provider"
      type = "string"
    }
    columns {
      name = "postal_code"
      type = "string"
    }
    columns {
      name = "latitude"
      type = "string"
    }
    columns {
      name = "longitude"
      type = "string"
    }
    columns {
      name = "accuracy_radius"
      type = "string"
    }
  }
}

# GeoLite2-City-Locations-en.csv — geoname_id → country / city names.
resource "aws_glue_catalog_table" "geoip_locations" {
  name          = "geoip_locations"
  database_name = aws_glue_catalog_database.security_audit.name
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    "skip.header.line.count" = "1"
    "classification"         = "csv"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.geoip.id}/locations/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.serde2.OpenCSVSerde"
      parameters = {
        "separatorChar" = ","
        "quoteChar"     = "\""
        "escapeChar"    = "\\"
      }
    }

    columns {
      name = "geoname_id"
      type = "string"
    }
    columns {
      name = "locale_code"
      type = "string"
    }
    columns {
      name = "continent_code"
      type = "string"
    }
    columns {
      name = "continent_name"
      type = "string"
    }
    columns {
      name = "country_iso_code"
      type = "string"
    }
    columns {
      name = "country_name"
      type = "string"
    }
    columns {
      name = "subdivision_1_iso_code"
      type = "string"
    }
    columns {
      name = "subdivision_1_name"
      type = "string"
    }
    columns {
      name = "subdivision_2_iso_code"
      type = "string"
    }
    columns {
      name = "subdivision_2_name"
      type = "string"
    }
    columns {
      name = "city_name"
      type = "string"
    }
    columns {
      name = "metro_code"
      type = "string"
    }
    columns {
      name = "time_zone"
      type = "string"
    }
    columns {
      name = "is_in_european_union"
      type = "string"
    }
  }
}
