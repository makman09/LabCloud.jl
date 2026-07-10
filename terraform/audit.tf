resource "aws_kms_key" "audit" {
  description             = "Encrypts audit logs — separate blast radius from PHI key"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Purpose   = "audit-logs"
    DataClass = "AuditTrail"
  }
}

resource "aws_kms_alias" "audit" {
  name          = "alias/audit-logs-key"
  target_key_id = aws_kms_key.audit.key_id
}

resource "aws_s3_bucket" "audit_logs" {
  bucket              = "caucellcloud-audit-logs"
  object_lock_enabled = true

  tags = {
    Purpose   = "audit-logs"
    DataClass = "AuditTrail"
  }
}

resource "aws_s3_bucket_versioning" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.audit_retention_days
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.audit.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "audit_logs" {
  bucket = aws_s3_bucket.audit_logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
