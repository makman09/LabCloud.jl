resource "aws_s3_bucket" "phi" {
  for_each = toset(var.phi_bucket_names)

  bucket              = each.value
  object_lock_enabled = true

  tags = {
    Purpose   = "research"
    DataClass = "PHI"
  }
}

resource "aws_s3_bucket_versioning" "phi" {
  for_each = aws_s3_bucket.phi

  bucket = each.value.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_object_lock_configuration" "phi" {
  for_each = aws_s3_bucket.phi

  bucket = each.value.id

  rule {
    default_retention {
      mode = "GOVERNANCE"
      days = var.object_lock_retention_days
    }
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "phi" {
  for_each = aws_s3_bucket.phi

  bucket = each.value.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "phi" {
  for_each = aws_s3_bucket.phi

  bucket = each.value.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "phi" {
  for_each = aws_s3_bucket.phi

  bucket = each.value.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          each.value.arn,
          "${each.value.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}
