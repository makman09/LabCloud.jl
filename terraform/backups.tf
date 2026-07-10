# NAS backup targets for Synology DSM's native backup tools — a separate concept from the
# research-*/caucell-*-landing buckets: this isn't a one-way append-only projection of the
# NAS, it's the actual off-site copy, so both buckets grant real delete to the DSM identity.
#
#   DS1823xs+ HyperBackup   ─S3 API─▶ caucellcloud-nas-hyperbackup   (versioned backup sets;
#                                       HyperBackup prunes its own old sets per its retention
#                                       schedule — the bucket must not fight that with Object
#                                       Lock, see below)
#   DS1823xs+ Cloud Sync    ─S3 API─▶ caucellcloud-nas-cloudsync     (live 1:1 mirror of
#                                       selected shares; deletes/overwrites when the NAS side
#                                       changes)
#
# No Object Lock on either bucket (unlike phi_buckets.tf/audit.tf): HyperBackup's retention
# scheme requires deleting whole old backup-set versions on its own schedule, and a
# GOVERNANCE/COMPLIANCE retention lock would turn those deletes into AccessDenied. Immutability
# here comes from IAM scoping instead — the synology-nas-backup identity below can act on
# nothing else in the account.
#
# Still treated as PHI for encryption purposes (reuses aws_kms_key.phi, same
# DenyInsecureTransport policy as phi_buckets.tf) since the NAS is the PHI source of truth.

# ──────────────────────────────────────────────────────────────────────
# HyperBackup target — versioned backup sets. No S3 versioning: HyperBackup already
# maintains its own version history internally, so bucket-level versioning would just
# accumulate noncurrent copies every time HyperBackup prunes a set on its own.
# ──────────────────────────────────────────────────────────────────────

resource "aws_s3_bucket" "nas_hyperbackup" {
  bucket = "caucellcloud-nas-hyperbackup"

  tags = {
    Purpose   = "nas-backup"
    DataClass = "PHI"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "nas_hyperbackup" {
  bucket = aws_s3_bucket.nas_hyperbackup.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "nas_hyperbackup" {
  bucket = aws_s3_bucket.nas_hyperbackup.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "nas_hyperbackup" {
  bucket = aws_s3_bucket.nas_hyperbackup.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.nas_hyperbackup.arn,
          "${aws_s3_bucket.nas_hyperbackup.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_lifecycle_configuration" "nas_hyperbackup" {
  bucket = aws_s3_bucket.nas_hyperbackup.id

  rule {
    id     = "hot-to-cold"
    status = "Enabled"

    filter {
      prefix = ""
    }

    transition {
      days          = var.nas_backup_ia_transition_days
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = var.nas_backup_glacier_transition_days
      storage_class = "GLACIER"
    }

    transition {
      days          = var.nas_backup_deep_archive_transition_days
      storage_class = "DEEP_ARCHIVE"
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }
}

# ──────────────────────────────────────────────────────────────────────
# Cloud Sync target — live mirror. Versioning stays on here (unlike HyperBackup) since
# Cloud Sync has no internal version history of its own; S3 versions are the only
# protection against an errant overwrite/delete on the NAS side. Noncurrent versions
# still age into cold storage and eventually expire so they don't accumulate forever.
# ──────────────────────────────────────────────────────────────────────

resource "aws_s3_bucket" "nas_cloudsync" {
  bucket = "caucellcloud-nas-cloudsync"

  tags = {
    Purpose   = "nas-backup"
    DataClass = "PHI"
  }
}

resource "aws_s3_bucket_versioning" "nas_cloudsync" {
  bucket = aws_s3_bucket.nas_cloudsync.id

  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "nas_cloudsync" {
  bucket = aws_s3_bucket.nas_cloudsync.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = aws_kms_key.phi.arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "nas_cloudsync" {
  bucket = aws_s3_bucket.nas_cloudsync.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_policy" "nas_cloudsync" {
  bucket = aws_s3_bucket.nas_cloudsync.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.nas_cloudsync.arn,
          "${aws_s3_bucket.nas_cloudsync.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_lifecycle_configuration" "nas_cloudsync" {
  bucket = aws_s3_bucket.nas_cloudsync.id

  rule {
    id     = "hot-to-cold-current"
    status = "Enabled"

    filter {
      prefix = ""
    }

    transition {
      days          = var.nas_backup_ia_transition_days
      storage_class = "STANDARD_IA"
    }

    transition {
      days          = var.nas_backup_glacier_transition_days
      storage_class = "GLACIER"
    }

    transition {
      days          = var.nas_backup_deep_archive_transition_days
      storage_class = "DEEP_ARCHIVE"
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 7
    }
  }

  rule {
    id     = "noncurrent-version-cleanup"
    status = "Enabled"

    filter {
      prefix = ""
    }

    noncurrent_version_transition {
      noncurrent_days = var.nas_backup_ia_transition_days
      storage_class   = "STANDARD_IA"
    }

    noncurrent_version_expiration {
      noncurrent_days = var.nas_cloudsync_noncurrent_expiration_days
    }
  }
}

# ──────────────────────────────────────────────────────────────────────
# DSM identity — static access key entered directly into HyperBackup's and Cloud Sync's
# S3-compatible-storage setup screens. Same static-key shape as synology_collector in
# synology_audit.tf (the NAS has no other way to authenticate to AWS today).
# ──────────────────────────────────────────────────────────────────────

resource "aws_iam_user" "synology_nas_backup" {
  name = "synology-nas-backup"

  tags = {
    Purpose = "nas-backup"
  }
}

resource "aws_iam_access_key" "synology_nas_backup" {
  user = aws_iam_user.synology_nas_backup.name
}

resource "aws_iam_user_policy" "synology_nas_backup" {
  name = "synology-nas-backup-s3-access"
  user = aws_iam_user.synology_nas_backup.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ListBackupBuckets"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation",
          "s3:ListBucketMultipartUploads",
          "s3:ListBucketVersions"
        ]
        Resource = [
          aws_s3_bucket.nas_hyperbackup.arn,
          aws_s3_bucket.nas_cloudsync.arn
        ]
      },
      {
        Sid    = "ReadWriteBackupObjects"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:DeleteObjectVersion",
          "s3:AbortMultipartUpload",
          "s3:ListMultipartUploadParts"
        ]
        Resource = [
          "${aws_s3_bucket.nas_hyperbackup.arn}/*",
          "${aws_s3_bucket.nas_cloudsync.arn}/*"
        ]
      },
      {
        Sid    = "PhiKeyUseViaS3"
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = aws_kms_key.phi.arn
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${var.region}.amazonaws.com"
          }
        }
      }
    ]
  })
}
