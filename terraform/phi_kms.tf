resource "aws_kms_key" "phi" {
  description             = "Encrypts PHI at rest in research-* S3 buckets"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  tags = {
    Purpose   = "research"
    DataClass = "PHI"
  }
}

resource "aws_kms_alias" "phi" {
  name          = "alias/phi-research-key"
  target_key_id = aws_kms_key.phi.key_id
}

resource "aws_kms_key_policy" "phi" {
  key_id = aws_kms_key.phi.id

  policy = jsonencode({
    Id      = "hipaa-phi-key-policy"
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
        Sid       = "AllowKeyAdministration"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.kms_key_admin.arn }
        Action = [
          "kms:Create*",
          "kms:Describe*",
          "kms:Enable*",
          "kms:List*",
          "kms:Put*",
          "kms:Update*",
          "kms:Revoke*",
          "kms:Disable*",
          "kms:Get*",
          "kms:TagResource",
          "kms:UntagResource"
        ]
        Resource = "*"
      },
      {
        Sid       = "AllowKeyDeletionOnlyWithMFA"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.kms_key_admin.arn }
        Action = [
          "kms:ScheduleKeyDeletion",
          "kms:CancelKeyDeletion"
        ]
        Resource = "*"
        Condition = {
          Bool = { "aws:MultiFactorAuthPresent" = "true" }
        }
      },
      {
        Sid       = "AllowLabOperatorEncrypt"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.lab_operator.arn }
        Action = [
          "kms:Encrypt",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${var.region}.amazonaws.com"
          }
        }
      },
      {
        # Also covers what used to be a separate "AllowDecryptForBypassRole" statement:
        # S3PhiBypassRole is now LabOperatorRole (see iam.tf), so an MFA-conditioned Decrypt
        # grant for that principal here would just be a redundant subset of this unconditioned
        # one — same principal, same kms:ViaService/EncryptionContext scope.
        Sid       = "AllowLabOperatorDecrypt"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.lab_operator.arn }
        Action = [
          "kms:Decrypt",
          "kms:ReEncrypt*"
        ]
        Resource = "*"
        Condition = {
          StringEquals = {
            "kms:ViaService" = "s3.${var.region}.amazonaws.com"
          }
          StringLike = {
            "kms:EncryptionContext:aws:s3:arn" = [
              "arn:aws:s3:::research-*",
              "arn:aws:s3:::research-*/*"
            ]
          }
        }
      },
      {
        Sid       = "AllowLabOperatorGrants"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_role.lab_operator.arn }
        Action = [
          "kms:CreateGrant",
          "kms:ListGrants",
          "kms:RevokeGrant"
        ]
        Resource = "*"
        Condition = {
          Bool = { "kms:GrantIsForAWSResource" = "true" }
        }
      },
      {
        Sid       = "DenyDestructiveActionsWithoutMFA"
        Effect    = "Deny"
        Principal = "*"
        Action = [
          "kms:ScheduleKeyDeletion",
          "kms:DisableKey"
        ]
        Resource = "*"
        Condition = {
          BoolIfExists = { "aws:MultiFactorAuthPresent" = "false" }
        }
      }
    ]
  })
}
