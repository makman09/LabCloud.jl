resource "aws_iam_role_policy" "audit_reader" {
  name = "audit-log-read-access"
  role = aws_iam_role.audit_reader.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ReadAuditBucket"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.audit_logs.arn,
          "${aws_s3_bucket.audit_logs.arn}/*"
        ]
      },
      {
        Sid    = "CloudTrailLookup"
        Effect = "Allow"
        Action = [
          "cloudtrail:LookupEvents",
          "cloudtrail:GetTrailStatus",
          "cloudtrail:DescribeTrails"
        ]
        Resource = "*"
      },
      {
        Sid    = "DenyAuditLogModification"
        Effect = "Deny"
        Action = [
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:DeleteObjectVersion"
        ]
        Resource = "${aws_s3_bucket.audit_logs.arn}/*"
      },
      {
        Sid    = "AthenaQueryAccess"
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
        Sid    = "GlueCatalogRead"
        Effect = "Allow"
        Action = [
          "glue:GetDatabase",
          "glue:GetTable",
          "glue:GetPartitions",
          "glue:GetPartition"
        ]
        Resource = [
          "arn:aws:glue:${var.region}:${var.account_id}:catalog",
          "arn:aws:glue:${var.region}:${var.account_id}:database/${aws_glue_catalog_database.security_audit.name}",
          "arn:aws:glue:${var.region}:${var.account_id}:table/${aws_glue_catalog_database.security_audit.name}/*"
        ]
      },
      {
        Sid    = "ResultsBucketAccess"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:GetBucketLocation",
          "s3:ListBucket"
        ]
        Resource = [
          aws_s3_bucket.athena_results.arn,
          "${aws_s3_bucket.athena_results.arn}/*"
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

resource "aws_iam_role_policy" "lab_operator" {
  name = "lab-operator-access"
  role = aws_iam_role.lab_operator.id

  # Union of the former BucketProvisioner (control-plane), PhiApplicationRole (PHI data
  # plane), admin-delete-flow, and S3PhiBypassRole grants. Note what's deliberately absent: no
  # DenyPHIReadAndDestroy guardrail (this role must read PHI content) and no read on
  # caucell-*-landing/* outside the bypass Sid (vendor landing stays ingest-only for routine
  # ops, matching the pre-existing boundary). ListResearchPhiBuckets and
  # BypassAndDeleteLockedObjects are the former phi_bypass_s3 policy verbatim, each carrying
  # its own aws:MultiFactorAuthPresent condition — the lab-operator user's routine (no-MFA)
  # session can never satisfy it, only a session re-assumed with a fresh MFA factor from
  # lab-operator's own virtual MFA device (see iam.tf's BypassDeleteRequiresMfa trust
  # statement and aws_iam_user_policy.lab_operator_self_mfa) can.
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ListResearchPhiBuckets"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:ListBucketVersions",
          # Teardown must find in-flight multipart uploads: a versioned bucket with zero
          # object versions still refuses delete_bucket while any multipart upload is open.
          "s3:ListBucketMultipartUploads"
        ]
        Resource = [
          "arn:aws:s3:::research-*",
          "arn:aws:s3:::caucell-*-landing"
        ]
        Condition = {
          Bool = { "aws:MultiFactorAuthPresent" = "true" }
        }
      },
      {
        Sid    = "BypassAndDeleteLockedObjects"
        Effect = "Allow"
        Action = [
          "s3:BypassGovernanceRetention",
          "s3:PutObjectRetention",
          "s3:DeleteObject",
          "s3:DeleteObjectVersion",
          "s3:GetObject",
          "s3:GetObjectVersion",
          # Abort in-flight multipart uploads during teardown (paired with the
          # ListBucketMultipartUploads grant above).
          "s3:AbortMultipartUpload"
        ]
        Resource = [
          "arn:aws:s3:::research-*/*",
          "arn:aws:s3:::caucell-*-landing/*"
        ]
        Condition = {
          Bool = { "aws:MultiFactorAuthPresent" = "true" }
        }
      },
      {
        Sid    = "S3BucketManagementAndTeardown"
        Effect = "Allow"
        Action = [
          "s3:CreateBucket",
          "s3:PutBucketTagging",
          "s3:PutBucketPolicy",
          "s3:PutEncryptionConfiguration",
          "s3:PutBucketObjectLockConfiguration",
          "s3:PutBucketVersioning",
          "s3:PutBucketPublicAccessBlock",
          "s3:PutLifecycleConfiguration",
          "s3:ListBucket",
          "s3:DeleteBucketPolicy",
          "s3:DeleteBucket"
        ]
        Resource = [
          "arn:aws:s3:::research-*",
          "arn:aws:s3:::caucell-*-landing"
        ]
      },
      {
        Sid      = "S3ListAllBuckets"
        Effect   = "Allow"
        Action   = "s3:ListAllMyBuckets"
        Resource = "*"
      },
      {
        Sid    = "S3ResearchObjectReadWrite"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:PutObject",
          "s3:DeleteObject"
        ]
        Resource = "arn:aws:s3:::research-*/*"
      },
      {
        Sid      = "S3LandingPlaceholderPut"
        Effect   = "Allow"
        Action   = "s3:PutObject"
        Resource = "arn:aws:s3:::caucell-*-landing/*"
      },
      {
        Sid    = "S3ResearchBucketMetadata"
        Effect = "Allow"
        Action = [
          "s3:GetBucketLocation",
          "s3:GetBucketVersioning",
          "s3:GetEncryptionConfiguration"
        ]
        Resource = "arn:aws:s3:::research-*"
      },
      {
        Sid    = "IAMUserLifecycle"
        Effect = "Allow"
        Action = [
          "iam:CreateUser",
          "iam:TagUser",
          "iam:PutUserPolicy",
          "iam:CreateAccessKey",
          "iam:ListAccessKeys",
          "iam:DeleteAccessKey",
          "iam:DeleteUserPolicy",
          "iam:DeleteLoginProfile",
          "iam:DeleteUser"
        ]
        Resource = [
          # New customers live under the /lab-customers/ IAM path (bare username); this path
          # literal is coupled to LAB_CUSTOMER_PATH in LabAPI/Provision.jl. The LabCustomer-*
          # entry is retained so retroactive (pre-path) users stay manageable.
          "arn:aws:iam::${var.account_id}:user/lab-customers/*",
          "arn:aws:iam::${var.account_id}:user/LabCustomer-*",
          "arn:aws:iam::${var.account_id}:user/LabVendor-*"
        ]
      },
      {
        Sid    = "IAMGroupMembership"
        Effect = "Allow"
        Action = [
          "iam:AddUserToGroup",
          "iam:RemoveUserFromGroup"
        ]
        Resource = [
          "arn:aws:iam::${var.account_id}:group/LabCustomers",
          "arn:aws:iam::${var.account_id}:group/LabVendors"
        ]
      },
      {
        Sid      = "KMSDescribeKey"
        Effect   = "Allow"
        Action   = "kms:DescribeKey"
        Resource = aws_kms_key.phi.arn
      }
    ]
  })
}

resource "aws_iam_user_policy" "lab_operator_self_mfa" {
  # Lets lab-operator manage its own virtual MFA device: look up/provision it before
  # re-assuming LabOperatorRole via the BypassDeleteRequiresMfa trust statement (iam.tf).
  # terraform-admin can't be granted this instead — its permissions boundary
  # (terraform-admin-boundary) explicitly denies iam:PutUserPolicy et al. targeting its own
  # user, to block self-privilege-escalation. terraform-admin CAN still write policies onto
  # OTHER users (this one, e.g.), just never onto itself — so lab-operator provisioning its
  # own MFA device is both the simpler and the only viable path.
  #
  # sts:GetSessionToken (Resource always "*" — the action has no resource-level permissions):
  # AWSIdent.jl's assume_bypass_role no longer passes SerialNumber/TokenCode straight to
  # sts:AssumeRole — confirmed empirically that a single-step AssumeRole-with-MFA call can
  # leave the resulting session without aws:MultiFactorAuthPresent=true when the same
  # principal also has an unconditional assume path (STS doesn't reliably exercise MFA
  # validation if it isn't needed to authorize the call). Instead it first calls
  # GetSessionToken with the MFA code to get a genuinely MFA'd temporary session for
  # lab-operator itself, THEN assumes LabOperatorRole from that session with no MFA params
  # needed — STS propagates aws:MultiFactorAuthPresent=true from an already-MFA'd caller into
  # any role it assumes, unambiguously.
  name = "lab-operator-self-mfa"
  user = aws_iam_user.lab_operator.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "ManageOwnMfaDevice"
        Effect = "Allow"
        Action = [
          "iam:ListMFADevices",
          "iam:GetUser",
          "iam:CreateVirtualMFADevice",
          "iam:EnableMFADevice",
          "iam:DeactivateMFADevice",
          "iam:DeleteVirtualMFADevice",
        ]
        Resource = [
          aws_iam_user.lab_operator.arn,
          "arn:aws:iam::${var.account_id}:mfa/lab-operator-mfa",
        ]
      },
      {
        Sid      = "MfaSessionToken"
        Effect   = "Allow"
        Action   = "sts:GetSessionToken"
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_user_policy" "audit_dashboard_admin" {
  name = "audit-dashboard-admin-access"
  user = aws_iam_user.audit_dashboard_admin.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "QuickSightAccess"
        Effect = "Allow"
        Action = [
          "quicksight:*"
        ]
        Resource = "*"
      },
      {
        Sid    = "QuickSightServiceRoleConfig"
        Effect = "Allow"
        Action = [
          "iam:PassRole"
        ]
        Resource = aws_iam_role.quicksight_service.arn
        Condition = {
          StringEquals = {
            "iam:PassedToService" = "quicksight.amazonaws.com"
          }
        }
      },
      {
        Sid      = "AssumeAuditReaderRole"
        Effect   = "Allow"
        Action   = "sts:AssumeRole"
        Resource = aws_iam_role.audit_reader.arn
      },
      {
        Sid    = "AllowChangeOwnPassword"
        Effect = "Allow"
        Action = [
          "iam:ChangePassword",
          "iam:GetAccountPasswordPolicy"
        ]
        Resource = aws_iam_user.audit_dashboard_admin.arn
      },
      {
        Sid    = "AthenaAccess"
        Effect = "Allow"
        Action = [
          "athena:StartQueryExecution",
          "athena:GetQueryExecution",
          "athena:GetQueryResults",
          "athena:StopQueryExecution",
          "athena:GetWorkGroup",
          "athena:ListWorkGroups"
        ]
        Resource = [
          "arn:aws:athena:${var.region}:${var.account_id}:workgroup/${aws_athena_workgroup.audit.name}",
          "arn:aws:athena:${var.region}:${var.account_id}:workgroup/primary"
        ]
      },
      {
        Sid    = "GlueReadAccess"
        Effect = "Allow"
        Action = [
          "glue:GetDatabase",
          "glue:GetDatabases",
          "glue:GetTable",
          "glue:GetTables",
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
        Sid    = "AuditS3Access"
        Effect = "Allow"
        Action = [
          "s3:GetObject",
          "s3:ListBucket",
          "s3:GetBucketLocation"
        ]
        Resource = [
          aws_s3_bucket.audit_logs.arn,
          "${aws_s3_bucket.audit_logs.arn}/*"
        ]
      },
      {
        Sid    = "ResultsS3Access"
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
        Sid    = "KmsDecryptAuditLogs"
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

resource "aws_iam_role_policy" "kms_admin_put_key_policy" {
  name = "kms-put-key-policy"
  role = aws_iam_role.kms_key_admin.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "kms:PutKeyPolicy"
        Resource = aws_kms_key.phi.arn
        Condition = {
          Bool = { "aws:MultiFactorAuthPresent" = "true" }
        }
      }
    ]
  })
}
