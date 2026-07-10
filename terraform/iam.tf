resource "aws_iam_role" "kms_key_admin" {
  name = "KmsKeyAdmin"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = var.admin_user_arns }
        Action    = "sts:AssumeRole"
        Condition = {
          Bool            = { "aws:MultiFactorAuthPresent" = "true" }
          NumericLessThan = { "aws:MultiFactorAuthAge" = "3600" }
        }
      }
    ]
  })

  tags = {
    Purpose = "kms-administration"
  }
}

resource "aws_iam_role" "audit_reader" {
  name = "AuditReader"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect    = "Allow"
        Principal = { AWS = var.admin_user_arns }
        Action    = "sts:AssumeRole"
        Condition = {
          Bool            = { "aws:MultiFactorAuthPresent" = "true" }
          NumericLessThan = { "aws:MultiFactorAuthAge" = "3600" }
        }
      },
      {
        Effect    = "Allow"
        Principal = { AWS = aws_iam_user.audit_dashboard_admin.arn }
        Action    = "sts:AssumeRole"
      }
    ]
  })

  tags = {
    Purpose = "audit"
  }
}

resource "aws_iam_user" "lab_operator" {
  name = "lab-operator"

  tags = {
    Purpose = "lab-operations"
  }
}

resource "aws_iam_access_key" "lab_operator" {
  user = aws_iam_user.lab_operator.name
}

resource "aws_iam_user" "audit_dashboard_admin" {
  name          = "AuditDashboardAdmin"
  force_destroy = true

  tags = {
    Purpose = "audit-dashboard"
  }
}

resource "aws_iam_user_login_profile" "audit_dashboard_admin" {
  user                    = aws_iam_user.audit_dashboard_admin.name
  password_length         = 32
  password_reset_required = true
}

resource "aws_iam_role" "lab_operator" {
  name                 = "LabOperatorRole"
  max_session_duration = 14400

  # Merged from BucketProvisioner (control-plane provisioning), PhiApplicationRole (PHI data
  # plane), and the ad-hoc admin identity previously used only for delete-flow IAM/bucket
  # teardown. Deliberate blast-radius increase, accepted in exchange for one operating
  # identity instead of three. S3PhiBypassRole (governance-retention bypass delete) was
  # folded in here too, and the bypass path itself was later collapsed onto the SAME
  # lab-operator identity rather than a separate human (terraform-admin): lab-operator
  # assumes this role with no MFA for routine automation, and can separately re-assume it
  # with a fresh MFA factor (its own virtual MFA device, see aws_iam_user_policy.
  # lab_operator_self_mfa) for the bypass-delete path. This trades away the isolation a
  # distinct bypass identity gave — a leaked lab-operator static key plus its MFA seed can
  # now reach the destructive Sids too — in exchange for a single operating credential. The
  # two paths land in the same role, but the destructive Sids in iam_policies.tf's
  # lab_operator policy carry their own aws:MultiFactorAuthPresent condition — gating moved
  # from "which role can you even assume" to "which permissions does your session's MFA
  # state unlock within this role."
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        # BoolIfExists + "false" (not a bare, unconditioned statement): when this same
        # principal supplies valid SerialNumber/TokenCode, this statement must NOT also
        # match, or STS has an unconditionally-allowed path available and never bothers
        # exercising the MFA-validation code path at all — leaving the resulting session
        # without aws:MultiFactorAuthPresent=true even though a valid code was supplied.
        # Confirmed empirically: with both statements unconditioned/conditioned on the same
        # principal, s3:ListBucketVersions (gated on aws:MultiFactorAuthPresent in
        # iam_policies.tf) was denied even via a fresh, valid MFA code passed straight to
        # sts:AssumeRole. Making the two statements mutually exclusive forces STS to actually
        # validate MFA whenever it's supplied.
        Sid       = "RoutineAutomationNoMfa"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_user.lab_operator.arn }
        Action    = "sts:AssumeRole"
        Condition = {
          BoolIfExists = { "aws:MultiFactorAuthPresent" = "false" }
        }
      },
      {
        Sid       = "BypassDeleteRequiresMfa"
        Effect    = "Allow"
        Principal = { AWS = aws_iam_user.lab_operator.arn }
        Action    = "sts:AssumeRole"
        Condition = {
          Bool            = { "aws:MultiFactorAuthPresent" = "true" }
          NumericLessThan = { "aws:MultiFactorAuthAge" = "3600" }
        }
      }
    ]
  })

  tags = {
    Purpose   = "lab-operations"
    DataClass = "PHI"
  }
}
