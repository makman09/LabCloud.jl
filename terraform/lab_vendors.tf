# Shared, account-level infra for lab vendors — the inbound counterpart to lab_customers.tf.
# Per-vendor onboarding (the IAM user, its s3-bucket-access policy, group membership, and access
# key) is owned by the CLI — LabVendorAPI.py / src/provision.py::create_vendor_iam_user — not
# Terraform. This file only holds the group and KMS policy that every vendor joins.
#
# KMS note: the vendor user gets phi-key use via this group policy plus the key's
# EnableRootAccountPermissions account delegation (see phi_kms.tf) — exactly the path
# LabCustomers uses. The key policy itself is intentionally NOT edited. Do not add an
# encryption-context condition here: vendor objects live in `caucell-*-landing`, not `research-*`.
resource "aws_iam_group" "lab_vendors" {
  name = "LabVendors"
}

resource "aws_iam_group_policy" "lab_vendors_kms" {
  name  = "lab-vendors-kms-access"
  group = aws_iam_group.lab_vendors.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
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
