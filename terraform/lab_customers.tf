# Shared, account-level infra for lab customers. Per-researcher onboarding (the IAM user,
# its s3-bucket-access policy, group membership, and access key) is owned by the CLI —
# LabCustomersAPI.py / src/provision.py::create_lab_iam_user — not Terraform. This file only
# holds the group and KMS policy that every customer joins.
resource "aws_iam_group" "lab_customers" {
  name = "LabCustomers"
}

resource "aws_iam_group_policy" "lab_customers_kms" {
  name  = "lab-customers-kms-access"
  group = aws_iam_group.lab_customers.name

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
