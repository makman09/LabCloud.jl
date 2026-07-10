# Published dashboard, kept DRY: the visual definition lives once in
# quicksight_analysis.tf (the editable source of truth). A template snapshots that
# analysis, and the dashboard publishes from the template. To ship visual changes:
#   1. edit aws_quicksight_analysis.audit
#   2. bump version_description below (forces a fresh template snapshot + republish)
#   3. terraform apply

resource "aws_quicksight_template" "audit" {
  aws_account_id      = var.account_id
  template_id         = "audit-dashboard-template"
  name                = "CloudTrail Audit Dashboard template"
  version_description = "v12-ip-tooltip-state"

  source_entity {
    source_analysis {
      arn = aws_quicksight_analysis.audit.arn

      data_set_references {
        data_set_placeholder = "CloudTrail Audit Dashboard"
        data_set_arn         = aws_quicksight_data_set.audit_dashboard.arn
      }

      data_set_references {
        data_set_placeholder = "Synology NAS Access"
        data_set_arn         = aws_quicksight_data_set.synology_access.arn
      }
    }
  }
}

resource "aws_quicksight_dashboard" "audit" {
  aws_account_id      = var.account_id
  dashboard_id        = "30cea662-7b49-4901-a5bf-ae0f93c46a3c"
  name                = "Audit Dashboard"
  version_description = "v12-ip-tooltip-state"

  source_entity {
    source_template {
      arn = aws_quicksight_template.audit.arn

      data_set_references {
        data_set_placeholder = "CloudTrail Audit Dashboard"
        data_set_arn         = aws_quicksight_data_set.audit_dashboard.arn
      }

      data_set_references {
        data_set_placeholder = "Synology NAS Access"
        data_set_arn         = aws_quicksight_data_set.synology_access.arn
      }
    }
  }

  lifecycle {
    ignore_changes = [permissions]
  }
}
