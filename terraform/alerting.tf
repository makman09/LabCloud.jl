resource "aws_sns_topic" "phi_security_alerts" {
  name = "phi-security-alerts"

  tags = {
    Purpose = "security-monitoring"
  }
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.phi_security_alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

resource "aws_sns_topic_policy" "phi_security_alerts" {
  arn = aws_sns_topic.phi_security_alerts.arn

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowEventBridgePublish"
        Effect    = "Allow"
        Principal = { Service = "events.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.phi_security_alerts.arn
      },
      {
        Sid       = "AllowCloudWatchAlarmPublish"
        Effect    = "Allow"
        Principal = { Service = "cloudwatch.amazonaws.com" }
        Action    = "sns:Publish"
        Resource  = aws_sns_topic.phi_security_alerts.arn
        Condition = {
          StringEquals = { "aws:SourceAccount" = var.account_id }
        }
      }
    ]
  })
}

resource "aws_cloudwatch_event_rule" "bucket_tag_changes" {
  name        = "phi-bucket-tag-changes"
  description = "Detects tag changes on research-* buckets"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["PutBucketTagging", "DeleteBucketTagging"]
      requestParameters = {
        bucketName = [{ prefix = "research-" }]
      }
    }
  })

  tags = {
    Purpose = "security-monitoring"
  }
}

resource "aws_cloudwatch_event_target" "bucket_tag_changes" {
  rule      = aws_cloudwatch_event_rule.bucket_tag_changes.name
  target_id = "sns"
  arn       = aws_sns_topic.phi_security_alerts.arn

  input_transformer {
    input_paths = {
      account  = "$.account"
      region   = "$.region"
      time     = "$.time"
      action   = "$.detail.eventName"
      bucket   = "$.detail.requestParameters.bucketName"
      user     = "$.detail.userIdentity.arn"
      sourceIP = "$.detail.sourceIPAddress"
    }
    # Emit a quoted, \n-delimited plain-text template for SNS email.
    # Do NOT use jsonencode(): it HTML-escapes "<", ">", "&" into
    # < > &, which stops EventBridge from substituting
    # the <var> placeholders (and leaves \n literal in the email body).
    input_template = "\"${join("\\n", [
      "PHI Security Alert: Bucket Tag Change",
      "",
      "Account:    <account>",
      "Region:     <region>",
      "Time:       <time>",
      "Action:     <action>",
      "Bucket:     <bucket>",
      "User:       <user>",
      "Source IP:  <sourceIP>",
    ])}\""
  }
}

resource "aws_cloudwatch_event_rule" "bucket_policy_changes" {
  name        = "phi-bucket-policy-changes"
  description = "Detects policy changes on research-* buckets"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["PutBucketPolicy", "DeleteBucketPolicy"]
      requestParameters = {
        bucketName = [{ prefix = "research-" }]
      }
    }
  })

  tags = {
    Purpose = "security-monitoring"
  }
}

resource "aws_cloudwatch_event_target" "bucket_policy_changes" {
  rule      = aws_cloudwatch_event_rule.bucket_policy_changes.name
  target_id = "sns"
  arn       = aws_sns_topic.phi_security_alerts.arn

  input_transformer {
    input_paths = {
      account  = "$.account"
      region   = "$.region"
      time     = "$.time"
      action   = "$.detail.eventName"
      bucket   = "$.detail.requestParameters.bucketName"
      user     = "$.detail.userIdentity.arn"
      sourceIP = "$.detail.sourceIPAddress"
    }
    input_template = "\"${join("\\n", [
      "PHI Security Alert: Bucket Policy Change",
      "",
      "Account:    <account>",
      "Region:     <region>",
      "Time:       <time>",
      "Action:     <action>",
      "Bucket:     <bucket>",
      "User:       <user>",
      "Source IP:  <sourceIP>",
    ])}\""
  }
}

resource "aws_cloudwatch_event_rule" "bypass_role_assumed" {
  name        = "phi-bypass-role-assumed"
  description = "Detects the MFA-gated bypass-delete assumption of LabOperatorRole"

  # S3PhiBypassRole is now LabOperatorRole (see iam.tf), assumed both by the no-MFA
  # lab-operator automation user and, separately, by that same lab-operator user re-assuming
  # with a fresh MFA factor from its own virtual MFA device. Those two paths are no longer
  # distinguishable by roleArn (or even principal) alone, so this matches on the presence of
  # an MFA `serialNumber` in the AssumeRole call itself — only the bypass path ever supplies
  # one (src/aws.py's assume_bypass_role).
  event_pattern = jsonencode({
    source      = ["aws.sts"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["sts.amazonaws.com"]
      eventName   = ["AssumeRole"]
      requestParameters = {
        roleArn      = [aws_iam_role.lab_operator.arn]
        serialNumber = [{ exists = true }]
      }
    }
  })

  tags = {
    Purpose = "security-monitoring"
  }
}

resource "aws_cloudwatch_event_target" "bypass_role_assumed" {
  rule      = aws_cloudwatch_event_rule.bypass_role_assumed.name
  target_id = "sns"
  arn       = aws_sns_topic.phi_security_alerts.arn

  input_transformer {
    input_paths = {
      account  = "$.account"
      region   = "$.region"
      time     = "$.time"
      role     = "$.detail.requestParameters.roleArn"
      user     = "$.detail.userIdentity.arn"
      sourceIP = "$.detail.sourceIPAddress"
    }
    input_template = "\"${join("\\n", [
      "PHI Security Alert: Bypass Role Assumed",
      "",
      "Account:     <account>",
      "Region:      <region>",
      "Time:        <time>",
      "Role ARN:    <role>",
      "Assumed By:  <user>",
      "Source IP:   <sourceIP>",
    ])}\""
  }
}

resource "aws_cloudwatch_event_rule" "kms_destructive_actions" {
  name        = "phi-kms-destructive-actions"
  description = "Detects KMS key deletion, disable, or policy changes"

  event_pattern = jsonencode({
    source      = ["aws.kms"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["kms.amazonaws.com"]
      eventName   = ["ScheduleKeyDeletion", "DisableKey", "PutKeyPolicy"]
    }
  })

  tags = {
    Purpose = "security-monitoring"
  }
}

resource "aws_cloudwatch_event_target" "kms_destructive_actions" {
  rule      = aws_cloudwatch_event_rule.kms_destructive_actions.name
  target_id = "sns"
  arn       = aws_sns_topic.phi_security_alerts.arn

  input_transformer {
    input_paths = {
      account  = "$.account"
      region   = "$.region"
      time     = "$.time"
      action   = "$.detail.eventName"
      keyId    = "$.detail.requestParameters.keyId"
      user     = "$.detail.userIdentity.arn"
      sourceIP = "$.detail.sourceIPAddress"
    }
    input_template = "\"${join("\\n", [
      "PHI Security Alert: KMS Destructive Action",
      "",
      "Account:    <account>",
      "Region:     <region>",
      "Time:       <time>",
      "Action:     <action>",
      "Key ID:     <keyId>",
      "User:       <user>",
      "Source IP:  <sourceIP>",
    ])}\""
  }
}

resource "aws_cloudwatch_event_rule" "object_lock_bypass_deletes" {
  name        = "phi-object-lock-bypass-deletes"
  description = "Detects Object Lock governance bypass deletes on research-* buckets"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["DeleteObject", "DeleteObjectVersion"]
      requestParameters = {
        bucketName                          = [{ prefix = "research-" }]
        "x-amz-bypass-governance-retention" = ["true"]
      }
    }
  })

  tags = {
    Purpose = "security-monitoring"
  }
}

resource "aws_cloudwatch_event_target" "object_lock_bypass_deletes" {
  rule      = aws_cloudwatch_event_rule.object_lock_bypass_deletes.name
  target_id = "sns"
  arn       = aws_sns_topic.phi_security_alerts.arn

  input_transformer {
    input_paths = {
      account   = "$.account"
      region    = "$.region"
      time      = "$.time"
      action    = "$.detail.eventName"
      bucket    = "$.detail.requestParameters.bucketName"
      objectKey = "$.detail.requestParameters.key"
      user      = "$.detail.userIdentity.arn"
      sourceIP  = "$.detail.sourceIPAddress"
    }
    input_template = "\"${join("\\n", [
      "PHI Security Alert: Object Lock Bypass Delete",
      "",
      "Account:     <account>",
      "Region:      <region>",
      "Time:        <time>",
      "Action:      <action>",
      "Bucket:      <bucket>",
      "Object Key:  <objectKey>",
      "User:        <user>",
      "Source IP:   <sourceIP>",
    ])}\""
  }
}

resource "aws_cloudwatch_event_rule" "bucket_deleted" {
  name        = "phi-bucket-deleted"
  description = "Detects deletion of research-* buckets"

  event_pattern = jsonencode({
    source      = ["aws.s3"]
    detail-type = ["AWS API Call via CloudTrail"]
    detail = {
      eventSource = ["s3.amazonaws.com"]
      eventName   = ["DeleteBucket"]
      requestParameters = {
        bucketName = [{ prefix = "research-" }]
      }
    }
  })

  tags = {
    Purpose = "security-monitoring"
  }
}

resource "aws_cloudwatch_event_target" "bucket_deleted" {
  rule      = aws_cloudwatch_event_rule.bucket_deleted.name
  target_id = "sns"
  arn       = aws_sns_topic.phi_security_alerts.arn

  input_transformer {
    input_paths = {
      account  = "$.account"
      region   = "$.region"
      time     = "$.time"
      bucket   = "$.detail.requestParameters.bucketName"
      user     = "$.detail.userIdentity.arn"
      sourceIP = "$.detail.sourceIPAddress"
    }
    input_template = "\"${join("\\n", [
      "PHI Security Alert: Bucket Deleted",
      "",
      "Account:    <account>",
      "Region:     <region>",
      "Time:       <time>",
      "Bucket:     <bucket>",
      "User:       <user>",
      "Source IP:  <sourceIP>",
    ])}\""
  }
}

resource "aws_cloudwatch_event_rule" "athena_query_failures" {
  name        = "audit-athena-query-failures"
  description = "Detects failed Athena queries in the audit workgroup"

  event_pattern = jsonencode({
    source      = ["aws.athena"]
    detail-type = ["Athena Query State Change"]
    detail = {
      currentState  = ["FAILED"]
      workGroupName = [aws_athena_workgroup.audit.name]
    }
  })

  tags = {
    Purpose = "security-monitoring"
  }
}

resource "aws_cloudwatch_event_target" "athena_query_failures" {
  rule      = aws_cloudwatch_event_rule.athena_query_failures.name
  target_id = "sns"
  arn       = aws_sns_topic.phi_security_alerts.arn

  input_transformer {
    input_paths = {
      account   = "$.account"
      region    = "$.region"
      time      = "$.time"
      queryId   = "$.detail.queryExecutionId"
      workgroup = "$.detail.workGroupName"
      state     = "$.detail.currentState"
    }
    input_template = "\"${join("\\n", [
      "Audit Alert: Athena Query Failed",
      "",
      "Account:    <account>",
      "Region:     <region>",
      "Time:       <time>",
      "Query ID:   <queryId>",
      "Workgroup:  <workgroup>",
      "State:      <state>",
    ])}\""
  }
}
