output "audit_kms_key_arn" {
  value = aws_kms_key.audit.arn
}

output "audit_bucket_arn" {
  value = aws_s3_bucket.audit_logs.arn
}

output "audit_bucket_id" {
  value = aws_s3_bucket.audit_logs.id
}

output "audit_reader_role_arn" {
  value = aws_iam_role.audit_reader.arn
}

output "lab_operator_role_arn" {
  value = aws_iam_role.lab_operator.arn
}

output "lab_operator_access_key_id" {
  value = aws_iam_access_key.lab_operator.id
}

output "lab_operator_secret_access_key" {
  value     = aws_iam_access_key.lab_operator.secret
  sensitive = true
}

output "athena_workgroup_name" {
  value = aws_athena_workgroup.audit.name
}

output "athena_results_bucket_id" {
  value = aws_s3_bucket.athena_results.id
}

output "glue_database_name" {
  value = aws_glue_catalog_database.security_audit.name
}

output "audit_dashboard_admin_username" {
  value = aws_iam_user.audit_dashboard_admin.name
}

output "audit_dashboard_admin_password" {
  value     = aws_iam_user_login_profile.audit_dashboard_admin.password
  sensitive = true
}

output "quicksight_audit_admins_group_arn" {
  value = aws_quicksight_group.audit_admins.arn
}

output "quicksight_audit_viewers_group_arn" {
  value = aws_quicksight_group.audit_viewers.arn
}

output "quicksight_audit_log_group" {
  value = aws_cloudwatch_log_group.quicksight_audit.name
}

output "synology_firehose_stream_name" {
  value = aws_kinesis_firehose_delivery_stream.synology.name
}

output "synology_collector_access_key_id" {
  value = aws_iam_access_key.synology_collector.id
}

output "synology_collector_secret_access_key" {
  value     = aws_iam_access_key.synology_collector.secret
  sensitive = true
}

output "nas_hyperbackup_bucket_id" {
  value = aws_s3_bucket.nas_hyperbackup.id
}

output "nas_cloudsync_bucket_id" {
  value = aws_s3_bucket.nas_cloudsync.id
}

output "synology_nas_backup_access_key_id" {
  value = aws_iam_access_key.synology_nas_backup.id
}

output "synology_nas_backup_secret_access_key" {
  value     = aws_iam_access_key.synology_nas_backup.secret
  sensitive = true
}
